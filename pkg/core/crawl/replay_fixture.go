package crawl

import (
	"errors"
	"net/url"
	"sort"
	"strings"
	"time"
)

// ErrReplayNotAuthorized is returned when a replay fixture is requested
// without explicit authorization. Replay fixtures contain credential-bearing
// material and are only legitimate for authorized targets.
var ErrReplayNotAuthorized = errors.New("crawl: replay fixtures require explicit authorization")

// ReplayFixture is a real replay sample captured from runtime traffic. It is
// memory-only (never persisted) and short-lived: raw body, multi-value
// headers, cookie/credential references, content-type, encoding, the
// initiating page, and refresh info for dynamic parameters. Build it only
// under authorization via BuildReplayFixture.
type ReplayFixture struct {
	OperationID   string                `json:"-"`
	URL           string                `json:"-"`
	Method        string                `json:"-"`
	Headers       map[string][]string   `json:"-"`
	Body          []byte                `json:"-"`
	ContentType   string                `json:"-"`
	Encoding      string                `json:"-"`
	PageURL       string                `json:"-"`
	CapturedAt    time.Time             `json:"-"`
	ExpiresAt     time.Time             `json:"-"`
	DynamicParams []DynamicParamRefresh `json:"-"`
}

// DynamicParamRefresh marks a parameter whose captured value goes stale and
// must be refreshed from live traffic on each replay (token, signature,
// nonce, timestamp).
type DynamicParamRefresh struct {
	Name          string `json:"-"`
	Location      string `json:"-"` // header | query | body | cookie
	Kind          string `json:"-"` // token | signature | nonce | timestamp | session
	CapturedValue string `json:"-"`
}

// replayFixtureTTL bounds how long a fixture may be considered fresh.
const replayFixtureTTL = 30 * time.Minute

// BuildReplayFixture builds an in-memory replay fixture from one runtime
// network record. It refuses to run without explicit authorization.
func BuildReplayFixture(record NetworkRecord, authorized bool) (ReplayFixture, error) {
	if !authorized {
		return ReplayFixture{}, ErrReplayNotAuthorized
	}
	fixture := ReplayFixture{
		URL:         strings.TrimSpace(record.URL),
		Method:      strings.ToUpper(strings.TrimSpace(record.Method)),
		Headers:     make(map[string][]string, len(record.RequestHeaders)),
		Body:        []byte(record.RequestBody),
		PageURL:     strings.TrimSpace(record.PageURL),
		CapturedAt:  record.FetchedAt,
		ExpiresAt:   record.FetchedAt.Add(replayFixtureTTL),
		ContentType: strings.TrimSpace(record.RequestHeaders["Content-Type"]),
	}
	if fixture.ContentType == "" {
		fixture.ContentType = strings.TrimSpace(record.RequestHeaders["content-type"])
	}
	for name, value := range record.RequestHeaders {
		fixture.Headers[name] = []string{value}
	}
	fixture.OperationID = replayFixtureOperationID(fixture.Method, fixture.URL)
	fixture.DynamicParams = detectReplayDynamicParams(fixture)
	return fixture, nil
}

// BuildReplayFixtures builds fixtures for a record set, stopping at the first
// authorization failure.
func BuildReplayFixtures(records []NetworkRecord, authorized bool) ([]ReplayFixture, error) {
	if !authorized {
		return nil, ErrReplayNotAuthorized
	}
	fixtures := make([]ReplayFixture, 0, len(records))
	for _, record := range records {
		fixture, err := BuildReplayFixture(record, authorized)
		if err != nil {
			return nil, err
		}
		fixtures = append(fixtures, fixture)
	}
	return fixtures, nil
}

// IsFresh reports whether the fixture is still within its short-term TTL.
func (fixture ReplayFixture) IsFresh(now time.Time) bool {
	return now.Before(fixture.ExpiresAt)
}

func replayFixtureOperationID(method, rawURL string) string {
	parsed, err := url.Parse(rawURL)
	path := strings.TrimSpace(rawURL)
	if err == nil && parsed.Path != "" {
		path = parsed.Path
	}
	return buildOperationSpecID(OperationSpec{Method: method, PathTemplate: path})
}

// detectReplayDynamicParams scans headers, query, and the JSON body for
// parameters that go stale between capture and replay.
func detectReplayDynamicParams(fixture ReplayFixture) []DynamicParamRefresh {
	result := make([]DynamicParamRefresh, 0, 4)

	for name, values := range fixture.Headers {
		kind := dynamicParamKind(name)
		if kind == "" {
			continue
		}
		for _, value := range values {
			result = append(result, DynamicParamRefresh{
				Name:          name,
				Location:      "header",
				Kind:          kind,
				CapturedValue: value,
			})
		}
	}

	if parsed, err := url.Parse(fixture.URL); err == nil {
		for name, values := range parsed.Query() {
			kind := dynamicParamKind(name)
			if kind == "" {
				continue
			}
			for _, value := range values {
				result = append(result, DynamicParamRefresh{
					Name:          name,
					Location:      "query",
					Kind:          kind,
					CapturedValue: value,
				})
			}
		}
	}

	if strings.Contains(strings.ToLower(fixture.ContentType), "json") && len(fixture.Body) > 0 {
		for _, name := range topLevelJSONKeys(string(fixture.Body)) {
			kind := dynamicParamKind(name)
			if kind == "" {
				continue
			}
			result = append(result, DynamicParamRefresh{
				Name:     name,
				Location: "body",
				Kind:     kind,
			})
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Location == result[j].Location {
			return result[i].Name < result[j].Name
		}
		return result[i].Location < result[j].Location
	})
	return result
}

// dynamicParamKind classifies a dynamic parameter name into a refresh kind.
func dynamicParamKind(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(lower, "timestamp") || lower == "ts" || strings.HasSuffix(lower, "_ts"):
		return "timestamp"
	case strings.Contains(lower, "nonce"):
		return "nonce"
	case strings.Contains(lower, "sign"):
		return "signature"
	case strings.Contains(lower, "token") || strings.Contains(lower, "ticket") ||
		strings.Contains(lower, "session") || strings.Contains(lower, "csrf") ||
		strings.Contains(lower, "xsrf") || lower == "authorization" || lower == "cookie":
		return "token"
	default:
		return ""
	}
}

// topLevelJSONKeys extracts top-level keys of a JSON object body without
// failing on malformed payloads.
func topLevelJSONKeys(body string) []string {
	body = strings.TrimSpace(body)
	if !strings.HasPrefix(body, "{") {
		return nil
	}
	keys := make([]string, 0, 8)
	depth := 0
	quote := byte(0)
	escaped := false
	keyStart := -1
	for index := 0; index < len(body); index++ {
		ch := body[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				if depth == 1 && keyStart >= 0 {
					keys = append(keys, body[keyStart+1:index])
					keyStart = -1
				}
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'':
			if depth == 1 {
				quote = ch
				keyStart = index
			} else {
				quote = ch
			}
		case '{', '[':
			depth++
		case '}', ']':
			depth--
		}
	}
	return keys
}

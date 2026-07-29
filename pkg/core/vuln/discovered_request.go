package vuln

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/qiwentaidi/clients"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
)

const shiroRememberMeProbeCookie = "rememberMe=true"
const fastjsonProbeBody = `{"\u0040\u0074\u0079\u0070\u0065":"java.lang.AutoCloseabl\u0065"}`

// ScanDiscoveredRequests runs special-purpose checks against requests observed
// by the dynamic browser capture.  It is deliberately separate from the
// generic API replay scanner: each detector can use only the evidence that is
// appropriate for it and avoid path guessing.
func ScanDiscoveredRequests(targetURL string, requests []structs.DiscoveredRequest, enabled bool) []structs.FingerprintResult {
	if !enabled || len(requests) == 0 {
		return nil
	}

	results := scanFastjsonDiscoveredEndpoints(requests)
	results = append(results, scanShiroDiscoveredEndpoints(targetURL, requests)...)
	return mergeFingerprintResults(results)
}

// SelectShiroCandidates returns only concrete, same-origin, non-root endpoint
// URLs.  Shiro's rememberMe probe must not inherit a captured method, headers,
// body, or query values, and it must never create a root-path probe.
func SelectShiroCandidates(targetURL string, requests []structs.DiscoveredRequest) []string {
	target, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil
	}

	seen := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		candidate, err := url.Parse(strings.TrimSpace(request.URL))
		if err != nil || candidate.Scheme == "" || candidate.Host == "" {
			continue
		}
		if !sameOrigin(target, candidate) || isRootPath(candidate.Path) {
			continue
		}

		// The probe models the reference implementation's URL-only behavior:
		// request-specific query parameters and fragments are never replayed.
		candidate.RawQuery = ""
		candidate.ForceQuery = false
		candidate.Fragment = ""
		candidate.RawFragment = ""
		candidate.RawPath = ""
		seen[candidate.String()] = struct{}{}
	}

	result := make([]string, 0, len(seen))
	for candidate := range seen {
		result = append(result, candidate)
	}
	sort.Strings(result)
	return result
}

// SelectFastjsonCandidates is the selection boundary for the future Fastjson
// detector.  It deliberately retains the full captured request, so a probe can
// fingerprint and de-duplicate JSON requests without changing Shiro's URL-only
// policy.
func SelectFastjsonCandidates(requests []structs.DiscoveredRequest) []structs.DiscoveredRequest {
	seen := make(map[string]struct{}, len(requests))
	result := make([]structs.DiscoveredRequest, 0, len(requests))
	for _, request := range requests {
		if !isJSONRequest(request) {
			continue
		}
		fingerprint := DiscoveredRequestFingerprint(request)
		if fingerprint == "" {
			continue
		}
		if _, exists := seen[fingerprint]; exists {
			continue
		}
		seen[fingerprint] = struct{}{}
		result = append(result, request)
	}
	return result
}

// DiscoveredRequestFingerprint is stable for the fields that affect a JSON
// request.  It provides the de-duplication key required by request-aware
// detectors without including volatile authentication headers.
func DiscoveredRequestFingerprint(request structs.DiscoveredRequest) string {
	parsed, err := url.Parse(strings.TrimSpace(request.URL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	method := strings.ToUpper(strings.TrimSpace(request.Method))
	if method == "" {
		method = http.MethodGet
	}
	return strings.Join([]string{
		method,
		strings.ToLower(parsed.Scheme),
		strings.ToLower(parsed.Host),
		parsed.EscapedPath(),
		parsed.RawQuery,
		discoveredRequestContentType(request),
		strings.TrimSpace(request.Body),
	}, "\x00")
}

func scanShiroDiscoveredEndpoints(targetURL string, requests []structs.DiscoveredRequest) []structs.FingerprintResult {
	candidates := SelectShiroCandidates(targetURL, requests)
	findings := make([]structs.FingerprintResult, 0, len(candidates))
	for _, candidate := range candidates {
		response, err := clients.DoRequest(http.MethodGet, candidate, map[string]string{"Cookie": shiroRememberMeProbeCookie}, nil, 10, clients.NewRestyClient(nil, true))
		if err != nil || response == nil {
			continue
		}

		setCookies := response.Header().Values("Set-Cookie")
		if !hasShiroDeleteMeCookie(setCookies) {
			continue
		}

		body := response.Body()
		result := newFingerprintResult(candidate)
		result.StatusCode = response.StatusCode()
		result.Length = len(body)
		result.Title = clients.GetTitle(body)
		result.Detect = "DiscoveredRequestShiro"
		result.Fingerprints = []structs.FingerprintMatch{{Name: "shiro"}}
		findings = append(findings, result)
	}
	return findings
}

func scanFastjsonDiscoveredEndpoints(requests []structs.DiscoveredRequest) []structs.FingerprintResult {
	candidates := SelectFastjsonCandidates(requests)
	seen := make(map[string]struct{}, len(candidates))
	results := make([]structs.FingerprintResult, 0, len(candidates))
	for _, candidate := range candidates {
		if !hasJSONBody(candidate) {
			continue
		}
		requestURL := strings.TrimSpace(candidate.URL)
		if _, exists := seen[requestURL]; exists {
			continue
		}
		seen[requestURL] = struct{}{}

		result := newFingerprintResult(requestURL)
		result.StatusCode = candidate.ResponseCode
		result.Length = len(candidate.ResponseBody)
		result.Title = clients.GetTitle([]byte(candidate.ResponseBody))
		result.Detect = candidate.Source
		result.Fingerprints = []structs.FingerprintMatch{{Name: "json-request"}}

		response, err := clients.DoRequest(
			http.MethodPost,
			requestURL,
			map[string]string{"Content-Type": "application/json"},
			strings.NewReader(fastjsonProbeBody),
			10,
			clients.NewRestyClient(nil, true),
		)
		if err != nil || response == nil {
			results = append(results, result)
			continue
		}

		body := response.Body()
		if bytes.Contains(body, []byte("fastjson-version")) {
			result.StatusCode = response.StatusCode()
			result.Length = len(body)
			result.Title = clients.GetTitle(body)
			result.Detect = "DiscoveredRequestFastjson"
			result.Fingerprints = []structs.FingerprintMatch{{Name: "fastjson"}}
		}

		results = append(results, result)
	}
	return results
}

func newFingerprintResult(rawURL string) structs.FingerprintResult {
	return structs.FingerprintResult{URL: rawURL}
}

func mergeFingerprintResults(items []structs.FingerprintResult) []structs.FingerprintResult {
	byURL := make(map[string]structs.FingerprintResult, len(items))
	for _, item := range items {
		if item.URL == "" || len(item.Fingerprints) == 0 {
			continue
		}
		current := byURL[item.URL]
		if current.URL == "" {
			current = item
		} else {
			mergeFingerprintResultDetails(&current, item)
			current.Fingerprints = append(current.Fingerprints, item.Fingerprints...)
		}
		current.Fingerprints = dedupeFingerprintMatches(current.Fingerprints)
		byURL[item.URL] = current
	}

	urls := make([]string, 0, len(byURL))
	for requestURL := range byURL {
		urls = append(urls, requestURL)
	}
	sort.Strings(urls)
	results := make([]structs.FingerprintResult, 0, len(urls))
	for _, requestURL := range urls {
		results = append(results, byURL[requestURL])
	}
	return results
}

func mergeFingerprintResultDetails(current *structs.FingerprintResult, incoming structs.FingerprintResult) {
	if current.StatusCode == 0 {
		current.StatusCode = incoming.StatusCode
	}
	if current.Length == 0 {
		current.Length = incoming.Length
	}
	if current.Title == "" {
		current.Title = incoming.Title
	}
	if current.Detect == "" {
		current.Detect = incoming.Detect
	}
}

func dedupeFingerprintMatches(matches []structs.FingerprintMatch) []structs.FingerprintMatch {
	seen := make(map[string]struct{}, len(matches))
	result := make([]structs.FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		key := match.Name
		if match.Name == "" {
			continue
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, match)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func hasShiroDeleteMeCookie(values []string) bool {
	for _, value := range values {
		pair := strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
		keyValue := strings.SplitN(pair, "=", 2)
		if len(keyValue) != 2 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(keyValue[0]), "rememberMe") && strings.EqualFold(strings.TrimSpace(keyValue[1]), "deleteMe") {
			return true
		}
	}
	return false
}

func isJSONRequest(request structs.DiscoveredRequest) bool {
	contentType := discoveredRequestContentType(request)
	return strings.Contains(contentType, "application/json") || strings.HasSuffix(contentType, "+json")
}

func hasJSONBody(request structs.DiscoveredRequest) bool {
	body := strings.TrimSpace(request.Body)
	return body != "" && json.Valid([]byte(body))
}

func discoveredRequestContentType(request structs.DiscoveredRequest) string {
	if contentType := strings.ToLower(strings.TrimSpace(request.ContentType)); contentType != "" {
		return contentType
	}
	for key, value := range request.Headers {
		if strings.EqualFold(key, "Content-Type") {
			return strings.ToLower(strings.TrimSpace(value))
		}
	}
	return ""
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func isRootPath(path string) bool {
	return strings.TrimSpace(path) == "" || path == "/"
}

package crawl

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestOperationSpecFromBlueprintStripsDynamicValues(t *testing.T) {
	blueprint := RequestBlueprint{
		Method:            "post",
		Path:              "/api/reports/{reportId}",
		BaseURL:           "https://intranet.example.com/api",
		Confidence:        "high",
		ExtractionSource:  "js-static-callgraph",
		UnresolvedSymbols: []string{"buildQuery"},
		Params: []RequestBlueprintParam{
			{Name: "reportId", Location: "path", ValueExpr: "id", Resolved: false},
			{Name: "includeInactive", Location: "json", Value: "false", Resolved: true, ResolvedFrom: "literal"},
			{Name: "token", Location: "query", Value: "abc123", Resolved: true, ResolvedFrom: "static-value"},
			{Name: "nonce", Location: "json", ValueExpr: "makeNonce()", Resolved: true, ResolvedFrom: "expression-symbol", Value: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"},
		},
		Headers: []RequestBlueprintHeader{
			{Name: "Authorization", Value: "Bearer secret", Source: "interceptor"},
			{Name: "X-App", Value: "trail", Source: "axios.create"},
		},
		PayloadCarrier: "body",
		PayloadFormat:  "json",
		PayloadPreview: "{includeInactive:false}",
	}

	spec := OperationSpecFromBlueprint(blueprint, "https://intranet.example.com")
	if spec.Method != "POST" || spec.PathTemplate != "/api/reports/{reportId}" {
		t.Fatalf("unexpected spec identity: %#v", spec)
	}
	if spec.Origin != "https://intranet.example.com" {
		t.Fatalf("expected origin, got %q", spec.Origin)
	}

	params := map[string]OperationSpecParam{}
	for _, param := range spec.Params {
		params[param.Name] = param
	}
	if !params["reportId"].Dynamic || params["reportId"].DynamicReason != "unresolved-symbol" {
		t.Fatalf("unresolved path param must be dynamic: %#v", params["reportId"])
	}
	if params["includeInactive"].Dynamic || params["includeInactive"].Value != "false" {
		t.Fatalf("static literal must persist: %#v", params["includeInactive"])
	}
	if !params["token"].Dynamic || params["token"].Value != "" {
		t.Fatalf("token value must be stripped: %#v", params["token"])
	}
	if !params["nonce"].Dynamic || params["nonce"].Value != "" {
		t.Fatalf("ephemeral digest value must be stripped: %#v", params["nonce"])
	}

	headers := map[string]OperationSpecHeader{}
	for _, header := range spec.Headers {
		headers[header.Name] = header
	}
	if !headers["Authorization"].Dynamic || headers["Authorization"].Value != "" {
		t.Fatalf("authorization header value must be stripped: %#v", headers["Authorization"])
	}
	if headers["X-App"].Dynamic || headers["X-App"].Value != "trail" {
		t.Fatalf("static safe header must persist: %#v", headers["X-App"])
	}

	for _, want := range []string{"path:reportId", "query:token", "json:nonce", "header:Authorization"} {
		if !containsString(spec.RequiresRuntime, want) {
			t.Fatalf("expected RequiresRuntime to contain %q, got %#v", want, spec.RequiresRuntime)
		}
	}
	if spec.PayloadTemplate != "{includeInactive:false}" {
		t.Fatalf("expected payload template, got %q", spec.PayloadTemplate)
	}

	// The spec must remain persistable: no stripped values leak via JSON.
	serialized, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("spec must marshal: %v", err)
	}
	if strings.Contains(string(serialized), "Bearer secret") || strings.Contains(string(serialized), "9f86d081") {
		t.Fatalf("credential material leaked into spec JSON: %s", serialized)
	}
}

func TestOperationSpecsFromBlueprintsOriginFallback(t *testing.T) {
	blueprint := RequestBlueprint{
		Method:           "GET",
		Path:             "/api/list",
		BaseURL:          "https://api.example.com/v1",
		ExtractionSource: "js-static-callgraph",
	}
	spec := OperationSpecFromBlueprint(blueprint, "")
	if spec.Origin != "https://api.example.com" {
		t.Fatalf("expected origin derived from baseURL, got %q", spec.Origin)
	}
}

func TestBuildReplayFixtureRequiresAuthorization(t *testing.T) {
	record := NetworkRecord{URL: "https://example.com/api/x", Method: "GET"}
	if _, err := BuildReplayFixture(record, false); err != ErrReplayNotAuthorized {
		t.Fatalf("expected authorization error, got %v", err)
	}
	if _, err := BuildReplayFixtures([]NetworkRecord{record}, false); err != ErrReplayNotAuthorized {
		t.Fatalf("expected authorization error for batch, got %v", err)
	}
}

func TestBuildReplayFixtureCapturesAndClassifies(t *testing.T) {
	fetchedAt := time.Now()
	record := NetworkRecord{
		URL:    "https://example.com/api/reports?token=q1w2e3&page=1&timestamp=1726740000",
		Method: "post",
		RequestHeaders: map[string]string{
			"Content-Type":  "application/json;charset=utf-8",
			"Authorization": "Bearer abc.def.ghi",
			"X-App":         "trail",
		},
		RequestBody: `{"sign":"deadbeef","reportId":42,"nonce":"n-1"}`,
		PageURL:     "https://example.com/reports",
		FetchedAt:   fetchedAt,
	}
	fixture, err := BuildReplayFixture(record, true)
	if err != nil {
		t.Fatalf("authorized build must succeed: %v", err)
	}
	if fixture.Method != "POST" || fixture.ContentType != "application/json;charset=utf-8" {
		t.Fatalf("unexpected fixture: %#v", fixture)
	}
	if fixture.PageURL != "https://example.com/reports" || fixture.ExpiresAt.Sub(fetchedAt) != replayFixtureTTL {
		t.Fatalf("expected page URL and TTL, got %#v", fixture)
	}
	if string(fixture.Body) != record.RequestBody {
		t.Fatal("raw body must be preserved")
	}
	if !fixture.IsFresh(fetchedAt.Add(time.Minute)) || fixture.IsFresh(fetchedAt.Add(time.Hour)) {
		t.Fatal("freshness TTL misbehaving")
	}

	type key struct{ location, name, kind string }
	seen := map[key]bool{}
	for _, param := range fixture.DynamicParams {
		seen[key{param.Location, strings.ToLower(param.Name), param.Kind}] = true
	}
	for _, want := range []key{
		{"query", "token", "token"},
		{"query", "timestamp", "timestamp"},
		{"header", "authorization", "token"},
		{"body", "sign", "signature"},
		{"body", "nonce", "nonce"},
	} {
		if !seen[want] {
			t.Fatalf("missing dynamic param %#v in %#v", want, fixture.DynamicParams)
		}
	}
	// Static query params must not require refresh.
	if seen[key{"query", "page", "token"}] {
		t.Fatal("static query param misclassified")
	}
}

package web

import (
	"testing"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestCollaborativeRiskClassification(t *testing.T) {
	cases := map[string]string{
		"/api/sms/sendCode": "sms-action",
		"/api/apply/save":   "state-changing-action",
		"/api/health":       "",
	}
	for route, expected := range cases {
		if actual := collaborativeRiskCategory(route); actual != expected {
			t.Fatalf("risk category for %s = %q, want %q", route, actual, expected)
		}
	}
}

func TestBuildCollaborativeActionsNeverIncludesSafeBlueprints(t *testing.T) {
	actions := buildCollaborativeActions([]crawl.RequestBlueprint{
		{ID: "safe", Path: "/api/health", Method: "GET"},
		{ID: "save", Path: "/api/apply/save", Method: "POST"},
	})
	if len(actions) != 1 {
		t.Fatalf("actions count = %d, want 1", len(actions))
	}
	if actions[0].BlueprintID != "save" || actions[0].Decision != "pending" {
		t.Fatalf("unexpected action: %#v", actions[0])
	}
}

func TestNormalizeCollaborativeTargetRejectsNonHTTP(t *testing.T) {
	if _, err := normalizeCollaborativeTarget("https://example.test/app"); err != nil {
		t.Fatalf("expected https target to pass: %v", err)
	}
	if _, err := normalizeCollaborativeTarget("file:///tmp/target"); err == nil {
		t.Fatal("expected file target to fail")
	}
}

func TestMergeHighRiskRoutesKeepsRequiredRoutes(t *testing.T) {
	routes := mergeHighRiskRoutes([]string{"save", "custom"}, []string{"SMS", "save"})
	if len(routes) != 3 || routes[0] != "save" || routes[1] != "custom" || routes[2] != "sms" {
		t.Fatalf("unexpected merged routes: %#v", routes)
	}
}

func TestBuildCollaborativeTestResultsUsesExecutionEvidence(t *testing.T) {
	now := time.Now()
	results := buildCollaborativeTestResults(
		[]database.APIResource{{URL: "https://example.test/api/profile", Method: "GET", ResponseCode: 200, ResponseBody: "ok", FetchedAt: now}},
		[]database.VulnRecord{{URL: "https://example.test/api/profile", Method: "GET", Level: "medium", Title: "未授权访问", CreatedAt: now.Add(time.Second)}},
		nil,
	)
	if len(results) != 2 || results[0].Kind != "security-finding" || results[1].StatusCode != 200 {
		t.Fatalf("unexpected test evidence: %#v", results)
	}
}

func TestCollaborativeHARRecordsUseCapturedRequestEvidence(t *testing.T) {
	records := collaborativeHARRecords("task", 1, []byte(`{"log":{"entries":[{"request":{"url":"https://example.test/api/me","method":"GET"},"response":{"status":200,"content":{"text":"{}"}}}]}}`))
	if len(records) != 1 || records[0].Method != "GET" || records[0].ResponseCode != 200 {
		t.Fatalf("unexpected HAR records: %#v", records)
	}
}

func TestCollaborativeOpenAPIBlueprintsExtractRoutes(t *testing.T) {
	blueprints := collaborativeOpenAPIBlueprints("openapi.yaml", []byte("paths:\n  /api/orders:\n    get: {}\n    post: {}\n"))
	if len(blueprints) != 2 || blueprints[0].Path != "/api/orders" {
		t.Fatalf("unexpected OpenAPI blueprints: %#v", blueprints)
	}
}

func TestCollaborativeEndpointCluesGroupSourcesWithoutDroppingEvidence(t *testing.T) {
	clues := buildCollaborativeEndpointClues("https://example.test/app/", []crawl.RequestBlueprint{
		{ID: "one", Method: "GET", Path: "/api/profile", Confidence: "medium", Source: crawl.RequestBlueprintSource{File: "app.js", Snippet: "client.get('/api/profile')"}},
		{ID: "two", Method: "GET", Path: "https://example.test/api/profile", Confidence: "high", Source: crawl.RequestBlueprintSource{File: "account.js", Snippet: "request('/api/profile')"}},
		{ID: "three", Method: "POST", Path: "/api/profile", Confidence: "high", Source: crawl.RequestBlueprintSource{File: "account.js", Snippet: "save profile"}},
	})
	if len(clues) != 2 {
		t.Fatalf("clue count = %d, want 2: %#v", len(clues), clues)
	}
	if clues[0].Method != "GET" || len(clues[0].Evidence) != 2 || clues[0].Confidence != "high" {
		t.Fatalf("GET clue did not merge source evidence: %#v", clues[0])
	}
}

func TestCollaborativeTestResultsExposeOnlyPersistedProtocolTraces(t *testing.T) {
	now := time.Now()
	results := buildCollaborativeTestResults(
		[]database.APIResource{{URL: "https://example.test/api/secure", Method: "GET", TraceID: "trace-1", HasProtocolTrace: true, FetchedAt: now}},
		nil,
		[]database.ProtocolTraceRecord{{TraceID: "trace-1"}},
	)
	if len(results) != 1 || !results[0].HasProtocolTrace || results[0].TraceID != "trace-1" {
		t.Fatalf("expected persisted protocol trace on test result: %#v", results)
	}
}

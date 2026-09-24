package sdk

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qiwentaidi/katana/pkg/apicontext"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

func TestDetectOperationVulnsHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DetectOperationVulns(&APIAssetResult{Store: NewAPIStore()}, &DetectOptions{Context: ctx})
	if err != context.Canceled {
		t.Fatalf("canceled detection error = %v, want context.Canceled", err)
	}
}

func detectTestAssets(t *testing.T, srv *httptest.Server) *APIAssetResult {
	t.Helper()
	store := NewAPIStore()
	store.Add(apicontext.Build(apicontext.Observation{
		Method:      "GET",
		URL:         srv.URL + "/api/users/123",
		ReqHeaders:  map[string]string{"Authorization": "Bearer x"},
		RespStatus:  200,
		RespHeaders: map[string]string{"Content-Type": "application/json"},
		RespBody:    []byte(`{"id":123,"name":"alice"}`),
	}))
	return &APIAssetResult{Store: store}
}

func TestDetectOperationVulnsAuthorizationFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// anonymous variant still gets the data -> vulnerable
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":123,"name":"alice"}`))
	}))
	defer srv.Close()

	var events []ScanEvent
	result, err := DetectOperationVulns(detectTestAssets(t, srv), &DetectOptions{
		Target: srv.URL,
		OnFinding: func(event ScanEvent) bool {
			events = append(events, event)
			return true
		},
	})
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if len(result.Checks) != 1 {
		t.Fatalf("expected 1 authorization check, got %d", len(result.Checks))
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %+v", result.Vulnerabilities)
	}
	record := result.Vulnerabilities[0]
	if record.AuthorizationEvidence == nil || record.AuthorizationEvidence.Baseline == nil || record.AuthorizationEvidence.Anonymous == nil {
		t.Fatalf("missing comparative evidence: %+v", record)
	}
	if !strings.Contains(record.Request, "GET /api/users/123") || !strings.Contains(record.Response, `"name":"alice"`) || record.ResponseLength != len(`{"id":123,"name":"alice"}`) || record.ResponseType != "application/json" {
		t.Fatalf("missing legacy evidence fields: %+v", record)
	}
	encoded, err := json.Marshal(events[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	var restored database.VulnRecord
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.AuthorizationEvidence == nil || restored.AuthorizationEvidence.Baseline == nil || restored.AuthorizationEvidence.Anonymous.Response != record.Response {
		t.Fatalf("event serialization lost evidence: %s", encoded)
	}

	if record.Type != "authorization" || record.TaskID != "sdk-detect" || record.Method != "GET" {
		t.Errorf("unexpected record: %+v", record)
	}
	if len(events) != 1 || events[0].Type != EventTypeVulnerability {
		t.Fatalf("expected 1 vulnerability event, got %+v", events)
	}
	if _, ok := events[0].Data.(database.VulnRecord); !ok {
		t.Errorf("event Data should be database.VulnRecord, got %T", events[0].Data)
	}
}

func TestDetectOperationVulnsNotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":123,"name":"alice"}`))
	}))
	defer srv.Close()

	result, err := DetectOperationVulns(detectTestAssets(t, srv), nil)
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if len(result.Vulnerabilities) != 0 {
		t.Fatalf("expected no vulnerabilities, got %+v", result.Vulnerabilities)
	}
	if len(result.Checks) != 1 {
		t.Fatalf("check should still be recorded, got %d", len(result.Checks))
	}
}

func TestDetectOperationVulnsFindsAnonymousRuntimeAPI(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":123,"name":"alice","email":"alice@example.test"}`))
	}))
	defer srv.Close()

	assets := &APIAssetResult{RuntimeRecords: []crawl.NetworkRecord{{
		URL:             srv.URL + "/api/users/123",
		Method:          http.MethodGet,
		RequestHeaders:  map[string]string{"Accept": "application/json"},
		ResponseCode:    http.StatusOK,
		ResponseHeaders: map[string]string{"Content-Type": "application/json"},
		ResponseBody:    `{"id":123,"name":"alice","email":"alice@example.test"}`,
	}}}
	result, err := DetectOperationVulns(assets, &DetectOptions{TaskID: "anonymous-runtime"})
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if len(result.Checks) != 0 {
		t.Fatalf("anonymous runtime API should not create comparative checks, got %d", len(result.Checks))
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected one anonymous unauthorized finding, got %+v", result.Vulnerabilities)
	}
	if calls != 0 {
		t.Fatalf("anonymous runtime evidence should be assessed without a replay, got %d HTTP calls", calls)
	}
	record := result.Vulnerabilities[0]
	if record.Type != "未授权访问" || record.TaskID != "anonymous-runtime" || record.URL != srv.URL+"/api/users/123" {
		t.Errorf("unexpected anonymous finding: %+v", record)
	}
}

func TestDetectOperationVulnsSkipsAuthenticatedRuntimeAPI(t *testing.T) {
	assets := &APIAssetResult{RuntimeRecords: []crawl.NetworkRecord{{
		URL:            "https://example.test/api/users/123",
		Method:         http.MethodGet,
		RequestHeaders: map[string]string{"Authorization": "Bearer secret"},
	}}}
	result, err := DetectOperationVulns(assets, nil)
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if len(result.Vulnerabilities) != 0 {
		t.Fatalf("authenticated runtime request must not use anonymous detector, got %+v", result.Vulnerabilities)
	}
}

func TestDetectOperationVulnsSkipsCustomAuthenticationHeader(t *testing.T) {
	assets := &APIAssetResult{RuntimeRecords: []crawl.NetworkRecord{{
		URL:            "https://example.test/api/users/123",
		Method:         http.MethodGet,
		RequestHeaders: map[string]string{"X-Custom-Auth": "secret"},
		ResponseCode:   http.StatusOK,
		ResponseBody:   `{"id":123,"name":"alice"}`,
	}}}
	result, err := DetectOperationVulns(assets, nil)
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if len(result.Vulnerabilities) != 0 {
		t.Fatalf("custom-auth runtime request must not use anonymous detector, got %+v", result.Vulnerabilities)
	}
}

type fakeFuzzer struct{ records []database.VulnRecord }

func (f fakeFuzzer) Name() string { return "fake" }
func (f fakeFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	out := make([]database.VulnRecord, 0, len(f.records))
	for _, record := range f.records {
		record.URL = spec.Origin + spec.PathTemplate
		out = append(out, record)
	}
	return out
}

func TestDetectOperationVulnsFuzzerExtensionPoint(t *testing.T) {
	assets := &APIAssetResult{
		Store: NewAPIStore(),
		OperationSpecs: []crawl.OperationSpec{
			{ID: "ops_1", Origin: "https://example.com", Method: "GET", PathTemplate: "/api/list"},
			{ID: "ops_2", Origin: "https://example.com", Method: "POST", PathTemplate: "/api/update"},
		},
	}
	fuzzer := fakeFuzzer{records: []database.VulnRecord{{VulnID: "fuzz-1", Type: "sqli"}}}

	eventCount := 0
	result, err := DetectOperationVulns(assets, &DetectOptions{
		TaskID:  "task-9",
		Fuzzers: []OperationFuzzer{fuzzer},
		OnFinding: func(event ScanEvent) bool {
			eventCount++
			return true
		},
	})
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if len(result.Vulnerabilities) != 2 || eventCount != 2 {
		t.Fatalf("expected 2 fuzz findings (one per spec), got records=%d events=%d", len(result.Vulnerabilities), eventCount)
	}
	for _, record := range result.Vulnerabilities {
		if record.TaskID != "task-9" {
			t.Errorf("fuzzer record should inherit TaskID, got %+v", record)
		}
	}
}

func TestDetectOperationVulnsCallbackStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":123,"name":"alice"}`))
	}))
	defer srv.Close()

	calls := 0
	result, err := DetectOperationVulns(detectTestAssets(t, srv), &DetectOptions{
		Fuzzers: []OperationFuzzer{fakeFuzzer{records: []database.VulnRecord{{VulnID: "f1"}, {VulnID: "f2"}}}},
		OnFinding: func(event ScanEvent) bool {
			calls++
			return false // stop after the first finding
		},
	})
	if err != nil {
		t.Fatalf("DetectOperationVulns: %v", err)
	}
	if calls != 1 || len(result.Vulnerabilities) != 1 {
		t.Fatalf("callback false should stop after first finding, calls=%d records=%d", calls, len(result.Vulnerabilities))
	}
}

func TestDetectOperationVulnsNilAssets(t *testing.T) {
	if _, err := DetectOperationVulns(nil, nil); err == nil {
		t.Fatal("expected error for nil assets")
	}
}

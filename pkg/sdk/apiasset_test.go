package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qiwentaidi/katana/pkg/apicontext"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

func TestExportOpenAPI(t *testing.T) {
	store := NewAPIStore()
	store.Add(apicontext.Build(apicontext.Observation{
		Method:     "GET",
		URL:        "https://example.com/api/users/123?debug=true",
		ReqHeaders: map[string]string{"Authorization": "Bearer x"},
		RespStatus: 200,
		RespHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		RespBody: []byte(`{"id":123,"name":"alice"}`),
	}))

	raw, err := ExportOpenAPI(store, "Test")
	if err != nil {
		t.Fatalf("ExportOpenAPI: %v", err)
	}
	text := string(raw)
	for _, want := range []string{`"openapi": "3.1.0"`, "/api/users/{id}", `"confidence"`} {
		if !strings.Contains(text, want) {
			t.Errorf("export missing %q", want)
		}
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
}

func TestRunAuthorizationCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			// anonymous variant still gets the data -> vulnerable
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"id":123,"name":"alice"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":123,"name":"alice"}`))
	}))
	defer srv.Close()

	ctx := apicontext.Build(apicontext.Observation{
		Method:     "GET",
		URL:        srv.URL + "/api/users/123",
		ReqHeaders: map[string]string{"Authorization": "Bearer x"},
		RespStatus: 200,
		RespHeaders: map[string]string{
			"Content-Type": "application/json",
		},
		RespBody: []byte(`{"id":123,"name":"alice"}`),
	})

	verdict := RunAuthorizationCheck(ctx, nil)
	if !verdict.Conclusive || !verdict.Vulnerable {
		t.Fatalf("expected vulnerable verdict, got %+v", verdict)
	}
}

func TestExportOpenAPIWithSpecs(t *testing.T) {
	store := NewAPIStore()
	store.Add(apicontext.Build(apicontext.Observation{
		Method:     "GET",
		URL:        "https://example.com/api/observed",
		RespStatus: 200,
	}))

	specs := []crawl.OperationSpec{
		{
			// duplicates the runtime observation: runtime must win
			ID:           "ops_dup",
			Method:       "GET",
			PathTemplate: "/api/observed",
			Confidence:   "high",
		},
		{
			ID:           "ops_query",
			Method:       "GET",
			PathTemplate: "/api/list",
			Confidence:   "high",
			Params: []crawl.OperationSpecParam{
				{Name: "page", Location: "query", Value: "1", Confidence: "high"},
				{Name: "token", Location: "query", Dynamic: true, DynamicReason: "dynamic-name"},
			},
			RequiresRuntime: []string{"header:Authorization", "query:token"},
			Headers:         []crawl.OperationSpecHeader{{Name: "Authorization", Dynamic: true}},
		},
		{
			ID:             "ops_body",
			Method:         "POST",
			PathTemplate:   "/api/poc/update",
			Confidence:     "high",
			PayloadCarrier: "body",
			PayloadFormat:  "json",
			Params: []crawl.OperationSpecParam{
				{Name: "content", Location: "json", Dynamic: true, DynamicReason: "unresolved-symbol"},
			},
		},
	}

	raw, err := ExportOpenAPIWithSpecs(store, specs, "Test")
	if err != nil {
		t.Fatalf("ExportOpenAPIWithSpecs: %v", err)
	}
	var doc struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			SecuritySchemes map[string]json.RawMessage `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	if len(doc.Paths) != 3 {
		t.Fatalf("expected 3 paths, got %d: %s", len(doc.Paths), raw)
	}

	// runtime observation is preserved for the duplicate path
	observed := string(doc.Paths["/api/observed"]["get"])
	if !strings.Contains(observed, `"observations"`) {
		t.Errorf("runtime operation was overwritten by spec: %s", observed)
	}

	// static query operation: dynamic param marked, no value leaked
	queryOp := string(doc.Paths["/api/list"]["get"])
	for _, want := range []string{`"source"`, `"dynamic"`, `"requiresRuntime"`, `"name": "page"`, `"name": "token"`} {
		if !strings.Contains(queryOp, want) {
			t.Errorf("static query operation missing %q: %s", want, queryOp)
		}
	}
	var queryOperation struct {
		Parameters []map[string]any `json:"parameters"`
		Security   []any            `json:"security"`
	}
	if err := json.Unmarshal(doc.Paths["/api/list"]["get"], &queryOperation); err != nil {
		t.Fatalf("parse static operation: %v", err)
	}
	for _, param := range queryOperation.Parameters {
		if param["name"] == "token" {
			if _, leaked := param["example"]; leaked {
				t.Errorf("dynamic param token leaked an example value: %v", param)
			}
		}
	}
	if len(queryOperation.Security) == 0 {
		t.Errorf("expected bearerAuth security on spec requiring Authorization header")
	}
	if _, ok := doc.Components.SecuritySchemes["bearerAuth"]; !ok {
		t.Errorf("expected bearerAuth security scheme in components")
	}

	// static body operation: json requestBody with dynamic field marked
	bodyOp := string(doc.Paths["/api/poc/update"]["post"])
	for _, want := range []string{"application/json", `"content"`, `"dynamic"`} {
		if !strings.Contains(bodyOp, want) {
			t.Errorf("static body operation missing %q: %s", want, bodyOp)
		}
	}
}

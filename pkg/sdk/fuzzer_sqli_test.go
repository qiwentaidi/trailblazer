package sdk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

func TestSQLInjectionFuzzerDetectsErrorBased(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "%27") || strings.Contains(r.URL.RawQuery, "'") {
			w.Write([]byte("You have an error in your SQL syntax; check the manual"))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	fuzzer := NewSQLInjectionFuzzer(SQLInjectionConfig{Enabled: true})
	findings := fuzzer.Fuzz(crawl.OperationSpec{
		ID:           "ops_abc",
		Origin:       srv.URL,
		Method:       "GET",
		PathTemplate: "/api/user",
		Params: []crawl.OperationSpecParam{
			{Name: "id", Location: "query", Value: "1"},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %+v", findings)
	}
	record := findings[0]
	if record.Type != "SQL_INJECTION" || record.Level != "high" || record.VulnID != "sqli-ops_abc" {
		t.Errorf("unexpected record: %+v", record)
	}
	if !strings.Contains(record.URL, "/api/user") {
		t.Errorf("record URL should target the spec path: %s", record.URL)
	}
}

func TestSQLInjectionFuzzerSkipsCredentialNamedParams(t *testing.T) {
	spec := crawl.OperationSpec{
		Origin:       "https://example.com",
		Method:       "GET",
		PathTemplate: "/api/list",
		Params: []crawl.OperationSpecParam{
			{Name: "page", Location: "query", Value: "1"},
			{Name: "sign", Location: "query", Dynamic: true, DynamicReason: "dynamic-name"},
			{Name: "content", Location: "query", Dynamic: true, DynamicReason: "unresolved-symbol"},
		},
	}
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if fuzzTargets != 2 {
		t.Fatalf("expected 2 fuzz targets (page + unresolved content), got %d", fuzzTargets)
	}
	if _, ok := apiReq.Params["sign"]; ok {
		t.Errorf("credential-named param must not be fabricated: %v", apiReq.Params)
	}
	if apiReq.Params.Get("content") != "1" {
		t.Errorf("unresolved-symbol param should carry placeholder value, got %q", apiReq.Params.Get("content"))
	}
}

func TestSQLInjectionFuzzerBuildsJSONBody(t *testing.T) {
	spec := crawl.OperationSpec{
		Origin:         "https://example.com",
		Method:         "POST",
		PathTemplate:   "/api/poc/update",
		PayloadCarrier: "body",
		PayloadFormat:  "json",
		Params: []crawl.OperationSpecParam{
			{Name: "filename", Location: "json", Value: "a.txt"},
			{Name: "content", Location: "json", Dynamic: true, DynamicReason: "unresolved-symbol"},
		},
		Headers: []crawl.OperationSpecHeader{
			{Name: "Authorization", Dynamic: true},
			{Name: "X-App", Value: "demo"},
		},
	}
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if fuzzTargets != 2 {
		t.Fatalf("expected 2 fuzz targets, got %d", fuzzTargets)
	}
	if !strings.Contains(apiReq.Body, `"filename":"a.txt"`) || !strings.Contains(apiReq.Body, `"content":"1"`) {
		t.Errorf("json body should contain static + placeholder fields, got %s", apiReq.Body)
	}
	if apiReq.Headers["Content-Type"] != "application/json" {
		t.Errorf("expected json content type, got %q", apiReq.Headers["Content-Type"])
	}
	if _, leaked := apiReq.Headers["Authorization"]; leaked {
		t.Error("dynamic Authorization header must not be fabricated")
	}
	if apiReq.Headers["X-App"] != "demo" {
		t.Error("static header should be carried")
	}
}

func TestSQLInjectionFuzzerSkipsEmptySpecs(t *testing.T) {
	fuzzer := NewSQLInjectionFuzzer(SQLInjectionConfig{Enabled: true})
	if findings := fuzzer.Fuzz(crawl.OperationSpec{Method: "GET", PathTemplate: "/api/x"}); findings != nil {
		t.Errorf("missing origin should yield no findings, got %+v", findings)
	}
	if findings := fuzzer.Fuzz(crawl.OperationSpec{Origin: "https://example.com", Method: "GET", PathTemplate: "/api/x"}); findings != nil {
		t.Errorf("spec without fuzzable params should yield no findings, got %+v", findings)
	}
}

func TestSQLInjectionFuzzerPathTemplateSubstitution(t *testing.T) {
	spec := crawl.OperationSpec{
		Origin:       "https://example.com",
		Method:       "GET",
		PathTemplate: "/api/users/{id}",
		Params: []crawl.OperationSpecParam{
			{Name: "id", Location: "path", Value: "42"},
			{Name: "debug", Location: "query", Value: "true"},
		},
	}
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if apiReq.URL != "https://example.com/api/users/42" {
		t.Errorf("path template not substituted: %s", apiReq.URL)
	}
	if fuzzTargets != 1 { // 路径参数不计入 fuzz 目标（占位替换），query 参数计入
		t.Errorf("expected 1 fuzz target, got %d", fuzzTargets)
	}
}

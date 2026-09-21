package sdk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

func TestLFIFuzzerDetectsFileRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "..") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	fuzzer := NewLFIFuzzer(LFIConfig{Enabled: true})
	findings := fuzzer.Fuzz(crawl.OperationSpec{
		ID:           "ops_lfi",
		Origin:       srv.URL,
		Method:       "GET",
		PathTemplate: "/api/download",
		Params: []crawl.OperationSpecParam{
			{Name: "file", Location: "query", Value: "report.pdf"},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 LFI finding, got %+v", findings)
	}
	if findings[0].Type != "LFI" || findings[0].VulnID != "lfi-ops_lfi" || findings[0].Level != "high" {
		t.Errorf("unexpected record: %+v", findings[0])
	}
}

func TestSSRFFuzzerDetectsFileSchemeFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("url"), "file:///etc/passwd") {
			// 模拟服务端实际取回了 file:// 目标内容
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	fuzzer := NewSSRFFuzzer(SSRFConfig{Enabled: true})
	findings := fuzzer.Fuzz(crawl.OperationSpec{
		ID:           "ops_ssrf",
		Origin:       srv.URL,
		Method:       "GET",
		PathTemplate: "/api/fetch",
		Params: []crawl.OperationSpecParam{
			{Name: "url", Location: "query", Dynamic: true, DynamicReason: "unresolved-symbol"},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 SSRF finding, got %+v", findings)
	}
	if findings[0].Type != "SSRF" || findings[0].VulnID != "ssrf-ops_ssrf" {
		t.Errorf("unexpected record: %+v", findings[0])
	}
}

func TestWebFuzzersSkipSpecsWithoutParams(t *testing.T) {
	spec := crawl.OperationSpec{Origin: "https://example.com", Method: "GET", PathTemplate: "/api/x"}
	fuzzers := []OperationFuzzer{
		NewLFIFuzzer(LFIConfig{Enabled: true}),
		NewSSRFFuzzer(SSRFConfig{Enabled: true}),
		NewXSSFuzzer(XSSConfig{Enabled: true}),
	}
	for _, fuzzer := range fuzzers {
		if findings := fuzzer.Fuzz(spec); findings != nil {
			t.Errorf("%s: spec without params should yield no findings, got %+v", fuzzer.Name(), findings)
		}
	}
}

func TestXSSFuzzerSkipsNonHTMLResponse(t *testing.T) {
	// JSON 响应不可渲染，XSS 检测应直接跳过（API 场景的常见情况）。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"echo":"` + r.URL.Query().Get("q") + `"}`))
	}))
	defer srv.Close()

	fuzzer := NewXSSFuzzer(XSSConfig{Enabled: true})
	findings := fuzzer.Fuzz(crawl.OperationSpec{
		ID:           "ops_xss",
		Origin:       srv.URL,
		Method:       "GET",
		PathTemplate: "/api/search",
		Params: []crawl.OperationSpecParam{
			{Name: "q", Location: "query", Dynamic: true, DynamicReason: "unresolved-symbol"},
		},
	})
	if findings != nil {
		t.Errorf("JSON response should not yield XSS findings, got %+v", findings)
	}
}

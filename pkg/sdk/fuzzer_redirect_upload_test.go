package sdk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

func TestRedirectFuzzerDetectsExternalRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("next"), "evil.com") {
			http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	findings := NewRedirectFuzzer(RedirectConfig{Enabled: true}).Fuzz(crawl.OperationSpec{
		ID:           "ops_redirect",
		Origin:       srv.URL,
		Method:       http.MethodGet,
		PathTemplate: "/api/continue",
		Params:       []crawl.OperationSpecParam{{Name: "next", Location: "query", Value: "/dashboard"}},
	})
	if len(findings) != 1 {
		t.Fatalf("expected one redirect finding, got %+v", findings)
	}
	if findings[0].Type != "REDIRECT" || findings[0].VulnID != "redirect-ops_redirect" {
		t.Errorf("unexpected redirect finding: %+v", findings[0])
	}
}

type successfulUploadChecker struct{}

func (successfulUploadChecker) CheckFileUpload(responseBody, testFileName, testContent string) (bool, string, error) {
	if !strings.Contains(responseBody, "uploaded") || testFileName != "test.html" || testContent == "" {
		return false, "", nil
	}
	return true, "/uploads/test.html", nil
}

func TestFileUploadFuzzerDetectsConfirmedUpload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
			t.Fatalf("expected multipart upload, got Content-Type=%q", r.Header.Get("Content-Type"))
		}
		w.Write([]byte(`{"status":"uploaded"}`))
	}))
	defer srv.Close()

	findings := NewFileUploadFuzzer(UploadConfig{Enabled: true}, successfulUploadChecker{}).Fuzz(crawl.OperationSpec{
		ID:           "ops_upload",
		Origin:       srv.URL,
		Method:       http.MethodPost,
		PathTemplate: "/api/upload",
	})
	if len(findings) != 1 {
		t.Fatalf("expected one file upload finding, got %+v", findings)
	}
	if findings[0].Type != "FILE_UPLOAD" || findings[0].VulnID != "upload-ops_upload" || !strings.Contains(findings[0].Request, "multipart/form-data") {
		t.Errorf("unexpected file upload finding: %+v", findings[0])
	}
}

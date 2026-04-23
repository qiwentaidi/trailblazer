package xss

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
)

func withBrowserVerifier(verifier xssExecutionVerifier, fn func()) {
	original := browserXSSVerifier
	browserXSSVerifier = verifier
	defer func() {
		browserXSSVerifier = original
	}()
	fn()
}

func TestXSSSkipsJSONReflectionResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echo":%q}`, r.URL.Query().Get("input"))
	}))
	defer server.Close()

	withBrowserVerifier(func(apiReq structs.APIRequest, payload, responseBody string) bool {
		t.Fatal("browser verifier should not run for json responses")
		return false
	}, func() {
		result, err := TestXSS(structs.APIRequest{
			URL:     server.URL,
			Method:  http.MethodGet,
			Headers: map[string]string{},
			Params:  url.Values{"input": []string{"test"}},
		}, config.XSSConfig{Enabled: true})
		if err != nil {
			t.Fatalf("TestXSS error: %v", err)
		}
		if result == nil || result.Vulnerable {
			t.Fatalf("expected json reflection not to be reported as xss, got %#v", result)
		}
	})
}

func TestXSSRequiresBrowserExecutionConfirmation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, r.URL.Query().Get("input"))
	}))
	defer server.Close()

	withBrowserVerifier(func(apiReq structs.APIRequest, payload, responseBody string) bool {
		return false
	}, func() {
		result, err := TestXSS(structs.APIRequest{
			URL:     server.URL,
			Method:  http.MethodGet,
			Headers: map[string]string{},
			Params:  url.Values{"input": []string{"test"}},
		}, config.XSSConfig{Enabled: true})
		if err != nil {
			t.Fatalf("TestXSS error: %v", err)
		}
		if result == nil || result.Vulnerable {
			t.Fatalf("expected reflected html without execution confirmation not to be reported, got %#v", result)
		}
	})
}

func TestXSSSkipsEscapedHiddenInputAttributeReflection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(
			w,
			`<html><body><form><input type="hidden" id="url" value=%q /></form></body></html>`,
			r.URL.Query().Get("input"),
		)
	}))
	defer server.Close()

	withBrowserVerifier(func(apiReq structs.APIRequest, payload, responseBody string) bool {
		t.Fatal("browser verifier should not run for escaped hidden input reflection")
		return false
	}, func() {
		result, err := TestXSS(structs.APIRequest{
			URL:     server.URL,
			Method:  http.MethodGet,
			Headers: map[string]string{},
			Params:  url.Values{"input": []string{"test"}},
		}, config.XSSConfig{Enabled: true})
		if err != nil {
			t.Fatalf("TestXSS error: %v", err)
		}
		if result == nil || result.Vulnerable {
			t.Fatalf("expected escaped hidden input reflection not to be reported as xss, got %#v", result)
		}
	})
}

func TestXSSReportsOnlyAfterBrowserExecutionConfirmation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body>%s</body></html>`, r.URL.Query().Get("input"))
	}))
	defer server.Close()

	withBrowserVerifier(func(apiReq structs.APIRequest, payload, responseBody string) bool {
		return strings.Contains(payload, "__TB_XSS_HIT__")
	}, func() {
		result, err := TestXSS(structs.APIRequest{
			URL:     server.URL,
			Method:  http.MethodGet,
			Headers: map[string]string{},
			Params:  url.Values{"input": []string{"test"}},
		}, config.XSSConfig{Enabled: true})
		if err != nil {
			t.Fatalf("TestXSS error: %v", err)
		}
		if result == nil || !result.Vulnerable {
			t.Fatalf("expected xss to be reported after browser confirmation, got %#v", result)
		}
		if !strings.Contains(result.Payload, "__TB_XSS_HIT__") {
			t.Fatalf("expected confirmed payload to carry execution marker, got %q", result.Payload)
		}
		if result.Confidence == "" || result.ConfidenceReason == "" {
			t.Fatalf("expected confirmed xss to include confidence metadata, got %#v", result)
		}
	})
}

func TestContainsExecutablePatternRecognizesExecutionMarkerScript(t *testing.T) {
	marker := buildExecutionMarker("unit")
	payload := "<script>" + buildExecutionSnippet(marker) + "</script>"
	body := "<html><body>" + payload + "</body></html>"

	if !containsExecutablePattern(body, payload) {
		t.Fatalf("expected executable marker payload to be recognized, payload=%q body=%q", payload, body)
	}
}

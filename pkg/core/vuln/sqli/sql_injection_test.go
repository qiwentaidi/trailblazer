package sqli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
)

func TestSQLInjectionDetectsNewErrorBasedSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if strings.Contains(user, "'") {
			http.Error(w, "You have an error in your SQL syntax;", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), newErrorBasedConfig())
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected vulnerability, got %#v", result)
	}
	if result.Type != "error-based" {
		t.Fatalf("expected error-based, got %q", result.Type)
	}
	if !strings.HasPrefix(result.Response, "HTTP/1.1 500") {
		t.Fatalf("expected response evidence to include status line, got %q", result.Response)
	}
	if result.ResponseLength == 0 {
		t.Fatalf("expected response body length to be preserved")
	}
}

func TestSQLInjectionSkipsExistingErrorPageFalsePositive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), newErrorBasedConfig())
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Vulnerable {
		t.Fatalf("expected false positive to be suppressed, got %#v", result)
	}
}

func TestSQLInjectionBooleanBasedRequiresParityWithinBothQuoteGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		switch user {
		case "'":
			http.Error(w, "syntax error near quote", http.StatusInternalServerError)
			return
		case "''", "":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Vulnerable {
		t.Fatalf("quote-only response difference must not be reported as boolean SQL injection, got %#v", result)
	}
}

func TestSQLInjectionBooleanBasedDoesNotRequireMatchingBaseline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		switch user {
		case "'", "'''":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("odd quote group trace=1234567890123"))
			return
		case "''", "''''":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("even quote group trace=1234567890123 request=550e8400-e29b-41d4-a716-446655440000"))
			return
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("baseline differs from both probe groups"))
		}
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected boolean-based vulnerability without a matching baseline, got %#v", result)
	}
	if result.Type != "boolean-based" {
		t.Fatalf("expected boolean-based, got %q", result.Type)
	}
	if result.Payload != "'" {
		t.Fatalf("expected one-quote payload, got %q", result.Payload)
	}
}

func TestSQLInjectionBooleanBasedSkipsGenericValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		if strings.Contains(user, "'") {
			http.Error(w, "invalid input", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Vulnerable {
		t.Fatalf("expected generic validation behavior to be suppressed, got %#v", result)
	}
}

func TestSQLInjectionBooleanBasedSkipsEmptyBodyStatusOnlyDifference(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("user") {
		case "'", "'''":
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Vulnerable {
		t.Fatalf("expected status-only empty-body difference to be suppressed, got %#v", result)
	}
}

func newTestAPIRequest(rawURL string) structs.APIRequest {
	return structs.APIRequest{
		URL:     rawURL,
		Method:  http.MethodGet,
		Headers: map[string]string{},
		Params:  url.Values{"user": {""}},
	}
}

func newErrorBasedConfig() config.SQLInjectionConfig {
	return config.SQLInjectionConfig{
		Enabled: true,
		Rules: []config.SQLiPayloadRule{
			{
				Payloads:     []string{"'"},
				Type:         "error-based",
				BodyContains: []string{"sql syntax"},
			},
		},
	}
}

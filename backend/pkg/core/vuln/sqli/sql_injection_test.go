package sqli

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
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

func TestSQLInjectionTimeBasedRequiresDelayDelta(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		time.Sleep(250 * time.Millisecond)
		if strings.Contains(strings.ToLower(user), "sleep") {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	cfg := config.SQLInjectionConfig{
		Enabled: true,
		Rules: []config.SQLiPayloadRule{
			{
				Payloads:   []string{"' OR SLEEP(5)--"},
				Type:       "time-based",
				MinDelayMs: 200,
			},
		},
	}

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), cfg)
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Vulnerable {
		t.Fatalf("expected slow baseline to be suppressed, got %#v", result)
	}
}

func TestSQLInjectionBooleanBasedRequiresStableDifferentialPattern(t *testing.T) {
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
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected boolean-based vulnerability, got %#v", result)
	}
	if result.Type != "boolean-based" {
		t.Fatalf("expected boolean-based, got %q", result.Type)
	}
	if result.Payload != "'" {
		t.Fatalf("expected single-quote payload, got %q", result.Payload)
	}
}

func TestSQLInjectionBooleanBasedAllowsDynamicBaselineContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		switch user {
		case "'":
			http.Error(w, "query failed trace=1234567890123", http.StatusInternalServerError)
			return
		case "''", "":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok trace=1234567890123 request=550e8400-e29b-41d4-a716-446655440000"))
			return
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok trace=1234567890123"))
		}
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected boolean-based vulnerability with dynamic baseline, got %#v", result)
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

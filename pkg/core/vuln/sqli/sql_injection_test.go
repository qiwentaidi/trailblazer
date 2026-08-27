package sqli

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

func TestSQLInjectionDetectsNumericBooleanBasedSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("user")
		switch user {
		case "1 AND 1=1", "1 AND 2=2":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("matched row"))
		case "1 AND 1=2", "1 AND 2=3":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("no rows"))
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("baseline"))
		}
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected numeric boolean-based vulnerability, got %#v", result)
	}
	if result.Type != "boolean-based" {
		t.Fatalf("expected boolean-based, got %q", result.Type)
	}
}

func TestSQLInjectionInjectsJSONBodyPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "'") {
			http.Error(w, "You have an error in your SQL syntax;", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	req := structs.APIRequest{
		URL:            server.URL,
		Method:         http.MethodPost,
		Headers:        map[string]string{"Content-Type": "application/json"},
		Params:         url.Values{"user": {"alice"}},
		Body:           `{"user":"alice","page":1}`,
		PayloadCarrier: "body",
		PayloadFormat:  "json",
	}
	result, err := TestSQLInjection(req, newErrorBasedConfig())
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected JSON body SQL injection detection, got %#v", result)
	}
}

func TestSQLInjectionInjectsFormBodyPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "%27") {
			http.Error(w, "You have an error in your SQL syntax;", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	req := structs.APIRequest{
		URL:            server.URL,
		Method:         http.MethodPost,
		Headers:        map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		Params:         url.Values{"user": {"alice"}},
		Body:           "user=alice&page=1",
		PayloadCarrier: "body",
		PayloadFormat:  "form",
	}
	result, err := TestSQLInjection(req, newErrorBasedConfig())
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected form body SQL injection detection, got %#v", result)
	}
}

func TestSQLInjectionDetectsTimeBasedSignal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(strings.ToUpper(r.URL.Query().Get("user")), "SLEEP") {
			time.Sleep(2100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || !result.Vulnerable {
		t.Fatalf("expected time-based vulnerability, got %#v", result)
	}
	if result.Type != "time-based" {
		t.Fatalf("expected time-based, got %q", result.Type)
	}
}

func TestSQLInjectionStopsAtProbeBudget(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	payloads := make([]string, 100)
	for i := range payloads {
		payloads[i] = "' OR " + strings.Repeat("1", i%5+1)
	}
	result, err := TestSQLInjection(newTestAPIRequest(server.URL), config.SQLInjectionConfig{
		Enabled:  true,
		Payloads: payloads,
	})
	if err != nil {
		t.Fatalf("TestSQLInjection returned error: %v", err)
	}
	if result == nil || result.Vulnerable {
		t.Fatalf("expected non-vulnerable budget result, got %#v", result)
	}
	if got := atomic.LoadInt32(&requests); got > maxSQLiProbeRequests {
		t.Fatalf("expected at most %d requests, got %d", maxSQLiProbeRequests, got)
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

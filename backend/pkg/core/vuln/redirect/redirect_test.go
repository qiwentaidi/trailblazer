package redirect

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
)

func TestRedirectIgnoresSameOriginLandingWithPayloadInQuery(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login?redirectUrl="+url.QueryEscape(r.URL.Query().Get("redirectUrl")), http.StatusFound)
	})
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("login page"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result, err := TestRedirectVulnerability(structs.APIRequest{
		URL:    server.URL + "/api",
		Method: http.MethodGet,
		Params: url.Values{
			"redirectUrl": []string{"https://safe.example/internal"},
		},
	}, config.RedirectConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestRedirectVulnerability returned error: %v", err)
	}
	if result.Vulnerable {
		t.Fatalf("expected non-vulnerable result, got vulnerable: %+v", result)
	}
}

func TestRedirectDetectsExternalFinalTarget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Query().Get("redirectUrl"), http.StatusFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	result, err := TestRedirectVulnerability(structs.APIRequest{
		URL:    server.URL + "/api",
		Method: http.MethodGet,
		Params: url.Values{
			"redirectUrl": []string{"https://safe.example/internal"},
		},
	}, config.RedirectConfig{Enabled: true})
	if err != nil {
		t.Fatalf("TestRedirectVulnerability returned error: %v", err)
	}
	if !result.Vulnerable {
		t.Fatalf("expected vulnerable result, got: %+v", result)
	}
}

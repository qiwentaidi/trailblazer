package crawl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectContentTypePrefersFormOrJSONWhenParamsExist(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Content-Type") {
		case "":
			fmt.Fprint(w, "missing content type")
		case "application/x-www-form-urlencoded":
			fmt.Fprint(w, "accepted form")
		case "application/json":
			fmt.Fprint(w, "accepted json")
		case "text/plain":
			fmt.Fprint(w, "accepted text")
		default:
			fmt.Fprintf(w, "%s not supported", r.Header.Get("Content-Type"))
		}
	}))
	defer server.Close()

	got := detectContentType(server.URL, map[string]string{}, true)
	if got != "application/x-www-form-urlencoded" {
		t.Fatalf("expected form-urlencoded when params exist, got %q", got)
	}
}

func TestDetectContentTypeStillAllowsTextPlainWithoutParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("Content-Type") {
		case "":
			fmt.Fprint(w, "missing content type")
		case "text/plain":
			fmt.Fprint(w, "accepted text")
		case "application/json", "application/x-www-form-urlencoded":
			fmt.Fprintf(w, "%s not supported", r.Header.Get("Content-Type"))
		default:
			fmt.Fprintf(w, "%s not supported", r.Header.Get("Content-Type"))
		}
	}))
	defer server.Close()

	got := detectContentType(server.URL, map[string]string{}, false)
	if got != "text/plain" {
		t.Fatalf("expected text/plain without params, got %q", got)
	}
}

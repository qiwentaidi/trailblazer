package sdk

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

func TestSameAPIAssetOriginNormalizesDefaultPort(t *testing.T) {
	base, _ := url.Parse("https://1.94.192.27:443/admin/")
	tests := []struct {
		candidate string
		want      bool
	}{
		{"https://1.94.192.27/assets/app.js", true},
		{"https://1.94.192.27:443/assets/app.js", true},
		{"https://1.94.192.27:8443/assets/app.js", false},
		{"http://1.94.192.27/assets/app.js", false},
		{"https://other.example/assets/app.js", false},
	}
	for _, tc := range tests {
		candidate, _ := url.Parse(tc.candidate)
		if got := sameAPIAssetOrigin(base, candidate); got != tc.want {
			t.Errorf("sameAPIAssetOrigin(%q) = %t, want %t", tc.candidate, got, tc.want)
		}
	}
}

func TestCollectAPIAssetJSWithInvalidCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/assets/app.js" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/javascript")
		_, _ = w.Write([]byte("const api = '/api/items';"))
	}))
	defer server.Close()

	resources := collectAPIAssetJS(server.URL+"/admin/", []string{server.URL + "/assets/app.js"}, &APICrawlOptions{})
	if len(resources) != 1 || resources[0].Content != "const api = '/api/items';" {
		t.Fatalf("JS resources = %+v, want downloaded script", resources)
	}
}

func TestCollectAPIAssetJSDoesNotFollowOffOriginRedirect(t *testing.T) {
	var redirected atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirected.Store(true)
		_, _ = w.Write([]byte("external script"))
	}))
	defer destination.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/app.js", http.StatusFound)
	}))
	defer source.Close()

	resources := collectAPIAssetJS(source.URL, []string{source.URL + "/app.js"}, &APICrawlOptions{})
	if len(resources) != 0 || redirected.Load() {
		t.Fatalf("off-origin redirect was followed: resources=%d redirected=%t", len(resources), redirected.Load())
	}
}

func TestBuildAPIAssetSiteTreeIncludesTargetAndDiscoveredURLs(t *testing.T) {
	tree := buildAPIAssetSiteTree("https://example.test/app/#/home", []string{
		"https://example.test/static/app.js",
		"https://example.test/api/users?id=1",
		"https://example.test/static/app.js",
		"javascript:alert(1)",
	})
	if len(tree) != 1 || tree[0].Label != "https://example.test" {
		t.Fatalf("site tree root = %#v", tree)
	}
	labels := make(map[string]int)
	var collect func([]crawl.ElTreeNode)
	collect = func(nodes []crawl.ElTreeNode) {
		for _, node := range nodes {
			labels[node.Label]++
			collect(node.Children)
		}
	}
	collect(tree)
	for _, label := range []string{"app", "static", "app.js", "api", "users", "?id=1"} {
		if labels[label] != 1 {
			t.Errorf("node %q occurs %d times, want 1", label, labels[label])
		}
	}
	if labels["javascript:"] != 0 {
		t.Fatal("non-HTTP URL must not enter site tree")
	}
	encoded, err := json.Marshal(APIAssetResult{SiteTree: tree})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload["siteTree"]) == 0 || string(payload["siteTree"]) == "[]" {
		t.Fatalf("siteTree missing from APIAssetResult JSON: %s", encoded)
	}
}

func TestBuildAPIAssetRootCandidatesRestoresStaticAndRuntimeRoots(t *testing.T) {
	store := NewAPIStore()
	roots := buildAPIAssetRootCandidates(
		"https://example.test/#/dashboard",
		[]crawl.OperationSpec{
			{PathTemplate: "/api/ai/generate-shot-image"},
			{PathTemplate: "/api/ai/script-to-storyboard"},
		},
		[]crawl.NetworkRecord{{URL: "https://example.test/gateway/api/v1/users?id=1"}},
		store,
	)
	// Keep every legacy candidate: the broad /api/ root is useful for asset
	// grouping while the prefixed/versioned roots preserve routing precision.
	want := []string{"/api/", "/api/v1/", "/gateway/api/", "/gateway/api/v1/", "https://example.test"}
	if !reflect.DeepEqual(roots, want) {
		t.Fatalf("API Roots = %#v, want %#v", roots, want)
	}
}

func TestExportOpenAPIAssetsUsesSharedAPIRootAsServerBase(t *testing.T) {
	assets := &APIAssetResult{
		Store: NewAPIStore(),
		OperationSpecs: []crawl.OperationSpec{
			{ID: "ops_image", Method: "POST", PathTemplate: "/api/ai/generate-shot-image"},
			{ID: "ops_voice", Method: "POST", PathTemplate: "/api/ai/generate-tts-voice"},
		},
		APIRootCandidates: []string{"/api/", "http://10.10.0.54"},
	}
	raw, err := ExportOpenAPIAssets(assets, "test")
	if err != nil {
		t.Fatalf("ExportOpenAPIAssets: %v", err)
	}
	var document struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("decode OpenAPI: %v", err)
	}
	if len(document.Servers) != 1 || document.Servers[0].URL != "http://10.10.0.54/api" {
		t.Fatalf("servers = %+v, want http://10.10.0.54/api", document.Servers)
	}
	if _, ok := document.Paths["/ai/generate-shot-image"]; !ok {
		t.Fatalf("rebased path missing from %#v", document.Paths)
	}
	if _, ok := document.Paths["/api/ai/generate-shot-image"]; ok {
		t.Fatalf("unrebased path must not remain in %#v", document.Paths)
	}
}

func TestBuildAPIAssetRootCandidatesKeepsSiteRootWithoutAPIRoutes(t *testing.T) {
	roots := buildAPIAssetRootCandidates("https://example.test/app", nil, nil, NewAPIStore())
	want := []string{"https://example.test"}
	if !reflect.DeepEqual(roots, want) {
		t.Fatalf("API Roots = %#v, want %#v", roots, want)
	}
}

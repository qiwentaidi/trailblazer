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
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
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

func TestCollectAPIAssetJSFollowsDocumentAndRecursiveModules(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/admin/":
			_, _ = w.Write([]byte(`<script type="module" src="/admin/assets/main.js"></script><link rel="modulepreload" href="/admin/assets/preload.js">`))
		case "/admin/assets/main.js":
			_, _ = w.Write([]byte(`import "./preload.js"; import "./missing.js"; const page = () => import("./lazy.js");`))
		case "/admin/assets/preload.js":
			_, _ = w.Write([]byte(`export const preload = true;`))
		case "/admin/assets/lazy.js":
			_, _ = w.Write([]byte(`import { shared } from "./shared.js"; export { shared };`))
		case "/admin/assets/shared.js":
			_, _ = w.Write([]byte(`import "./main.js"; export const shared = true;`))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("<html>SPA fallback</html>"))
		}
	}))
	defer server.Close()

	resources := collectAPIAssetJS(server.URL+"/admin/", nil, &APICrawlOptions{})
	if len(resources) != 4 {
		t.Fatalf("JS resources = %d, want four distinct modules: %+v", len(resources), resources)
	}
	if requests.Load() != 6 {
		t.Fatalf("requests = %d, want document, four modules, and one HTML fallback", requests.Load())
	}
	limited := collectAPIAssetJS(server.URL+"/admin/", nil, &APICrawlOptions{MaxJSResources: 2})
	if len(limited) != 2 {
		t.Fatalf("limited JS resources = %d, want 2", len(limited))
	}
}

func TestPrefixAPIAssetBlueprintPathsFromRuntime(t *testing.T) {
	blueprints := []crawl.RequestBlueprint{
		{Method: "GET", Path: "/config/getConfig"},
		{Method: "POST", Path: "/login/account"},
	}
	records := []crawl.NetworkRecord{{URL: "https://example.test/adminapi/config/getConfig"}}
	got := prefixAPIAssetBlueprintPaths(blueprints, records)
	if got[0].Path != "/adminapi/config/getConfig" || got[1].Path != "/adminapi/login/account" {
		t.Fatalf("prefixed blueprints = %+v", got)
	}
	if blueprints[0].Path != "/config/getConfig" {
		t.Fatal("source blueprints were modified")
	}
	if ambiguous := prefixAPIAssetBlueprintPaths(blueprints, []crawl.NetworkRecord{
		{URL: "https://example.test/adminapi/config/getConfig"},
		{URL: "https://example.test/config/getConfig"},
	}); ambiguous[0].Path != "/config/getConfig" {
		t.Fatalf("ambiguous prefix changed paths: %+v", ambiguous)
	}
}

func TestSupplementAPIAssetUploadActions(t *testing.T) {
	resources := []database.JSResource{{
		URL:     "https://example.test/assets/upload.js",
		Content: "const action=`${config.baseURL}${config.prefix}/upload/${props.type}`; return {action:action};",
	}}
	got := supplementAPIAssetUploadActions(nil, resources)
	if len(got) != 1 || got[0].Method != "POST" || got[0].Path != "/upload/{type}" || got[0].ID == "" {
		t.Fatalf("upload action blueprint = %+v", got)
	}
	if len(supplementAPIAssetUploadActions(got, resources)) != 1 {
		t.Fatal("upload action was duplicated")
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

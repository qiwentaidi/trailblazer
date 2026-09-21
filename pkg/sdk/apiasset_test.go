package sdk

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
)

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

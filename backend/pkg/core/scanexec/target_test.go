package scanexec

import (
	"strings"
	"sync"
	"testing"
	"time"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/structs"
)

type denyTemplateReviewerStub struct {
	confirmed bool
}

func (s denyTemplateReviewerStub) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	return s.confirmed, "stub", nil
}

func TestBindStaticContexts(t *testing.T) {
	vulns := []database.VulnRecord{
		{
			URL: "https://example.com/api/common/getCitys",
		},
	}
	jsResources := []database.JSResource{
		{
			URL:       "https://example.com/app.js",
			Content:   `axios.get("/api/common/getCitys").then(renderCities)`,
			FetchedAt: time.Now(),
		},
		{
			URL:       "https://example.com/other.js",
			Content:   `fetch("/api/other/demo")`,
			FetchedAt: time.Now(),
		},
	}

	bindStaticContexts(vulns, jsResources)

	if len(vulns[0].StaticContexts) != 1 {
		t.Fatalf("expected 1 static context, got %d", len(vulns[0].StaticContexts))
	}
	if vulns[0].StaticContexts[0].SourceURL != "https://example.com/app.js" {
		t.Fatalf("unexpected source url: %s", vulns[0].StaticContexts[0].SourceURL)
	}
	if !strings.Contains(vulns[0].StaticContexts[0].Snippet, "/api/common/getCitys") {
		t.Fatalf("expected snippet to contain matched path, got %q", vulns[0].StaticContexts[0].Snippet)
	}
}

func TestBuildAssetInfoPreservesAIVerifiedFlag(t *testing.T) {
	assets := buildAssetInfo(structs.FindSomething{
		Sensitive: []structs.InfoSource{
			{Filed: "password=adminTest", Source: "https://example.com/app.js", AIVerified: true},
		},
	})

	if len(assets.Sensitive) != 1 {
		t.Fatalf("expected 1 sensitive asset, got %d", len(assets.Sensitive))
	}
	if !assets.Sensitive[0].AIVerified {
		t.Fatal("expected sensitive asset to preserve aiVerified")
	}
}

func TestBuildAssetVulnerabilitiesPreserveAIVerifiedFlag(t *testing.T) {
	vulns := buildAssetVulnerabilities(AssetInfo{
		Sensitive: []SensitiveItem{
			{Value: `password:"adminTest"`, Source: "https://example.com/app.js", AIVerified: true},
		},
	})

	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if !vulns[0].AIVerified {
		t.Fatal("expected sensitive vulnerability to preserve aiVerified")
	}
}

func TestBuildFrontendRoutesNormalizesHashAndFiltersAPI(t *testing.T) {
	routes := buildFrontendRoutes([]crawl.FrontendRouteRecord{
		{Path: "https://example.com/#/admin/users", SourceKind: "router-get-routes"},
		{Path: "/admin/users?tab=1", SourceKind: "router-options"},
		{Path: "/api/users", SourceKind: "router-get-routes"},
		{Path: "/assets/logo.svg", SourceKind: "router-get-routes"},
		{Path: "/noise/route", SourceKind: "window-scan"},
	})

	if len(routes) != 1 {
		t.Fatalf("expected 1 frontend route after filtering, got %#v", routes)
	}
	if routes[0] != "/admin/users" {
		t.Fatalf("expected normalized frontend route, got %#v", routes)
	}
}

func TestBuildFrontendRoutesDropsUnconfirmedSourceKinds(t *testing.T) {
	routes := buildFrontendRoutes([]crawl.FrontendRouteRecord{
		{Path: "/admin/users", SourceKind: "window-scan"},
		{Path: "/admin/roles", SourceKind: "array-push"},
		{Path: "/admin/dashboard", SourceKind: "react-fiber-scan"},
	})

	if len(routes) != 0 {
		t.Fatalf("expected unconfirmed frontend routes to be dropped, got %#v", routes)
	}
}

func TestBuildFrontendRoutesKeepsConfirmedReactSourceKinds(t *testing.T) {
	routes := buildFrontendRoutes([]crawl.FrontendRouteRecord{
		{Path: "/console/home/dashboard", SourceKind: "react-router-provider"},
		{Path: "/console/login", SourceKind: "react-jsx-routes"},
	})

	if len(routes) != 2 {
		t.Fatalf("expected confirmed react frontend routes to be kept, got %#v", routes)
	}
}

func TestBuildStaticAPIRoutesFiltersAndDedupes(t *testing.T) {
	routes := buildStaticAPIRoutes(
		structs.FindSomething{
			APIRoute: []structs.InfoSource{
				{Filed: "/api/users"},
				{Filed: "/api/users[id]"},
				{Filed: " https://example.com/api/users "},
			},
		},
		func() crawl.NetworkLinks {
			var links crawl.NetworkLinks
			links.Classification.APIRoute = []string{"/api/users", "/api/roles"}
			return links
		}(),
		crawl.Filter{},
	)

	if len(routes) != 2 {
		t.Fatalf("expected 2 static routes, got %#v", routes)
	}
	if routes[0] != "https://example.com/api/users" || routes[1] != "/api/roles" {
		t.Fatalf("unexpected static routes: %#v", routes)
	}
}

func TestBuildFrontendRouteDeltasUsesVisibleRoutesOnly(t *testing.T) {
	deltas := buildFrontendRouteDeltas(
		[]string{"/admin/users"},
		[]crawl.FrontendRouteRecord{
			{Path: "https://example.com/#/admin/users", SourceKind: "history-push", Source: "history.pushState", PageURL: "https://example.com/#/login"},
			{Path: "/api/users", SourceKind: "history-push", Source: "history.pushState", PageURL: "https://example.com/#/login"},
		},
	)

	if len(deltas) != 1 {
		t.Fatalf("expected 1 frontend delta, got %#v", deltas)
	}
	if deltas[0].Path != "/admin/users" {
		t.Fatalf("unexpected frontend delta path: %#v", deltas)
	}
	if deltas[0].SourceKind != "history-push" {
		t.Fatalf("unexpected source kind: %#v", deltas)
	}
}

func TestDiffStringSliceReturnsRuntimeOnlyRoutes(t *testing.T) {
	diff := diffStringSlice(
		[]string{"https://example.com/api/users", "/api/roles", "/api/roles"},
		[]string{"/api/roles"},
	)

	if len(diff) != 1 || diff[0] != "https://example.com/api/users" {
		t.Fatalf("unexpected diff: %#v", diff)
	}
}

func TestClassifyRuntimeAPIRouteSourcePrefersProtocolTrace(t *testing.T) {
	source := classifyRuntimeAPIRouteSource(
		"https://example.com/api/users",
		[]crawl.NetworkRecord{{URL: "https://example.com/api/users"}},
		[]crawl.ProtocolTraceRecord{{RequestURL: "https://example.com/api/users?id=1"}},
	)

	if source != "protocol-trace" {
		t.Fatalf("expected protocol-trace source, got %s", source)
	}
}

func TestAnnotateUnauthorizedNoiseMarksClusterAsAIVerified(t *testing.T) {
	denyTemplateAIReviewCache = sync.Map{}

	vulns := []database.VulnRecord{
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			URL:            "https://example.com/api/a",
			Request:        "GET /api/a HTTP/1.1",
			Response:       `{"success":false,"message":"请先登录","trace_id":"abc"}`,
			ResponseLength: 64,
		},
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			URL:            "https://example.com/api/b",
			Request:        "GET /api/b HTTP/1.1",
			Response:       `{"success":false,"message":"请先登录","trace_id":"def"}`,
			ResponseLength: 64,
		},
		{
			Title:          "未授权访问",
			Type:           "未授权访问",
			URL:            "https://example.com/api/c",
			Request:        "GET /api/c HTTP/1.1",
			Response:       `{"success":false,"message":"请先登录","trace_id":"ghi"}`,
			ResponseLength: 64,
		},
	}

	annotated := annotateUnauthorizedNoise(vulns, denyTemplateReviewerStub{confirmed: true})
	for _, vuln := range annotated {
		if !vuln.AIVerified {
			t.Fatalf("expected vuln %s to be ai verified", vuln.URL)
		}
		if vuln.DenyTemplateID == "" {
			t.Fatalf("expected vuln %s to receive deny template id", vuln.URL)
		}
	}
}

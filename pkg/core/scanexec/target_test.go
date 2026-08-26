package scanexec

import (
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	weaklogin "github.com/qiwentaidi/trailblazer/pkg/core/vuln/weaklogin"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type denyTemplateReviewerStub struct {
	confirmed bool
	calls     int
}

func (s *denyTemplateReviewerStub) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	s.calls++
	return s.confirmed, "stub", nil
}

type structuredUnauthorizedReviewerStub struct {
	review crawl.UnauthorizedAIReview
	calls  int
}

func (s *structuredUnauthorizedReviewerStub) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	return s.review.IsFalsePositive(), s.review.Reason, nil
}

func (s *structuredUnauthorizedReviewerStub) ReviewUnauthorizedAccess(targetURL, requestPreview, responsePreview string) (crawl.UnauthorizedAIReview, error) {
	s.calls++
	return s.review, nil
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

func TestExtractWebpackChunkJSLinks(t *testing.T) {
	content := `u.e=function(e){var n=({}[e]||e)+"."+{0:"87e70602",1:"32c8143c",8:"1f9ff966"}[e]+".js"}`

	links := extractWebpackChunkJSLinks("https://example.com/assets/main.6281bd04.js", content)

	want := []string{
		"https://example.com/assets/0.87e70602.js",
		"https://example.com/assets/1.32c8143c.js",
		"https://example.com/assets/8.1f9ff966.js",
	}
	for _, item := range want {
		if !containsStringLocal(links, item) {
			t.Fatalf("expected chunk link %q, got %#v", item, links)
		}
	}
}

func TestNormalizeJSURLHandlesProtocolRelativeLinks(t *testing.T) {
	got := normalizeJSURL("https://example.com/app/", "//cdn.example.com/a.js")
	if got != "https://cdn.example.com/a.js" {
		t.Fatalf("expected protocol-relative JS URL to keep CDN host, got %q", got)
	}
}

func TestNormalizeJSURLUsesPageDirectoryForRelativeLinks(t *testing.T) {
	got := normalizeJSURL("https://web.cupdata.com/ncoas/0581/m/", "static/js/app.js")
	want := "https://web.cupdata.com/ncoas/0581/m/static/js/app.js"
	if got != want {
		t.Fatalf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestNormalizeJSURLUsesOriginForRootRelativeLinks(t *testing.T) {
	got := normalizeJSURL("https://web.cupdata.com/ncoas/0581/m/", "/static/js/app.js")
	want := "https://web.cupdata.com/static/js/app.js"
	if got != want {
		t.Fatalf("normalizeJSURL() = %q, want %q", got, want)
	}
}

func TestFetchStaticHintJSResourcesSendsPageReferer(t *testing.T) {
	var gotReferer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotReferer = r.Header.Get("Referer")
		if gotReferer == "" {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			_, _ = w.Write([]byte("<html>range error</html>"))
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte("window.__manifest_ok__=true;"))
	}))
	defer server.Close()

	homeURL := server.URL + "/ncoas/0581/m/"
	resources := fetchStaticHintJSResources("task", 1, homeURL, []string{"static/js/manifest.js"}, nil)
	if len(resources) != 1 {
		t.Fatalf("expected one JS resource, got %#v", resources)
	}
	if resources[0].ResponseCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d with content %q", resources[0].ResponseCode, resources[0].Content)
	}
	if resources[0].Content != "window.__manifest_ok__=true;" {
		t.Fatalf("unexpected content: %q", resources[0].Content)
	}
	if gotReferer != homeURL {
		t.Fatalf("Referer = %q, want %q", gotReferer, homeURL)
	}
}

func containsStringLocal(items []string, value string) bool {
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

func TestDedupeVulnerabilitiesHandlesUnauthorizedTrailingSlash(t *testing.T) {
	tests := []struct {
		name      string
		responses [2]string
		lengths   [2]int
		wantCount int
	}{
		{name: "same response", responses: [2]string{`{"detail":"ok"}`, `{"detail":"ok"}`}, lengths: [2]int{15, 15}, wantCount: 1},
		{name: "different response", responses: [2]string{`{"detail":"first"}`, `{"detail":"second"}`}, lengths: [2]int{18, 19}, wantCount: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := dedupeVulnerabilities([]database.VulnRecord{
				{Title: "未授权访问", Type: "未授权访问", Method: "GET", URL: "https://sentry.weixing-tech.com/api/0", Response: tt.responses[0], ResponseLength: tt.lengths[0]},
				{Title: "未授权访问", Type: "未授权访问", Method: "GET", URL: "https://sentry.weixing-tech.com/api/0/", Response: tt.responses[1], ResponseLength: tt.lengths[1]},
			})
			if len(vulns) != tt.wantCount {
				t.Fatalf("deduped findings = %#v, want %d", vulns, tt.wantCount)
			}
		})
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
	if vulns[0].Method != http.MethodGet {
		t.Fatalf("expected sensitive vulnerability method GET, got %q", vulns[0].Method)
	}
}

func TestDedupeAssetsMergesSensitiveValuesAcrossSources(t *testing.T) {
	assets := AssetInfo{
		Phone: []SensitiveItem{
			{Value: "15159277491", Source: "http://47.98.57.184:8085/article/31.html"},
			{Value: "15159277491", Source: "http://47.98.57.184:8085/article/36.html", AIVerified: true},
		},
	}

	dedupeAssets(&assets)

	if len(assets.Phone) != 1 {
		t.Fatalf("expected one phone asset after same-value dedupe, got %#v", assets.Phone)
	}
	if assets.Phone[0].Source != "http://47.98.57.184:8085/article/31.html" {
		t.Fatalf("expected first source to be retained, got %q", assets.Phone[0].Source)
	}
	if len(assets.Phone[0].Sources) != 2 {
		t.Fatalf("expected two merged sources, got %#v", assets.Phone[0].Sources)
	}
	if assets.Phone[0].Sources[1] != "http://47.98.57.184:8085/article/36.html" {
		t.Fatalf("expected second source to be retained, got %#v", assets.Phone[0].Sources)
	}
	if !assets.Phone[0].AIVerified {
		t.Fatal("expected ai verification flag to be merged")
	}

	vulns := buildAssetVulnerabilities(assets)
	if len(vulns) != 1 {
		t.Fatalf("expected one phone vulnerability after asset dedupe, got %#v", vulns)
	}
	if vulns[0].URL != "http://47.98.57.184:8085/article/31.html" {
		t.Fatalf("expected vulnerability to retain representative source, got %q", vulns[0].URL)
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
		"https://example.com/app/",
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
	if routes[0] != "/api/roles" || routes[1] != "/api/users" {
		t.Fatalf("unexpected static routes: %#v", routes)
	}
}

func TestBuildAPIRoutesPrefersRuntimeAbsoluteOverStaticRelative(t *testing.T) {
	routes := buildAPIRoutes(
		"https://example.com/app/",
		structs.FindSomething{
			APIRoute: []structs.InfoSource{
				{Filed: "/api/users"},
			},
		},
		func() crawl.NetworkLinks {
			var links crawl.NetworkLinks
			links.Classification.APIRoute = []string{"https://example.com/api/users"}
			return links
		}(),
		[]crawl.NetworkRecord{{URL: "https://example.com/api/users"}},
		nil,
		crawl.Filter{},
	)

	if len(routes) != 1 {
		t.Fatalf("expected one runtime route, got %#v", routes)
	}
	if routes[0] != "https://example.com/api/users" {
		t.Fatalf("expected runtime absolute route to be kept, got %#v", routes)
	}
}

func TestBuildAPIRoutesKeepsStaticRelativeWhenAbsoluteIsDiscoveryOnly(t *testing.T) {
	routes := buildAPIRoutes(
		"https://web.cupdata.com/ncoas/0581/m/",
		structs.FindSomething{
			APIRoute: []structs.InfoSource{
				{Filed: "/m/api/save"},
			},
		},
		func() crawl.NetworkLinks {
			var links crawl.NetworkLinks
			links.Classification.APIRoute = []string{"https://web.cupdata.com/m/api/save"}
			return links
		}(),
		nil,
		nil,
		crawl.Filter{},
	)

	if len(routes) != 1 {
		t.Fatalf("expected one static route, got %#v", routes)
	}
	if routes[0] != "/m/api/save" {
		t.Fatalf("expected static relative route to be kept, got %#v", routes)
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

func TestAnnotateUnauthorizedNoiseRequiresIndividualAIReview(t *testing.T) {
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
	}

	reviewer := &denyTemplateReviewerStub{confirmed: false}
	annotated := annotateUnauthorizedNoise(vulns, reviewer, make(map[string]struct{}))
	if reviewer.calls != len(vulns) {
		t.Fatalf("AI review calls = %d, want %d", reviewer.calls, len(vulns))
	}
	for _, vuln := range annotated {
		if !vuln.AIVerified {
			t.Fatalf("expected vuln %s to be ai verified", vuln.URL)
		}
	}
}

func TestAnnotateUnauthorizedNoiseFiltersDeniedOrUncheckedResults(t *testing.T) {
	vulns := []database.VulnRecord{{
		Title:    "未授权访问",
		Type:     "未授权访问",
		URL:      "https://example.com/api/a",
		Request:  "GET /api/a HTTP/1.1",
		Response: `{"data":{"id":1}}`,
	}}

	if got := annotateUnauthorizedNoise(vulns, nil, make(map[string]struct{})); len(got) != 0 {
		t.Fatalf("unchecked unauthorized findings = %#v, want none", got)
	}
	if got := annotateUnauthorizedNoise(vulns, &denyTemplateReviewerStub{confirmed: true}, make(map[string]struct{})); len(got) != 0 {
		t.Fatalf("AI-denied unauthorized findings = %#v, want none", got)
	}
}

func TestAnnotateUnauthorizedNoiseTreatsTypedNilReviewerAsMissing(t *testing.T) {
	vulns := []database.VulnRecord{{
		Title:    "未授权访问",
		Type:     "未授权访问",
		URL:      "https://example.com/api/a",
		Request:  "GET /api/a HTTP/1.1",
		Response: `{"data":{"id":1}}`,
	}}

	var checker *crawl.SensitiveInfoChecker
	reviewer := asDenyTemplateReviewer(checker)
	got := annotateUnauthorizedNoise(vulns, reviewer, make(map[string]struct{}))
	if len(got) != 0 {
		t.Fatalf("typed-nil reviewer must be treated as missing, got %#v", got)
	}
}

func TestAnnotateUnauthorizedNoisePersistsManualStructuredReview(t *testing.T) {
	vulns := []database.VulnRecord{{
		Title:      "未授权访问",
		Type:       "未授权访问",
		Confidence: "high",
		URL:        "https://example.com/resource/client/getCopywriting",
		Request:    "GET /resource/client/getCopywriting HTTP/1.1",
		Response:   `{"code":0,"data":{"labelInfo":{"workbenchLabel":"demo"}}}`,
	}}
	reviewer := &structuredUnauthorizedReviewerStub{review: crawl.UnauthorizedAIReview{
		Verdict:            "NEEDS_MANUAL_REVIEW",
		VulnerabilityType:  "UNKNOWN",
		Confidence:         90,
		ProtectedResource:  crawl.AITruthUnknown,
		SensitiveDataFound: crawl.AITruthUnknown,
		Evidence:           []string{},
		Reason:             "缺少接口权限设计证据",
		Impact:             "无法确认安全影响",
		RiskLevel:          "UNKNOWN",
		MissingEvidence:    []string{"登录前后对比"},
		RecommendedAction:  "人工确认接口是否设计为公开接口",
	}}

	annotated := annotateUnauthorizedNoise(vulns, reviewer, make(map[string]struct{}))
	if len(annotated) != 1 {
		t.Fatalf("manual-review findings = %#v, want one finding", annotated)
	}
	if !annotated[0].AIVerified {
		t.Fatal("manual-review finding must remain marked as AI reviewed")
	}
	if annotated[0].AIReviewVerdict != "NEEDS_MANUAL_REVIEW" || annotated[0].AIReviewConfidence != manualUnauthorizedReviewConfidenceCap {
		t.Fatalf("structured AI review was not persisted: %#v", annotated[0])
	}
	if annotated[0].Confidence != "medium" {
		t.Fatalf("manual review should downgrade high confidence to medium, got %q", annotated[0].Confidence)
	}
}

func TestBuildJSFindOptionsLeavesAICheckerNilWhenDisabled(t *testing.T) {
	options := buildJSFindOptions(
		Options{},
		"https://example.com",
		nil,
		"https://example.com/api",
		crawl.StaticEndpointHintBundle{},
		nil,
		nil,
	)
	if options.AIChecker != nil {
		t.Fatalf("disabled OpenAI checker must remain nil, got %#v", options.AIChecker)
	}
}

func TestAnnotateUnauthorizedNoiseReusesFilteredTemplateWithinScan(t *testing.T) {
	vulns := []database.VulnRecord{
		{
			Title:    "未授权访问",
			Type:     "未授权访问",
			URL:      "https://example.com/api/a",
			Request:  "GET /api/a HTTP/1.1",
			Response: `{"code":200,"message":"错误的 URI /api/a","success":false}`,
		},
		{
			Title:    "未授权访问",
			Type:     "未授权访问",
			URL:      "https://example.com/api/b",
			Request:  "GET /api/b HTTP/1.1",
			Response: `{"code":200,"message":"错误的 URI /api/b","success":false}`,
		},
	}

	reviewer := &denyTemplateReviewerStub{confirmed: true}
	annotated := annotateUnauthorizedNoise(vulns, reviewer, make(map[string]struct{}))
	if len(annotated) != 0 {
		t.Fatalf("filtered findings = %#v, want none", annotated)
	}
	if reviewer.calls != 1 {
		t.Fatalf("AI review calls = %d, want 1", reviewer.calls)
	}
}

func TestResolveWeakCredsIncludesObservedLoginCredential(t *testing.T) {
	creds := resolveWeakCreds([]string{" admin : admin123 ", "invalid", "1:Test@123456"})

	if len(creds) != 2 {
		t.Fatalf("expected 2 normalized creds, got %#v", creds)
	}
	if creds[0] != "admin:admin123" {
		t.Fatalf("expected first normalized cred, got %#v", creds)
	}
	if creds[1] != autogeneratedLoginEventCred {
		t.Fatalf("expected observed login credential to be preserved, got %#v", creds)
	}
}

func TestResolveWeakCredsFallsBackToBuiltins(t *testing.T) {
	creds := resolveWeakCreds(nil)

	if len(creds) != len(builtinWeakCreds)+1 {
		t.Fatalf("expected builtin weak creds plus observed login cred, got %#v", creds)
	}
	if creds[len(creds)-1] != autogeneratedLoginEventCred {
		t.Fatalf("expected autogenerated login cred, got %#v", creds)
	}
}

func TestBuildWeakLoginVulnerabilityRecordsPrefilledCredentialSuccess(t *testing.T) {
	record := buildWeakLoginVulnerability(Options{TaskID: "task-1", Version: 2}, "https://example.com/login", &weaklogin.WeakFormLoginResult{
		Vulnerable:        true,
		Username:          "<prefilled>",
		Password:          "<prefilled>",
		Response:          `{"authenticated":true,"principal":"labuser"}`,
		Reason:            "页面预填充凭据直接触发登录成功",
		UsedPrefilledCred: true,
	})

	if record.Type != "WEAK_PASSWORD" || record.Level != "high" || record.Method != "FORM" {
		t.Fatalf("unexpected weak-login vulnerability metadata: %#v", record)
	}
	if record.TaskID != "task-1" || record.Version != 2 || record.URL != "https://example.com/login" {
		t.Fatalf("unexpected weak-login vulnerability identity: %#v", record)
	}
	if !strings.Contains(record.Description, "<prefilled>") || !strings.Contains(record.Description, "页面预填充凭据直接触发登录成功") {
		t.Fatalf("expected prefilled credential evidence in description, got %q", record.Description)
	}
}

func TestInferWeakLoginTargetURLsPrefersCapturedLoginPages(t *testing.T) {
	targets := inferWeakLoginTargetURLs(
		"https://example.com/",
		[]crawl.NetworkRecord{
			{
				URL:         "https://example.com/api/auth/login",
				PageURL:     "https://example.com/#/login",
				RequestBody: `{"username":"1","password":"Test@123456"}`,
			},
		},
		[]crawl.FrontendRouteRecord{
			{Path: "/console/login", SourceKind: "react-router-provider"},
		},
	)

	if len(targets) < 2 {
		t.Fatalf("expected multiple login targets, got %#v", targets)
	}
	if targets[0] != "https://example.com/#/login" {
		t.Fatalf("expected captured login page first, got %#v", targets)
	}
	if targets[1] != "https://example.com/console/login" {
		t.Fatalf("expected frontend login route candidate, got %#v", targets)
	}
}

func TestInferWeakLoginTargetURLsFallsBackToEntryTarget(t *testing.T) {
	targets := inferWeakLoginTargetURLs(
		"https://example.com/login",
		nil,
		nil,
	)

	if len(targets) != 1 || targets[0] != "https://example.com/login" {
		t.Fatalf("expected fallback target URL, got %#v", targets)
	}
}

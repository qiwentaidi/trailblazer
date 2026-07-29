package scanexec

import (
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"net/http"
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

func TestBuildDiscoveredRequestsPreservesDynamicRequestEvidence(t *testing.T) {
	requests := buildDiscoveredRequests([]crawl.NetworkRecord{{
		URL:    "https://example.com/api/orders",
		Method: "POST",
		RequestHeaders: map[string]string{
			"Content-Type": "application/json",
			"X-Trace":      "captured",
		},
		RequestBody:     `{"id":1}`,
		ResponseHeaders: map[string]string{"Server": "unit-test"},
		ResponseBody:    `{"ok":true}`,
		ResponseCode:    http.StatusCreated,
		MIMEType:        "application/json",
	}})

	if len(requests) != 1 {
		t.Fatalf("expected one discovered request, got %#v", requests)
	}
	if requests[0].ContentType != "application/json" || requests[0].Body != `{"id":1}` {
		t.Fatalf("unexpected discovered request: %#v", requests[0])
	}
	if requests[0].Headers["X-Trace"] != "captured" || requests[0].Source != "dynamic-browser-capture" {
		t.Fatalf("expected captured evidence to be retained: %#v", requests[0])
	}
	if requests[0].ResponseCode != http.StatusCreated || requests[0].ResponseMIMEType != "application/json" ||
		requests[0].ResponseHeaders["Server"] != "unit-test" || requests[0].ResponseBody != `{"ok":true}` {
		t.Fatalf("expected captured response metadata to be retained: %#v", requests[0])
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

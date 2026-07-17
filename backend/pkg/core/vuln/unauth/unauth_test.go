package unauth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/structs"
)

func resetUnauthorizedTestState(t *testing.T) {
	t.Helper()

	seenHTMLHashes.Lock()
	seenHTMLHashes.items = make(map[string]struct{})
	seenHTMLHashes.Unlock()

	responseSignatureTracker.Lock()
	responseSignatureTracker.counts = make(map[string]int)
	responseSignatureTracker.Unlock()

	responseTemplateTracker.Lock()
	responseTemplateTracker.clusters = make(map[string][]responseTemplateCluster)
	responseTemplateTracker.Unlock()

	learnedAuthPatternRegistry.Lock()
	learnedAuthPatternRegistry.loaded = false
	learnedAuthPatternRegistry.patterns = nil
	learnedAuthPatternRegistry.index = make(map[string]struct{})
	learnedAuthPatternRegistry.Unlock()
}

func initTempSQLiteForUnauthTest(t *testing.T) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "unauth-test.db")
	if database.DB != nil {
		_ = database.DB.Close()
		database.DB = nil
	}
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("failed to init sqlite: %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})
}

func TestAssessConfidenceLowersRepeatedGenericErrors(t *testing.T) {
	resetUnauthorizedTestState(t)

	body := `{"code":"err.common.system.error","msg":"系统错误","success":false}`
	for i := 0; i < 5; i++ {
		confidence, reason := assessConfidence(200, body, "https://example.com/api/message/query")
		if confidence != "low" {
			t.Fatalf("confidence = %q, want low; reason=%q", confidence, reason)
		}
		if i == 4 {
			if reason != "低置信：结果更像相似拒绝模板或通用错误响应" {
				t.Fatalf("reason = %q, want low confidence statement", reason)
			}
		}
	}
}

func TestAssessConfidenceKeepsStructuredDataHigher(t *testing.T) {
	resetUnauthorizedTestState(t)

	body := `{"code":200,"data":{"list":[{"id":1,"name":"alice"},{"id":2,"name":"bob"}],"total":2},"success":true}`
	confidence, reason := assessConfidence(200, body, "https://example.com/api/orders/query")
	if confidence != "high" {
		t.Fatalf("confidence = %q, want high; reason=%q", confidence, reason)
	}
	if reason != "高置信：响应包含明确业务数据返回" {
		t.Fatalf("reason = %q, want high confidence statement", reason)
	}
}

func TestClassifyUnauthorizedExposureMarksPublicGeoData(t *testing.T) {
	body := `{"code":200,"data":[{"code":"110000","name":"北京市","province":"北京市","city":"北京市","district":"朝阳区"}],"success":true}`
	exposure, reason := classifyUnauthorizedExposure(body, "https://example.com/api/base/city/list")
	if exposure != "public_data" {
		t.Fatalf("exposure = %q, want public_data; reason=%q", exposure, reason)
	}
	if level := adjustUnauthorizedRiskLevel("medium", exposure); level != "info" {
		t.Fatalf("adjusted level = %q, want info", level)
	}
}

func TestClassifyUnauthorizedExposureMarksBasicReferenceData(t *testing.T) {
	body := `{"data":[{"label":"启用","value":"enabled","dictLabel":"启用","dictValue":"enabled","sort":1}],"success":true}`
	exposure, reason := classifyUnauthorizedExposure(body, "https://example.com/api/system/dict/options")
	if exposure != "basic_reference" {
		t.Fatalf("exposure = %q, want basic_reference; reason=%q", exposure, reason)
	}
	if level := adjustUnauthorizedRiskLevel("high", exposure); level != "low" {
		t.Fatalf("adjusted level = %q, want low", level)
	}
}

func TestClassifyUnauthorizedExposureKeepsSensitiveUserDataHigh(t *testing.T) {
	body := `{"data":{"records":[{"user":"alice","phone":"13800138000","email":"alice@example.com","role":"admin"}],"total":1},"success":true}`
	exposure, reason := classifyUnauthorizedExposure(body, "https://example.com/api/admin/users/list")
	if exposure != "sensitive_data" {
		t.Fatalf("exposure = %q, want sensitive_data; reason=%q", exposure, reason)
	}
	if level := adjustUnauthorizedRiskLevel("low", exposure); level != "high" {
		t.Fatalf("adjusted level = %q, want high", level)
	}
}

func TestShouldTreatHTMLAsUnauthorizedRejectsLoginPage(t *testing.T) {
	body := `<!doctype html><html><body><h1>用户登录</h1><form><input name="username"/><input name="password"/></form><div>请先登录后访问</div></body></html>`
	if shouldTreatHTMLAsUnauthorized(body, "https://example.com/admin/login") {
		t.Fatal("expected login html to be rejected")
	}
}

func TestShouldTreatHTMLAsUnauthorizedRejectsGenericErrorPage(t *testing.T) {
	body := `<!doctype html><html><body><h1>403 Forbidden</h1><p>访问受限</p><p>系统错误</p></body></html>`
	if shouldTreatHTMLAsUnauthorized(body, "https://example.com/admin/orders") {
		t.Fatal("expected generic error html to be rejected")
	}
}

func TestShouldTreatHTMLAsUnauthorizedRejectsSPAShell(t *testing.T) {
	body := `<!doctype html><html><body><div id="app"></div><script src="/static/js/app.js"></script></body></html>`
	if shouldTreatHTMLAsUnauthorized(body, "https://example.com/dashboard") {
		t.Fatal("expected spa shell html to be rejected")
	}
}

func TestShouldTreatHTMLAsUnauthorizedAcceptsBusinessTablePage(t *testing.T) {
	body := `<!doctype html><html><body><h1>用户管理后台</h1><table><tr><th>姓名</th><th>邮箱</th><th>手机号</th></tr><tr><td>Alice</td><td>alice@example.com</td><td>13800138000</td></tr></table></body></html>`
	if !shouldTreatHTMLAsUnauthorized(body, "https://example.com/admin/users") {
		t.Fatal("expected business html with sensitive data to be accepted")
	}
}

func TestShouldSkipUnauthTestSkipsPublicAuthEndpoints(t *testing.T) {
	for _, rawURL := range []string{
		"https://example.com/api/auth/login",
		"https://example.com/api/user/logout",
		"https://example.com/api/captcha/generate",
		"https://example.com/api/auth/sendSmsCode?mobile=13800138000",
		"https://example.com/open/kaptcha/image",
	} {
		if !shouldSkipUnauthTest(rawURL) {
			t.Fatalf("expected %s to be skipped", rawURL)
		}
	}
}

func TestShouldSkipUnauthTestSkipsFrameworkInternalEndpoints(t *testing.T) {
	for _, rawURL := range []string{
		"https://example.com/__nextjs_launch-editor?",
		"https://example.com/__nextjs_restart_dev",
		"https://example.com/_next/static/chunks/app.js",
		"https://example.com/@vite/client",
	} {
		if !shouldSkipUnauthTest(rawURL) {
			t.Fatalf("expected %s to be skipped", rawURL)
		}
	}
}

func TestShouldSkipUnauthTestKeepsBusinessCodeEndpoints(t *testing.T) {
	for _, rawURL := range []string{
		"https://example.com/api/system/dict/code/list",
		"https://example.com/api/area/countryCode/list",
		"https://example.com/api/order/verification-record/detail",
		"https://example.com/api/invite/verifyResult",
	} {
		if shouldSkipUnauthTest(rawURL) {
			t.Fatalf("expected %s not to be skipped", rawURL)
		}
	}
}

func TestShouldRejectUnauthorizedPayloadRequiresStructuredBusinessResponse(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		reject bool
	}{
		{name: "empty JSON object", body: "{}", reject: true},
		{name: "plain ok", body: "ok", reject: true},
		{name: "binary payload", body: "\x89PNG\r\n\x1a\n", reject: true},
		{name: "HTML payload", body: "<html><body>business page</body></html>", reject: true},
		{name: "JSON payload", body: `{"data":{"user_id":1}}`, reject: false},
		{name: "XML payload", body: "<response><user_id>1</user_id></response>", reject: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reject, _ := shouldRejectUnauthorizedPayload(tt.body)
			if reject != tt.reject {
				t.Fatalf("shouldRejectUnauthorizedPayload(%q) = %t, want %t", tt.body, reject, tt.reject)
			}
		})
	}
}

func TestTestUnauthorizedAccessRejectsGenericJSONTemplate(t *testing.T) {
	resetUnauthorizedTestState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"err.common.system.error","msg":"系统错误","success":false}`))
	}))
	defer server.Close()

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/cities",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)

	if err == nil {
		t.Fatal("expected generic template response to be rejected")
	}
	if vulnerable {
		t.Fatal("expected generic template response not to be marked vulnerable")
	}
}

func TestTestUnauthorizedAccessRejectsBadRequestWithoutBusinessData(t *testing.T) {
	resetUnauthorizedTestState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Bad Request", http.StatusBadRequest)
	}))
	defer server.Close()

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/orders/query",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)

	if err == nil {
		t.Fatal("expected bad request response to be rejected")
	}
	if vulnerable {
		t.Fatal("expected bad request response not to be marked vulnerable")
	}
}

func TestTestUnauthorizedAccessRejectsRepeatedNonBusinessTemplate(t *testing.T) {
	resetUnauthorizedTestState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"request rejected","hint":"visit denied"}`))
	}))
	defer server.Close()

	for i := 0; i < 2; i++ {
		vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
			URL:     server.URL + "/api/repeated",
			Method:  http.MethodGet,
			Headers: map[string]string{},
		}, nil)
		if err != nil {
			t.Fatalf("unexpected early rejection on iteration %d: %v", i, err)
		}
		if !vulnerable {
			t.Fatalf("expected first repeated template probes to remain observable on iteration %d", i)
		}
	}

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/repeated",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err == nil {
		t.Fatal("expected repeated template response to be rejected")
	}
	if vulnerable {
		t.Fatal("expected repeated template response not to be marked vulnerable")
	}
}

func TestTestUnauthorizedAccessRejectsRepeatedSimilarTemplateWithinSameHost(t *testing.T) {
	resetUnauthorizedTestState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"human.verify","message":"请完成人机校验后重试","route":"` + r.URL.Path + `","challenge":"` + r.URL.Query().Get("scene") + `"}`))
	}))
	defer server.Close()

	for i, path := range []string{"/api/owa-mail/list", "/api/owa-calendar/list"} {
		vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
			URL:     server.URL + path + "?scene=" + path,
			Method:  http.MethodGet,
			Headers: map[string]string{},
		}, nil)
		if err != nil {
			t.Fatalf("unexpected early rejection on iteration %d: %v", i, err)
		}
		if !vulnerable {
			t.Fatalf("expected similar template probes to remain observable on iteration %d", i)
		}
	}

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/owa-copilot/list?scene=/api/owa-copilot/list",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err == nil {
		t.Fatal("expected similar repeated template response to be rejected")
	}
	if vulnerable {
		t.Fatal("expected similar repeated template response not to be marked vulnerable")
	}
}

func TestTestUnauthorizedAccessTracksSimilarTemplatePerHost(t *testing.T) {
	resetUnauthorizedTestState(t)

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":"human.verify","message":"请完成人机校验后重试","route":"` + r.URL.Path + `","challenge":"` + r.Host + `"}`))
	}

	serverA := httptest.NewServer(http.HandlerFunc(handler))
	defer serverA.Close()
	serverB := httptest.NewServer(http.HandlerFunc(handler))
	defer serverB.Close()

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     serverA.URL + "/api/a",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err != nil || !vulnerable {
		t.Fatalf("expected first host A probe to pass through, vulnerable=%v err=%v", vulnerable, err)
	}

	vulnerable, _, _, err = TestUnauthorizedAccess("", structs.APIRequest{
		URL:     serverB.URL + "/api/b",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err != nil || !vulnerable {
		t.Fatalf("expected host B probe not to affect host A cluster, vulnerable=%v err=%v", vulnerable, err)
	}

	vulnerable, _, _, err = TestUnauthorizedAccess("", structs.APIRequest{
		URL:     serverA.URL + "/api/c",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err != nil || !vulnerable {
		t.Fatalf("expected second host A probe to remain below threshold, vulnerable=%v err=%v", vulnerable, err)
	}

	vulnerable, _, _, err = TestUnauthorizedAccess("", structs.APIRequest{
		URL:     serverA.URL + "/api/d",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err == nil {
		t.Fatal("expected third host A similar template to be rejected")
	}
	if vulnerable {
		t.Fatal("expected rejected host A similar template not to be marked vulnerable")
	}
}

func TestTestUnauthorizedAccessLearnsAuthPhraseIntoSQLite(t *testing.T) {
	resetUnauthorizedTestState(t)
	initTempSQLiteForUnauthTest(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"请先完成统一身份认证后再访问"}`))
	}))
	defer server.Close()

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/cities",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err == nil {
		t.Fatal("expected auth-required response to be rejected")
	}
	if vulnerable {
		t.Fatal("expected auth-required response not to be marked vulnerable")
	}

	patterns, err := database.ListEnabledLearnedAuthPatterns()
	if err != nil {
		t.Fatalf("failed to list learned auth patterns: %v", err)
	}
	if len(patterns) == 0 {
		t.Fatal("expected learned auth patterns to be stored")
	}

	found := false
	for _, pattern := range patterns {
		if pattern == `请先完成统一身份认证后再访问` {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected exact learned pattern to be stored, got %#v", patterns)
	}
}

func TestTestUnauthorizedAccessUsesLearnedAuthPhraseWithoutManualConfig(t *testing.T) {
	resetUnauthorizedTestState(t)
	initTempSQLiteForUnauthTest(t)

	if err := database.UpsertLearnedAuthPattern(`请先完成统一身份认证后再访问`, "seed"); err != nil {
		t.Fatalf("failed to seed learned auth pattern: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message":"请先完成统一身份认证后再访问"}`))
	}))
	defer server.Close()

	vulnerable, _, _, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/cities",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err == nil {
		t.Fatal("expected learned auth phrase to reject response")
	}
	if vulnerable {
		t.Fatal("expected learned auth phrase not to be marked vulnerable")
	}
}

func TestTestUnauthorizedAccessAnnotatesPublicDataExposure(t *testing.T) {
	resetUnauthorizedTestState(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"code":"310000","name":"上海市","province":"上海市","city":"上海市","district":"浦东新区"}],"success":true}`))
	}))
	defer server.Close()

	vulnerable, _, assessment, err := TestUnauthorizedAccess("", structs.APIRequest{
		URL:     server.URL + "/api/base/city/list",
		Method:  http.MethodGet,
		Headers: map[string]string{},
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !vulnerable {
		t.Fatal("expected public city list to still be identified as unauthorized access")
	}
	if assessment.DataExposure != "public_data" {
		t.Fatalf("data exposure = %q, want public_data", assessment.DataExposure)
	}
	if assessment.RiskLevel != "info" {
		t.Fatalf("risk level = %q, want info", assessment.RiskLevel)
	}
	if assessment.ExposureReason == "" {
		t.Fatal("expected non-empty exposure reason")
	}
}

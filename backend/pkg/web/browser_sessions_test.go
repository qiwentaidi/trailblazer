package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
)

func TestGetBrowserSessionsReturnsPagedRecords(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	firstStartedAt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	secondStartedAt := firstStartedAt.Add(15 * time.Minute)
	if _, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:      "sess-1",
		SiteHost:       "alpha.example.com",
		EntryURL:       "https://alpha.example.com/login",
		Status:         "running",
		Mode:           "manual",
		BrowserMode:    "chromedp",
		ProxyType:      "burp",
		BrowserVisible: true,
		StartedAt:      firstStartedAt,
		LastActivityAt: firstStartedAt,
	}); err != nil {
		t.Fatalf("CreateBrowserSession(sess-1) error = %v", err)
	}
	if _, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:             "sess-2",
		SiteHost:              "beta.example.com",
		EntryURL:              "https://beta.example.com/",
		Status:                "completed",
		Mode:                  "auto",
		BrowserMode:           "chromedp",
		ProxyType:             "platform-proxy",
		BrowserVisible:        false,
		PageCount:             2,
		RequestCount:          12,
		SuspiciousCryptoCount: 3,
		StartedAt:             secondStartedAt,
		LastActivityAt:        secondStartedAt,
		EndedAt:               secondStartedAt.Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateBrowserSession(sess-2) error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/browser-sessions?page=1&size=10&status=completed", nil)
	ctx.Request = req

	getBrowserSessions(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data       []database.BrowserSessionRecord `json:"data"`
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data) != 1 {
		t.Fatalf("len(response.Data) = %d, want 1", len(response.Data))
	}
	if response.Pagination.Total != 1 {
		t.Fatalf("pagination.total = %d, want 1", response.Pagination.Total)
	}
	if got := response.Data[0].SessionID; got != "sess-2" {
		t.Fatalf("session_id = %q, want %q", got, "sess-2")
	}
	if got := response.Data[0].SuspiciousCryptoCount; got != 3 {
		t.Fatalf("suspicious_crypto_count = %d, want 3", got)
	}
}

func TestGetBrowserSessionDetailIncludesPages(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	startedAt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	if _, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:      "sess-detail",
		SiteHost:       "bittalk-user.shuiyou.com.cn",
		EntryURL:       "https://bittalk-user.shuiyou.com.cn/",
		Status:         "running",
		Mode:           "manual",
		BrowserMode:    "chromedp",
		ProxyType:      "burp",
		BrowserVisible: true,
		StartedAt:      startedAt,
		LastActivityAt: startedAt,
	}); err != nil {
		t.Fatalf("CreateBrowserSession() error = %v", err)
	}
	if err := database.UpsertBrowserPage(database.BrowserPageRecord{
		PageID:     "page-1",
		SessionID:  "sess-detail",
		URL:        "https://bittalk-user.shuiyou.com.cn/#/middleView/login",
		Title:      "智能咨询平台",
		IsEntry:    true,
		CreatedAt:  startedAt,
		LastSeenAt: startedAt.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("UpsertBrowserPage() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/browser-sessions/sess-detail", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "sessionId", Value: "sess-detail"}}

	getBrowserSessionDetail(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Session database.BrowserSessionRecord `json:"session"`
			Pages   []database.BrowserPageRecord  `json:"pages"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if got := response.Data.Session.SiteHost; got != "bittalk-user.shuiyou.com.cn" {
		t.Fatalf("site_host = %q, want %q", got, "bittalk-user.shuiyou.com.cn")
	}
	if len(response.Data.Pages) != 1 {
		t.Fatalf("len(response.Data.Pages) = %d, want 1", len(response.Data.Pages))
	}
	if got := response.Data.Pages[0].PageID; got != "page-1" {
		t.Fatalf("page_id = %q, want %q", got, "page-1")
	}
}

func TestGetBrowserSessionDetailIncludesSuspiciousTraces(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	startedAt := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	if _, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:             "sess-trace",
		SiteHost:              "bittalk-user.shuiyou.com.cn",
		EntryURL:              "https://bittalk-user.shuiyou.com.cn/",
		Status:                "completed",
		Mode:                  "manual",
		BrowserMode:           "chromedp",
		ProxyType:             "http",
		ProxyAddress:          "http://127.0.0.1:8080",
		BrowserVisible:        true,
		PageCount:             1,
		RequestCount:          2,
		SuspiciousCryptoCount: 1,
		StartedAt:             startedAt,
		LastActivityAt:        startedAt,
		EndedAt:               startedAt.Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateBrowserSession() error = %v", err)
	}
	if err := database.ReplaceBrowserSessionTraces("sess-trace", []database.BrowserSessionTraceRecord{{
		SessionID:         "sess-trace",
		TraceID:           "trace-1",
		RequestURL:        "https://bittalk-user.shuiyou.com.cn/account/web/zh/register/rsa/gy/query",
		Method:            http.MethodGet,
		Algorithms:        []string{"rsa"},
		ResponsePlaintext: `{"code":"SUCCESS","data":"MIGf..."}`,
		SuspiciousReason:  "命中算法: rsa",
		CreatedAt:         startedAt,
	}}); err != nil {
		t.Fatalf("ReplaceBrowserSessionTraces() error = %v", err)
	}
	if err := database.ReplaceBrowserSessionRequests("sess-trace", []database.BrowserSessionRequestRecord{{
		SessionID:        "sess-trace",
		TraceID:          "trace-1",
		URL:              "https://bittalk-user.shuiyou.com.cn/account/web/zh/register/rsa/gy/query",
		Method:           http.MethodGet,
		ResponseBody:     `{"code":"SUCCESS","data":"MIGf..."}`,
		HasProtocolTrace: true,
		IsSuspicious:     true,
		SuspiciousTrace:  "命中算法: rsa",
		CreatedAt:        startedAt,
	}}); err != nil {
		t.Fatalf("ReplaceBrowserSessionRequests() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/browser-sessions/sess-trace", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "sessionId", Value: "sess-trace"}}

	getBrowserSessionDetail(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Session          database.BrowserSessionRecord          `json:"session"`
			Requests         []database.BrowserSessionRequestRecord `json:"requests"`
			SuspiciousTraces []database.BrowserSessionTraceRecord   `json:"suspiciousTraces"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data.SuspiciousTraces) != 1 {
		t.Fatalf("len(response.Data.SuspiciousTraces) = %d, want 1", len(response.Data.SuspiciousTraces))
	}
	if len(response.Data.Requests) != 1 {
		t.Fatalf("len(response.Data.Requests) = %d, want 1", len(response.Data.Requests))
	}
	if got := response.Data.SuspiciousTraces[0].TraceID; got != "trace-1" {
		t.Fatalf("trace_id = %q, want %q", got, "trace-1")
	}
}

func TestPersistBrowserSessionSnapshotWritesRunningSuspiciousTraces(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	startedAt := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	session, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:      "sess-running-trace",
		SiteHost:       "bittalk-user.shuiyou.com.cn",
		EntryURL:       "https://bittalk-user.shuiyou.com.cn/",
		Status:         "running",
		Mode:           "manual",
		BrowserMode:    "chromedp",
		BrowserVisible: true,
		PageCount:      1,
		StartedAt:      startedAt,
		LastActivityAt: startedAt,
	})
	if err != nil {
		t.Fatalf("CreateBrowserSession() error = %v", err)
	}

	persistBrowserSessionSnapshot(session, startedAt, crawl.CaptureSnapshot{
		APIRecords: []crawl.NetworkRecord{{
			URL:              "https://bittalk-user.shuiyou.com.cn/account/web/zh/register/rsa/gy/query",
			Method:           http.MethodGet,
			ResponseBody:     `{"code":"SUCCESS","data":"MIGf..."}`,
			HasProtocolTrace: true,
			FetchedAt:        startedAt.Add(5 * time.Second),
		}},
		ProtocolTraces: []crawl.ProtocolTraceRecord{{
			TraceID:    "trace-running",
			RequestURL: "https://bittalk-user.shuiyou.com.cn/account/web/zh/register/rsa/gy/query",
			Method:     http.MethodGet,
			Algorithms: []string{"rsa"},
			SessionMaterials: map[string]string{
				"latest_response_plaintext": `{"code":"SUCCESS","data":"MIGf..."}`,
			},
			CreatedAt: startedAt,
		}},
		CapturedAt: startedAt.Add(30 * time.Second),
	}, "running", time.Time{})

	updated, err := database.GetBrowserSessionByID("sess-running-trace")
	if err != nil {
		t.Fatalf("GetBrowserSessionByID() error = %v", err)
	}
	if updated == nil {
		t.Fatal("expected browser session to exist")
	}
	if got := updated.Status; got != "running" {
		t.Fatalf("status = %q, want running", got)
	}
	if got := updated.SuspiciousCryptoCount; got != 1 {
		t.Fatalf("suspicious_crypto_count = %d, want 1", got)
	}

	traces, err := database.ListBrowserSessionTraces("sess-running-trace")
	if err != nil {
		t.Fatalf("ListBrowserSessionTraces() error = %v", err)
	}
	if len(traces) != 1 {
		t.Fatalf("len(traces) = %d, want 1", len(traces))
	}
	if got := traces[0].TraceID; got != "trace-running" {
		t.Fatalf("trace_id = %q, want trace-running", got)
	}
	requests, err := database.ListBrowserSessionRequests("sess-running-trace")
	if err != nil {
		t.Fatalf("ListBrowserSessionRequests() error = %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("len(requests) = %d, want 1", len(requests))
	}
	if !requests[0].IsSuspicious {
		t.Fatalf("expected first request to be suspicious")
	}
}

func TestReplaceBrowserSessionTracesPreservesStepsAndSessionMaterials(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "browser_session_trace_payloads.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	startedAt := time.Date(2026, 4, 23, 11, 0, 0, 0, time.UTC)
	if _, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:      "sess-materials",
		SiteHost:       "bittalk-user.shuiyou.com.cn",
		EntryURL:       "https://bittalk-user.shuiyou.com.cn/",
		Status:         "completed",
		Mode:           "manual",
		BrowserMode:    "chromedp",
		BrowserVisible: true,
		StartedAt:      startedAt,
		LastActivityAt: startedAt,
	}); err != nil {
		t.Fatalf("CreateBrowserSession() error = %v", err)
	}

	err := database.ReplaceBrowserSessionTraces("sess-materials", []database.BrowserSessionTraceRecord{{
		SessionID:    "sess-materials",
		TraceID:      "trace-materials",
		RequestURL:   "https://bittalk-user.shuiyou.com.cn/account/web/zh/login/zhmmdl",
		Method:       http.MethodPost,
		Algorithms:   []string{"rsa.encrypt"},
		RequestSteps: []database.ProtocolCryptoStep{{Source: "window.JSEncrypt.prototype.encrypt", Algorithm: "rsa.encrypt", InputPreview: "{\"uuid\":\"u1\",\"mm\":\"123\"}", OutputPreview: "ciphertext"}},
		ResponseSteps: []database.ProtocolCryptoStep{{
			Source:        "JSON.parse",
			Algorithm:     "json.parse",
			InputPreview:  "{\"code\":\"FAIL\"}",
			OutputPreview: "{\"code\":\"FAIL\"}",
		}},
		SessionMaterials: map[string]string{
			"rsa_public_key":        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCv83oCAP5Nkj9tIJboQvbzmBNJuGwBAHUB+WdhM70c3pvE2vizlWzsTpxEgzHR22S3/emz5XDc5Xmf/xSCnKe/rxAHil2osTHQf2T4yAkfwW5jKtMaXd5ooRAE2yvFmzBr3x3CGvDxZBKT2pCv8pfKLe0KbJ4bAwGjgEgRqXXAjwIDAQAB",
			"rsa_public_key_source": "https://bittalk-user.shuiyou.com.cn/account/web/zh/register/rsa/gy/query",
		},
		CreatedAt: startedAt,
	}})
	if err != nil {
		t.Fatalf("ReplaceBrowserSessionTraces() error = %v", err)
	}

	traces, err := database.ListBrowserSessionTraces("sess-materials")
	if err != nil {
		t.Fatalf("ListBrowserSessionTraces() error = %v", err)
	}
	if len(traces) != 1 {
		t.Fatalf("len(traces) = %d, want 1", len(traces))
	}
	if got := traces[0].RequestSteps[0].Algorithm; got != "rsa.encrypt" {
		t.Fatalf("request_steps[0].algorithm = %q, want rsa.encrypt", got)
	}
	if got := traces[0].SessionMaterials["rsa_public_key_source"]; got == "" {
		t.Fatalf("expected rsa_public_key_source to be preserved, got empty")
	}
}

func TestBuildSuspiciousBrowserSessionTracesPrefersMatchingNetworkResponse(t *testing.T) {
	loginURL := "https://bittalk-user.shuiyou.com.cn/account/web/zh/login/zhmdl"
	captchaURL := "https://bittalk-user.shuiyou.com.cn/account/web/zh/login/createCaptcha"
	loginResponse := `{"code":"NA_BUSINESS_VALID_ERROR_ADD_CAPTCHA_FAIL","param":["用户名或密码错误"],"data":null}`
	captchaResponse := `{"code":"SUCCESS","data":{"imageCode":"data:image/png;base64,iVBORw0KGgo="}}`

	traces := buildSuspiciousBrowserSessionTraces("sess-response-match", []crawl.ProtocolTraceRecord{{
		TraceID:          "trace-login",
		RequestURL:       loginURL,
		Method:           http.MethodPost,
		FinalRequestBody: `{"yhm":"admin"}`,
		Algorithms:       []string{"json.stringify", "rsa.encrypt(inferred)"},
		SessionMaterials: map[string]string{
			"latest_response_plaintext": captchaResponse,
		},
	}}, []crawl.NetworkRecord{
		{
			URL:          captchaURL,
			Method:       http.MethodGet,
			ResponseBody: captchaResponse,
		},
		{
			URL:          loginURL,
			Method:       http.MethodPost,
			RequestBody:  `{"yhm":"admin"}`,
			ResponseBody: loginResponse,
		},
	})

	if len(traces) != 1 {
		t.Fatalf("len(traces) = %d, want 1", len(traces))
	}
	if got := traces[0].ResponsePlaintext; got != loginResponse {
		t.Fatalf("response_plaintext = %q, want matching login response %q", got, loginResponse)
	}
}

func TestBuildSuspiciousBrowserSessionTracesLinksSessionRSAPublicKey(t *testing.T) {
	publicKeyURL := "https://bittalk-user.shuiyou.com.cn/account/web/zh/register/rsa/gy/query"
	loginURL := "https://bittalk-user.shuiyou.com.cn/account/web/zh/login/zhmmdl"
	publicKey := "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCv83oCAP5Nkj9tIJboQvbzmBNJuGwBAHUB+WdhM70c3pvE2vizlWzsTpxEgzHR22S3/emz5XDc5Xmf/xSCnKe/rxAHil2osTHQf2T4yAkfwW5jKtMaXd5ooRAE2yvFmzBr3x3CGvDxZBKT2pCv8pfKLe0KbJ4bAwGjgEgRqXXAjwIDAQAB"

	traces := buildSuspiciousBrowserSessionTraces("sess-rsa-key", []crawl.ProtocolTraceRecord{
		{
			TraceID:    "trace-public-key",
			RequestURL: publicKeyURL,
			Method:     http.MethodGet,
			Algorithms: []string{"rsa"},
			SessionMaterials: map[string]string{
				"latest_response_plaintext": `{"code":"SUCCESS","data":"` + publicKey + `"}`,
			},
		},
		{
			TraceID:    "trace-login",
			RequestURL: loginURL,
			Method:     http.MethodPost,
			Algorithms: []string{"json.stringify", "rsa.encrypt"},
			RequestSteps: []crawl.ProtocolCryptoStep{{
				Source:        "window.JSEncrypt.prototype.encrypt",
				Algorithm:     "rsa.encrypt",
				InputPreview:  `{"uuid":"u1","mm":"123456"}`,
				OutputPreview: "ciphertext",
			}},
			FinalRequestBody: `{"mm":"ciphertext"}`,
		},
	}, nil)

	if len(traces) != 2 {
		t.Fatalf("len(traces) = %d, want 2", len(traces))
	}

	var loginTrace *database.BrowserSessionTraceRecord
	for idx := range traces {
		if traces[idx].TraceID == "trace-login" {
			loginTrace = &traces[idx]
			break
		}
	}
	if loginTrace == nil {
		t.Fatal("expected login trace to exist")
	}
	if got := loginTrace.SessionMaterials["rsa_public_key"]; got != publicKey {
		t.Fatalf("rsa_public_key = %q, want %q", got, publicKey)
	}
	if got := loginTrace.SessionMaterials["rsa_public_key_source"]; got != publicKeyURL {
		t.Fatalf("rsa_public_key_source = %q, want %q", got, publicKeyURL)
	}
}

func TestBuildSuspiciousBrowserSessionTracesSkipsJSONOnlySignals(t *testing.T) {
	traces := buildSuspiciousBrowserSessionTraces("sess-json-only", []crawl.ProtocolTraceRecord{{
		TraceID:          "trace-json-only",
		RequestURL:       "https://example.com/api/demo",
		Method:           http.MethodPost,
		FinalRequestBody: `{"a":1}`,
		Algorithms:       []string{"json.stringify", "json.parse"},
		RequestSteps: []crawl.ProtocolCryptoStep{{
			Source:    "JSON.stringify",
			Algorithm: "json.stringify",
		}},
		ResponseSteps: []crawl.ProtocolCryptoStep{{
			Source:    "JSON.parse",
			Algorithm: "json.parse",
		}},
	}}, nil)

	if len(traces) != 0 {
		t.Fatalf("expected json-only signals to be skipped, got %#v", traces)
	}
}

func TestCountSuspiciousTraceSignalsSkipsJSONOnlySignals(t *testing.T) {
	count := countSuspiciousTraceSignals([]crawl.ProtocolTraceRecord{
		{
			TraceID:    "trace-json-only",
			RequestURL: "https://example.com/api/json-only",
			Method:     http.MethodPost,
			Algorithms: []string{"json.stringify", "json.parse"},
			RequestSteps: []crawl.ProtocolCryptoStep{{
				Source:    "JSON.stringify",
				Algorithm: "json.stringify",
			}},
		},
		{
			TraceID:    "trace-rsa",
			RequestURL: "https://example.com/api/rsa",
			Method:     http.MethodPost,
			Algorithms: []string{"rsa.encrypt", "json.stringify"},
		},
	})

	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
}

func TestDeleteBrowserSessionRemovesSessionPagesAndTraces(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	startedAt := time.Date(2026, 4, 23, 10, 0, 0, 0, time.UTC)
	if _, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:      "sess-delete",
		SiteHost:       "bittalk-user.shuiyou.com.cn",
		EntryURL:       "https://bittalk-user.shuiyou.com.cn/",
		Status:         "completed",
		Mode:           "manual",
		BrowserMode:    "chromedp",
		BrowserVisible: true,
		StartedAt:      startedAt,
		LastActivityAt: startedAt,
	}); err != nil {
		t.Fatalf("CreateBrowserSession() error = %v", err)
	}
	if err := database.UpsertBrowserPage(database.BrowserPageRecord{
		PageID:     "page-delete",
		SessionID:  "sess-delete",
		URL:        "https://bittalk-user.shuiyou.com.cn/",
		IsEntry:    true,
		CreatedAt:  startedAt,
		LastSeenAt: startedAt,
	}); err != nil {
		t.Fatalf("UpsertBrowserPage() error = %v", err)
	}
	if err := database.ReplaceBrowserSessionTraces("sess-delete", []database.BrowserSessionTraceRecord{{
		SessionID:        "sess-delete",
		TraceID:          "trace-delete",
		RequestURL:       "https://bittalk-user.shuiyou.com.cn/api",
		Method:           http.MethodGet,
		Algorithms:       []string{"rsa"},
		SuspiciousReason: "命中算法: rsa",
		CreatedAt:        startedAt,
	}}); err != nil {
		t.Fatalf("ReplaceBrowserSessionTraces() error = %v", err)
	}
	if err := database.ReplaceBrowserSessionRequests("sess-delete", []database.BrowserSessionRequestRecord{{
		SessionID:       "sess-delete",
		TraceID:         "trace-delete",
		URL:             "https://bittalk-user.shuiyou.com.cn/api",
		Method:          http.MethodGet,
		IsSuspicious:    true,
		SuspiciousTrace: "命中算法: rsa",
		CreatedAt:       startedAt,
	}}); err != nil {
		t.Fatalf("ReplaceBrowserSessionRequests() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodDelete, "/api/browser-sessions/sess-delete", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "sessionId", Value: "sess-delete"}}

	deleteBrowserSession(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	session, err := database.GetBrowserSessionByID("sess-delete")
	if err != nil {
		t.Fatalf("GetBrowserSessionByID() error = %v", err)
	}
	if session != nil {
		t.Fatalf("expected session to be deleted, got %#v", session)
	}
	pages, err := database.ListBrowserPagesBySessionID("sess-delete")
	if err != nil {
		t.Fatalf("ListBrowserPagesBySessionID() error = %v", err)
	}
	if len(pages) != 0 {
		t.Fatalf("len(pages) = %d, want 0", len(pages))
	}
	traces, err := database.ListBrowserSessionTraces("sess-delete")
	if err != nil {
		t.Fatalf("ListBrowserSessionTraces() error = %v", err)
	}
	if len(traces) != 0 {
		t.Fatalf("len(traces) = %d, want 0", len(traces))
	}
	requests, err := database.ListBrowserSessionRequests("sess-delete")
	if err != nil {
		t.Fatalf("ListBrowserSessionRequests() error = %v", err)
	}
	if len(requests) != 0 {
		t.Fatalf("len(requests) = %d, want 0", len(requests))
	}
}

func TestLaunchBrowserSessionPersistsProxyConfiguration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	done := make(chan struct{}, 1)
	originalCapture := captureBrowserSessionNetworkActivity
	captureBrowserSessionNetworkActivity = func(targetURL string, options crawl.CaptureOptions) ([]string, []crawl.NetworkRecord, []crawl.ProtocolTraceRecord) {
		if got := strings.TrimSpace(options.ProxyServer); got != "http://127.0.0.1:8080" {
			t.Errorf("ProxyServer = %q, want %q", got, "http://127.0.0.1:8080")
		}
		if got := strings.TrimSpace(options.ProxyBypassList); got != "<-loopback>" {
			t.Errorf("ProxyBypassList = %q, want %q", got, "<-loopback>")
		}
		done <- struct{}{}
		return nil, []crawl.NetworkRecord{{URL: targetURL, Method: http.MethodGet}}, []crawl.ProtocolTraceRecord{{
			TraceID:    "trace-1",
			RequestURL: targetURL,
			Method:     http.MethodGet,
			Algorithms: []string{"rsa"},
		}}
	}
	defer func() {
		captureBrowserSessionNetworkActivity = originalCapture
	}()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/api/browser-sessions/launch", strings.NewReader(`{
		"targetUrl":"https://bittalk-user.shuiyou.com.cn/",
		"browserVisible":true,
		"proxyServer":"http://127.0.0.1:8080",
		"proxyBypassList":"<-loopback>",
		"captureDurationSeconds":1,
		"timeoutSeconds":5
	}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	launchBrowserSession(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for launched browser session capture")
	}
	waitForBrowserSessionStatus(t, "completed")

	sessions, total, err := database.ListBrowserSessions(1, 10, database.BrowserSessionListFilters{})
	if err != nil {
		t.Fatalf("ListBrowserSessions() error = %v", err)
	}
	if total != 1 || len(sessions) != 1 {
		t.Fatalf("sessions total=%d len=%d, want 1", total, len(sessions))
	}
	if got := sessions[0].ProxyType; got != "http" {
		t.Fatalf("ProxyType = %q, want %q", got, "http")
	}
	if got := sessions[0].ProxyAddress; got != "http://127.0.0.1:8080" {
		t.Fatalf("ProxyAddress = %q, want %q", got, "http://127.0.0.1:8080")
	}
}

func TestLaunchBrowserSessionZeroCaptureDurationWaitsForManualExit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	done := make(chan struct{}, 1)
	originalCapture := captureBrowserSessionNetworkActivity
	captureBrowserSessionNetworkActivity = func(targetURL string, options crawl.CaptureOptions) ([]string, []crawl.NetworkRecord, []crawl.ProtocolTraceRecord) {
		if got := options.Timeout; got != 0 {
			t.Errorf("Timeout = %v, want %v", got, 0)
		}
		if got := options.PostInteractionWait; got != 0 {
			t.Errorf("PostInteractionWait = %v, want %v", got, 0)
		}
		done <- struct{}{}
		return nil, nil, nil
	}
	defer func() {
		captureBrowserSessionNetworkActivity = originalCapture
	}()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/api/browser-sessions/launch", strings.NewReader(`{
		"targetUrl":"https://bittalk-user.shuiyou.com.cn/",
		"browserVisible":true,
		"captureDurationSeconds":0
	}`))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	launchBrowserSession(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for manual browser session capture")
	}
	waitForBrowserSessionStatus(t, "completed")
}

func waitForBrowserSessionStatus(t *testing.T, wantStatus string) {
	t.Helper()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		sessions, _, err := database.ListBrowserSessions(1, 10, database.BrowserSessionListFilters{})
		if err != nil {
			t.Fatalf("ListBrowserSessions() error = %v", err)
		}
		for _, session := range sessions {
			if session.Status == wantStatus {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for browser session status %q", wantStatus)
}

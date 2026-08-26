package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"
)

func TestGetTaskStaticProtocolAnalysisCachesByTaskAndVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	staticProtocolAnalysisGroup = singleflight.Group{}
	defer func(
		previousAnalyze func(string, ...int) (*crawl.StaticProtocolAnalysisResult, error),
		previousQuery func(string, int) (*crawl.StaticProtocolAnalysisResult, bool, error),
		previousSave func(string, int, *crawl.StaticProtocolAnalysisResult) error,
	) {
		analyzeStoredJSProtocols = previousAnalyze
		queryStoredStaticProtocol = previousQuery
		saveStoredStaticProtocol = previousSave
		staticProtocolAnalysisGroup = singleflight.Group{}
	}(analyzeStoredJSProtocols, queryStoredStaticProtocol, saveStoredStaticProtocol)

	var (
		storedMu sync.Mutex
		stored   = map[string]*crawl.StaticProtocolAnalysisResult{}
	)
	var callCount int32

	queryStoredStaticProtocol = func(taskID string, version int) (*crawl.StaticProtocolAnalysisResult, bool, error) {
		storedMu.Lock()
		defer storedMu.Unlock()
		result, ok := stored[taskID]
		return result, ok, nil
	}

	saveStoredStaticProtocol = func(taskID string, version int, result *crawl.StaticProtocolAnalysisResult) error {
		storedMu.Lock()
		defer storedMu.Unlock()
		stored[taskID] = result
		return nil
	}

	analyzeStoredJSProtocols = func(taskID string, versions ...int) (*crawl.StaticProtocolAnalysisResult, error) {
		atomic.AddInt32(&callCount, 1)
		return &crawl.StaticProtocolAnalysisResult{
			TaskID:      taskID,
			JSCount:     3,
			GeneratedAt: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
			Profiles:    []crawl.StaticProtocolProfile{},
			APIContexts: []crawl.StaticAPIContext{
				{
					URL:        "/api/poc/sync-setting",
					Method:     "POST",
					SourceFile: "https://example.com/assets/index.js",
					Snippet:    `request.post("/api/poc/sync-setting",{enable:true})`,
				},
			},
		}, nil
	}

	router := gin.New()
	router.GET("/api/task/:taskId/static-protocol-analysis", getTaskStaticProtocolAnalysis)

	first := httptest.NewRecorder()
	firstReq := httptest.NewRequest(http.MethodGet, "/api/task/task-1/static-protocol-analysis?version=1", nil)
	router.ServeHTTP(first, firstReq)
	if first.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d body=%s", first.Code, first.Body.String())
	}

	second := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodGet, "/api/task/task-1/static-protocol-analysis?version=1", nil)
	router.ServeHTTP(second, secondReq)
	if second.Code != http.StatusOK {
		t.Fatalf("expected second request to succeed, got %d body=%s", second.Code, second.Body.String())
	}

	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Fatalf("expected analyzer to run once, got %d", got)
	}

	var secondResp struct {
		Cached bool `json:"cached"`
		Data   struct {
			TaskID      string                   `json:"task_id"`
			APIContexts []crawl.StaticAPIContext `json:"api_contexts"`
		} `json:"data"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResp); err != nil {
		t.Fatalf("expected response to parse: %v", err)
	}
	if !secondResp.Cached {
		t.Fatalf("expected second response to be marked cached")
	}
	if secondResp.Data.TaskID != "task-1" {
		t.Fatalf("expected cached response to preserve task id, got %q", secondResp.Data.TaskID)
	}
	if len(secondResp.Data.APIContexts) != 1 {
		t.Fatalf("expected cached response to preserve api contexts, got %#v", secondResp.Data.APIContexts)
	}
}

func TestGetTaskStaticProtocolAnalysisDeduplicatesConcurrentRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)

	staticProtocolAnalysisGroup = singleflight.Group{}
	defer func(
		previousAnalyze func(string, ...int) (*crawl.StaticProtocolAnalysisResult, error),
		previousQuery func(string, int) (*crawl.StaticProtocolAnalysisResult, bool, error),
		previousSave func(string, int, *crawl.StaticProtocolAnalysisResult) error,
	) {
		analyzeStoredJSProtocols = previousAnalyze
		queryStoredStaticProtocol = previousQuery
		saveStoredStaticProtocol = previousSave
		staticProtocolAnalysisGroup = singleflight.Group{}
	}(analyzeStoredJSProtocols, queryStoredStaticProtocol, saveStoredStaticProtocol)

	var (
		storedMu sync.Mutex
		stored   = map[string]*crawl.StaticProtocolAnalysisResult{}
	)

	queryStoredStaticProtocol = func(taskID string, version int) (*crawl.StaticProtocolAnalysisResult, bool, error) {
		storedMu.Lock()
		defer storedMu.Unlock()
		result, ok := stored[taskID]
		return result, ok, nil
	}

	saveStoredStaticProtocol = func(taskID string, version int, result *crawl.StaticProtocolAnalysisResult) error {
		storedMu.Lock()
		defer storedMu.Unlock()
		stored[taskID] = result
		return nil
	}

	var callCount int32
	analyzeStoredJSProtocols = func(taskID string, versions ...int) (*crawl.StaticProtocolAnalysisResult, error) {
		atomic.AddInt32(&callCount, 1)
		time.Sleep(50 * time.Millisecond)
		return &crawl.StaticProtocolAnalysisResult{
			TaskID:      taskID,
			JSCount:     5,
			GeneratedAt: time.Date(2026, 4, 20, 12, 0, 0, 0, time.UTC),
			Profiles:    []crawl.StaticProtocolProfile{},
		}, nil
	}

	router := gin.New()
	router.GET("/api/task/:taskId/static-protocol-analysis", getTaskStaticProtocolAnalysis)

	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/task/task-2/static-protocol-analysis?version=2", nil)
			router.ServeHTTP(recorder, req)
			if recorder.Code != http.StatusOK {
				t.Errorf("expected concurrent request to succeed, got %d body=%s", recorder.Code, recorder.Body.String())
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Fatalf("expected analyzer to run once for concurrent requests, got %d", got)
	}
}

func TestBuildStaticAPIContextsFromAssetsMatchesStoredJS(t *testing.T) {
	routes := []database.AssetValue{
		{Value: "/api/poc/sync-setting"},
	}
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/assets/index.js",
			Content: `
const submit=()=>request.post("/api/poc/sync-setting",{enable:true,scope:"all"});
`,
		},
	}

	contexts := buildStaticAPIContextsFromAssets(routes, jsResources)
	if len(contexts) != 1 {
		t.Fatalf("expected one api context, got %#v", contexts)
	}
	if contexts[0].Method != http.MethodPost {
		t.Fatalf("expected inferred method POST, got %q", contexts[0].Method)
	}
	if contexts[0].SourceFile != "https://example.com/assets/index.js" {
		t.Fatalf("unexpected source file: %q", contexts[0].SourceFile)
	}
	if !strings.Contains(contexts[0].Snippet, "/api/poc/sync-setting") {
		t.Fatalf("expected snippet to contain route, got %q", contexts[0].Snippet)
	}
}

func TestBuildStaticAPIContextsFromAssetsSkipsRoutesWithoutParams(t *testing.T) {
	routes := []database.AssetValue{
		{Value: "/api/allPocList"},
		{Value: "/api/poc/change-list"},
	}
	jsResources := []database.JSResource{
		{
			URL: "https://example.com/assets/index.js",
			Content: `
const list=()=>request.get("/api/allPocList");
const changes=(page,pageSize)=>request.get("/api/poc/change-list",{params:{page,pageSize}});
`,
		},
	}

	contexts := buildStaticAPIContextsFromAssets(routes, jsResources)
	if len(contexts) != 1 {
		t.Fatalf("expected only paramful api context to remain, got %#v", contexts)
	}
	if contexts[0].URL != "/api/poc/change-list" {
		t.Fatalf("expected only /api/poc/change-list to remain, got %#v", contexts)
	}
}

func TestEnrichStaticContextPayloadExtractsParams(t *testing.T) {
	context := crawl.StaticAPIContext{
		URL:    "/api/poc/change-status",
		Method: "POST",
		Snippet: `nP=(e,t)=>wn.post("/api/poc/change-status",{id:e,status:t}),
otherCall();`,
	}

	enrichStaticContextPayload(&context)
	if context.ParamCarrier != "arg" {
		t.Fatalf("expected arg carrier, got %q", context.ParamCarrier)
	}
	if context.ParamPreview != "{id:e,status:t}" {
		t.Fatalf("unexpected payload preview: %q", context.ParamPreview)
	}
	if len(context.Params) != 2 {
		t.Fatalf("expected 2 params, got %#v", context.Params)
	}
	if context.Params[0].Name != "id" || context.Params[0].Value != "e" {
		t.Fatalf("unexpected first param: %#v", context.Params[0])
	}
	if context.Params[1].Name != "status" || context.Params[1].Value != "t" {
		t.Fatalf("unexpected second param: %#v", context.Params[1])
	}
}

func TestEnrichStaticContextPayloadUsesCurrentURLAsAnchor(t *testing.T) {
	context := crawl.StaticAPIContext{
		URL:    "/api/poc/change-status",
		Method: "POST",
		Snippet: `tP=(e,t,n,r)=>wn.get("/api/poc/change-list",{params:{page:e,pageSize:t,keyword:n,status:r}}),
nP=(e,t)=>wn.post("/api/poc/change-status",{id:e,status:t}),
rP=()=>wn.post("/api/poc/sync-remote-details")`,
	}

	enrichStaticContextPayload(&context)
	if context.ParamPreview != "{id:e,status:t}" {
		t.Fatalf("expected anchored payload preview, got %q", context.ParamPreview)
	}
	if len(context.Params) != 2 || context.Params[0].Name != "id" || context.Params[1].Name != "status" {
		t.Fatalf("unexpected anchored params: %#v", context.Params)
	}
}

func TestMergeStaticAPIContextsDeduplicatesCaseOnlyRouteVariants(t *testing.T) {
	base := []crawl.StaticAPIContext{
		{
			URL:          "/Login",
			Method:       "POST",
			SourceFile:   "https://example.com/login.js",
			Snippet:      `client.post("/login", payload)`,
			ParamPreview: `{username:t,password:e}`,
		},
	}
	extra := []crawl.StaticAPIContext{
		{
			URL:          "/login",
			Method:       "POST",
			SourceFile:   "https://example.com/login.js",
			Snippet:      `client.post("/login", payload)`,
			ParamPreview: `{username:t,password:e}`,
		},
	}

	merged := mergeStaticAPIContexts(base, extra)
	if len(merged) != 1 {
		t.Fatalf("expected case-only variants to dedupe, got %#v", merged)
	}
	if merged[0].URL != "/login" {
		t.Fatalf("expected lowercase route to win, got %q", merged[0].URL)
	}
}

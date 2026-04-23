package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"trailblazer/pkg/core/crawl"

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
			TaskID string `json:"task_id"`
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

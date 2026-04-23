package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"trailblazer/pkg/core/database"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/gin-gonic/gin"
)

func TestRescanDoesNotDeletePreviousVersionData(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	backendRoot := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if err := os.Chdir(backendRoot); err != nil {
		t.Fatalf("os.Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(originalWD)
	})

	dbPath := filepath.Join(t.TempDir(), "task_versions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	task := &database.Task{
		ID:       "rescan-version-task",
		Name:     "rescan-version-task",
		Targets:  []string{"http://127.0.0.1:1"},
		Status:   "pending",
		Progress: 0,
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	firstVersion, err := database.CreateTaskVersion(task.ID, task.Targets, []byte(`{"scan":"v1"}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion() error = %v", err)
	}

	performAsyncScan([]string{"http://127.0.0.1:1"}, task.ID)

	versions, err := database.ListTaskVersions(task.ID)
	if err != nil {
		t.Fatalf("ListTaskVersions() error = %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("len(ListTaskVersions()) = %d, want 2", len(versions))
	}

	preserved, err := database.GetTaskVersion(task.ID, firstVersion.Version)
	if err != nil {
		t.Fatalf("GetTaskVersion(version 1) error = %v", err)
	}
	if preserved == nil {
		t.Fatal("GetTaskVersion(version 1) = nil, want preserved version")
	}
	if preserved.Version != 1 {
		t.Fatalf("preserved version = %d, want 1", preserved.Version)
	}

	latest, err := database.GetLatestTaskVersion(task.ID)
	if err != nil {
		t.Fatalf("GetLatestTaskVersion() error = %v", err)
	}
	if latest == nil {
		t.Fatal("GetLatestTaskVersion() = nil, want version 2")
	}
	if latest.Version != 2 {
		t.Fatalf("latest version = %d, want 2", latest.Version)
	}
}

func TestGetTaskVulnsVersionQueryUsesSelectedVersionWithoutMixing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "task_versions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	task := database.Task{
		ID:      "versioned-vulns-task",
		Name:    "versioned-vulns-task",
		Targets: []string{"https://example.com"},
		Status:  "pending",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	if _, err := database.CreateTaskVersion(task.ID, []string{"https://v1.example.com"}, []byte(`{"version":1}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion(version 1) error = %v", err)
	}
	if _, err := database.CreateTaskVersion(task.ID, []string{"https://v2.example.com"}, []byte(`{"version":2}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion(version 2) error = %v", err)
	}

	restoreES := installMockElasticsearch(t, map[string][]map[string]any{
		database.IndexVuln: {
			{
				"task_id":    task.ID,
				"version":    1,
				"vuln_id":    "v1-only",
				"title":      "v1-only",
				"level":      "low",
				"type":       "test",
				"url":        "https://v1.example.com",
				"method":     "GET",
				"created_at": "2026-04-08T00:00:00Z",
			},
			{
				"task_id":    task.ID,
				"vuln_id":    "legacy-v1",
				"title":      "legacy-v1",
				"level":      "medium",
				"type":       "test",
				"url":        "https://legacy.example.com",
				"method":     "GET",
				"created_at": "2026-04-08T01:00:00Z",
			},
			{
				"task_id":    task.ID,
				"version":    2,
				"vuln_id":    "v2-only",
				"title":      "v2-only",
				"level":      "high",
				"type":       "test",
				"url":        "https://v2.example.com",
				"method":     "GET",
				"created_at": "2026-04-08T02:00:00Z",
			},
		},
	})
	defer restoreES()

	t.Run("latest fallback uses latest version only", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		req := httptest.NewRequest(http.MethodGet, "/api/task/"+task.ID+"/vulns", nil)
		ctx.Request = req
		ctx.Params = gin.Params{{Key: "taskId", Value: task.ID}}

		getTaskVulns(ctx)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
		}

		var response struct {
			Data []database.VulnRecord `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
		}

		if len(response.Data) != 1 {
			t.Fatalf("len(response.Data) = %d, want 1", len(response.Data))
		}
		if response.Data[0].VulnID != "v2-only" {
			t.Fatalf("latest fallback returned vuln %q, want only v2 data", response.Data[0].VulnID)
		}
	})

	t.Run("selected version includes legacy docs as version 1", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(recorder)
		req := httptest.NewRequest(http.MethodGet, "/api/task/"+task.ID+"/vulns?version=1", nil)
		ctx.Request = req
		ctx.Params = gin.Params{{Key: "taskId", Value: task.ID}}

		getTaskVulns(ctx)

		if recorder.Code != http.StatusOK {
			t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
		}

		var response struct {
			Data []database.VulnRecord `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
		}

		if len(response.Data) != 2 {
			t.Fatalf("len(response.Data) = %d, want 2", len(response.Data))
		}

		gotIDs := map[string]bool{}
		for _, vuln := range response.Data {
			gotIDs[vuln.VulnID] = true
			if vuln.VulnID == "v2-only" {
				t.Fatalf("version=1 response mixed in latest version data: %#v", response.Data)
			}
		}

		for _, wantID := range []string{"v1-only", "legacy-v1"} {
			if !gotIDs[wantID] {
				t.Fatalf("version=1 response missing %q: %#v", wantID, response.Data)
			}
		}
	})
}

func TestGetTaskVulnsDedupesHTTPHTTPSDuplicates(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "task_versions.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	task := database.Task{
		ID:      "dedupe-vulns-task",
		Name:    "dedupe-vulns-task",
		Targets: []string{"https://example.com"},
		Status:  "pending",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	if _, err := database.CreateTaskVersion(task.ID, []string{"https://example.com"}, []byte(`{"version":1}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion() error = %v", err)
	}

	restoreES := installMockElasticsearch(t, map[string][]map[string]any{
		database.IndexVuln: {
			{
				"task_id":         task.ID,
				"version":         1,
				"vuln_id":         "http-dup",
				"title":           "dup",
				"level":           "medium",
				"type":            "未授权访问",
				"url":             "http://example.com/api/common/getCitys",
				"method":          "GET",
				"response_length": 100,
				"created_at":      "2026-04-20T10:00:00Z",
			},
			{
				"task_id":         task.ID,
				"version":         1,
				"vuln_id":         "https-dup",
				"title":           "dup",
				"level":           "medium",
				"type":            "未授权访问",
				"url":             "https://example.com/api/common/getCitys",
				"method":          "GET",
				"response_length": 100,
				"created_at":      "2026-04-20T10:01:00Z",
			},
		},
	})
	defer restoreES()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/"+task.ID+"/vulns?version=1", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "taskId", Value: task.ID}}

	getTaskVulns(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data []database.VulnRecord `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data) != 1 {
		t.Fatalf("len(response.Data) = %d, want 1; data=%#v", len(response.Data), response.Data)
	}
	if response.Data[0].URL != "https://example.com/api/common/getCitys" {
		t.Fatalf("expected https variant to be preserved, got %#v", response.Data[0])
	}
}

func installMockElasticsearch(t *testing.T, docsByIndex map[string][]map[string]any) func() {
	t.Helper()

	previousClient := database.ESClient
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{"http://mock-es.local"},
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode ES request body: %v", err)
			}

			index := extractSearchIndexFromPath(r.URL.Path)
			docs := docsByIndex[index]
			filtered := make([]map[string]any, 0, len(docs))
			for _, doc := range docs {
				if matchesESQuery(doc, body["query"]) {
					filtered = append(filtered, doc)
				}
			}

			response := map[string]any{
				"hits": map[string]any{
					"hits": makeSearchHits(filtered),
				},
			}
			payload, err := json.Marshal(response)
			if err != nil {
				t.Fatalf("encode ES response: %v", err)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":      []string{"application/json"},
					"X-Elastic-Product": []string{"Elasticsearch"},
				},
				Body: io.NopCloser(strings.NewReader(string(payload))),
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("elasticsearch.NewClient() error = %v", err)
	}
	database.ESClient = client

	return func() {
		database.ESClient = previousClient
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func extractSearchIndexFromPath(path string) string {
	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "_search" || trimmed == "" {
		return ""
	}
	if idx := strings.Index(trimmed, "/"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func makeSearchHits(docs []map[string]any) []map[string]any {
	hits := make([]map[string]any, 0, len(docs))
	for _, doc := range docs {
		hits = append(hits, map[string]any{"_source": doc})
	}
	return hits
}

func matchesESQuery(doc map[string]any, query any) bool {
	if query == nil {
		return true
	}

	queryMap, ok := query.(map[string]any)
	if !ok {
		return false
	}

	if term, ok := queryMap["term"].(map[string]any); ok {
		return matchesESTerm(doc, term)
	}
	if boolQuery, ok := queryMap["bool"].(map[string]any); ok {
		return matchesESBool(doc, boolQuery)
	}
	if exists, ok := queryMap["exists"].(map[string]any); ok {
		field, _ := exists["field"].(string)
		_, present := lookupESField(doc, field)
		return present
	}

	return false
}

func matchesESBool(doc map[string]any, boolQuery map[string]any) bool {
	if mustRaw, ok := boolQuery["must"]; ok {
		for _, clause := range toClauseList(mustRaw) {
			if !matchesESQuery(doc, clause) {
				return false
			}
		}
	}
	if mustNotRaw, ok := boolQuery["must_not"]; ok {
		for _, clause := range toClauseList(mustNotRaw) {
			if matchesESQuery(doc, clause) {
				return false
			}
		}
	}
	if shouldRaw, ok := boolQuery["should"]; ok {
		clauses := toClauseList(shouldRaw)
		if len(clauses) == 0 {
			return true
		}

		matches := 0
		for _, clause := range clauses {
			if matchesESQuery(doc, clause) {
				matches++
			}
		}

		minimum := 1
		switch value := boolQuery["minimum_should_match"].(type) {
		case float64:
			minimum = int(value)
		case int:
			minimum = value
		}
		return matches >= minimum
	}

	return true
}

func toClauseList(raw any) []any {
	switch clauses := raw.(type) {
	case []any:
		return clauses
	default:
		return []any{raw}
	}
}

func matchesESTerm(doc map[string]any, term map[string]any) bool {
	for field, want := range term {
		got, ok := lookupESField(doc, field)
		if !ok {
			return false
		}
		if !equalESValue(got, want) {
			return false
		}
	}
	return true
}

func lookupESField(doc map[string]any, field string) (any, bool) {
	normalized := strings.TrimSuffix(field, ".keyword")
	value, ok := doc[normalized]
	return value, ok
}

func equalESValue(got, want any) bool {
	switch wantValue := want.(type) {
	case float64:
		switch gotValue := got.(type) {
		case float64:
			return gotValue == wantValue
		case int:
			return float64(gotValue) == wantValue
		}
	case int:
		switch gotValue := got.(type) {
		case float64:
			return gotValue == float64(wantValue)
		case int:
			return gotValue == wantValue
		}
	case string:
		gotValue, ok := got.(string)
		return ok && gotValue == wantValue
	}
	return got == want
}

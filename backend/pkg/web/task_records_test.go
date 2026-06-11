package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
)

func TestGetTasksOmitsVulnCountFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "tasks.db")
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
		ID:               "task-1",
		Name:             "task-1",
		Targets:          []string{"https://example.com"},
		Status:           "completed",
		Progress:         100,
		HighestRiskLevel: "high",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/records?page=1&size=10", nil)
	ctx.Request = req

	getTasks(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data) != 1 {
		t.Fatalf("len(response.Data) = %d, want 1", len(response.Data))
	}

	item := response.Data[0]
	if _, ok := item["highestRiskLevel"]; !ok {
		t.Fatalf("response missing highestRiskLevel: %#v", item)
	}

	for _, key := range []string{"vulnCount", "vulnCountHigh", "vulnCountMedium", "vulnCountLow", "vulnCountInfo"} {
		if _, ok := item[key]; ok {
			t.Fatalf("response unexpectedly includes %q: %#v", key, item)
		}
	}
}

func TestGetTasksReturnsLatestVersionSummaryFields(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "tasks.db")
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
		ID:               "task-latest",
		Name:             "task-latest",
		Targets:          []string{"https://old.example.com"},
		Status:           "pending",
		Progress:         0,
		HighestRiskLevel: "low",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := database.CreateTaskVersion(task.ID, []string{"https://v1.example.com"}, []byte(`{"version":1}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion(version 1) error = %v", err)
	}

	secondVersion, err := database.CreateTaskVersion(task.ID, []string{"https://v2.example.com"}, []byte(`{"version":2}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion(version 2) error = %v", err)
	}
	if err := database.UpdateTaskVersionStatus(task.ID, secondVersion.Version, "completed", 100); err != nil {
		t.Fatalf("UpdateTaskVersionStatus() error = %v", err)
	}
	if err := database.UpdateTaskVersionHighestRiskLevel(task.ID, secondVersion.Version, "high"); err != nil {
		t.Fatalf("UpdateTaskVersionHighestRiskLevel() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/records?page=1&size=10", nil)
	ctx.Request = req

	getTasks(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data) != 1 {
		t.Fatalf("len(response.Data) = %d, want 1", len(response.Data))
	}

	item := response.Data[0]
	if got := item["status"]; got != "pending" {
		t.Fatalf("status = %#v, want base task status %q", got, "pending")
	}
	if got := item["progress"]; got != float64(0) {
		t.Fatalf("progress = %#v, want base task progress %d", got, 0)
	}

	targets, ok := item["targets"].([]any)
	if !ok {
		t.Fatalf("targets has unexpected type: %#v", item["targets"])
	}
	if len(targets) != 1 || targets[0] != "https://old.example.com" {
		t.Fatalf("targets = %#v, want base task targets", targets)
	}

	if got := item["highestRiskLevel"]; got != "high" {
		t.Fatalf("highestRiskLevel = %#v, want %q", got, "high")
	}
	if got := item["latestVersion"]; got != float64(2) {
		t.Fatalf("latestVersion = %#v, want %d", got, 2)
	}
	if got := item["latestStatus"]; got != "completed" {
		t.Fatalf("latestStatus = %#v, want %q", got, "completed")
	}
	if got := item["latestProgress"]; got != float64(100) {
		t.Fatalf("latestProgress = %#v, want %d", got, 100)
	}
	if got := item["versionCount"]; got != float64(2) {
		t.Fatalf("versionCount = %#v, want %d", got, 2)
	}
	if got := item["triggerType"]; got != "manual" {
		t.Fatalf("triggerType = %#v, want %q", got, "manual")
	}
	if _, ok := item["version"]; ok {
		t.Fatalf("response unexpectedly includes overloaded %q field: %#v", "version", item)
	}
}

func TestGetTasksSupportsKeywordAndStatusFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "tasks.db")
	if err := database.InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if database.DB != nil {
			_ = database.DB.Close()
			database.DB = nil
		}
	})

	alphaTask := database.Task{
		ID:               "task-alpha",
		Name:             "Alpha Gateway Scan",
		Targets:          []string{"https://alpha.example.com"},
		Status:           "pending",
		Progress:         0,
		HighestRiskLevel: "low",
	}
	if _, err := alphaTask.Save(); err != nil {
		t.Fatalf("alphaTask.Save() error = %v", err)
	}

	alphaVersion, err := database.CreateTaskVersion(alphaTask.ID, alphaTask.Targets, []byte(`{"version":1}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion(alpha) error = %v", err)
	}
	if err := database.UpdateTaskVersionStatus(alphaTask.ID, alphaVersion.Version, "running", 30); err != nil {
		t.Fatalf("UpdateTaskVersionStatus(alpha) error = %v", err)
	}

	betaTask := database.Task{
		ID:               "task-beta",
		Name:             "Beta Scan",
		Targets:          []string{"https://beta.example.com"},
		Status:           "completed",
		Progress:         100,
		HighestRiskLevel: "medium",
	}
	if _, err := betaTask.Save(); err != nil {
		t.Fatalf("betaTask.Save() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/records?page=1&size=10&keyword=Gateway&status=running", nil)
	ctx.Request = req

	getTasks(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Data []map[string]any `json:"data"`
		Pagination struct {
			Total float64 `json:"total"`
		} `json:"pagination"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data) != 1 {
		t.Fatalf("len(response.Data) = %d, want 1", len(response.Data))
	}
	if got := response.Pagination.Total; got != 1 {
		t.Fatalf("pagination.total = %v, want 1", got)
	}
	if got := response.Data[0]["id"]; got != "task-alpha" {
		t.Fatalf("id = %#v, want %q", got, "task-alpha")
	}
	if got := response.Data[0]["latestStatus"]; got != "running" {
		t.Fatalf("latestStatus = %#v, want %q", got, "running")
	}
}

func TestGetTasksFallsBackToTaskHighestRiskLevelWhenLatestVersionRiskIsEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "tasks.db")
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
		ID:               "task-low-fallback",
		Name:             "task-low-fallback",
		Targets:          []string{"https://example.com"},
		Status:           "completed",
		Progress:         100,
		HighestRiskLevel: "low",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	version, err := database.CreateTaskVersion(task.ID, task.Targets, []byte(`{"version":1}`), "manual")
	if err != nil {
		t.Fatalf("CreateTaskVersion() error = %v", err)
	}
	if err := database.UpdateTaskVersionStatus(task.ID, version.Version, "completed", 100); err != nil {
		t.Fatalf("UpdateTaskVersionStatus() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/records?page=1&size=10", nil)
	ctx.Request = req

	getTasks(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d", recorder.Code, http.StatusOK)
	}

	var response struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data) != 1 {
		t.Fatalf("len(response.Data) = %d, want 1", len(response.Data))
	}

	if got := response.Data[0]["highestRiskLevel"]; got != "low" {
		t.Fatalf("highestRiskLevel = %#v, want %q", got, "low")
	}
}

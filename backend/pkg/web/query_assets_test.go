package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"trailblazer/pkg/core/database"
)

func TestGetTaskAssetsReturnsEsAssetsWithoutTaskRecord(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreES := installMockElasticsearch(t, map[string][]map[string]any{
		database.IndexAsset: {
			{
				"task_id":    "es-only-task",
				"version":    1,
				"email":      []map[string]any{{"value": "admin@example.com", "source": []string{"https://example.com/login"}}},
				"id_card":    []string{},
				"phone":      []map[string]any{{"value": "13800000000", "source": "https://example.com/profile"}},
				"ip_url":     []map[string]any{{"value": "https://example.com/very/long/path", "source": []string{"https://example.com"}}},
				"api_root":   []map[string]any{{"value": "/api", "source": []string{"/api/demo"}}},
				"api_router": []map[string]any{{"value": "/api/demo", "source": []string{"https://example.com"}}},
				"created_at": "2026-04-13T13:00:00Z",
			},
		},
	})
	defer restoreES()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/es-only-task/assets?version=1", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "taskId", Value: "es-only-task"}}

	getTaskAssets(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			TaskID    string                `json:"taskId"`
			TaskName  string                `json:"taskName"`
			Email     []database.AssetValue `json:"email"`
			Phone     []database.AssetValue `json:"phone"`
			IPURL     []database.AssetValue `json:"ipUrl"`
			APIRoot   []database.AssetValue `json:"apiRoot"`
			APIRouter []database.AssetValue `json:"apiRouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if response.Data.TaskID != "es-only-task" {
		t.Fatalf("taskId = %q, want %q", response.Data.TaskID, "es-only-task")
	}
	if len(response.Data.Email) != 1 || response.Data.Email[0].Value != "admin@example.com" {
		t.Fatalf("email = %#v, want ES-backed email", response.Data.Email)
	}
	if len(response.Data.Email[0].Source) != 1 || response.Data.Email[0].Source[0] != "https://example.com/login" {
		t.Fatalf("email source = %#v, want ES-backed source", response.Data.Email[0].Source)
	}
	if len(response.Data.IPURL) != 1 || response.Data.IPURL[0].Value != "https://example.com/very/long/path" {
		t.Fatalf("ipUrl = %#v, want ES-backed asset", response.Data.IPURL)
	}
}

func TestGetTaskAssetsNormalizesLegacyStringArrays(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreES := installMockElasticsearch(t, map[string][]map[string]any{
		database.IndexAsset: {
			{
				"task_id":    "legacy-task",
				"version":    1,
				"email":      []string{"legacy@example.com"},
				"phone":      []string{"13800000001"},
				"ip_url":     []string{"https://legacy.example.com/api/demo"},
				"api_root":   []string{"/api"},
				"api_router": []string{"/api/demo"},
				"created_at": "2026-04-13T13:00:00Z",
			},
		},
		database.IndexSiteTree: {
			{
				"task_id":    "legacy-task",
				"version":    1,
				"node_id":    "root/0",
				"parent_id":  "0",
				"label":      "首页接口",
				"url":        "https://legacy.example.com/api/demo",
				"level":      1,
				"created_at": "2026-04-13T13:00:00Z",
			},
		},
	})
	defer restoreES()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/legacy-task/assets?version=1", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "taskId", Value: "legacy-task"}}

	getTaskAssets(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Email []database.AssetValue `json:"email"`
			IPURL []database.AssetValue `json:"ipUrl"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data.Email) != 1 || response.Data.Email[0].Value != "legacy@example.com" {
		t.Fatalf("email = %#v, want legacy string value normalized", response.Data.Email)
	}
	if len(response.Data.Email[0].Source) != 0 {
		t.Fatalf("email source = %#v, want empty sources for legacy strings", response.Data.Email[0].Source)
	}
	if len(response.Data.IPURL) != 1 || response.Data.IPURL[0].Value != "https://legacy.example.com/api/demo" {
		t.Fatalf("ipUrl = %#v, want legacy string value normalized", response.Data.IPURL)
	}
	if len(response.Data.IPURL[0].Source) != 1 || response.Data.IPURL[0].Source[0] != "https://legacy.example.com/api/demo" {
		t.Fatalf("ipUrl source = %#v, want backfilled absolute URL source", response.Data.IPURL[0].Source)
	}
}

func TestGetTaskAssetsMergesMultipleAssetDocumentsForSameTaskVersion(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restoreES := installMockElasticsearch(t, map[string][]map[string]any{
		database.IndexAsset: {
			{
				"task_id":    "multi-target-task",
				"version":    1,
				"email":      []map[string]any{{"value": "first@example.com", "source": []string{"https://a.example.com"}}},
				"ip_url":     []map[string]any{{"value": "https://a.example.com/api/one", "source": []string{"https://a.example.com"}}},
				"api_root":   []map[string]any{{"value": "https://a.example.com/api", "source": []string{"https://a.example.com/api/one"}}},
				"api_router": []map[string]any{{"value": "/api/one", "source": []string{"https://a.example.com"}}},
				"created_at": "2026-04-15T09:00:00Z",
			},
			{
				"task_id":    "multi-target-task",
				"version":    1,
				"phone":      []map[string]any{{"value": "13800000002", "source": []string{"https://b.example.com"}}},
				"ip_url":     []map[string]any{{"value": "https://b.example.com/api/two", "source": []string{"https://b.example.com"}}},
				"api_root":   []map[string]any{{"value": "https://b.example.com/api", "source": []string{"https://b.example.com/api/two"}}},
				"api_router": []map[string]any{{"value": "/api/two", "source": []string{"https://b.example.com"}}},
				"created_at": "2026-04-15T09:00:00Z",
			},
			{
				"task_id":    "multi-target-task",
				"version":    1,
				"ip_url":     []map[string]any{{"value": "https://a.example.com/api/one", "source": []string{"https://merged.example.com"}}},
				"api_router": []map[string]any{{"value": "/api/one", "source": []string{"https://merged.example.com"}}},
				"created_at": "2026-04-15T09:00:00Z",
			},
		},
	})
	defer restoreES()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/api/task/multi-target-task/assets?version=1", nil)
	ctx.Request = req
	ctx.Params = gin.Params{{Key: "taskId", Value: "multi-target-task"}}

	getTaskAssets(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Email     []database.AssetValue `json:"email"`
			Phone     []database.AssetValue `json:"phone"`
			IPURL     []database.AssetValue `json:"ipUrl"`
			APIRoot   []database.AssetValue `json:"apiRoot"`
			APIRouter []database.AssetValue `json:"apiRouter"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if len(response.Data.Email) != 1 || response.Data.Email[0].Value != "first@example.com" {
		t.Fatalf("email = %#v, want merged email values", response.Data.Email)
	}
	if len(response.Data.Phone) != 1 || response.Data.Phone[0].Value != "13800000002" {
		t.Fatalf("phone = %#v, want merged phone values", response.Data.Phone)
	}
	if len(response.Data.IPURL) != 2 {
		t.Fatalf("ipUrl len = %d, want 2 merged assets; values=%#v", len(response.Data.IPURL), response.Data.IPURL)
	}
	if len(response.Data.APIRoot) != 3 {
		t.Fatalf("apiRoot len = %d, want 3 merged assets including derived /api root; values=%#v", len(response.Data.APIRoot), response.Data.APIRoot)
	}
	if len(response.Data.APIRouter) != 2 {
		t.Fatalf("apiRouter len = %d, want 2 merged assets; values=%#v", len(response.Data.APIRouter), response.Data.APIRouter)
	}

	var mergedIPURL *database.AssetValue
	for i := range response.Data.IPURL {
		if response.Data.IPURL[i].Value == "https://a.example.com/api/one" {
			mergedIPURL = &response.Data.IPURL[i]
			break
		}
	}
	if mergedIPURL == nil {
		t.Fatalf("missing merged ipUrl asset: %#v", response.Data.IPURL)
	}
	if len(mergedIPURL.Source) != 2 {
		t.Fatalf("merged ipUrl source len = %d, want 2; values=%#v", len(mergedIPURL.Source), mergedIPURL.Source)
	}
}

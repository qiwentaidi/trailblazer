package database

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/elastic/go-elasticsearch/v8"
)

func TestQueryTaskByIDFallsBackToSQLiteAndAppliesLatestVersion(t *testing.T) {
	dbPath := t.TempDir() + "/query_task.db"
	if err := InitSQLite(dbPath); err != nil {
		t.Fatalf("InitSQLite() error = %v", err)
	}
	t.Cleanup(func() {
		if DB != nil {
			_ = DB.Close()
			DB = nil
		}
		ESClient = nil
	})

	task := &Task{
		ID:       "task-query-test",
		Name:     "Query task",
		Targets:  []string{"https://example.com"},
		Status:   "pending",
		Progress: 0,
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	if _, err := CreateTaskVersion(task.ID, []string{"https://version.example.com"}, []byte(`{"k":"v"}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion() error = %v", err)
	}
	if err := UpdateTaskVersionStatus(task.ID, 1, "completed", 100); err != nil {
		t.Fatalf("UpdateTaskVersionStatus() error = %v", err)
	}

	got, err := QueryTaskByID(task.ID)
	if err != nil {
		t.Fatalf("QueryTaskByID() error = %v", err)
	}
	if got == nil {
		t.Fatal("QueryTaskByID() = nil, want task")
	}
	if got.TaskID != task.ID {
		t.Fatalf("TaskID = %q, want %q", got.TaskID, task.ID)
	}
	if got.TaskName != task.Name {
		t.Fatalf("TaskName = %q, want %q", got.TaskName, task.Name)
	}
	if got.Status != "completed" {
		t.Fatalf("Status = %q, want completed", got.Status)
	}
	if len(got.Targets) != 1 || got.Targets[0] != "https://version.example.com" {
		t.Fatalf("Targets = %#v, want version snapshot", got.Targets)
	}
}

func TestQueryAPIResourcesByTaskIDUsesUnmappedDateSort(t *testing.T) {
	restoreES, requests := installCapturingMockElasticsearch(t, map[string][]map[string]any{
		IndexAPI: {
			{
				"task_id":    "task-api-test",
				"version":    1,
				"url":        "https://example.com/api",
				"method":     "GET",
				"fetched_at": "2026-06-12T10:00:00Z",
			},
		},
	})
	defer restoreES()

	resources, err := QueryAPIResourcesByTaskID("task-api-test", 1)
	if err != nil {
		t.Fatalf("QueryAPIResourcesByTaskID() error = %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("len(resources) = %d, want 1", len(resources))
	}

	body := findRequestBodyForIndex(t, requests, IndexAPI)
	assertDateSortUsesUnmappedType(t, body, "fetched_at")
}

func TestQueryProtocolTracesByTaskIDUsesUnmappedDateSort(t *testing.T) {
	restoreES, requests := installCapturingMockElasticsearch(t, map[string][]map[string]any{
		IndexProtocol: {
			{
				"task_id":     "task-protocol-test",
				"version":     1,
				"trace_id":    "trace-1",
				"request_url": "https://example.com/api",
				"method":      "POST",
				"created_at":  "2026-06-12T10:00:00Z",
			},
		},
	})
	defer restoreES()

	traces, err := QueryProtocolTracesByTaskID("task-protocol-test", 1)
	if err != nil {
		t.Fatalf("QueryProtocolTracesByTaskID() error = %v", err)
	}
	if len(traces) != 1 {
		t.Fatalf("len(traces) = %d, want 1", len(traces))
	}

	body := findRequestBodyForIndex(t, requests, IndexProtocol)
	assertDateSortUsesUnmappedType(t, body, "created_at")
}

func installCapturingMockElasticsearch(t *testing.T, docsByIndex map[string][]map[string]any) (func(), *[]capturedESRequest) {
	t.Helper()

	previousClient := ESClient
	requests := make([]capturedESRequest, 0, 4)
	client, err := elasticsearch.NewClient(elasticsearch.Config{
		Addresses: []string{"http://mock-es.local"},
		Transport: capturingRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			payload, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatalf("io.ReadAll() error = %v", err)
			}

			var body map[string]any
			if err := json.Unmarshal(payload, &body); err != nil {
				t.Fatalf("json.Unmarshal() error = %v; payload=%s", err, string(payload))
			}

			index := extractSearchIndexFromPath(r.URL.Path)
			requests = append(requests, capturedESRequest{
				Index: index,
				Body:  body,
			})

			hits := make([]map[string]any, 0, len(docsByIndex[index]))
			for _, doc := range docsByIndex[index] {
				hits = append(hits, map[string]any{"_source": doc})
			}

			response := map[string]any{
				"hits": map[string]any{
					"hits": hits,
				},
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":      []string{"application/json"},
					"X-Elastic-Product": []string{"Elasticsearch"},
				},
				Body: io.NopCloser(strings.NewReader(string(encoded))),
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("elasticsearch.NewClient() error = %v", err)
	}
	ESClient = client

	return func() {
		ESClient = previousClient
	}, &requests
}

type capturedESRequest struct {
	Index string
	Body  map[string]any
}

type capturingRoundTripFunc func(*http.Request) (*http.Response, error)

func (f capturingRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func findRequestBodyForIndex(t *testing.T, requests *[]capturedESRequest, index string) map[string]any {
	t.Helper()

	for _, request := range *requests {
		if request.Index == index {
			return request.Body
		}
	}
	t.Fatalf("missing request for index %q", index)
	return nil
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

func assertDateSortUsesUnmappedType(t *testing.T, body map[string]any, field string) {
	t.Helper()

	rawSort, ok := body["sort"].([]any)
	if !ok || len(rawSort) == 0 {
		t.Fatalf("sort = %#v, want non-empty sort clause", body["sort"])
	}

	firstSort, ok := rawSort[0].(map[string]any)
	if !ok {
		t.Fatalf("first sort = %#v, want object", rawSort[0])
	}

	fieldSort, ok := firstSort[field].(map[string]any)
	if !ok {
		t.Fatalf("sort[%q] = %#v, want object", field, firstSort[field])
	}
	if got := fieldSort["order"]; got != "desc" {
		t.Fatalf("sort[%q].order = %#v, want %q", field, got, "desc")
	}
	if got := fieldSort["unmapped_type"]; got != "date" {
		t.Fatalf("sort[%q].unmapped_type = %#v, want %q", field, got, "date")
	}
}

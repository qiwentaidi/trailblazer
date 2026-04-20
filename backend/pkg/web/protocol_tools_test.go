package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/protocoltool"

	"github.com/gin-gonic/gin"
)

func TestExplainProtocolTracePayloadUsesSelectedVersionTrace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "protocol_tools_explain_versions.db")
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
		ID:      "protocol-tools-explain-task",
		Name:    "protocol-tools-explain-task",
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
		database.IndexProtocol: {
			{
				"task_id":     task.ID,
				"version":     1,
				"trace_id":    "trace-1",
				"page_url":    "https://v1.example.com/page",
				"request_url": "https://v1.example.com/api/orders",
				"session_materials": map[string]any{
					"latest_response_plaintext": "{\"version\":1}",
				},
			},
			{
				"task_id":     task.ID,
				"version":     2,
				"trace_id":    "trace-1",
				"page_url":    "https://v2.example.com/page",
				"request_url": "https://v2.example.com/api/orders",
				"session_materials": map[string]any{
					"latest_response_plaintext": "{\"version\":2}",
				},
			},
		},
	})
	defer restoreES()

	originalExplain := protocolTraceAIExplain
	protocolTraceAIExplain = func(trace *database.ProtocolTraceRecord) (*protocoltool.ProtocolExplainResult, error) {
		return &protocoltool.ProtocolExplainResult{
			TraceID:     trace.TraceID,
			Explanation: trace.PageURL,
			Model:       "stub-model",
		}, nil
	}
	defer func() {
		protocolTraceAIExplain = originalExplain
	}()

	payload, err := json.Marshal(map[string]any{
		"traceId": "trace-1",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/task/"+task.ID+"/protocol-tools/explain?version=1", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "taskId", Value: task.ID}}

	explainProtocolTracePayload(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			TraceID     string `json:"trace_id"`
			Explanation string `json:"explanation"`
			Model       string `json:"model"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if response.Data.TraceID != "trace-1" {
		t.Fatalf("trace_id = %q, want trace-1", response.Data.TraceID)
	}
	if response.Data.Explanation != "https://v1.example.com/page" {
		t.Fatalf("explanation = %q, want version 1 page url", response.Data.Explanation)
	}
	if response.Data.Model != "stub-model" {
		t.Fatalf("model = %q, want stub-model", response.Data.Model)
	}
}

func TestExplainProtocolTracePayloadStreamsSSE(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "protocol_tools_explain_stream.db")
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
		ID:      "protocol-tools-explain-stream-task",
		Name:    "protocol-tools-explain-stream-task",
		Targets: []string{"https://example.com"},
		Status:  "pending",
	}
	if _, err := task.Save(); err != nil {
		t.Fatalf("Task.Save() error = %v", err)
	}

	if _, err := database.CreateTaskVersion(task.ID, []string{"https://v1.example.com"}, []byte(`{"version":1}`), "manual"); err != nil {
		t.Fatalf("CreateTaskVersion(version 1) error = %v", err)
	}

	restoreES := installMockElasticsearch(t, map[string][]map[string]any{
		database.IndexProtocol: {
			{
				"task_id":     task.ID,
				"version":     1,
				"trace_id":    "trace-1",
				"page_url":    "https://v1.example.com/page",
				"request_url": "https://v1.example.com/api/orders",
			},
		},
	})
	defer restoreES()

	originalExplainStream := protocolTraceAIExplainStream
	protocolTraceAIExplainStream = func(_ context.Context, trace *database.ProtocolTraceRecord, onDelta func(string)) (*protocoltool.ProtocolExplainResult, error) {
		onDelta("以下是该协议轨迹的白话解释：\n\n")
		onDelta("## 请求甬道\n\n1. hello\n\n")
		onDelta("## 响应甬道\n\n1. world")
		return &protocoltool.ProtocolExplainResult{
			TraceID:     trace.TraceID,
			Explanation: "以下是该协议轨迹的白话解释：\n\n## 请求甬道\n\n1. hello\n\n## 响应甬道\n\n1. world",
			Model:       "stream-model",
		}, nil
	}
	defer func() {
		protocolTraceAIExplainStream = originalExplainStream
	}()

	payload, err := json.Marshal(map[string]any{
		"traceId": "trace-1",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/task/"+task.ID+"/protocol-tools/explain?version=1", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Request.Header.Set("Accept", "text/event-stream")
	ctx.Params = gin.Params{{Key: "taskId", Value: task.ID}}

	explainProtocolTracePayload(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); !strings.Contains(got, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", got)
	}

	body := recorder.Body.String()
	for _, expected := range []string{
		"event: start",
		`"trace_id":"trace-1"`,
		"event: delta",
		`"delta":"## 请求甬道\n\n1. hello"`,
		`"delta":"\n\n## 响应甬道\n\n1. world"`,
		"event: done",
		`"explanation":"## 请求甬道\n\n1. hello\n\n## 响应甬道\n\n1. world"`,
		`"model":"stream-model"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("stream body missing %q; body=%s", expected, body)
		}
	}
	if strings.Contains(body, "以下是该协议轨迹的白话解释") {
		t.Fatalf("stream body should not include intro text; body=%s", body)
	}
}

func TestDecryptProtocolPayloadUsesSelectedVersionTrace(t *testing.T) {
	gin.SetMode(gin.TestMode)

	dbPath := filepath.Join(t.TempDir(), "protocol_tools_versions.db")
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
		ID:      "protocol-tools-task",
		Name:    "protocol-tools-task",
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
		database.IndexProtocol: {
			{
				"task_id":                    task.ID,
				"version":                    1,
				"trace_id":                   "trace-1",
				"page_url":                   "https://v1.example.com/page",
				"request_url":                "https://v1.example.com/api/orders",
				"latest_response_ciphertext": "abcd1234",
				"latest_response_plaintext":  "{\"version\":1}",
				"session_materials": map[string]any{
					"latest_response_ciphertext": "abcd1234",
					"latest_response_plaintext":  "{\"version\":1}",
				},
			},
			{
				"task_id":                    task.ID,
				"version":                    2,
				"trace_id":                   "trace-1",
				"page_url":                   "https://v2.example.com/page",
				"request_url":                "https://v2.example.com/api/orders",
				"latest_response_ciphertext": "deadbeef",
				"latest_response_plaintext":  "{\"version\":2}",
				"session_materials": map[string]any{
					"latest_response_ciphertext": "deadbeef",
					"latest_response_plaintext":  "{\"version\":2}",
				},
			},
		},
	})
	defer restoreES()

	payload, err := json.Marshal(map[string]any{
		"traceId":    "trace-1",
		"ciphertext": "abcd1234",
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/api/task/"+task.ID+"/protocol-tools/decrypt?version=1", bytes.NewReader(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Params = gin.Params{{Key: "taskId", Value: task.ID}}

	decryptProtocolPayload(ctx)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d, want %d; body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	var response struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			Plaintext  string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; body=%s", err, recorder.Body.String())
	}

	if response.Data.Ciphertext != "abcd1234" {
		t.Fatalf("ciphertext = %q, want version 1 trace ciphertext", response.Data.Ciphertext)
	}
	if response.Data.Plaintext != "{\"version\":1}" {
		t.Fatalf("plaintext = %q, want version 1 trace plaintext", response.Data.Plaintext)
	}
}

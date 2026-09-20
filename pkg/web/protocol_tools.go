package web

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/protocoltool"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

var protocolTraceAIExplain = defaultProtocolTraceAIExplain
var protocolTraceAIExplainStream = defaultProtocolTraceAIExplainStream

type protocolExplainStreamSanitizer struct {
	raw        strings.Builder
	emittedLen int
}

func trimProtocolExplainLead(content string) string {
	normalized := strings.TrimSpace(strings.ReplaceAll(content, "\r\n", "\n"))
	if normalized == "" {
		return ""
	}

	for _, marker := range []string{
		"## 请求甬道",
		"### 请求甬道",
		"# 请求甬道",
		"## 请求链路",
		"### 请求链路",
		"# 请求链路",
	} {
		if index := strings.Index(normalized, marker); index >= 0 {
			return strings.TrimSpace(normalized[index:])
		}
	}

	for _, marker := range []string{"\n1. ", "\n- ", "\n* "} {
		if index := strings.Index(normalized, marker); index >= 0 {
			return strings.TrimSpace(normalized[index+1:])
		}
	}

	if strings.HasPrefix(normalized, "1. ") || strings.HasPrefix(normalized, "- ") || strings.HasPrefix(normalized, "* ") {
		return normalized
	}

	return ""
}

func (s *protocolExplainStreamSanitizer) Append(delta string) string {
	s.raw.WriteString(delta)
	sanitized := trimProtocolExplainLead(s.raw.String())
	if sanitized == "" || len(sanitized) <= s.emittedLen {
		return ""
	}

	next := sanitized[s.emittedLen:]
	s.emittedLen = len(sanitized)
	return next
}

func (s *protocolExplainStreamSanitizer) Final() string {
	return trimProtocolExplainLead(s.raw.String())
}

func getProtocolTraceForTool(taskID, traceID string, version *int) (*database.ProtocolTraceRecord, error) {
	traceID = strings.TrimSpace(traceID)
	if traceID == "" {
		return nil, nil
	}
	return database.QueryProtocolTraceByTaskAndTraceID(taskID, traceID, versionArgs(version)...)
}

// encryptProtocolPayload 使用 trace 材料顺向构造新的加密请求
func encryptProtocolPayload(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	var body struct {
		TraceID           string `json:"traceId"`
		Plaintext         string `json:"plaintext"`
		KeyHex            string `json:"keyHex"`
		Token             string `json:"token"`
		ChannelCode       string `json:"channelCode"`
		KeyExchangeHeader string `json:"keyExchangeHeader"`
		Nonce             string `json:"nonce"`
		Timestamp         string `json:"timestamp"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	trace, err := getProtocolTraceForTool(taskID, body.TraceID, version)
	if err != nil {
		c.JSON(404, gin.H{"error": "protocol trace not found", "detail": err.Error()})
		return
	}

	result, err := protocoltool.EncryptWithTrace(
		trace,
		body.KeyHex,
		body.Plaintext,
		body.Token,
		body.ChannelCode,
		body.KeyExchangeHeader,
		body.Nonce,
		body.Timestamp,
	)
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to encrypt", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": result})
}

func explainProtocolTracePayload(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	var body struct {
		TraceID string `json:"traceId"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	trace, err := getProtocolTraceForTool(taskID, body.TraceID, version)
	if err != nil {
		c.JSON(404, gin.H{"error": "protocol trace not found", "detail": err.Error()})
		return
	}
	if trace == nil {
		c.JSON(400, gin.H{"error": "missing protocol trace"})
		return
	}

	if wantsProtocolExplainStream(c) {
		streamProtocolTraceExplanation(c, trace)
		return
	}

	result, err := protocolTraceAIExplain(trace)
	if err != nil {
		c.JSON(400, gin.H{"error": "failed to explain protocol trace", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": result})
}

func defaultProtocolTraceAIExplain(trace *database.ProtocolTraceRecord) (*protocoltool.ProtocolExplainResult, error) {
	openAIConfig, err := loadProtocolOpenAIConfig()
	if err != nil {
		return nil, err
	}
	if !openAIConfig.Enabled || strings.TrimSpace(openAIConfig.APIKey) == "" {
		return nil, fmt.Errorf("AI 协议解释未启用或缺少 API Key")
	}

	traceSummary, err := protocoltool.BuildProtocolTraceExplanationInput(trace)
	if err != nil {
		return nil, err
	}

	checker := crawl.NewSensitiveInfoChecker(
		openAIConfig.APIKey,
		openAIConfig.BaseURL,
		openAIConfig.Model,
	)
	explanation, err := checker.ExplainProtocolTrace(traceSummary)
	if err != nil {
		return nil, err
	}
	explanation = trimProtocolExplainLead(explanation)
	if explanation == "" {
		return nil, fmt.Errorf("AI 未返回有效的协议解释列表")
	}

	return &protocoltool.ProtocolExplainResult{
		TraceID:     strings.TrimSpace(trace.TraceID),
		Explanation: strings.TrimSpace(explanation),
		Model:       strings.TrimSpace(openAIConfig.Model),
	}, nil
}

func defaultProtocolTraceAIExplainStream(ctx context.Context, trace *database.ProtocolTraceRecord, onDelta func(string)) (*protocoltool.ProtocolExplainResult, error) {
	openAIConfig, err := loadProtocolOpenAIConfig()
	if err != nil {
		return nil, err
	}
	if !openAIConfig.Enabled || strings.TrimSpace(openAIConfig.APIKey) == "" {
		return nil, fmt.Errorf("AI 协议解释未启用或缺少 API Key")
	}

	traceSummary, err := protocoltool.BuildProtocolTraceExplanationInput(trace)
	if err != nil {
		return nil, err
	}

	checker := crawl.NewSensitiveInfoChecker(
		openAIConfig.APIKey,
		openAIConfig.BaseURL,
		openAIConfig.Model,
	)
	checker.SetContext(ctx)

	explanation, err := checker.ExplainProtocolTraceStream(traceSummary, onDelta)
	if err != nil {
		return nil, err
	}
	explanation = trimProtocolExplainLead(explanation)
	if explanation == "" {
		return nil, fmt.Errorf("AI 未返回有效的协议解释列表")
	}

	return &protocoltool.ProtocolExplainResult{
		TraceID:     strings.TrimSpace(trace.TraceID),
		Explanation: strings.TrimSpace(explanation),
		Model:       strings.TrimSpace(openAIConfig.Model),
	}, nil
}

func wantsProtocolExplainStream(c *gin.Context) bool {
	accept := strings.ToLower(strings.TrimSpace(c.GetHeader("Accept")))
	return strings.Contains(accept, "text/event-stream") || c.Query("stream") == "1"
}

func writeProtocolExplainSSE(c *gin.Context, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.Writer, "event: %s\n", event); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.Writer, "data: %s\n\n", data); err != nil {
		return err
	}
	c.Writer.Flush()
	return nil
}

func streamProtocolTraceExplanation(c *gin.Context, trace *database.ProtocolTraceRecord) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	traceID := strings.TrimSpace(trace.TraceID)
	sanitizer := &protocolExplainStreamSanitizer{}
	if err := writeProtocolExplainSSE(c, "start", gin.H{
		"trace_id": traceID,
	}); err != nil {
		return
	}

	result, err := protocolTraceAIExplainStream(c.Request.Context(), trace, func(delta string) {
		sanitizedDelta := sanitizer.Append(delta)
		if strings.TrimSpace(sanitizedDelta) == "" {
			return
		}
		if c.Request.Context().Err() != nil {
			return
		}
		_ = writeProtocolExplainSSE(c, "delta", gin.H{
			"trace_id": traceID,
			"delta":    sanitizedDelta,
		})
	})
	if err != nil {
		_ = writeProtocolExplainSSE(c, "error", gin.H{
			"error":  "failed to explain protocol trace",
			"detail": err.Error(),
		})
		return
	}
	result.Explanation = sanitizer.Final()
	if result.Explanation == "" {
		_ = writeProtocolExplainSSE(c, "error", gin.H{
			"error":  "failed to explain protocol trace",
			"detail": "AI 未返回有效的协议解释列表",
		})
		return
	}

	_ = writeProtocolExplainSSE(c, "done", gin.H{
		"trace_id":    result.TraceID,
		"explanation": result.Explanation,
		"model":       result.Model,
	})
}
func loadProtocolOpenAIConfig() (config.OpenAI, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config.OpenAI{}, err
	}

	var fullConfig config.ConfigYAML
	if err := yaml.Unmarshal(data, &fullConfig); err != nil {
		return config.OpenAI{}, err
	}

	return fullConfig.OpenAI, nil
}

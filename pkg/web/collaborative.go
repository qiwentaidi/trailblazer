package web

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/protocoltool"
	"gopkg.in/yaml.v3"
)

const collaborativeSessionDocument = "collaborative_test_session"

const (
	collaborativeAttachmentDirectory = "data/collaborative-uploads"
	maxCollaborativeAttachmentSize   = 5 << 20
	maxCollaborativeAttachments      = 8
)

var collaborativeHighRiskRoutes = []string{
	"sms", "sendcode", "upload", "login", "logout", "token", "pay", "order",
	"save", "submit", "apply", "delete", "remove", "update", "modify",
}

type collaborativeCoverage struct {
	JSResources                int `json:"jsResources"`
	APIRoutesDiscovered        int `json:"apiRoutesDiscovered"`
	RequestBlueprintsExtracted int `json:"requestBlueprintsExtracted"`
	AutoTested                 int `json:"autoTested"`
	RuntimeRequests            int `json:"runtimeRequests"`
	SecurityFindings           int `json:"securityFindings"`
	PendingReview              int `json:"pendingReview"`
	NotRunnable                int `json:"notRunnable"`
}

// collaborativeProgressEvent is a user-visible, auditable execution update.
// It describes work actually performed by the scanner; it is not a model's
// hidden reasoning or a synthetic chat response.
type collaborativeProgressEvent struct {
	ID        string    `json:"id"`
	Stage     string    `json:"stage"`
	State     string    `json:"state"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// collaborativeEndpointEvidence keeps the extraction context behind a single
// endpoint clue. Multiple call sites are evidence for one endpoint, not
// separate endpoints in the collaborative testing UI.
type collaborativeEndpointEvidence struct {
	File    string `json:"file,omitempty"`
	Snippet string `json:"snippet,omitempty"`
	Client  string `json:"client,omitempty"`
	BaseURL string `json:"baseUrl,omitempty"`
}

type collaborativeEndpointClue struct {
	ID                string                          `json:"id"`
	Path              string                          `json:"path"`
	Method            string                          `json:"method"`
	Confidence        string                          `json:"confidence"`
	UnresolvedSymbols []string                        `json:"unresolvedSymbols,omitempty"`
	Representative    crawl.RequestBlueprint          `json:"representative"`
	Evidence          []collaborativeEndpointEvidence `json:"evidence"`
}

// collaborativeTestResult is evidence from an actual browser request, scanner
// finding, or an explicitly authorised replay. It deliberately does not turn a
// JS blueprint into a successful test result without execution evidence.
type collaborativeTestResult struct {
	ID               string    `json:"id"`
	Route            string    `json:"route"`
	Method           string    `json:"method"`
	Kind             string    `json:"kind"`
	Status           string    `json:"status"`
	StatusCode       int       `json:"statusCode,omitempty"`
	ResponseSize     int       `json:"responseSize,omitempty"`
	RiskLevel        string    `json:"riskLevel,omitempty"`
	TraceID          string    `json:"traceId,omitempty"`
	HasProtocolTrace bool      `json:"hasProtocolTrace,omitempty"`
	Summary          string    `json:"summary"`
	CreatedAt        time.Time `json:"createdAt"`
}

type collaborativeAttachment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	Detail     string `json:"detail,omitempty"`
	StorageKey string `json:"storageKey"`
	Path       string `json:"-"`
}

type collaborativeDecision struct {
	ID        string    `json:"id"`
	ActionID  string    `json:"actionId,omitempty"`
	Route     string    `json:"route"`
	Method    string    `json:"method"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason"`
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"createdAt"`
}

type collaborativeAction struct {
	ID                string                  `json:"id"`
	BlueprintID       string                  `json:"blueprintId"`
	Route             string                  `json:"route"`
	Method            string                  `json:"method"`
	RiskLevel         string                  `json:"riskLevel"`
	ActionType        string                  `json:"actionType"`
	Reason            string                  `json:"reason"`
	RiskHypotheses    []string                `json:"riskHypotheses"`
	SuggestedNextStep string                  `json:"suggestedNextStep"`
	Requirements      []string                `json:"requirements"`
	Decision          string                  `json:"decision"`
	DecisionNote      string                  `json:"decisionNote,omitempty"`
	ApprovedBy        string                  `json:"approvedBy,omitempty"`
	ApprovedAt        *time.Time              `json:"approvedAt,omitempty"`
	RequestPreview    crawl.RequestBlueprint  `json:"requestPreview"`
	Execution         *collaborativeExecution `json:"execution,omitempty"`
}

type collaborativeExecution struct {
	StatusCode int       `json:"statusCode"`
	Response   string    `json:"response"`
	ExecutedAt time.Time `json:"executedAt"`
}

type collaborativeSession struct {
	ID                 string                       `json:"id"`
	TaskID             string                       `json:"taskId"`
	Target             string                       `json:"target"`
	Status             string                       `json:"status"`
	Stage              string                       `json:"stage"`
	Error              string                       `json:"error,omitempty"`
	CreatedAt          time.Time                    `json:"createdAt"`
	UpdatedAt          time.Time                    `json:"updatedAt"`
	Coverage           collaborativeCoverage        `json:"coverage"`
	RequestBlueprints  []crawl.RequestBlueprint     `json:"requestBlueprints"`
	TestResults        []collaborativeTestResult    `json:"testResults"`
	Attachments        []collaborativeAttachment    `json:"attachments"`
	Timeline           []collaborativeProgressEvent `json:"timeline"`
	EndpointClues      []collaborativeEndpointClue  `json:"endpointClues"`
	PendingRiskActions []collaborativeAction        `json:"pendingRiskActions"`
	TestDecisions      []collaborativeDecision      `json:"testDecisions"`
}

type collaborativeSessionSubscriber chan *collaborativeSession

var collaborativeSessionStream = struct {
	sync.RWMutex
	subscribers map[string]map[collaborativeSessionSubscriber]struct{}
}{subscribers: make(map[string]map[collaborativeSessionSubscriber]struct{})}

func createCollaborativeTest(c *gin.Context) {
	targetValue, uploads, err := collaborativeRequestInputs(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	target, err := normalizeCollaborativeTarget(targetValue)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	sessionID := uuid.NewString()
	taskID := "collab-" + sessionID
	task := database.Task{ID: taskID, Name: "协同测试 " + target.Host, Targets: []string{target.String()}, Status: "pending", Progress: 0}
	if _, err := task.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create scan task", "detail": err.Error()})
		return
	}
	attachments, err := persistCollaborativeAttachments(sessionID, uploads)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session := collaborativeSession{ID: sessionID, TaskID: taskID, Target: target.String(), Status: "running", Stage: "collecting", CreatedAt: now, UpdatedAt: now, RequestBlueprints: []crawl.RequestBlueprint{}, TestResults: []collaborativeTestResult{}, Attachments: attachments, Timeline: []collaborativeProgressEvent{}, EndpointClues: []collaborativeEndpointClue{}, PendingRiskActions: []collaborativeAction{}, TestDecisions: []collaborativeDecision{}}
	appendCollaborativeProgress(&session, "collecting", "completed", "已创建协同测试任务", "目标已验证，准备启动真实扫描。")
	if err := saveCollaborativeSession(&session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create collaborative session", "detail": err.Error()})
		return
	}

	go runCollaborativeScan(sessionID)
	c.JSON(http.StatusAccepted, gin.H{"data": session})
}

func getCollaborativeTest(c *gin.Context) {
	session, err := loadCollaborativeSession(c.Param("sessionId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "collaborative session not found"})
		return
	}
	// Sessions created before the evidence view existed are hydrated from the
	// persisted scan records so a completed real task does not look empty.
	shouldPersist := false
	if session.Status != "running" && len(session.TestResults) == 0 {
		apiRecords, _ := database.QueryAPIResourcesByTaskID(session.TaskID)
		vulnerabilities, _ := database.QueryVulnsByTaskID(session.TaskID)
		traces, _ := database.QueryProtocolTracesByTaskID(session.TaskID)
		session.TestResults = buildCollaborativeTestResults(apiRecords, vulnerabilities, traces)
		session.Coverage.RuntimeRequests = countCollaborativeResults(session.TestResults, "runtime-request")
		session.Coverage.SecurityFindings = countCollaborativeResults(session.TestResults, "security-finding")
		shouldPersist = true
	}
	if len(session.EndpointClues) == 0 && len(session.RequestBlueprints) > 0 {
		session.EndpointClues = buildCollaborativeEndpointClues(session.Target, session.RequestBlueprints)
		session.Coverage.APIRoutesDiscovered = len(session.EndpointClues)
		shouldPersist = true
	}
	if shouldPersist {
		_ = saveCollaborativeSession(session)
	}
	c.JSON(http.StatusOK, gin.H{"data": session})
}

func streamCollaborativeTest(c *gin.Context) {
	sessionID := c.Param("sessionId")
	subscriber, unsubscribe := subscribeCollaborativeSession(sessionID)
	defer unsubscribe()
	session, err := loadCollaborativeSession(sessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "collaborative session not found"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.SSEvent("session", session)
	c.Writer.Flush()

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case updated := <-subscriber:
			c.SSEvent("session", updated)
			c.Writer.Flush()
		case <-heartbeat.C:
			c.SSEvent("keepalive", gin.H{"at": time.Now().UTC()})
			c.Writer.Flush()
		case <-c.Request.Context().Done():
			return
		}
	}
}

func runtimeDecryptCollaborativeTestResult(c *gin.Context) {
	session, err := loadCollaborativeSession(c.Param("sessionId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "collaborative session not found"})
		return
	}
	for _, result := range session.TestResults {
		if result.ID != c.Param("resultId") {
			continue
		}
		if !result.HasProtocolTrace || strings.TrimSpace(result.TraceID) == "" {
			c.JSON(http.StatusConflict, gin.H{"error": "this result has no browser protocol trace; server replay ciphertext cannot be runtime decrypted"})
			return
		}
		trace, traceErr := database.QueryProtocolTraceByTaskAndTraceID(session.TaskID, result.TraceID)
		if traceErr != nil || trace == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "protocol trace not found"})
			return
		}
		ciphertext := ""
		apiRecords, _ := database.QueryAPIResourcesByTaskID(session.TaskID)
		for _, record := range apiRecords {
			if record.TraceID == result.TraceID {
				ciphertext = record.ResponseBody
				break
			}
		}
		decrypted, decryptErr := protocoltool.RuntimeDecryptWithTrace(trace, ciphertext)
		if decryptErr != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "runtime decrypt unavailable", "detail": decryptErr.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": decrypted})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "test result not found"})
}

func decideCollaborativeAction(c *gin.Context) {
	session, err := loadCollaborativeSession(c.Param("sessionId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "collaborative session not found"})
		return
	}
	var body struct {
		Decision           string `json:"decision"`
		Note               string `json:"note"`
		TestEnvironment    string `json:"testEnvironment"`
		TestIdentity       string `json:"testIdentity"`
		AuthorizationScope string `json:"authorizationScope"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	decision := strings.TrimSpace(body.Decision)
	if !isCollaborativeDecision(decision) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported decision"})
		return
	}

	actionID := c.Param("actionId")
	for index := range session.PendingRiskActions {
		action := &session.PendingRiskActions[index]
		if action.ID != actionID {
			continue
		}
		if action.Decision != "pending" {
			c.JSON(http.StatusConflict, gin.H{"error": "action already decided"})
			return
		}
		if decision == "authorized-replay" && (strings.TrimSpace(body.TestEnvironment) == "" || strings.TrimSpace(body.TestIdentity) == "" || strings.TrimSpace(body.AuthorizationScope) == "") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "authorized replay requires testEnvironment, testIdentity, and authorizationScope"})
			return
		}
		now := time.Now().UTC()
		actor, _ := c.Get("username")
		action.Decision = decision
		action.DecisionNote = collaborativeDecisionNote(decision, body.Note, body.TestEnvironment, body.TestIdentity, body.AuthorizationScope)
		if decision == "authorized-replay" {
			action.ApprovedAt = &now
			action.ApprovedBy, _ = actor.(string)
		}
		session.TestDecisions = append(session.TestDecisions, collaborativeDecision{ID: uuid.NewString(), ActionID: action.ID, Route: action.Route, Method: action.Method, Decision: decision, Reason: action.DecisionNote, Actor: action.ApprovedBy, CreatedAt: now})
		session.Coverage.PendingReview = countPendingCollaborativeActions(session.PendingRiskActions)
		if session.Coverage.PendingReview == 0 {
			session.Stage = "completed"
			session.Status = "completed"
		}
		appendCollaborativeProgress(session, session.Stage, "completed", "已记录人工决策", fmt.Sprintf("%s %s 已标记为%s。", action.Method, action.Route, decisionTagLabel(decision)))
		session.UpdatedAt = now
		if err := saveCollaborativeSession(session); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist decision", "detail": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": session})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "risk action not found"})
}

func executeCollaborativeAction(c *gin.Context) {
	session, err := loadCollaborativeSession(c.Param("sessionId"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "collaborative session not found"})
		return
	}
	var body struct {
		Body    string            `json:"body"`
		Headers map[string]string `json:"headers"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json"})
		return
	}
	for index := range session.PendingRiskActions {
		action := &session.PendingRiskActions[index]
		if action.ID != c.Param("actionId") {
			continue
		}
		if action.Decision != "authorized-replay" {
			c.JSON(http.StatusConflict, gin.H{"error": "action is not approved for replay"})
			return
		}
		if action.Execution != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "action has already been executed"})
			return
		}
		requestURL, err := resolveCollaborativeReplayURL(session.Target, action.RequestPreview.Path)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		allowedHosts, err := configuredReplayHosts()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load replay configuration"})
			return
		}
		if !isCollaborativeReplayHostAllowed(requestURL.Hostname(), allowedHosts) {
			c.JSON(http.StatusForbidden, gin.H{"error": "replay target host is not in collaborative-testing.allowed-replay-hosts"})
			return
		}
		if len(action.RequestPreview.UnresolvedSymbols) > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "request has unresolved dynamic symbols; use dry-run until the request can be completed"})
			return
		}
		req, err := http.NewRequest(action.Method, requestURL.String(), strings.NewReader(body.Body))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to build replay request"})
			return
		}
		for key, value := range body.Headers {
			req.Header.Set(key, value)
		}
		if body.Body != "" && req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/json")
		}
		client := &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": "authorized replay failed", "detail": err.Error()})
			return
		}
		defer response.Body.Close()
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 16*1024))
		now := time.Now().UTC()
		action.Execution = &collaborativeExecution{StatusCode: response.StatusCode, Response: string(responseBody), ExecutedAt: now}
		session.TestResults = append(session.TestResults, collaborativeTestResult{ID: uuid.NewString(), Route: action.Route, Method: action.Method, Kind: "authorized-replay", Status: "completed", StatusCode: response.StatusCode, ResponseSize: len(responseBody), Summary: fmt.Sprintf("人工授权后由服务端执行一次请求，HTTP %d；加密响应需浏览器协议轨迹才能运行时解密。", response.StatusCode), CreatedAt: now})
		session.TestDecisions = append(session.TestDecisions, collaborativeDecision{ID: uuid.NewString(), ActionID: action.ID, Route: action.Route, Method: action.Method, Decision: "executed", Reason: fmt.Sprintf("authorized replay completed with HTTP %d", response.StatusCode), Actor: action.ApprovedBy, CreatedAt: now})
		appendCollaborativeProgress(session, "completed", "completed", "已执行一次人工授权请求", fmt.Sprintf("%s %s 返回 HTTP %d。", action.Method, action.Route, response.StatusCode))
		session.UpdatedAt = now
		if err := saveCollaborativeSession(session); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist replay audit", "detail": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": session})
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "risk action not found"})
}

func runCollaborativeScan(sessionID string) {
	session, err := loadCollaborativeSession(sessionID)
	if err != nil {
		return
	}
	collectingEventID := appendCollaborativeProgress(session, "collecting", "running", "正在采集目标页面与运行期请求", "扫描任务正在执行；结果会在采集完成后写入。")
	_ = saveCollaborativeSession(session)
	performAsyncScan([]string{session.Target}, session.TaskID, collaborativeHighRiskRoutes...)
	// The scan persists JS resources asynchronously. A short bounded retry makes
	// the session wait for those writes without inventing frontend data.
	var resources []database.JSResource
	var apiRecords []database.APIResource
	for attempt := 0; attempt < 10; attempt++ {
		resources, _ = database.QueryJSByTaskID(session.TaskID)
		apiRecords, _ = database.QueryAPIResourcesByTaskID(session.TaskID)
		if len(resources) > 0 && len(apiRecords) > 0 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	session, err = loadCollaborativeSession(sessionID)
	if err != nil {
		return
	}
	if task, taskErr := database.QueryTaskByID(session.TaskID); taskErr == nil && task != nil && task.Status == "failed" {
		session.Status, session.Stage, session.Error = "failed", "failed", "scan task failed"
		completeCollaborativeProgress(session, collectingEventID, "failed", "扫描任务失败", "请检查目标可达性与服务端扫描日志。")
		appendCollaborativeProgress(session, "failed", "failed", "协同测试未完成", "扫描任务失败，未生成接口线索或测试结论。")
		_ = saveCollaborativeSession(session)
		return
	}
	completeCollaborativeProgress(session, collectingEventID, "completed", "已完成页面与请求采集", fmt.Sprintf("已保存 %d 个 JS 资源和 %d 条运行期请求记录。", len(resources), len(apiRecords)))
	session.Stage = "analyzing"
	analyzingEventID := appendCollaborativeProgress(session, "analyzing", "running", "正在解析 JS 并生成接口线索", "根据已保存的 JavaScript 和附件提取请求构造证据。")
	_ = saveCollaborativeSession(session)
	attachmentBlueprints := ingestCollaborativeAttachments(session)
	resources, _ = database.QueryJSByTaskID(session.TaskID)
	apiRecords, _ = database.QueryAPIResourcesByTaskID(session.TaskID)
	vulnerabilities, _ := database.QueryVulnsByTaskID(session.TaskID)
	traces, _ := database.QueryProtocolTracesByTaskID(session.TaskID)
	blueprints := append(crawl.BuildJSRequestBlueprints(resources), attachmentBlueprints...)
	endpointClues := buildCollaborativeEndpointClues(session.Target, blueprints)
	completeCollaborativeProgress(session, analyzingEventID, "completed", "已生成接口线索", fmt.Sprintf("从 %d 条原始请求构造证据中归并出 %d 个唯一接口。", len(blueprints), len(endpointClues)))
	riskEventID := appendCollaborativeProgress(session, "analyzing", "running", "正在进行风险分级与测试规划", "低风险检查将自动纳入扫描范围；高风险动作将等待人工决定。")
	_ = saveCollaborativeSession(session)
	actions := buildCollaborativeActions(blueprints)
	autoTested, notRunnable := 0, 0
	decisions := make([]collaborativeDecision, 0, len(blueprints))
	now := time.Now().UTC()
	for _, blueprint := range blueprints {
		if collaborativeRiskCategory(blueprint.Path) != "" {
			continue
		}
		decision := "auto-tested"
		reason := "已纳入真实扫描任务的安全范围自动检查。"
		if len(blueprint.UnresolvedSymbols) > 0 {
			decision, reason, notRunnable = "not-runnable", "请求含未解析的动态符号，未发送请求。", notRunnable+1
		} else {
			autoTested++
		}
		decisions = append(decisions, collaborativeDecision{ID: uuid.NewString(), Route: blueprint.Path, Method: blueprint.Method, Decision: decision, Reason: reason, Actor: "system", CreatedAt: now})
	}
	session.Status = "completed"
	session.Stage = "awaiting_approval"
	if len(actions) == 0 {
		session.Stage = "completed"
	}
	session.RequestBlueprints = blueprints
	session.EndpointClues = endpointClues
	session.TestResults = buildCollaborativeTestResults(apiRecords, vulnerabilities, traces)
	session.PendingRiskActions = actions
	session.TestDecisions = decisions
	session.Coverage = collaborativeCoverage{JSResources: len(resources), APIRoutesDiscovered: len(endpointClues), RequestBlueprintsExtracted: len(blueprints), AutoTested: autoTested, RuntimeRequests: countCollaborativeResults(session.TestResults, "runtime-request"), SecurityFindings: countCollaborativeResults(session.TestResults, "security-finding"), PendingReview: len(actions), NotRunnable: notRunnable}
	if len(actions) == 0 {
		completeCollaborativeProgress(session, riskEventID, "completed", "已完成自动测试规划", fmt.Sprintf("%d 个接口已纳入自动检查，未发现需要人工审批的高风险动作。", autoTested))
	} else {
		completeCollaborativeProgress(session, riskEventID, "waiting", "发现需要人工审批的高风险动作", fmt.Sprintf("已生成 %d 个待审批动作；在你批准前不会发送这些高风险请求。", len(actions)))
	}
	_ = saveCollaborativeSession(session)
}

func buildCollaborativeTestResults(apiRecords []database.APIResource, vulnerabilities []database.VulnRecord, traces []database.ProtocolTraceRecord) []collaborativeTestResult {
	traceIDs := make(map[string]struct{}, len(traces))
	for _, trace := range traces {
		if strings.TrimSpace(trace.TraceID) != "" {
			traceIDs[trace.TraceID] = struct{}{}
		}
	}
	result := make([]collaborativeTestResult, 0, len(apiRecords)+len(vulnerabilities))
	for _, record := range apiRecords {
		route := collaborativeRouteFromURL(record.URL)
		if route == "" {
			continue
		}
		_, hasTrace := traceIDs[record.TraceID]
		result = append(result, collaborativeTestResult{ID: uuid.NewString(), Route: route, Method: strings.ToUpper(record.Method), Kind: "runtime-request", Status: "recorded", StatusCode: record.ResponseCode, ResponseSize: len(record.ResponseBody), TraceID: record.TraceID, HasProtocolTrace: record.HasProtocolTrace && hasTrace, Summary: fmt.Sprintf("浏览器运行期真实请求已记录：HTTP %d，响应 %d B。", record.ResponseCode, len(record.ResponseBody)), CreatedAt: record.FetchedAt})
	}
	for _, vulnerability := range vulnerabilities {
		route := collaborativeRouteFromURL(vulnerability.URL)
		if route == "" {
			continue
		}
		result = append(result, collaborativeTestResult{ID: uuid.NewString(), Route: route, Method: strings.ToUpper(vulnerability.Method), Kind: "security-finding", Status: "finding", RiskLevel: vulnerability.Level, Summary: fmt.Sprintf("自动安全检测发现：%s。", vulnerability.Title), CreatedAt: vulnerability.CreatedAt})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].CreatedAt.After(result[right].CreatedAt) })
	return result
}

func collaborativeRouteFromURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return ""
	}
	if parsed.Path == "" {
		return "/"
	}
	return parsed.Path
}

func countCollaborativeResults(results []collaborativeTestResult, kind string) int {
	count := 0
	for _, result := range results {
		if result.Kind == kind {
			count++
		}
	}
	return count
}

func buildCollaborativeActions(blueprints []crawl.RequestBlueprint) []collaborativeAction {
	result := make([]collaborativeAction, 0)
	for _, blueprint := range blueprints {
		category := collaborativeRiskCategory(blueprint.Path)
		if category == "" {
			continue
		}
		result = append(result, collaborativeAction{ID: uuid.NewString(), BlueprintID: blueprint.ID, Route: blueprint.Path, Method: blueprint.Method, RiskLevel: "high", ActionType: category, Reason: "匹配高风险业务动作规则：" + category, RiskHypotheses: collaborativeHypotheses(category), SuggestedNextStep: "先查看 Dry-run；只在授权测试环境中批准重放。", Requirements: []string{"explicit human approval", "test environment", "test identity", "audit trail"}, Decision: "pending", RequestPreview: blueprint})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Route < result[right].Route })
	return result
}

func collaborativeRiskCategory(route string) string {
	value := strings.ToLower(route)
	switch {
	case strings.Contains(value, "sms") || strings.Contains(value, "sendcode"):
		return "sms-action"
	case strings.Contains(value, "upload"):
		return "file-upload-action"
	case strings.Contains(value, "login") || strings.Contains(value, "logout") || strings.Contains(value, "token"):
		return "auth-session-action"
	case strings.Contains(value, "pay") || strings.Contains(value, "order"):
		return "payment-action"
	case strings.Contains(value, "save") || strings.Contains(value, "submit") || strings.Contains(value, "apply") || strings.Contains(value, "delete") || strings.Contains(value, "remove") || strings.Contains(value, "update") || strings.Contains(value, "modify"):
		return "state-changing-action"
	default:
		return ""
	}
}

func collaborativeHypotheses(category string) []string {
	switch category {
	case "sms-action":
		return []string{"短信发送对象篡改", "频率限制缺失"}
	case "file-upload-action":
		return []string{"文件类型校验", "文件存储隔离"}
	case "auth-session-action":
		return []string{"会话固定", "认证绕过"}
	case "payment-action":
		return []string{"支付金额篡改", "重复订单"}
	default:
		return []string{"越权业务操作", "参数篡改", "重复提交"}
	}
}

func normalizeCollaborativeTarget(value string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(value))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("target must be a valid http(s) URL")
	}
	return parsed, nil
}

func collaborativeRequestInputs(c *gin.Context) (string, []*multipart.FileHeader, error) {
	if strings.HasPrefix(c.GetHeader("Content-Type"), "multipart/form-data") {
		if err := c.Request.ParseMultipartForm(int64(maxCollaborativeAttachmentSize * maxCollaborativeAttachments)); err != nil {
			return "", nil, fmt.Errorf("invalid multipart request")
		}
		files := c.Request.MultipartForm.File["attachments"]
		if err := validateCollaborativeAttachmentHeaders(files); err != nil {
			return "", nil, err
		}
		return c.PostForm("target"), files, nil
	}
	var body struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		return "", nil, fmt.Errorf("invalid json")
	}
	return body.Target, nil, nil
}

func validateCollaborativeAttachmentHeaders(files []*multipart.FileHeader) error {
	if len(files) > maxCollaborativeAttachments {
		return fmt.Errorf("at most %d attachments are allowed", maxCollaborativeAttachments)
	}
	for _, file := range files {
		if file == nil || file.Size > maxCollaborativeAttachmentSize {
			return fmt.Errorf("each attachment must be at most %d MB", maxCollaborativeAttachmentSize>>20)
		}
		if collaborativeAttachmentKind(file.Filename) == "" {
			return fmt.Errorf("unsupported attachment: %s", filepath.Base(file.Filename))
		}
	}
	return nil
}

func persistCollaborativeAttachments(sessionID string, files []*multipart.FileHeader) ([]collaborativeAttachment, error) {
	if len(files) == 0 {
		return []collaborativeAttachment{}, nil
	}
	directory := filepath.Join(collaborativeAttachmentDirectory, sessionID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("failed to prepare attachment storage")
	}
	attachments := make([]collaborativeAttachment, 0, len(files))
	for _, file := range files {
		kind := collaborativeAttachmentKind(file.Filename)
		id := uuid.NewString()
		path := filepath.Join(directory, id+strings.ToLower(filepath.Ext(file.Filename)))
		source, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("failed to read attachment %s", filepath.Base(file.Filename))
		}
		destination, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			source.Close()
			return nil, fmt.Errorf("failed to save attachment")
		}
		written, copyErr := io.Copy(destination, io.LimitReader(source, maxCollaborativeAttachmentSize+1))
		closeErr := destination.Close()
		source.Close()
		if copyErr != nil || closeErr != nil || written > maxCollaborativeAttachmentSize {
			_ = os.Remove(path)
			return nil, fmt.Errorf("failed to save attachment %s", filepath.Base(file.Filename))
		}
		attachments = append(attachments, collaborativeAttachment{ID: id, Name: filepath.Base(file.Filename), Size: written, Kind: kind, Status: "uploaded", StorageKey: filepath.Base(path), Path: path})
	}
	return attachments, nil
}

func collaborativeAttachmentKind(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".har":
		return "har"
	case ".js":
		return "javascript"
	case ".json", ".yaml", ".yml":
		return "api-document"
	case ".txt", ".md":
		return "test-context"
	case ".zip":
		return "archive"
	default:
		return ""
	}
}

func ingestCollaborativeAttachments(session *collaborativeSession) []crawl.RequestBlueprint {
	if session == nil || len(session.Attachments) == 0 {
		return nil
	}
	version := 0
	if latest, err := database.GetLatestTaskVersion(session.TaskID); err == nil && latest != nil {
		version = latest.Version
	}
	if version <= 0 {
		return nil
	}
	blueprints := make([]crawl.RequestBlueprint, 0)
	for index := range session.Attachments {
		attachment := &session.Attachments[index]
		attachment.Path = filepath.Join(collaborativeAttachmentDirectory, session.ID, attachment.StorageKey)
		if attachment.Kind == "test-context" {
			attachment.Status, attachment.Detail = "available", "已保存为人工测试上下文。"
			continue
		}
		payloads, err := collaborativeAttachmentPayloads(*attachment)
		if err != nil {
			attachment.Status, attachment.Detail = "failed", err.Error()
			continue
		}
		if len(payloads) == 0 {
			attachment.Status, attachment.Detail = "available", "未提取到可分析的 HAR、OpenAPI 或 JS 内容。"
			continue
		}
		attachment.Status, attachment.Detail = "analyzed", "已纳入本次协同测试分析。"
		for _, payload := range payloads {
			switch collaborativeAttachmentKind(payload.name) {
			case "javascript":
				_ = database.SaveJSResource(database.JSResource{TaskID: session.TaskID, Version: version, URL: "attachment://" + attachment.ID + "/" + payload.name, Content: string(payload.data), ResponseCode: http.StatusOK, Size: len(payload.data), FetchedAt: time.Now().UTC()})
			case "har":
				for _, record := range collaborativeHARRecords(session.TaskID, version, payload.data) {
					_ = database.SaveAPIResource(record)
				}
			case "api-document":
				blueprints = append(blueprints, collaborativeOpenAPIBlueprints(payload.name, payload.data)...)
			}
		}
	}
	return blueprints
}

type collaborativeAttachmentPayload struct {
	name string
	data []byte
}

func collaborativeAttachmentPayloads(attachment collaborativeAttachment) ([]collaborativeAttachmentPayload, error) {
	data, err := os.ReadFile(attachment.Path)
	if err != nil {
		return nil, fmt.Errorf("attachment file is unavailable")
	}
	if attachment.Kind != "archive" {
		return []collaborativeAttachmentPayload{{name: attachment.Name, data: data}}, nil
	}
	reader, err := zip.OpenReader(attachment.Path)
	if err != nil {
		return nil, fmt.Errorf("invalid zip attachment")
	}
	defer reader.Close()
	payloads := make([]collaborativeAttachmentPayload, 0)
	for _, file := range reader.File {
		if len(payloads) >= maxCollaborativeAttachments || file.FileInfo().IsDir() || file.UncompressedSize64 > maxCollaborativeAttachmentSize || collaborativeAttachmentKind(file.Name) == "" || collaborativeAttachmentKind(file.Name) == "archive" {
			continue
		}
		stream, openErr := file.Open()
		if openErr != nil {
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(stream, maxCollaborativeAttachmentSize+1))
		stream.Close()
		if readErr == nil && len(content) <= maxCollaborativeAttachmentSize {
			payloads = append(payloads, collaborativeAttachmentPayload{name: filepath.Base(file.Name), data: content})
		}
	}
	return payloads, nil
}

func collaborativeHARRecords(taskID string, version int, data []byte) []database.APIResource {
	var document struct {
		Log struct {
			Entries []struct {
				StartedDateTime time.Time `json:"startedDateTime"`
				Request         struct {
					URL      string `json:"url"`
					Method   string `json:"method"`
					PostData struct {
						Text string `json:"text"`
					} `json:"postData"`
				} `json:"request"`
				Response struct {
					Status  int `json:"status"`
					Content struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if json.Unmarshal(data, &document) != nil {
		return nil
	}
	result := make([]database.APIResource, 0, len(document.Log.Entries))
	for _, entry := range document.Log.Entries {
		if _, err := url.ParseRequestURI(entry.Request.URL); err != nil || entry.Request.Method == "" {
			continue
		}
		fetchedAt := entry.StartedDateTime
		if fetchedAt.IsZero() {
			fetchedAt = time.Now().UTC()
		}
		result = append(result, database.APIResource{TaskID: taskID, Version: version, URL: entry.Request.URL, Method: strings.ToUpper(entry.Request.Method), RequestBody: entry.Request.PostData.Text, ResponseBody: entry.Response.Content.Text, ResponseCode: entry.Response.Status, FetchedAt: fetchedAt})
	}
	return result
}

func collaborativeOpenAPIBlueprints(name string, data []byte) []crawl.RequestBlueprint {
	var document struct {
		Paths map[string]map[string]any `json:"paths" yaml:"paths"`
	}
	if json.Unmarshal(data, &document) != nil && yaml.Unmarshal(data, &document) != nil {
		return nil
	}
	result := make([]crawl.RequestBlueprint, 0)
	for path, operations := range document.Paths {
		for method := range operations {
			method = strings.ToUpper(method)
			if method != http.MethodGet && method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete && method != http.MethodHead {
				continue
			}
			result = append(result, crawl.RequestBlueprint{ID: uuid.NewString(), Path: path, Method: method, Confidence: "high", ConfidenceReason: "OpenAPI attachment", ExtractionSource: "openapi-attachment", Source: crawl.RequestBlueprintSource{File: name, Snippet: "OpenAPI path definition"}})
		}
	}
	return result
}

func uniqueCollaborativeRoutes(blueprints []crawl.RequestBlueprint) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(blueprints))
	for _, blueprint := range blueprints {
		key := strings.ToUpper(blueprint.Method) + " " + blueprint.Path
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, key)
		}
	}
	return result
}

func buildCollaborativeEndpointClues(target string, blueprints []crawl.RequestBlueprint) []collaborativeEndpointClue {
	clues := make([]collaborativeEndpointClue, 0, len(blueprints))
	index := make(map[string]int, len(blueprints))
	for _, blueprint := range blueprints {
		path := strings.TrimSpace(blueprint.Path)
		method := strings.ToUpper(strings.TrimSpace(blueprint.Method))
		if path == "" || method == "" {
			continue
		}
		key := collaborativeEndpointKey(target, method, path)
		if existing, ok := index[key]; ok {
			clue := &clues[existing]
			clue.Evidence = appendCollaborativeEndpointEvidence(clue.Evidence, blueprint)
			clue.UnresolvedSymbols = appendUniqueCollaborativeStrings(clue.UnresolvedSymbols, blueprint.UnresolvedSymbols...)
			if collaborativeBlueprintConfidenceRank(blueprint.Confidence) > collaborativeBlueprintConfidenceRank(clue.Confidence) {
				clue.Confidence = blueprint.Confidence
				clue.Representative = blueprint
			}
			continue
		}
		index[key] = len(clues)
		clues = append(clues, collaborativeEndpointClue{
			ID:                uuid.NewSHA1(uuid.Nil, []byte(key)).String(),
			Path:              path,
			Method:            method,
			Confidence:        blueprint.Confidence,
			UnresolvedSymbols: append([]string(nil), blueprint.UnresolvedSymbols...),
			Representative:    blueprint,
			Evidence:          appendCollaborativeEndpointEvidence(nil, blueprint),
		})
	}
	sort.SliceStable(clues, func(left, right int) bool {
		if clues[left].Path == clues[right].Path {
			return clues[left].Method < clues[right].Method
		}
		return clues[left].Path < clues[right].Path
	})
	return clues
}

func collaborativeEndpointKey(target, method, path string) string {
	resolved, err := resolveCollaborativeReplayURL(target, path)
	if err == nil {
		resolved.Fragment = ""
		resolved.RawQuery = ""
		resolved.Path = strings.TrimRight(resolved.EscapedPath(), "/")
		if resolved.Path == "" {
			resolved.Path = "/"
		}
		return method + "\x00" + strings.ToLower(resolved.Scheme) + "://" + strings.ToLower(resolved.Host) + resolved.Path
	}
	return method + "\x00" + strings.TrimRight(path, "/")
}

func appendCollaborativeEndpointEvidence(items []collaborativeEndpointEvidence, blueprint crawl.RequestBlueprint) []collaborativeEndpointEvidence {
	evidence := collaborativeEndpointEvidence{File: strings.TrimSpace(blueprint.Source.File), Snippet: strings.TrimSpace(blueprint.Source.Snippet), Client: strings.TrimSpace(blueprint.Client), BaseURL: strings.TrimSpace(blueprint.BaseURL)}
	key := strings.Join([]string{evidence.File, evidence.Snippet, evidence.Client, evidence.BaseURL}, "\x00")
	for _, item := range items {
		if key == strings.Join([]string{item.File, item.Snippet, item.Client, item.BaseURL}, "\x00") {
			return items
		}
	}
	return append(items, evidence)
}

func appendUniqueCollaborativeStrings(items []string, values ...string) []string {
	seen := make(map[string]struct{}, len(items)+len(values))
	result := make([]string, 0, len(items)+len(values))
	for _, value := range append(items, values...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func collaborativeBlueprintConfidenceRank(value string) int {
	switch value {
	case "high":
		return 3
	case "medium":
		return 2
	default:
		return 1
	}
}

func isCollaborativeDecision(value string) bool {
	return value == "skipped" || value == "dry-run" || value == "authorized-replay" || value == "more-analysis" || value == "false-positive"
}

func decisionTagLabel(decision string) string {
	switch decision {
	case "skipped":
		return "已跳过"
	case "dry-run":
		return "Dry-run"
	case "authorized-replay":
		return "已授权"
	case "more-analysis":
		return "继续分析"
	case "false-positive":
		return "误报"
	default:
		return decision
	}
}

func collaborativeDecisionNote(decision, note, environment, identity, scope string) string {
	if strings.TrimSpace(note) != "" {
		return strings.TrimSpace(note)
	}
	if decision == "authorized-replay" {
		return fmt.Sprintf("批准范围：%s；测试环境：%s；测试身份：%s。", strings.TrimSpace(scope), strings.TrimSpace(environment), strings.TrimSpace(identity))
	}
	if decision == "dry-run" {
		return "已生成真实请求蓝图预览，未发送请求。"
	}
	return decision
}

func resolveCollaborativeReplayURL(target, path string) (*url.URL, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid session target")
	}
	endpoint, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid request blueprint path")
	}
	if endpoint.IsAbs() {
		return endpoint, nil
	}
	return base.ResolveReference(endpoint), nil
}

func configuredReplayHosts() ([]string, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var value config.ConfigYAML
	if err := yaml.Unmarshal(data, &value); err != nil {
		return nil, err
	}
	return value.Collaborative.AllowedReplayHosts, nil
}

func isCollaborativeReplayHostAllowed(host string, allowed []string) bool {
	for _, item := range allowed {
		if strings.EqualFold(strings.TrimSpace(item), strings.TrimSpace(host)) {
			return true
		}
	}
	return false
}

func countPendingCollaborativeActions(actions []collaborativeAction) int {
	count := 0
	for _, action := range actions {
		if action.Decision == "pending" {
			count++
		}
	}
	return count
}

func appendCollaborativeProgress(session *collaborativeSession, stage, state, title, detail string) string {
	if session == nil {
		return ""
	}
	event := collaborativeProgressEvent{ID: uuid.NewString(), Stage: stage, State: state, Title: title, Detail: detail, CreatedAt: time.Now().UTC()}
	session.Timeline = append(session.Timeline, event)
	return event.ID
}

func completeCollaborativeProgress(session *collaborativeSession, eventID, state, title, detail string) {
	if session == nil || strings.TrimSpace(eventID) == "" {
		return
	}
	for index := len(session.Timeline) - 1; index >= 0; index-- {
		if session.Timeline[index].ID != eventID {
			continue
		}
		session.Timeline[index].State = state
		session.Timeline[index].Title = title
		session.Timeline[index].Detail = detail
		return
	}
}

func subscribeCollaborativeSession(sessionID string) (collaborativeSessionSubscriber, func()) {
	subscriber := make(collaborativeSessionSubscriber, 8)
	collaborativeSessionStream.Lock()
	if collaborativeSessionStream.subscribers[sessionID] == nil {
		collaborativeSessionStream.subscribers[sessionID] = make(map[collaborativeSessionSubscriber]struct{})
	}
	collaborativeSessionStream.subscribers[sessionID][subscriber] = struct{}{}
	collaborativeSessionStream.Unlock()
	return subscriber, func() {
		collaborativeSessionStream.Lock()
		defer collaborativeSessionStream.Unlock()
		subscribers := collaborativeSessionStream.subscribers[sessionID]
		delete(subscribers, subscriber)
		if len(subscribers) == 0 {
			delete(collaborativeSessionStream.subscribers, sessionID)
		}
	}
}

func publishCollaborativeSession(session *collaborativeSession) {
	if session == nil {
		return
	}
	collaborativeSessionStream.RLock()
	defer collaborativeSessionStream.RUnlock()
	for subscriber := range collaborativeSessionStream.subscribers[session.ID] {
		select {
		case subscriber <- session:
		default:
			// A slow browser should receive the next full session snapshot instead
			// of blocking the scan or accumulating an unbounded event backlog.
		}
	}
}

func saveCollaborativeSession(session *collaborativeSession) error {
	if session == nil {
		return fmt.Errorf("session is required")
	}
	session.UpdatedAt = time.Now().UTC()
	if err := database.SaveJSONDocument(collaborativeSessionDocument, session.ID, 0, "latest", session.UpdatedAt, session); err != nil {
		return err
	}
	publishCollaborativeSession(session)
	return nil
}

func loadCollaborativeSession(sessionID string) (*collaborativeSession, error) {
	documents, err := database.LoadJSONDocuments(collaborativeSessionDocument, sessionID, nil, 1)
	if err != nil || len(documents) == 0 {
		return nil, fmt.Errorf("session not found")
	}
	var session collaborativeSession
	if err := json.Unmarshal(documents[0], &session); err != nil {
		return nil, err
	}
	return &session, nil
}

package web

import (
	"database/sql"
	"encoding/json"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var captureBrowserSessionNetworkActivity = crawl.CaptureNetworkActivityWithOptions

func getBrowserSessions(c *gin.Context) {
	page := 1
	size := 10
	if value, err := strconv.Atoi(c.DefaultQuery("page", "1")); err == nil && value > 0 {
		page = value
	}
	if value, err := strconv.Atoi(c.DefaultQuery("size", "10")); err == nil && value > 0 && value <= 100 {
		size = value
	}

	filters := database.BrowserSessionListFilters{
		Keyword:  strings.TrimSpace(c.Query("keyword")),
		Status:   strings.TrimSpace(c.Query("status")),
		SiteHost: strings.TrimSpace(c.Query("siteHost")),
	}

	records, total, err := database.ListBrowserSessions(page, size, filters)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query browser sessions", "detail": err.Error()})
		return
	}

	totalPages := (total + size - 1) / size
	if totalPages == 0 {
		totalPages = 1
	}

	c.JSON(http.StatusOK, gin.H{
		"data": records,
		"pagination": map[string]any{
			"page":       page,
			"size":       size,
			"total":      total,
			"totalPages": totalPages,
			"hasNext":    page < totalPages,
			"hasPrev":    page > 1,
		},
	})
}

func getBrowserSessionDetail(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Param("sessionId"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sessionId is required"})
		return
	}

	session, err := database.GetBrowserSessionByID(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query browser session", "detail": err.Error()})
		return
	}
	if session == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "browser session not found"})
		return
	}

	pages, err := database.ListBrowserPagesBySessionID(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query browser pages", "detail": err.Error()})
		return
	}
	requests, err := database.ListBrowserSessionRequests(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query browser session requests", "detail": err.Error()})
		return
	}
	suspiciousTraces, err := database.ListBrowserSessionTraces(sessionID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to query browser session traces", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"session":          session,
			"pages":            pages,
			"requests":         requests,
			"suspiciousTraces": suspiciousTraces,
		},
	})
}

func deleteBrowserSession(c *gin.Context) {
	sessionID := strings.TrimSpace(c.Param("sessionId"))
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "sessionId is required"})
		return
	}

	if err := database.DeleteBrowserSession(sessionID); err != nil {
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "browser session not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete browser session", "detail": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "browser session deleted successfully"})
}

func launchBrowserSession(c *gin.Context) {
	var body struct {
		TargetURL              string `json:"targetUrl"`
		Mode                   string `json:"mode"`
		BrowserVisible         *bool  `json:"browserVisible"`
		ProxyServer            string `json:"proxyServer"`
		ProxyBypassList        string `json:"proxyBypassList"`
		ProxyType              string `json:"proxyType"`
		CaptureDurationSeconds int    `json:"captureDurationSeconds"`
		TimeoutSeconds         int    `json:"timeoutSeconds"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid json", "detail": err.Error()})
		return
	}

	targetURL := strings.TrimSpace(body.TargetURL)
	parsedURL, err := url.Parse(targetURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid targetUrl"})
		return
	}

	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		mode = "manual"
	}
	browserVisible := true
	if body.BrowserVisible != nil {
		browserVisible = *body.BrowserVisible
	}
	captureDurationSeconds := body.CaptureDurationSeconds
	if captureDurationSeconds < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "captureDurationSeconds must be >= 0"})
		return
	}
	if captureDurationSeconds != 0 && captureDurationSeconds <= 0 {
		captureDurationSeconds = 90
	}
	timeoutSeconds := body.TimeoutSeconds
	if captureDurationSeconds == 0 {
		timeoutSeconds = 0
	} else if timeoutSeconds <= captureDurationSeconds+10 {
		timeoutSeconds = captureDurationSeconds + 30
	}

	sessionID := uuid.NewString()
	startedAt := time.Now()
	proxyServer := strings.TrimSpace(body.ProxyServer)
	proxyType := strings.TrimSpace(body.ProxyType)
	if proxyType == "" {
		proxyType = inferProxyType(proxyServer)
	}

	record, err := database.CreateBrowserSession(database.BrowserSessionRecord{
		SessionID:      sessionID,
		SiteHost:       parsedURL.Host,
		EntryURL:       targetURL,
		Status:         "running",
		Mode:           mode,
		BrowserMode:    "chromedp",
		ProxyType:      proxyType,
		ProxyAddress:   proxyServer,
		BrowserVisible: browserVisible,
		PageCount:      1,
		StartedAt:      startedAt,
		LastActivityAt: startedAt,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create browser session", "detail": err.Error()})
		return
	}

	if err := database.UpsertBrowserPage(database.BrowserPageRecord{
		PageID:     sessionID + "-page-1",
		SessionID:  sessionID,
		URL:        targetURL,
		Title:      parsedURL.Host,
		IsEntry:    true,
		CreatedAt:  startedAt,
		LastSeenAt: startedAt,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create browser page", "detail": err.Error()})
		return
	}

	captureOptions := crawl.CaptureOptions{
		InitialWait:     2 * time.Second,
		BrowserVisible:  browserVisible,
		ProxyServer:     proxyServer,
		ProxyBypassList: strings.TrimSpace(body.ProxyBypassList),
	}
	if captureDurationSeconds == 0 {
		captureOptions.Timeout = 0
		captureOptions.PostInteractionWait = 0
	} else {
		captureOptions.Timeout = time.Duration(timeoutSeconds) * time.Second
		captureOptions.PostInteractionWait = time.Duration(captureDurationSeconds) * time.Second
	}

	go runLaunchedBrowserSession(record, captureOptions)

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"sessionId": record.SessionID,
			"status":    record.Status,
			"siteHost":  record.SiteHost,
			"entryUrl":  record.EntryURL,
			"keepOpen":  captureDurationSeconds == 0,
		},
	})
}

func runLaunchedBrowserSession(record *database.BrowserSessionRecord, options crawl.CaptureOptions) {
	if record == nil {
		return
	}

	startedAt := record.StartedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}

	options.OnUpdate = func(snapshot crawl.CaptureSnapshot) {
		persistBrowserSessionSnapshot(record, startedAt, snapshot, "running", time.Time{})
	}
	_, apiRecords, traces, frontendRoutes := captureBrowserSessionNetworkActivity(record.EntryURL, options)
	finishedAt := time.Now()
	persistBrowserSessionSnapshot(record, startedAt, crawl.CaptureSnapshot{
		APIRecords:     apiRecords,
		ProtocolTraces: traces,
		FrontendRoutes: frontendRoutes,
		CapturedAt:     finishedAt,
	}, "completed", finishedAt)
}

func persistBrowserSessionSnapshot(record *database.BrowserSessionRecord, startedAt time.Time, snapshot crawl.CaptureSnapshot, status string, endedAt time.Time) {
	if record == nil {
		return
	}
	if snapshot.CapturedAt.IsZero() {
		snapshot.CapturedAt = time.Now()
	}

	suspiciousTraces := buildSuspiciousBrowserSessionTraces(record.SessionID, snapshot.ProtocolTraces, snapshot.APIRecords)
	requestHistory := buildBrowserSessionRequestHistory(record.SessionID, snapshot.APIRecords, suspiciousTraces)
	_ = database.UpsertBrowserPage(database.BrowserPageRecord{
		PageID:     record.SessionID + "-page-1",
		SessionID:  record.SessionID,
		URL:        record.EntryURL,
		Title:      record.SiteHost,
		IsEntry:    true,
		CreatedAt:  startedAt,
		LastSeenAt: snapshot.CapturedAt,
	})
	_ = database.ReplaceBrowserSessionRequests(record.SessionID, requestHistory)
	_ = database.ReplaceBrowserSessionTraces(record.SessionID, suspiciousTraces)
	_ = database.UpdateBrowserSessionMetrics(
		record.SessionID,
		1,
		len(snapshot.APIRecords),
		countSuspiciousTraceSignals(snapshot.ProtocolTraces, snapshot.APIRecords),
		status,
		snapshot.CapturedAt,
		endedAt,
	)
}

func inferProxyType(proxyServer string) string {
	proxyServer = strings.TrimSpace(strings.ToLower(proxyServer))
	switch {
	case proxyServer == "":
		return "none"
	case strings.HasPrefix(proxyServer, "socks5://"):
		return "socks5"
	case strings.HasPrefix(proxyServer, "https://"):
		return "https"
	case strings.HasPrefix(proxyServer, "http://"):
		return "http"
	default:
		return "custom"
	}
}

func countSuspiciousTraceSignals(traces []crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) int {
	count := 0
	for _, trace := range traces {
		if hasMeaningfulBrowserSessionTraceSignal(trace, apiRecords) {
			count++
		}
	}
	return count
}

func buildSuspiciousBrowserSessionTraces(sessionID string, traces []crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) []database.BrowserSessionTraceRecord {
	rsaPublicKey, rsaPublicKeySource := findBrowserSessionRSAPublicKey(traces, apiRecords)
	result := make([]database.BrowserSessionTraceRecord, 0)
	for _, trace := range traces {
		if !hasMeaningfulBrowserSessionTraceSignal(trace, apiRecords) {
			continue
		}

		responsePlaintext, responseCiphertext := resolveBrowserSessionTraceResponse(trace, apiRecords)
		algorithms := filterMeaningfulBrowserSessionAlgorithms(trace.Algorithms)
		sessionMaterials := cloneBrowserSessionTraceMaterials(trace.SessionMaterials)
		enrichBrowserSessionTraceMaterials(sessionMaterials, trace, responsePlaintext, rsaPublicKey, rsaPublicKeySource)
		reason := "命中协议链路信号"
		if len(algorithms) > 0 {
			reason = "命中算法: " + strings.Join(algorithms, ", ")
		}

		result = append(result, database.BrowserSessionTraceRecord{
			SessionID:              sessionID,
			TraceID:                strings.TrimSpace(trace.TraceID),
			RequestURL:             strings.TrimSpace(trace.RequestURL),
			Method:                 strings.TrimSpace(trace.Method),
			Algorithms:             algorithms,
			RequestBeforeTransform: strings.TrimSpace(trace.RequestBeforeTransform),
			FinalRequestBody:       strings.TrimSpace(trace.FinalRequestBody),
			RequestSteps:           convertBrowserSessionTraceSteps(trace.RequestSteps),
			ResponseSteps:          convertBrowserSessionTraceSteps(trace.ResponseSteps),
			SessionMaterials:       sessionMaterials,
			ResponsePlaintext:      responsePlaintext,
			ResponseCiphertext:     responseCiphertext,
			SuspiciousReason:       reason,
			CreatedAt:              trace.CreatedAt,
		})
	}
	return result
}

func buildBrowserSessionRequestHistory(sessionID string, apiRecords []crawl.NetworkRecord, suspiciousTraces []database.BrowserSessionTraceRecord) []database.BrowserSessionRequestRecord {
	result := make([]database.BrowserSessionRequestRecord, 0, len(apiRecords))
	for _, record := range apiRecords {
		matchedTrace := findBrowserSessionSuspiciousTraceForRequest(record, suspiciousTraces)
		result = append(result, database.BrowserSessionRequestRecord{
			SessionID:        sessionID,
			TraceID:          strings.TrimSpace(record.TraceID),
			URL:              strings.TrimSpace(record.URL),
			Method:           strings.TrimSpace(record.Method),
			ResourceType:     strings.TrimSpace(record.ResourceType),
			RequestHeaders:   cloneBrowserSessionStringMap(record.RequestHeaders),
			RequestBody:      strings.TrimSpace(record.RequestBody),
			ResponseHeaders:  cloneBrowserSessionStringMap(record.ResponseHeaders),
			ResponseBody:     strings.TrimSpace(record.ResponseBody),
			ResponseCode:     record.ResponseCode,
			MIMEType:         strings.TrimSpace(record.MIMEType),
			HasProtocolTrace: record.HasProtocolTrace,
			IsSuspicious:     matchedTrace != nil,
			CreatedAt:        record.FetchedAt,
		})
		if matchedTrace != nil {
			result[len(result)-1].SuspiciousTrace = strings.TrimSpace(matchedTrace.SuspiciousReason)
		}
	}
	return result
}

func findBrowserSessionSuspiciousTraceForRequest(record crawl.NetworkRecord, suspiciousTraces []database.BrowserSessionTraceRecord) *database.BrowserSessionTraceRecord {
	traceID := strings.TrimSpace(record.TraceID)
	method := strings.ToUpper(strings.TrimSpace(record.Method))
	url := strings.TrimSpace(record.URL)
	body := strings.TrimSpace(record.RequestBody)

	if traceID != "" {
		for idx := range suspiciousTraces {
			if strings.TrimSpace(suspiciousTraces[idx].TraceID) == traceID {
				return &suspiciousTraces[idx]
			}
		}
	}

	var fallback *database.BrowserSessionTraceRecord
	for idx := range suspiciousTraces {
		trace := &suspiciousTraces[idx]
		if strings.ToUpper(strings.TrimSpace(trace.Method)) != method {
			continue
		}
		if strings.TrimSpace(trace.RequestURL) != url {
			continue
		}
		if body != "" && strings.TrimSpace(trace.FinalRequestBody) == body {
			return trace
		}
		if fallback == nil {
			fallback = trace
		}
	}
	return fallback
}

func hasMeaningfulBrowserSessionTraceSignal(trace crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) bool {
	if hasPlaintextOnlyBrowserSessionMaterials(trace) && !hasExplicitBrowserSessionCryptoSignal(trace) {
		return false
	}
	if isPlaintextOnlyBrowserSessionResponse(trace, apiRecords) && !hasExplicitBrowserSessionCryptoSignal(trace) {
		return false
	}
	if len(filterMeaningfulBrowserSessionAlgorithms(trace.Algorithms)) > 0 {
		return true
	}
	for _, step := range append(append([]crawl.ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		if isMeaningfulBrowserSessionStep(step) {
			return true
		}
	}
	return false
}

func filterMeaningfulBrowserSessionAlgorithms(algorithms []string) []string {
	filtered := make([]string, 0, len(algorithms))
	seen := make(map[string]bool, len(algorithms))
	for _, algorithm := range algorithms {
		normalized := strings.ToLower(strings.TrimSpace(algorithm))
		if normalized == "" || isIgnorableBrowserSessionAlgorithm(normalized) || seen[normalized] {
			continue
		}
		seen[normalized] = true
		filtered = append(filtered, strings.TrimSpace(algorithm))
	}
	return filtered
}

func isMeaningfulBrowserSessionStep(step crawl.ProtocolCryptoStep) bool {
	source := strings.ToLower(strings.TrimSpace(step.Source))
	algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))
	if isIgnorableBrowserSessionAlgorithm(source) && isIgnorableBrowserSessionAlgorithm(algorithm) {
		return false
	}
	if strings.Contains(source, "encrypt") || strings.Contains(source, "decrypt") || strings.Contains(source, "sign") {
		return true
	}
	if strings.Contains(algorithm, "encrypt") || strings.Contains(algorithm, "decrypt") || strings.Contains(algorithm, "sign") {
		return true
	}
	for _, token := range []string{"rsa", "sm2", "sm3", "sm4", "aes", "des", "tripledes", "rc4", "rabbit", "hmac", "sha", "md5"} {
		if strings.Contains(source, token) || strings.Contains(algorithm, token) {
			return true
		}
	}
	return false
}

func isIgnorableBrowserSessionAlgorithm(value string) bool {
	switch strings.TrimSpace(value) {
	case "",
		"json.parse",
		"json.stringify",
		"json.parse(inferred)",
		"json.stringify(inferred)",
		"json.parse()",
		"json.stringify()",
		"base64-encoded-payload",
		"hex-encoded-payload",
		"encrypted-field(inferred)":
		return true
	default:
		return false
	}
}

func hasExplicitBrowserSessionCryptoSignal(trace crawl.ProtocolTraceRecord) bool {
	if len(filterMeaningfulBrowserSessionAlgorithms(trace.Algorithms)) > 0 {
		return true
	}
	for _, step := range append(append([]crawl.ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		if isMeaningfulBrowserSessionStep(step) {
			return true
		}
	}
	return false
}

func hasPlaintextOnlyBrowserSessionMaterials(trace crawl.ProtocolTraceRecord) bool {
	if len(trace.SessionMaterials) == 0 {
		return false
	}
	hasPlaintext := false
	for key, value := range trace.SessionMaterials {
		normalizedKey := strings.TrimSpace(key)
		normalizedValue := strings.TrimSpace(value)
		if normalizedValue == "" {
			continue
		}
		switch normalizedKey {
		case "latest_response_plaintext":
			hasPlaintext = true
		default:
			return false
		}
	}
	return hasPlaintext
}

func isPlaintextOnlyBrowserSessionResponse(trace crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) bool {
	responsePlaintext, responseCiphertext := resolveBrowserSessionTraceResponse(trace, apiRecords)
	if strings.TrimSpace(responsePlaintext) == "" || strings.TrimSpace(responseCiphertext) != "" {
		return false
	}
	return len(trace.ResponseSteps) == 0
}

func resolveBrowserSessionTraceResponse(trace crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) (string, string) {
	if record, ok := findMatchingBrowserSessionAPIRecord(trace, apiRecords); ok {
		responseBody := strings.TrimSpace(record.ResponseBody)
		if responseBody != "" {
			return responseBody, ""
		}
	}

	return strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]),
		strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"])
}

func convertBrowserSessionTraceSteps(steps []crawl.ProtocolCryptoStep) []database.ProtocolCryptoStep {
	if len(steps) == 0 {
		return nil
	}
	converted := make([]database.ProtocolCryptoStep, 0, len(steps))
	for _, step := range steps {
		converted = append(converted, database.ProtocolCryptoStep{
			Source:        strings.TrimSpace(step.Source),
			Algorithm:     strings.TrimSpace(step.Algorithm),
			InputPreview:  strings.TrimSpace(step.InputPreview),
			OutputPreview: strings.TrimSpace(step.OutputPreview),
			CallID:        strings.TrimSpace(step.CallID),
			ParentCallID:  strings.TrimSpace(step.ParentCallID),
			FunctionPath:  strings.TrimSpace(step.FunctionPath),
			ModuleID:      strings.TrimSpace(step.ModuleID),
			Stack:         strings.TrimSpace(step.Stack),
			CapturedAtMS:  step.CapturedAtMS,
		})
	}
	return converted
}

func cloneBrowserSessionStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func cloneBrowserSessionTraceMaterials(materials map[string]string) map[string]string {
	if len(materials) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(materials))
	for key, value := range materials {
		cloned[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return cloned
}

func enrichBrowserSessionTraceMaterials(materials map[string]string, trace crawl.ProtocolTraceRecord, responsePlaintext, rsaPublicKey, rsaPublicKeySource string) {
	if materials == nil {
		return
	}

	if strings.TrimSpace(responsePlaintext) != "" && strings.TrimSpace(materials["latest_response_plaintext"]) == "" {
		materials["latest_response_plaintext"] = strings.TrimSpace(responsePlaintext)
	}

	if directKey := extractBrowserSessionRSAPublicKey(responsePlaintext); directKey != "" {
		materials["rsa_public_key"] = directKey
		if strings.TrimSpace(materials["rsa_public_key_source"]) == "" {
			materials["rsa_public_key_source"] = strings.TrimSpace(trace.RequestURL)
		}
	}

	if strings.TrimSpace(materials["rsa_public_key"]) == "" && strings.TrimSpace(materials["key_exchange_public_key"]) != "" {
		materials["rsa_public_key"] = strings.TrimSpace(materials["key_exchange_public_key"])
	}
	if strings.TrimSpace(materials["rsa_public_key"]) == "" && strings.TrimSpace(rsaPublicKey) != "" && browserSessionTraceHasRSA(trace) {
		materials["rsa_public_key"] = strings.TrimSpace(rsaPublicKey)
		if strings.TrimSpace(materials["rsa_public_key_source"]) == "" {
			materials["rsa_public_key_source"] = strings.TrimSpace(rsaPublicKeySource)
		}
	}
}

func browserSessionTraceHasRSA(trace crawl.ProtocolTraceRecord) bool {
	for _, algorithm := range trace.Algorithms {
		if strings.Contains(strings.ToLower(strings.TrimSpace(algorithm)), "rsa") {
			return true
		}
	}
	for _, step := range append(append([]crawl.ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		if strings.Contains(strings.ToLower(strings.TrimSpace(step.Algorithm)), "rsa") ||
			strings.Contains(strings.ToLower(strings.TrimSpace(step.Source)), "rsa") {
			return true
		}
	}
	return false
}

func findBrowserSessionRSAPublicKey(traces []crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) (string, string) {
	for _, trace := range traces {
		if key := firstNonEmptyBrowserSessionRSAPublicKey(
			extractBrowserSessionRSAPublicKey(trace.SessionMaterials["rsa_public_key"]),
			extractBrowserSessionRSAPublicKey(trace.SessionMaterials["key_exchange_public_key"]),
			extractBrowserSessionRSAPublicKey(trace.SessionMaterials["latest_response_plaintext"]),
		); key != "" {
			return key, strings.TrimSpace(trace.RequestURL)
		}
	}
	for _, record := range apiRecords {
		if key := extractBrowserSessionRSAPublicKey(record.ResponseBody); key != "" {
			return key, strings.TrimSpace(record.URL)
		}
	}
	return "", ""
}

func firstNonEmptyBrowserSessionRSAPublicKey(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func extractBrowserSessionRSAPublicKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if isLikelyBrowserSessionRSAPublicKey(trimmed) {
		return trimmed
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return ""
	}
	for _, key := range []string{"data", "publicKey", "rsaPublicKey", "rsa_public_key"} {
		value, ok := payload[key]
		if !ok {
			continue
		}
		text, _ := value.(string)
		text = strings.TrimSpace(text)
		if isLikelyBrowserSessionRSAPublicKey(text) {
			return text
		}
	}
	return ""
}

func isLikelyBrowserSessionRSAPublicKey(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if strings.Contains(value, "BEGIN PUBLIC KEY") || strings.Contains(value, "BEGIN RSA PUBLIC KEY") {
		return true
	}
	if len(value) < 100 {
		return false
	}
	if strings.HasPrefix(value, "MI") && !strings.ContainsAny(value, "{}[]:\"") {
		return true
	}
	return false
}

func findMatchingBrowserSessionAPIRecord(trace crawl.ProtocolTraceRecord, apiRecords []crawl.NetworkRecord) (crawl.NetworkRecord, bool) {
	traceID := strings.TrimSpace(trace.TraceID)
	traceMethod := strings.ToUpper(strings.TrimSpace(trace.Method))
	traceURL := strings.TrimSpace(trace.RequestURL)
	traceBody := strings.TrimSpace(trace.FinalRequestBody)

	if traceID != "" {
		for idx := range apiRecords {
			record := &apiRecords[idx]
			if strings.TrimSpace(record.TraceID) == traceID {
				return *record, true
			}
		}
	}

	var fallback *crawl.NetworkRecord
	for idx := range apiRecords {
		record := &apiRecords[idx]
		if strings.ToUpper(strings.TrimSpace(record.Method)) != traceMethod {
			continue
		}
		if strings.TrimSpace(record.URL) != traceURL {
			continue
		}
		if traceBody != "" && strings.TrimSpace(record.RequestBody) == traceBody {
			return *record, true
		}
		fallback = record
	}

	if fallback != nil {
		return *fallback, true
	}
	return crawl.NetworkRecord{}, false
}

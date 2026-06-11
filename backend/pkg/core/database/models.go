package database

import (
	"fmt"
	"strings"
	"time"
)

// TaskRecord 任务记录
type TaskRecord struct {
	TaskID    string    `json:"task_id"`
	TaskName  string    `json:"task_name"`
	Targets   []string  `json:"targets"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// BrowserSessionRecord 受控浏览器会话
type BrowserSessionRecord struct {
	SessionID             string    `json:"session_id"`
	SiteHost              string    `json:"site_host"`
	EntryURL              string    `json:"entry_url"`
	Status                string    `json:"status"`
	Mode                  string    `json:"mode"`
	BrowserMode           string    `json:"browser_mode,omitempty"`
	ProxyType             string    `json:"proxy_type,omitempty"`
	ProxyAddress          string    `json:"proxy_address,omitempty"`
	BrowserVisible        bool      `json:"browser_visible"`
	PageCount             int       `json:"page_count"`
	RequestCount          int       `json:"request_count"`
	SuspiciousCryptoCount int       `json:"suspicious_crypto_count"`
	StartedAt             time.Time `json:"started_at"`
	EndedAt               time.Time `json:"ended_at,omitempty"`
	LastActivityAt        time.Time `json:"last_activity_at"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// BrowserPageRecord 会话下的页面/标签页记录
type BrowserPageRecord struct {
	PageID     string    `json:"page_id"`
	SessionID  string    `json:"session_id"`
	URL        string    `json:"url"`
	Title      string    `json:"title,omitempty"`
	IsEntry    bool      `json:"is_entry"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

// BrowserSessionRequestRecord 会话下的请求/响应历史
type BrowserSessionRequestRecord struct {
	ID               int64             `json:"id"`
	SessionID        string            `json:"session_id"`
	TraceID          string            `json:"trace_id,omitempty"`
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	ResourceType     string            `json:"resource_type,omitempty"`
	RequestHeaders   map[string]string `json:"request_headers,omitempty"`
	RequestBody      string            `json:"request_body,omitempty"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
	ResponseBody     string            `json:"response_body,omitempty"`
	ResponseCode     int               `json:"response_code,omitempty"`
	MIMEType         string            `json:"mime_type,omitempty"`
	HasProtocolTrace bool              `json:"has_protocol_trace,omitempty"`
	IsSuspicious     bool              `json:"is_suspicious"`
	SuspiciousTrace  string            `json:"suspicious_trace,omitempty"`
	CreatedAt        time.Time         `json:"created_at"`
}

// BrowserSessionTraceRecord 会话下的可疑协议轨迹摘要
type BrowserSessionTraceRecord struct {
	ID                     int64                `json:"id"`
	SessionID              string               `json:"session_id"`
	TraceID                string               `json:"trace_id"`
	RequestURL             string               `json:"request_url"`
	Method                 string               `json:"method"`
	Algorithms             []string             `json:"algorithms"`
	RequestBeforeTransform string               `json:"request_before_transform,omitempty"`
	FinalRequestBody       string               `json:"final_request_body,omitempty"`
	RequestSteps           []ProtocolCryptoStep `json:"request_steps,omitempty"`
	ResponseSteps          []ProtocolCryptoStep `json:"response_steps,omitempty"`
	SessionMaterials       map[string]string    `json:"session_materials,omitempty"`
	ResponsePlaintext      string               `json:"response_plaintext,omitempty"`
	ResponseCiphertext     string               `json:"response_ciphertext,omitempty"`
	SuspiciousReason       string               `json:"suspicious_reason,omitempty"`
	CreatedAt              time.Time            `json:"created_at"`
}

// SiteTreeNode 网站树节点
type SiteTreeNode struct {
	TaskID    string    `json:"task_id"`
	Version   int       `json:"version"`
	NodeID    string    `json:"node_id"`
	Label     string    `json:"label"`
	ParentID  string    `json:"parent_id,omitempty"`
	URL       string    `json:"url,omitempty"`
	Level     int       `json:"level"`
	CreatedAt time.Time `json:"created_at"`
}

// JSResource JS资源记录
type JSResource struct {
	TaskID       string            `json:"task_id"`
	Version      int               `json:"version"`
	URL          string            `json:"url"`
	Content      string            `json:"content"`
	ResponseCode int               `json:"response_code"`
	Headers      map[string]string `json:"headers,omitempty"`
	Size         int               `json:"size"`
	FetchedAt    time.Time         `json:"fetched_at"`
}

// APIResource API资源记录
type APIResource struct {
	TaskID           string            `json:"task_id"`
	Version          int               `json:"version"`
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	TraceID          string            `json:"trace_id,omitempty"`
	HasProtocolTrace bool              `json:"has_protocol_trace,omitempty"`
	RequestHeaders   map[string]string `json:"request_headers,omitempty"`
	RequestBody      string            `json:"request_body,omitempty"`
	ResponseHeaders  map[string]string `json:"response_headers,omitempty"`
	ResponseBody     string            `json:"response_body,omitempty"`
	ResponseCode     int               `json:"response_code"`
	Headers          map[string]string `json:"headers,omitempty"`
	FetchedAt        time.Time         `json:"fetched_at"`
}

// ProtocolCryptoStep 协议解析中的加密/签名步骤
type ProtocolCryptoStep struct {
	Source        string `json:"source"`
	Algorithm     string `json:"algorithm,omitempty"`
	InputPreview  string `json:"input_preview,omitempty"`
	OutputPreview string `json:"output_preview,omitempty"`
	CallID        string `json:"call_id,omitempty"`
	ParentCallID  string `json:"parent_call_id,omitempty"`
	FunctionPath  string `json:"function_path,omitempty"`
	ModuleID      string `json:"module_id,omitempty"`
	Stack         string `json:"stack,omitempty"`
	CapturedAtMS  int64  `json:"captured_at_ms,omitempty"`
}

// ProtocolTraceRecord 协议轨迹记录
type ProtocolTraceRecord struct {
	TaskID                 string               `json:"task_id"`
	Version                int                  `json:"version"`
	TargetURL              string               `json:"target_url,omitempty"`
	TraceID                string               `json:"trace_id"`
	Transport              string               `json:"transport"`
	PageURL                string               `json:"page_url"`
	RequestURL             string               `json:"request_url"`
	Method                 string               `json:"method"`
	RequestHeaders         map[string]string    `json:"request_headers,omitempty"`
	RequestBeforeTransform string               `json:"request_before_transform,omitempty"`
	FinalRequestBody       string               `json:"final_request_body,omitempty"`
	RequestSteps           []ProtocolCryptoStep `json:"request_steps,omitempty"`
	ResponseSteps          []ProtocolCryptoStep `json:"response_steps,omitempty"`
	SignatureFields        []string             `json:"signature_fields,omitempty"`
	DynamicParams          map[string]string    `json:"dynamic_params,omitempty"`
	SessionMaterials       map[string]string    `json:"session_materials,omitempty"`
	Algorithms             []string             `json:"algorithms,omitempty"`
	Stack                  string               `json:"stack,omitempty"`
	CreatedAt              time.Time            `json:"created_at"`
}

type VulnStaticContext struct {
	SourceURL string `json:"source_url"`
	Snippet   string `json:"snippet"`
}

func (r *ProtocolTraceRecord) NormalizeForView() {
	if r == nil {
		return
	}

	if r.Method == "" {
		r.Method = "GET"
	}
	if r.SessionMaterials == nil {
		r.SessionMaterials = make(map[string]string)
	}
	if isProtocolTraceArtifact(r.RequestBeforeTransform) {
		r.RequestBeforeTransform = ""
	}
	if isProtocolTraceArtifact(r.SessionMaterials["latest_plaintext"]) {
		delete(r.SessionMaterials, "latest_plaintext")
	}
	if !isLikelyReadableResponsePlaintext(r.SessionMaterials["latest_response_plaintext"]) {
		delete(r.SessionMaterials, "latest_response_plaintext")
	}
	if r.FinalRequestBody != "" && r.SessionMaterials["latest_ciphertext"] == "" {
		r.SessionMaterials["latest_ciphertext"] = r.FinalRequestBody
	}

	backfillProtocolSessionMaterials(r)
	backfillProtocolRuntimeSteps(r)
	preferResponseStepPlaintext(r)
	suppressMirroredRequestPlaintext(r)

	if r.RequestBeforeTransform == "" {
		if plaintext := strings.TrimSpace(r.SessionMaterials["latest_plaintext"]); isLikelyJSONPreview(plaintext) {
			r.RequestBeforeTransform = plaintext
		}
	}

	r.RequestSteps = compactProtocolCryptoSteps(r.RequestSteps, r.RequestBeforeTransform)
	r.ResponseSteps = compactProtocolCryptoSteps(r.ResponseSteps, "")
	r.Algorithms = normalizeProtocolAlgorithms(append(append([]string{}, r.Algorithms...), inferProtocolAlgorithms(r.RequestSteps, r.ResponseSteps, r.FinalRequestBody)...))
	if hasPlaintextOnlyProtocolEvidence(r) || !hasMeaningfulProtocolSignal(r.RequestSteps, r.ResponseSteps, r.Algorithms) {
		r.RequestSteps = nil
		r.ResponseSteps = nil
	}
}

func suppressMirroredRequestPlaintext(trace *ProtocolTraceRecord) {
	if trace == nil {
		return
	}

	requestPlaintext := strings.TrimSpace(trace.RequestBeforeTransform)
	responsePlaintext := strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"])
	if requestPlaintext == "" || responsePlaintext == "" || requestPlaintext != responsePlaintext {
		return
	}
	if strings.TrimSpace(trace.FinalRequestBody) != "" || strings.TrimSpace(trace.SessionMaterials["latest_ciphertext"]) != "" {
		return
	}

	for _, step := range trace.RequestSteps {
		source := strings.ToLower(strings.TrimSpace(step.Source))
		algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))
		haystack := source + " " + algorithm
		if strings.Contains(haystack, "encrypt") ||
			strings.Contains(haystack, "sign") ||
			strings.Contains(haystack, "stringify") ||
			strings.Contains(haystack, ".se") ||
			strings.Contains(haystack, "request") {
			return
		}
	}

	trace.RequestBeforeTransform = ""
	delete(trace.SessionMaterials, "latest_plaintext")
}

func backfillProtocolSessionMaterials(trace *ProtocolTraceRecord) {
	for _, step := range append(append([]ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		source := strings.ToLower(strings.TrimSpace(step.Source))
		input := strings.TrimSpace(step.InputPreview)
		output := strings.TrimSpace(step.OutputPreview)

		if trace.SessionMaterials["sm4_key_hex"] == "" {
			switch {
			case strings.HasSuffix(source, ".sth") && isHex32(output):
				trace.SessionMaterials["sm4_key_hex"] = strings.ToLower(output)
			case (source == "window.atob" || source == "window.btoa") && isHex32(output):
				trace.SessionMaterials["sm4_key_hex"] = strings.ToLower(output)
			}
		}

		if trace.SessionMaterials["session_seed_b"] == "" {
			switch {
			case strings.HasSuffix(source, ".rn") && isDigits16(output):
				trace.SessionMaterials["session_seed_b"] = output
			case (source == "window.atob" || source == "window.btoa") && isHex32(output):
				if decoded := decodeHexASCII(output); isDigits16(decoded) {
					trace.SessionMaterials["session_seed_b"] = decoded
				}
			}
		}

		if trace.SessionMaterials["key_exchange_public_key"] == "" &&
			(source == "window.atob" || source == "window.btoa") &&
			isLikelySM2PublicKey(output) {
			trace.SessionMaterials["key_exchange_public_key"] = output
		}

		if trace.SessionMaterials["crypto_key_raw"] == "" &&
			(source == "window.atob" || source == "window.btoa") &&
			isLikelyPrintableAESKey(output) {
			trace.SessionMaterials["crypto_key_raw"] = output
		}

		if trace.SessionMaterials["latest_ciphertext"] == "" &&
			strings.HasSuffix(source, ".se") &&
			isHexCiphertext(output) {
			trace.SessionMaterials["latest_ciphertext"] = strings.ToLower(output)
		}

		if trace.SessionMaterials["latest_response_ciphertext"] == "" &&
			strings.HasSuffix(source, ".sd") &&
			isHexCiphertext(input) {
			trace.SessionMaterials["latest_response_ciphertext"] = strings.ToLower(input)
		}

		if trace.SessionMaterials["latest_response_plaintext"] == "" &&
			strings.HasSuffix(source, ".sd") &&
			output != "" {
			trace.SessionMaterials["latest_response_plaintext"] = output
		}
	}
}

func preferResponseStepPlaintext(trace *ProtocolTraceRecord) {
	if trace == nil {
		return
	}

	current := strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"])
	preferred := pickPreferredResponseStepPlaintext(trace.ResponseSteps)
	if responsePlaintextCandidateScore(preferred) > responsePlaintextCandidateScore(current) {
		trace.SessionMaterials["latest_response_plaintext"] = preferred
	}
}

func backfillProtocolRuntimeSteps(trace *ProtocolTraceRecord) {
	if trace == nil {
		return
	}
	if trace.SessionMaterials == nil {
		trace.SessionMaterials = make(map[string]string)
	}

	requestSource := firstNonEmptyString(
		trace.SessionMaterials["request_runtime_function_path"],
		"module.se",
	)
	requestModuleID := strings.TrimSpace(trace.SessionMaterials["request_runtime_module_id"])
	requestAlgorithm := inferSyntheticProtocolAlgorithm(trace, true)
	requestInput := strings.TrimSpace(firstNonEmptyString(
		trace.RequestBeforeTransform,
		trace.SessionMaterials["latest_plaintext"],
	))
	requestOutput := strings.TrimSpace(firstNonEmptyString(
		trace.FinalRequestBody,
		trace.SessionMaterials["latest_ciphertext"],
	))
	if requestInput != "" && requestOutput != "" && !hasProtocolStepForRuntime(trace.RequestSteps, requestSource, requestModuleID, "se") {
		trace.RequestSteps = append(trace.RequestSteps, ProtocolCryptoStep{
			Source:        requestSource,
			Algorithm:     requestAlgorithm,
			InputPreview:  requestInput,
			OutputPreview: requestOutput,
			FunctionPath:  normalizeSyntheticFunctionPath(requestSource),
			ModuleID:      requestModuleID,
		})
	}

	responseSource := firstNonEmptyString(
		trace.SessionMaterials["response_runtime_function_path"],
		"module.sd",
	)
	responseModuleID := strings.TrimSpace(trace.SessionMaterials["response_runtime_module_id"])
	responseAlgorithm := inferSyntheticProtocolAlgorithm(trace, false)
	responseInput := strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"])
	responseOutput := strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"])
	if responseInput != "" && responseOutput != "" && !hasProtocolStepForRuntime(trace.ResponseSteps, responseSource, responseModuleID, "sd") {
		trace.ResponseSteps = append(trace.ResponseSteps, ProtocolCryptoStep{
			Source:        responseSource,
			Algorithm:     responseAlgorithm,
			InputPreview:  responseInput,
			OutputPreview: responseOutput,
			FunctionPath:  normalizeSyntheticFunctionPath(responseSource),
			ModuleID:      responseModuleID,
		})
	}
}

func hasProtocolStepForRuntime(steps []ProtocolCryptoStep, source, moduleID, suffix string) bool {
	source = strings.ToLower(strings.TrimSpace(source))
	moduleID = strings.TrimSpace(moduleID)
	suffix = strings.ToLower(strings.TrimSpace(suffix))
	for _, step := range steps {
		stepSource := strings.ToLower(strings.TrimSpace(step.Source))
		stepFunctionPath := strings.ToLower(strings.TrimSpace(step.FunctionPath))
		stepModuleID := strings.TrimSpace(step.ModuleID)
		if source != "" && (stepSource == source || stepFunctionPath == source) {
			return true
		}
		if suffix != "" && (strings.HasSuffix(stepSource, "."+suffix) || stepSource == suffix || strings.HasSuffix(stepFunctionPath, "."+suffix) || stepFunctionPath == suffix) {
			if moduleID == "" || stepModuleID == "" || stepModuleID == moduleID {
				return true
			}
		}
	}
	return false
}

func inferSyntheticProtocolAlgorithm(trace *ProtocolTraceRecord, requestSide bool) string {
	if trace == nil {
		return ""
	}
	for _, algorithm := range trace.Algorithms {
		value := strings.ToLower(strings.TrimSpace(algorithm))
		switch {
		case strings.Contains(value, "sm4"):
			if requestSide {
				return "sm4.encrypt"
			}
			return "sm4.decrypt"
		case strings.Contains(value, "aes-gcm"):
			if requestSide {
				return "aes-gcm.encrypt"
			}
			return "aes-gcm.decrypt"
		case strings.Contains(value, "aes-cbc"):
			if requestSide {
				return "aes-cbc.encrypt"
			}
			return "aes-cbc.decrypt"
		}
	}
	if strings.TrimSpace(trace.SessionMaterials["sm4_key_hex"]) != "" {
		if requestSide {
			return "sm4.encrypt"
		}
		return "sm4.decrypt"
	}
	return ""
}

func normalizeSyntheticFunctionPath(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	if strings.Contains(source, ".") {
		return source
	}
	return "module." + source
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func pickPreferredResponseStepPlaintext(steps []ProtocolCryptoStep) string {
	for _, step := range steps {
		output := strings.TrimSpace(step.OutputPreview)
		if responsePlaintextCandidateScore(output) > 1 {
			return output
		}
	}

	for _, step := range steps {
		output := strings.TrimSpace(step.OutputPreview)
		if responsePlaintextCandidateScore(output) >= 0 {
			return output
		}
	}

	return ""
}

func responsePlaintextCandidateScore(text string) int {
	text = strings.TrimSpace(text)
	if !isLikelyReadableResponsePlaintext(text) {
		return -1
	}
	if text == "{}" || text == "[]" || text == "null" || text == `""` {
		return 1
	}
	score := len(text)
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		score += 20
	}
	if strings.Contains(text, ":") {
		score += 20
	}
	return score
}

func compactProtocolCryptoSteps(steps []ProtocolCryptoStep, requestBefore string) []ProtocolCryptoStep {
	if len(steps) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	result := make([]ProtocolCryptoStep, 0, len(steps))
	trimmedPlaintext := strings.TrimSpace(requestBefore)

	for i := len(steps) - 1; i >= 0; i-- {
		step := steps[i]
		input := strings.TrimSpace(step.InputPreview)
		output := strings.TrimSpace(step.OutputPreview)
		source := strings.TrimSpace(step.Source)
		algorithm := strings.TrimSpace(step.Algorithm)

		if input == "" && output == "" {
			continue
		}
		if isProtocolTraceArtifact(input) || isProtocolTraceArtifact(output) {
			continue
		}

		if strings.EqualFold(source, "JSON.stringify") || strings.EqualFold(algorithm, "json.stringify") {
			if trimmedPlaintext != "" && input != trimmedPlaintext && output != trimmedPlaintext {
				continue
			}
		}

		fingerprint := strings.Join([]string{
			strings.ToLower(source),
			strings.ToLower(algorithm),
			input,
			output,
			strings.TrimSpace(step.CallID),
			strings.TrimSpace(step.ParentCallID),
			strings.TrimSpace(step.FunctionPath),
			strings.TrimSpace(step.ModuleID),
		}, "\x00")
		if seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		result = append(result, step)
	}

	for left, right := 0, len(result)-1; left < right; left, right = left+1, right-1 {
		result[left], result[right] = result[right], result[left]
	}

	const maxViewSteps = 16
	if len(result) > maxViewSteps {
		prioritized := make([]ProtocolCryptoStep, 0, maxViewSteps)
		used := make(map[int]bool)

		for idx, step := range result {
			if isResponseDecryptStep(step) {
				prioritized = append(prioritized, step)
				used[idx] = true
			}
		}

		for idx := len(result) - 1; idx >= 0 && len(prioritized) < maxViewSteps; idx-- {
			if used[idx] {
				continue
			}
			prioritized = append(prioritized, result[idx])
			used[idx] = true
		}

		for left, right := 0, len(prioritized)-1; left < right; left, right = left+1, right-1 {
			prioritized[left], prioritized[right] = prioritized[right], prioritized[left]
		}
		result = prioritized
	}
	return result
}

func isResponseDecryptStep(step ProtocolCryptoStep) bool {
	source := strings.ToLower(strings.TrimSpace(step.Source))
	algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))

	if source == "sd" || strings.HasSuffix(source, ".sd") {
		return true
	}
	if strings.Contains(source, "decrypt") && !strings.Contains(source, "textdecoder.decode") {
		return true
	}
	return strings.Contains(algorithm, "sm4") || strings.Contains(algorithm, "aes-cbc") || strings.Contains(algorithm, "aes-gcm")
}

func inferProtocolAlgorithms(requestSteps, responseSteps []ProtocolCryptoStep, finalRequestBody string) []string {
	seen := make(map[string]bool)
	algorithms := make([]string, 0, len(requestSteps)+len(responseSteps)+1)
	push := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if seen[value] {
			return
		}
		seen[value] = true
		algorithms = append(algorithms, value)
	}

	for _, steps := range [][]ProtocolCryptoStep{requestSteps, responseSteps} {
		for _, step := range steps {
			if isProtocolHelperOnlyStep(step) {
				continue
			}
			if step.Algorithm != "" {
				push(step.Algorithm)
				continue
			}
			push(step.Source)
		}
	}

	body := strings.TrimSpace(finalRequestBody)
	switch {
	case isHexCiphertext(body):
		push("hex-encoded-payload")
	case isBase64Like(body):
		push("base64-encoded-payload")
	}

	return algorithms
}

func normalizeProtocolAlgorithms(algorithms []string) []string {
	filtered := make([]string, 0, len(algorithms))
	seen := make(map[string]bool, len(algorithms))
	for _, algorithm := range algorithms {
		trimmed := strings.TrimSpace(algorithm)
		normalized := strings.ToLower(trimmed)
		if normalized == "" || seen[normalized] {
			continue
		}
		seen[normalized] = true
		filtered = append(filtered, trimmed)
	}
	return filtered
}

func filterMeaningfulProtocolAlgorithms(algorithms []string) []string {
	filtered := make([]string, 0, len(algorithms))
	for _, algorithm := range normalizeProtocolAlgorithms(algorithms) {
		if isIgnorableProtocolAlgorithm(strings.ToLower(strings.TrimSpace(algorithm))) {
			continue
		}
		filtered = append(filtered, algorithm)
	}
	return filtered
}

func hasMeaningfulProtocolSignal(requestSteps, responseSteps []ProtocolCryptoStep, algorithms []string) bool {
	if len(filterMeaningfulProtocolAlgorithms(algorithms)) > 0 {
		return true
	}
	for _, steps := range [][]ProtocolCryptoStep{requestSteps, responseSteps} {
		for _, step := range steps {
			if isMeaningfulProtocolStep(step) {
				return true
			}
		}
	}
	return false
}

func isProtocolHelperOnlyStep(step ProtocolCryptoStep) bool {
	source := strings.ToLower(strings.TrimSpace(step.Source))
	algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))

	switch {
	case source == "json.stringify":
		return true
	case algorithm == "json.stringify":
		return true
	case source == "textencoder.encode":
		return true
	case algorithm == "text.encode":
		return true
	default:
		return false
	}
}

func isIgnorableProtocolAlgorithm(value string) bool {
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

func isMeaningfulProtocolStep(step ProtocolCryptoStep) bool {
	source := strings.ToLower(strings.TrimSpace(step.Source))
	algorithm := strings.ToLower(strings.TrimSpace(step.Algorithm))
	if isIgnorableProtocolAlgorithm(source) && isIgnorableProtocolAlgorithm(algorithm) {
		return false
	}
	if isProtocolHelperOnlyStep(step) {
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

func hasPlaintextOnlyProtocolEvidence(trace *ProtocolTraceRecord) bool {
	if trace == nil {
		return false
	}
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

	if !hasPlaintext {
		return false
	}
	if len(filterMeaningfulProtocolAlgorithms(trace.Algorithms)) > 0 {
		return false
	}
	for _, step := range append(append([]ProtocolCryptoStep{}, trace.RequestSteps...), trace.ResponseSteps...) {
		if isMeaningfulProtocolStep(step) {
			return false
		}
	}
	return true
}

func isLikelyJSONPreview(text string) bool {
	text = strings.TrimSpace(text)
	return strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[")
}

func isLikelyReadableResponsePlaintext(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}

	if isLikelyJSONPreview(text) || strings.HasPrefix(text, "<") {
		return true
	}

	if strings.HasPrefix(text, `"`) && strings.HasSuffix(text, `"`) && len(text) >= 2 {
		text = text[1 : len(text)-1]
	}
	if text == "" {
		return false
	}

	if strings.ContainsAny(text, " \n\r\t") {
		return true
	}
	if containsHan(text) {
		return true
	}
	if strings.ContainsAny(text, `:{}[],"`) {
		return true
	}
	if len(text) >= 32 && (isHexString(text) || isBase64Like(text)) {
		return false
	}

	return containsASCIIAlpha(text)
}

func containsASCIIAlpha(text string) bool {
	for _, ch := range text {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') {
			return true
		}
	}
	return false
}

func containsHan(text string) bool {
	for _, ch := range text {
		if ch >= '\u4e00' && ch <= '\u9fff' {
			return true
		}
	}
	return false
}

func isProtocolTraceArtifact(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	return strings.Contains(text, `"kind":"request-trace"`) ||
		strings.Contains(text, `"kind": "request-trace"`) ||
		strings.Contains(text, `"trace_id":"trace-`) ||
		strings.Contains(text, `"trace_id": "trace-`)
}

func isDigits16(text string) bool {
	if len(text) != 16 {
		return false
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func isHex32(text string) bool {
	return len(text) == 32 && isHexString(text)
}

func isHexCiphertext(text string) bool {
	return len(text) >= 32 && len(text)%2 == 0 && isHexString(text)
}

func isHexString(text string) bool {
	if text == "" {
		return false
	}
	for _, ch := range text {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

func isBase64Like(text string) bool {
	if len(text) < 24 || len(text)%4 != 0 {
		return false
	}
	for _, ch := range text {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '+' || ch == '/' || ch == '=':
		default:
			return false
		}
	}
	return true
}

func isLikelySM2PublicKey(text string) bool {
	text = strings.TrimSpace(text)
	return len(text) >= 128 && strings.HasPrefix(strings.ToUpper(text), "04") && isHexString(text)
}

func isLikelyPrintableAESKey(text string) bool {
	if len(text) != 16 && len(text) != 24 && len(text) != 32 {
		return false
	}
	for _, ch := range text {
		if ch < 32 || ch > 126 {
			return false
		}
	}
	return true
}

func decodeHexASCII(text string) string {
	if !isHexString(text) || len(text)%2 != 0 {
		return ""
	}
	var builder strings.Builder
	builder.Grow(len(text) / 2)
	for i := 0; i < len(text); i += 2 {
		pair := text[i : i+2]
		var value byte
		for j := 0; j < 2; j++ {
			value <<= 4
			switch ch := pair[j]; {
			case ch >= '0' && ch <= '9':
				value += ch - '0'
			case ch >= 'a' && ch <= 'f':
				value += ch - 'a' + 10
			case ch >= 'A' && ch <= 'F':
				value += ch - 'A' + 10
			default:
				return ""
			}
		}
		if value < 32 || value > 126 {
			return ""
		}
		builder.WriteByte(value)
	}
	return builder.String()
}

// VulnRecord 漏洞记录
type VulnRecord struct {
	TaskID             string              `json:"task_id"`
	Version            int                 `json:"version"`
	VulnID             string              `json:"vuln_id"`
	Title              string              `json:"title"`
	Level              string              `json:"level"` // high, medium, low, info
	Status             string              `json:"status,omitempty"`
	Type               string              `json:"type"`
	URL                string              `json:"url"`
	Method             string              `json:"method,omitempty"`
	Request            string              `json:"request,omitempty"`
	Response           string              `json:"response,omitempty"`
	ResponseType       string              `json:"response_type,omitempty"`
	TraceID            string              `json:"trace_id,omitempty"`
	HasProtocolTrace   bool                `json:"has_protocol_trace,omitempty"`
	ResponseCiphertext string              `json:"response_ciphertext,omitempty"`
	DecryptionStatus   string              `json:"decryption_status,omitempty"`
	DecryptionDetail   string              `json:"decryption_detail,omitempty"`
	ResponseLength     int                 `json:"response_length,omitempty"` // 原始响应长度（字节）
	Confidence         string              `json:"confidence,omitempty"`
	ConfidenceReason   string              `json:"confidence_reason,omitempty"`
	DenyTemplateID     string              `json:"deny_template_id,omitempty"`
	DenyTemplateKind   string              `json:"deny_template_kind,omitempty"`
	DenyTemplateLabel  string              `json:"deny_template_label,omitempty"`
	DenyTemplateCount  int                 `json:"deny_template_count,omitempty"`
	StaticContexts     []VulnStaticContext `json:"static_contexts,omitempty"`
	Description        string              `json:"description"`
	AIVerified         bool                `json:"ai_verified"` // AI辅助验证标记
	CreatedAt          time.Time           `json:"created_at"`
}

// AssetRecord 资产记录（统一存储所有资产类型）
type AssetRecord struct {
	TaskID        string       `json:"task_id"`
	Version       int          `json:"version"`
	Email         []AssetValue `json:"email,omitempty"`
	IDCard        []AssetValue `json:"id_card,omitempty"`
	Phone         []AssetValue `json:"phone,omitempty"`
	IPURL         []AssetValue `json:"ip_url"`                   // IP和URL列表
	FrontendRoute []AssetValue `json:"frontend_route,omitempty"` // 前端页面路由列表
	APIRoot       []AssetValue `json:"apiroot"`                  // API根路径列表
	APIRouter     []AssetValue `json:"apirouter"`                // API路由列表
	CreatedAt     time.Time    `json:"created_at"`
}

// User 用户模型
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`    // 不序列化密码字段
	Role      string    `json:"role"` // admin, user
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ES 索引名称
const (
	IndexSiteTree               = "trailblazer-sitetree"
	IndexJS                     = "trailblazer-js"
	IndexAPI                    = "trailblazer-api"
	IndexProtocol               = "trailblazer-protocol"
	IndexStaticProtocolAnalysis = "trailblazer-static-protocol"
	IndexVuln                   = "trailblazer-vuln"
	IndexAsset                  = "trailblazer-asset"
)

// SaveSiteTreeNode 保存网站树节点
func SaveSiteTreeNode(node SiteTreeNode) error {
	return InsertToES(node, IndexSiteTree, false)
}

// SaveJSResource 保存JS资源
func SaveJSResource(js JSResource) error {
	return InsertToES(js, IndexJS, false)
}

// SaveAPIResource 保存接口请求/响应记录
func SaveAPIResource(api APIResource) error {
	return InsertToES(api, IndexAPI, false)
}

// SaveProtocolTrace 保存协议轨迹记录
func SaveProtocolTrace(trace ProtocolTraceRecord) error {
	return InsertToES(trace, IndexProtocol, false)
}

// SaveVuln 保存漏洞
func SaveVuln(vuln VulnRecord) error {
	if strings.TrimSpace(vuln.Status) == "" {
		vuln.Status = "open"
	}

	err := InsertToES(vuln, IndexVuln, false)
	if err != nil {
		return err
	}

	go func(taskID string, version int) {
		if version <= 0 {
			if err := UpdateTaskHighestRiskLevel(taskID); err != nil {
				fmt.Printf("[WARNING] Failed to update highest risk level for task %s: %v\n", taskID, err)
			}
			return
		}

		vulns, err := QueryVulnsByTaskID(taskID)
		if err != nil {
			fmt.Printf("[WARNING] Failed to load vulns for task %s version %d: %v\n", taskID, version, err)
			return
		}

		versionVulns := make([]VulnRecord, 0, len(vulns))
		for _, current := range vulns {
			if current.Version == version {
				versionVulns = append(versionVulns, current)
			}
		}

		if err := UpdateTaskVersionHighestRiskLevelFromVulns(taskID, version, versionVulns); err != nil {
			fmt.Printf("[WARNING] Failed to update highest risk level for task %s version %d: %v\n", taskID, version, err)
		}
	}(vuln.TaskID, vuln.Version)

	return nil
}

func UpdateTaskVersionHighestRiskLevelFromVulns(taskID string, version int, vulns []VulnRecord) error {
	return UpdateTaskVersionHighestRiskLevel(taskID, version, highestRiskLevelFromVulns(vulns))
}

// SaveAsset 保存资产
func SaveAsset(asset AssetRecord) error {
	err := InsertToES(asset, IndexAsset, false)
	if err == nil {
		return nil
	}

	// 兼容旧版资产索引映射：当 email/ip_url 等字段仍是 text 时，
	// ES 无法接收 {value,source} 对象数组，此时自动回退为旧版字符串数组。
	if isLegacyAssetMappingError(err) {
		return InsertToES(toLegacyAssetRecord(asset), IndexAsset, false)
	}
	return err
}

func isLegacyAssetMappingError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "document_parsing_exception") &&
		strings.Contains(message, "Expected text") &&
		strings.Contains(message, "START_OBJECT")
}

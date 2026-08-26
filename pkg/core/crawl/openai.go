package crawl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// 定义最大并发数
const maxConcurrentRequests = 2

// 用于控制并发的信号通道
var sem = make(chan struct{}, maxConcurrentRequests)

// SensitiveInfoChecker 敏感信息检测器
type SensitiveInfoChecker struct {
	apiKey  string
	baseURL string
	model   string
	client  *http.Client
	ctx     context.Context
	debug   bool // 是否启用调试模式
}

func (c *SensitiveInfoChecker) SetContext(ctx context.Context) {
	if ctx == nil {
		c.ctx = context.Background()
		return
	}
	c.ctx = ctx
}

func (c *SensitiveInfoChecker) chatComplete(systemPrompt, userPrompt string, temperature float64, maxTokens int) (string, error) {
	sem <- struct{}{}
	defer func() {
		<-sem
	}()

	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": temperature,
		"max_tokens":  maxTokens,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no choices returned from model")
	}
	if finishReason := strings.TrimSpace(result.Choices[0].FinishReason); finishReason != "" && finishReason != "stop" {
		return "", fmt.Errorf("model output incomplete (finish_reason=%s)", finishReason)
	}

	return strings.TrimSpace(result.Choices[0].Message.Content), nil
}

func (c *SensitiveInfoChecker) chatCompleteStream(systemPrompt, userPrompt string, temperature float64, maxTokens int, onDelta func(string)) (string, error) {
	sem <- struct{}{}
	defer func() {
		<-sem
	}()

	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userPrompt},
		},
		"temperature": temperature,
		"max_tokens":  maxTokens,
		"stream":      true,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", err
	}

	ctx := c.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	streamClient := *c.client
	streamClient.Timeout = 0

	resp, err := streamClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API request failed: %d - %s", resp.StatusCode, string(body))
	}

	type streamResponse struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}

	reader := bufio.NewReader(resp.Body)
	var builder strings.Builder
	var eventLines []string
	receivedDone := false
	finishReason := ""

	processEvent := func(lines []string) error {
		if len(lines) == 0 {
			return nil
		}

		dataLines := make([]string, 0, len(lines))
		for _, line := range lines {
			if strings.HasPrefix(line, "data:") {
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}
		if len(dataLines) == 0 {
			return nil
		}

		payload := strings.Join(dataLines, "\n")
		if payload == "[DONE]" {
			receivedDone = true
			return nil
		}

		var result streamResponse
		if err := json.Unmarshal([]byte(payload), &result); err != nil {
			return err
		}

		for _, choice := range result.Choices {
			if strings.TrimSpace(choice.FinishReason) != "" {
				finishReason = strings.TrimSpace(choice.FinishReason)
			}
			if choice.Delta.Content == "" {
				continue
			}
			builder.WriteString(choice.Delta.Content)
			if onDelta != nil {
				onDelta(choice.Delta.Content)
			}
		}

		return nil
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}

		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			if err := processEvent(eventLines); err != nil {
				return "", err
			}
			eventLines = eventLines[:0]
		} else {
			eventLines = append(eventLines, trimmed)
		}

		if err == io.EOF {
			if err := processEvent(eventLines); err != nil {
				return "", err
			}
			break
		}
	}

	if !receivedDone {
		return "", fmt.Errorf("model stream ended before [DONE]")
	}
	if finishReason != "" && finishReason != "stop" {
		return "", fmt.Errorf("model output incomplete (finish_reason=%s)", finishReason)
	}

	return strings.TrimSpace(builder.String()), nil
}

// NewSensitiveInfoChecker 初始化敏感信息检测器
func NewSensitiveInfoChecker(apiKey, baseURL, model string) *SensitiveInfoChecker {
	return &SensitiveInfoChecker{
		apiKey:  apiKey,
		baseURL: baseURL,
		model:   model,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		ctx:   context.Background(),
		debug: false, // 默认关闭调试模式
	}
}

// SetDebug 设置调试模式
func (c *SensitiveInfoChecker) SetDebug(debug bool) {
	c.debug = debug
}

// Check 检查字段是否为真正的敏感信息
// 返回：(是否敏感, error)
func (c *SensitiveInfoChecker) Check(fieldContent string) (bool, error) {
	systemPrompt := `你是一个敏感信息检测专家。用户会提供通过正则表达式从JavaScript代码中提取的内容，你需要判断这些内容是否真的是敏感信息泄露。

判断标准：
1. TRUE（真实敏感信息泄露）的情况：
   - 包含真实的密码、密钥、API密钥、数据库连接字符串
   - 包含真实的邮箱地址、手机号码、身份证号码
   - 包含真实的服务器地址、数据库地址
   - 包含真实的用户凭据、认证信息
   - 包含硬编码账号密码、默认口令、弱口令、测试环境但可直接使用的登录凭据（如：username:"admin"、password:"admin123"）

2. FALSE（不是敏感信息泄露）的情况：
   - 只是变量名、函数名、参数名（如：password, username, apiKey）
   - 占位符、示例值（如：your_password, example@email.com）
   - 代码注释、文档说明
   - 配置模板、默认值
   - 测试数据、模拟数据
   - 代码表达式、函数调用、比较表达式、布尔表达式、对象属性片段、压缩后的JS片段
   - 值中出现明显代码特征时一律判定为 false，例如：De(c)、S===void、foo(bar)、a+b、x?y:z、[{required:!0}]

补充规则：
- 对于 username/password 这类字段，重点判断右侧“值”是否是可直接使用的字面量凭据。
- 如果右侧值看起来像代码，而不是字面量字符串、token、URL、邮箱、手机号、证书、密钥，则返回 false。
- 只要你不能明确确认它是可直接利用的敏感数据，就返回 false。

请仔细分析提供的文本内容，判断是否包含真实的敏感信息。只回答 true 或 false，不要输出其他任何内容。`

	reply, err := c.chatComplete(
		systemPrompt,
		fmt.Sprintf("请判断以下从JavaScript代码中提取的内容是否是真实的敏感信息泄露：\n\n%s\n\n注意：这可能是变量名、函数名、占位符或真实的敏感数据。请根据上述判断标准进行分析。", fieldContent),
		0.1,
		10,
	)
	if err != nil {
		return false, err
	}

	reply = strings.TrimSpace(strings.ToLower(reply))
	return reply == "true", nil
}

// ClassifyAPIRoutes 使用 AI 判断候选路由更像 API 还是页面/静态资源
// 返回值为 route -> true(api) / false(non-api)
func (c *SensitiveInfoChecker) ClassifyAPIRoutes(routes []string) (map[string]bool, error) {
	trimmedRoutes := make([]string, 0, len(routes))
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if route != "" {
			trimmedRoutes = append(trimmedRoutes, route)
		}
	}
	if len(trimmedRoutes) == 0 {
		return map[string]bool{}, nil
	}

	systemPrompt := `你是一个 Web 安全资产分类专家。用户会提供一组从 JavaScript 或前端路由中提取的路径，你需要判断每一项更可能是：
1. api: 后端接口路径、API endpoint、GraphQL endpoint、Ajax/Fetch 请求目标
2. page: 前端页面路由、Vue/React/UniApp 页面路径、导航路径
3. asset: 静态资源路径，如图片、字体、脚本、样式、媒体文件

判断原则：
- 包含 /api、/graphql、/rest、/service、后端动作词或明显接口风格的，优先判定为 api
- 包含 /pages/、/views/、/components/、/#/、前端页面层级、明显页面命名的，优先判定为 page
- 带静态资源后缀名、静态目录特征的，判定为 asset
- 不确定时，根据最可能用途判断，但不要把明显页面路由误判为 api

请仅输出 JSON 数组，每项格式为：
{"route":"原始路径","label":"api|page|asset","reason":"简短原因"}`

	type routeDecision struct {
		Route  string `json:"route"`
		Label  string `json:"label"`
		Reason string `json:"reason"`
	}

	reply, err := c.chatComplete(
		systemPrompt,
		fmt.Sprintf("请判断以下候选路径：\n%s", marshalRouteList(trimmedRoutes)),
		0.1,
		1200,
	)
	if err != nil {
		return nil, err
	}

	jsonStart := strings.Index(reply, "[")
	jsonEnd := strings.LastIndex(reply, "]")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("invalid AI route classification response")
	}

	var decisions []routeDecision
	if err := json.Unmarshal([]byte(reply[jsonStart:jsonEnd+1]), &decisions); err != nil {
		return nil, err
	}

	classification := make(map[string]bool, len(decisions))
	for _, item := range decisions {
		label := strings.ToLower(strings.TrimSpace(item.Label))
		if strings.TrimSpace(item.Route) == "" {
			continue
		}
		classification[item.Route] = label == "api"
	}

	return classification, nil
}

func buildProtocolTraceExplainPrompts(traceSummary string) (string, string) {
	systemPrompt := `你是一个前端协议链路解释助手。用户会提供结构化的协议轨迹，包括请求/响应步骤、会话材料、算法、请求头和明文/密文片段。

你的任务：
1. 只基于提供的结构化轨迹解释协议链路，不要臆造不存在的步骤。
2. 把链路写成白话，适合安全分析人员快速阅读。
3. 明确区分“已确认”与“推断”。
4. 优先解释：
   - 请求明文如何变成请求密文
   - 会话种子 / key / iv / nonce / timestamp / signature 如何生成或传递
   - 响应密文如何变成响应明文
5. 如果某一步没有足够证据，只能写“未确认”，不要硬猜。

输出要求：
- 使用简体中文
- 严格只输出两个 Markdown 二级标题，且顺序固定为“## 请求甬道”、“## 响应甬道”
- 每个标题下使用“1. 2. 3.”有序列表；每个要点尽量写成“标题：内容”的形式，标题使用纯文本，不要加粗、不要使用代码标记；如果该甬道缺少证据，也要保留标题并写“1. 未确认：...”
- 第一行必须直接从“## 请求甬道”开始，不要任何引言、抬头、前置说明或总结句
- 可以对“已确认”与“推断”使用 Markdown 强调标记，但不要对要点标题本身使用粗体
- 对函数名、字段名、算法名、关键材料优先使用行内代码标记
- 如果引用某个密文、明文、随机串、时间戳、签名或 key，只写值本身或用自然语言描述，不要输出内部存储字段名或原始 JSON 键名
- 严禁输出“latest_response_ciphertext: ...”、“latest_ciphertext: ...”、“nonce: ...”、“timestamp: ...”、“signature: ...”这类“键:值”样式的内部字段复述
- 控制在 4 到 8 个要点
- 不要复述整个原始 JSON
- 对推断步骤必须显式标注“推断”`

	userPrompt := fmt.Sprintf("请基于下面这条协议轨迹生成白话解释：\n\n%s", traceSummary)
	return systemPrompt, userPrompt
}

func (c *SensitiveInfoChecker) ExplainProtocolTrace(traceSummary string) (string, error) {
	systemPrompt, userPrompt := buildProtocolTraceExplainPrompts(traceSummary)

	return c.chatComplete(
		systemPrompt,
		userPrompt,
		0.2,
		1400,
	)
}

func (c *SensitiveInfoChecker) ExplainProtocolTraceStream(traceSummary string, onDelta func(string)) (string, error) {
	systemPrompt, userPrompt := buildProtocolTraceExplainPrompts(traceSummary)

	return c.chatCompleteStream(
		systemPrompt,
		userPrompt,
		0.2,
		1400,
		onDelta,
	)
}

func marshalRouteList(routes []string) string {
	lines := make([]string, 0, len(routes))
	for _, route := range routes {
		lines = append(lines, "- "+route)
	}
	return strings.Join(lines, "\n")
}

// AITruth is a tri-state value used when the request/response does not prove
// whether a resource is protected or whether sensitive data was returned.
// The parser accepts both the documented strings and JSON booleans so a model
// that ignores the string-only instruction does not silently corrupt the
// review result.
type AITruth string

const (
	AITruthTrue    AITruth = "true"
	AITruthFalse   AITruth = "false"
	AITruthUnknown AITruth = "unknown"
)

func (v *AITruth) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err == nil {
		value = strings.ToLower(strings.TrimSpace(value))
	} else {
		var boolean bool
		if err := json.Unmarshal(data, &boolean); err != nil {
			return fmt.Errorf("AI truth must be true, false, or unknown")
		}
		if boolean {
			value = string(AITruthTrue)
		} else {
			value = string(AITruthFalse)
		}
	}

	switch AITruth(value) {
	case AITruthTrue, AITruthFalse, AITruthUnknown:
		*v = AITruth(value)
		return nil
	default:
		return fmt.Errorf("invalid AI truth value %q", value)
	}
}

// UnauthorizedAIReview is the structured result returned by the unauthorized
// access reviewer. It is intentionally kept separate from VulnRecord so the
// model output can be validated before it affects scan results.
type UnauthorizedAIReview struct {
	Verdict            string   `json:"verdict"`
	VulnerabilityType  string   `json:"vulnerability_type"`
	Confidence         int      `json:"confidence"`
	ProtectedResource  AITruth  `json:"protected_resource"`
	SensitiveDataFound AITruth  `json:"sensitive_data_found"`
	Evidence           []string `json:"evidence"`
	Reason             string   `json:"reason"`
	Impact             string   `json:"impact"`
	RiskLevel          string   `json:"risk_level"`
	MissingEvidence    []string `json:"missing_evidence"`
	RecommendedAction  string   `json:"recommended_action"`
}

// EncryptedResponseAIReview only describes JavaScript evidence for a response
// that has already passed the local response-encryption envelope rule. It does
// not classify business fields as ciphertext and cannot change that rule.
type EncryptedResponseAIReview struct {
	Encrypted                AITruth  `json:"encrypted"`
	ResponseDecryptionLikely AITruth  `json:"response_decryption_likely"`
	Confidence               int      `json:"confidence"`
	Encoding                 string   `json:"encoding"`
	CandidateAlgorithms      []string `json:"candidate_algorithms"`
	Evidence                 []string `json:"evidence"`
	Reason                   string   `json:"reason"`
	RecommendedAction        string   `json:"recommended_action"`
}

func decodeEncryptedResponseAIReview(data []byte) (EncryptedResponseAIReview, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return EncryptedResponseAIReview{}, err
	}
	for _, field := range []string{"encrypted", "response_decryption_likely", "confidence", "encoding", "candidate_algorithms", "evidence", "reason", "recommended_action"} {
		value, ok := raw[field]
		if !ok || strings.TrimSpace(string(value)) == "null" {
			return EncryptedResponseAIReview{}, fmt.Errorf("missing required encrypted response AI field %q", field)
		}
	}

	var review EncryptedResponseAIReview
	if err := json.Unmarshal(data, &review); err != nil {
		return EncryptedResponseAIReview{}, err
	}
	if review.Encrypted != AITruthTrue {
		return EncryptedResponseAIReview{}, fmt.Errorf("encrypted response evidence review must preserve the confirmed envelope, got %q", review.Encrypted)
	}
	if review.ResponseDecryptionLikely != AITruthTrue && review.ResponseDecryptionLikely != AITruthFalse && review.ResponseDecryptionLikely != AITruthUnknown {
		return EncryptedResponseAIReview{}, fmt.Errorf("invalid response_decryption_likely value %q", review.ResponseDecryptionLikely)
	}
	if review.Confidence < 0 || review.Confidence > 100 {
		return EncryptedResponseAIReview{}, fmt.Errorf("encrypted response AI confidence must be between 0 and 100")
	}
	if review.Encoding != "hex" && review.Encoding != "base64" && review.Encoding != "mixed" && review.Encoding != "unknown" {
		return EncryptedResponseAIReview{}, fmt.Errorf("invalid encrypted response encoding %q", review.Encoding)
	}
	if review.RecommendedAction != "continue_js_analysis" && review.RecommendedAction != "needs_runtime_capture" {
		return EncryptedResponseAIReview{}, fmt.Errorf("invalid encrypted response recommended action %q", review.RecommendedAction)
	}
	return review, nil
}

// ReviewUncapturedEncryptedResponse reviews JavaScript evidence after the
// scanner has already confirmed a response-level encryption envelope. JS
// evidence is pre-selected by the scanner and is evidence, not executable code
// supplied to the model.
func (c *SensitiveInfoChecker) ReviewUncapturedEncryptedResponse(targetURL, requestPreview, responsePreview, jsEvidence string) (EncryptedResponseAIReview, error) {
	systemPrompt := `你是一名前端协议与应用安全分析助手。上游固定规则已经确认：该响应包含“响应级加密包装”，同时具备加密开关、非明文算法声明和顶层编码载荷。你的任务仅是复核所给 JavaScript 证据是否能解释响应解密链路，并给出后续分析线索。

严格规则：
1. 不要重新判断响应是否加密；不要把业务字段、card_id、token、UUID、签名或任意长字符串升级为密文。
2. 只能依据已给 JavaScript 证据描述可能的解密链路；不要假设未提供的密钥、函数或算法。
3. encrypted 必须返回 true，表示“上游结构化规则已确认响应加密包装”，不是你的独立判定；它绝不代表漏洞成立或已经解密成功。
4. response_decryption_likely 仅评价 JS 是否显示响应解密链路；若证据不足使用 unknown。
5. recommended_action 只能是 continue_js_analysis 或 needs_runtime_capture，不能将已确认的包装降级为明文。

只输出严格 JSON，不要 Markdown。所有字段都必须存在；encrypted 和 response_decryption_likely 只能是 true、false 或 unknown 字符串；confidence 为 0 到 100 的整数；encoding 只能是 hex、base64、mixed、unknown；recommended_action 只能是 continue_js_analysis、needs_runtime_capture。

JSON 格式：
{"encrypted":"true","response_decryption_likely":"true|false|unknown","confidence":0,"encoding":"hex|base64|mixed|unknown","candidate_algorithms":[],"evidence":[],"reason":"","recommended_action":"continue_js_analysis|needs_runtime_capture"}`

	if len(targetURL) > 1000 {
		targetURL = targetURL[:1000] + "...(URL已截断)"
	}
	if len(requestPreview) > 2500 {
		requestPreview = requestPreview[:2500] + "...(请求已截断)"
	}
	if len(responsePreview) > 5000 {
		responsePreview = responsePreview[:5000] + "...(响应已截断)"
	}
	if len(jsEvidence) > 6000 {
		jsEvidence = jsEvidence[:6000] + "...(JS证据已截断)"
	}

	reply, err := c.chatComplete(
		systemPrompt,
		fmt.Sprintf("目标 URL：%s\n\n请求报文：\n%s\n\n响应报文：\n%s\n\n已采集 JavaScript 证据：\n%s", targetURL, requestPreview, responsePreview, jsEvidence),
		0.1,
		900,
	)
	if err != nil {
		return EncryptedResponseAIReview{}, err
	}

	jsonBytes, err := extractJSONObject(reply)
	if err != nil {
		return EncryptedResponseAIReview{}, fmt.Errorf("failed to parse encrypted response AI review: %w", err)
	}
	review, err := decodeEncryptedResponseAIReview(jsonBytes)
	if err != nil {
		return EncryptedResponseAIReview{}, fmt.Errorf("failed to decode encrypted response AI review: %w", err)
	}
	return review, nil
}

func (r UnauthorizedAIReview) IsFalsePositive() bool {
	return r.Verdict == "FALSE_POSITIVE" ||
		r.VulnerabilityType == "PUBLIC_API" ||
		r.VulnerabilityType == "BUSINESS_ERROR"
}

func validateUnauthorizedAIReview(review UnauthorizedAIReview) error {
	valid := func(value string, allowed ...string) bool {
		for _, item := range allowed {
			if value == item {
				return true
			}
		}
		return false
	}

	if !valid(review.Verdict, "CONFIRMED", "FALSE_POSITIVE", "NEEDS_MANUAL_REVIEW") {
		return fmt.Errorf("invalid unauthorized AI verdict %q", review.Verdict)
	}
	if !valid(review.VulnerabilityType,
		"UNAUTHENTICATED_ACCESS", "PRIVILEGE_ESCALATION", "IDOR",
		"INFORMATION_DISCLOSURE", "PUBLIC_API", "BUSINESS_ERROR", "UNKNOWN") {
		return fmt.Errorf("invalid unauthorized AI vulnerability type %q", review.VulnerabilityType)
	}
	if review.Confidence < 0 || review.Confidence > 100 {
		return fmt.Errorf("unauthorized AI confidence must be between 0 and 100")
	}
	if !valid(string(review.ProtectedResource), string(AITruthTrue), string(AITruthFalse), string(AITruthUnknown)) {
		return fmt.Errorf("invalid protected_resource value %q", review.ProtectedResource)
	}
	if !valid(string(review.SensitiveDataFound), string(AITruthTrue), string(AITruthFalse), string(AITruthUnknown)) {
		return fmt.Errorf("invalid sensitive_data_found value %q", review.SensitiveDataFound)
	}
	if review.VulnerabilityType == "PUBLIC_API" && review.SensitiveDataFound == AITruthTrue {
		return fmt.Errorf("public API cannot be marked as returning sensitive data")
	}
	if !valid(review.RiskLevel, "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE", "UNKNOWN") {
		return fmt.Errorf("invalid unauthorized AI risk level %q", review.RiskLevel)
	}
	if review.Verdict == "CONFIRMED" {
		if review.ProtectedResource != AITruthTrue {
			return fmt.Errorf("confirmed unauthorized access requires protected_resource=true")
		}
		if review.VulnerabilityType == "PUBLIC_API" || review.VulnerabilityType == "BUSINESS_ERROR" || review.VulnerabilityType == "UNKNOWN" {
			return fmt.Errorf("confirmed verdict cannot use vulnerability type %q", review.VulnerabilityType)
		}
		if len(review.Evidence) == 0 {
			return fmt.Errorf("confirmed unauthorized access requires evidence")
		}
	}
	return nil
}

var requiredUnauthorizedAIReviewFields = []string{
	"verdict", "vulnerability_type", "confidence", "protected_resource",
	"sensitive_data_found", "evidence", "reason", "impact", "risk_level",
	"missing_evidence", "recommended_action",
}

func decodeUnauthorizedAIReview(data []byte) (UnauthorizedAIReview, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return UnauthorizedAIReview{}, err
	}
	for _, field := range requiredUnauthorizedAIReviewFields {
		value, ok := raw[field]
		if !ok || strings.TrimSpace(string(value)) == "null" {
			return UnauthorizedAIReview{}, fmt.Errorf("missing required unauthorized AI review field %q", field)
		}
	}

	var review UnauthorizedAIReview
	if err := json.Unmarshal(data, &review); err != nil {
		return UnauthorizedAIReview{}, err
	}
	if err := validateUnauthorizedAIReview(review); err != nil {
		return UnauthorizedAIReview{}, err
	}
	return review, nil
}

func extractJSONObject(reply string) ([]byte, error) {
	jsonStart := strings.Index(reply, "{")
	jsonEnd := strings.LastIndex(reply, "}")
	if jsonStart == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("AI reply does not contain a JSON object")
	}
	return []byte(reply[jsonStart : jsonEnd+1]), nil
}

// ReviewUnauthorizedAccess independently reviews an unauthenticated API
// candidate. A public API or a business error is not treated as a finding.
func (c *SensitiveInfoChecker) ReviewUnauthorizedAccess(targetURL, requestPreview, responsePreview string) (UnauthorizedAIReview, error) {
	systemPrompt := `你是一名应用安全审计复核专家。请独立判断一个“未授权访问”候选是否是真实安全风险，不要默认接受扫描器结论。

只有同时满足以下条件，才能输出 verdict=CONFIRMED：
1. 请求未携带有效身份凭证，或当前身份权限不足；
2. 访问了按接口语义应受保护的资源，或执行了受限操作；
3. 响应包含敏感数据、他人数据、管理数据，或产生了实际安全影响。

以下情况不能单独证明漏洞成立：HTTP 200、未携带 Cookie/Token、动态加载、响应长度大于 0、路径包含 user/config/policy/admin、响应包含 code=0，或接口被前端调用。

应判定为 FALSE_POSITIVE 的典型情况：
- 登录前初始化、确实不含敏感字段的公开配置、CDN 地址、客户端版本、页面文案、帮助/协议/政策信息；
- 验证码、挑战、登录/注册/找回密码前置接口；
- 公开健康检查、公开字典或公共基础数据；
- HTTP 200 但业务码明确表示错误、data=null 或 no data；空数组本身不能单独证明是误报。

必须结合响应字段判断是否真的有敏感数据。不要因为出现 config、version、server、trace、user、policy 等关键词就推断高风险。无法证明资源受保护或影响时，输出 NEEDS_MANUAL_REVIEW，不得输出 CONFIRMED。

只输出严格 JSON，不要 Markdown，不要附加解释。所有字段都必须存在；confidence 是 0 到 100 的整数；protected_resource 和 sensitive_data_found 只能是 true、false 或 unknown 字符串；evidence 和 missing_evidence 必须是字符串数组。

JSON 格式：
{"verdict":"CONFIRMED|FALSE_POSITIVE|NEEDS_MANUAL_REVIEW","vulnerability_type":"UNAUTHENTICATED_ACCESS|PRIVILEGE_ESCALATION|IDOR|INFORMATION_DISCLOSURE|PUBLIC_API|BUSINESS_ERROR|UNKNOWN","confidence":0,"protected_resource":"true|false|unknown","sensitive_data_found":"true|false|unknown","evidence":[],"reason":"","impact":"","risk_level":"CRITICAL|HIGH|MEDIUM|LOW|INFO|NONE|UNKNOWN","missing_evidence":[],"recommended_action":""}`

	if len(targetURL) > 1000 {
		targetURL = targetURL[:1000] + "...(URL已截断)"
	}
	if len(requestPreview) > 2500 {
		requestPreview = requestPreview[:2500] + "...(请求已截断)"
	}
	if len(responsePreview) > 5000 {
		responsePreview = responsePreview[:5000] + "...(响应已截断)"
	}

	reply, err := c.chatComplete(
		systemPrompt,
		fmt.Sprintf("目标 URL：%s\n\n请求报文：\n%s\n\n响应报文：\n%s", targetURL, requestPreview, responsePreview),
		0.1,
		700,
	)
	if err != nil {
		return UnauthorizedAIReview{}, err
	}

	jsonBytes, err := extractJSONObject(reply)
	if err != nil {
		return UnauthorizedAIReview{}, fmt.Errorf("failed to parse unauthorized AI review: %w", err)
	}
	review, err := decodeUnauthorizedAIReview(jsonBytes)
	if err != nil {
		return UnauthorizedAIReview{}, fmt.Errorf("failed to decode unauthorized AI review: %w", err)
	}
	return review, nil
}

// NameUnauthorizedFinding supplies a bounded business label only after the
// scanner has independently recorded an unauthorized-access finding. It does
// not decide whether the vulnerability exists, its risk level, or confidence.
func (c *SensitiveInfoChecker) NameUnauthorizedFinding(targetURL, method, requestPreview, responsePreview, dataExposure string) (UnauthorizedFindingName, error) {
	fallback := ClassifyUnauthorizedFindingFallback(targetURL, method, responsePreview, dataExposure)
	if len(targetURL) > 1000 {
		targetURL = targetURL[:1000] + "...(URL已截断)"
	}
	if len(requestPreview) > 2500 {
		requestPreview = requestPreview[:2500] + "...(请求已截断)"
	}
	if len(responsePreview) > 5000 {
		responsePreview = responsePreview[:5000] + "...(响应已截断)"
	}

	systemPrompt := `你负责给已确认的未授权访问漏洞做业务命名。漏洞是否成立、风险等级和置信度均已由规则确认；你不能推翻或改变它们。

只根据给出的 URL、方法、请求、响应和数据暴露评级识别业务对象，并从指定小类中选择一个。禁止猜测未出现的业务、用户、金额、权限或影响。业务对象应是 2 至 32 个字符的简短中文名词短语，不含标点、换行或敏感内容；不确定时填写“业务资源”。

小类只能是：未授权敏感信息读取、未授权业务数据读取、未授权业务查询、未授权状态变更、未授权业务接口访问。
只输出严格 JSON，不要 Markdown 或其他文本：
{"category":"访问控制缺陷","subcategory":"上述之一","business_object":"简短业务对象"}`

	reply, err := c.chatComplete(
		systemPrompt,
		fmt.Sprintf("目标 URL：%s\n请求方法：%s\n数据暴露评级：%s\n\n请求报文：\n%s\n\n已验证响应：\n%s", targetURL, method, dataExposure, requestPreview, responsePreview),
		0,
		180,
	)
	if err != nil {
		return fallback, err
	}
	jsonBytes, err := extractJSONObject(reply)
	if err != nil {
		return fallback, fmt.Errorf("failed to parse unauthorized finding name: %w", err)
	}
	var raw struct {
		Category       string `json:"category"`
		Subcategory    string `json:"subcategory"`
		BusinessObject string `json:"business_object"`
	}
	if err := json.Unmarshal(jsonBytes, &raw); err != nil {
		return fallback, fmt.Errorf("failed to decode unauthorized finding name: %w", err)
	}
	name := normalizeUnauthorizedFindingName(UnauthorizedFindingName{
		Category:       raw.Category,
		Subcategory:    raw.Subcategory,
		BusinessObject: raw.BusinessObject,
		Source:         "ai",
	}, targetURL, method, responsePreview, dataExposure)
	if name.Source != "ai" {
		return fallback, fmt.Errorf("invalid unauthorized finding name from AI")
	}
	return name, nil
}

// JudgeDenyTemplate preserves the old API for callers that only need a
// boolean filter decision. New callers should use ReviewUnauthorizedAccess.
func (c *SensitiveInfoChecker) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	review, err := c.ReviewUnauthorizedAccess("", requestPreview, responsePreview)
	if err != nil {
		return false, "", err
	}
	return review.IsFalsePositive(), strings.TrimSpace(review.Reason), nil
}

// CheckFileUpload 使用AI检查文件上传响应是否表示上传成功
// 返回：(是否上传成功, 上传文件URL(如果有), 错误信息)
func (c *SensitiveInfoChecker) CheckFileUpload(responseBody, testFileName, testContent string) (bool, string, error) {
	// 获取并发许可
	sem <- struct{}{}
	defer func() {
		<-sem
	}()

	systemPrompt := `你是一个文件上传漏洞检测专家。用户会提供文件上传接口的HTTP响应内容，你需要判断文件是否成功上传。

判断标准：
1. TRUE（文件上传成功）的情况：
   - 响应中包含文件路径、文件URL、文件访问地址
   - 响应状态码为200/201且包含成功信息
   - 响应中包含上传的文件内容（如HTML内容）
   - JSON响应中包含url、path、fileUrl、file_url、filePath、file_path、location等字段
   - 响应明确表示上传成功（如"上传成功"、"upload success"等）

2. FALSE（文件上传失败）的情况：
   - 响应包含错误信息（如"文件类型不允许"、"文件过大"、"上传失败"等）
   - 响应状态码为4xx/5xx且无成功信息
   - 响应为空或只包含错误提示
   - 响应明确表示拒绝上传

请仔细分析响应内容，判断文件是否成功上传。如果上传成功，请提取文件URL或路径（如果有）。只回答JSON格式：{"success": true/false, "url": "文件URL或路径（如果有）"}，不要输出其他任何内容。`

	// 限制响应体长度，避免超出token限制
	responsePreview := responseBody
	if len(responsePreview) > 3000 {
		responsePreview = responsePreview[:3000] + "...(响应过长，已截断)"
	}

	userContent := fmt.Sprintf(`请分析以下文件上传接口的响应，判断文件是否成功上传：

测试文件名：%s
测试文件内容：%s

HTTP响应内容：
%s

请判断文件是否成功上传，如果成功，请提取文件URL或路径。`, testFileName, testContent, responsePreview)

	requestBody := map[string]interface{}{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": userContent},
		},
		"temperature": 0.1,
		"max_tokens":  200,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return false, "", err
	}

	req, err := http.NewRequestWithContext(c.ctx, "POST", c.baseURL+"/chat/completions", strings.NewReader(string(jsonData)))
	if err != nil {
		return false, "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, "", fmt.Errorf("API request failed: %d - %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, "", err
	}

	if len(result.Choices) == 0 {
		return false, "", fmt.Errorf("no choices returned from model")
	}

	reply := strings.TrimSpace(result.Choices[0].Message.Content)

	// 尝试解析JSON响应
	var aiResult struct {
		Success bool   `json:"success"`
		URL     string `json:"url"`
	}

	// 尝试提取JSON（可能包含markdown代码块）
	jsonStart := strings.Index(reply, "{")
	jsonEnd := strings.LastIndex(reply, "}")
	if jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart {
		jsonStr := reply[jsonStart : jsonEnd+1]
		if err := json.Unmarshal([]byte(jsonStr), &aiResult); err == nil {
			return aiResult.Success, aiResult.URL, nil
		}
	}

	// 如果无法解析JSON，尝试简单判断
	replyLower := strings.ToLower(reply)
	if strings.Contains(replyLower, `"success":true`) || strings.Contains(replyLower, "success: true") {
		// 尝试提取URL
		urlPattern := regexp.MustCompile(`"url"\s*:\s*"([^"]+)"`)
		if matches := urlPattern.FindStringSubmatch(reply); len(matches) > 1 {
			return true, matches[1], nil
		}
		return true, "", nil
	}

	return false, "", nil
}

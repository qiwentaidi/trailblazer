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

// JudgeDenyTemplate 使用 AI 判断未授权候选是否应作为误报过滤。
// 返回：(是否应过滤, 原因, 错误)
func (c *SensitiveInfoChecker) JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error) {
	systemPrompt := `你是一个 Web 安全漏洞复核专家。用户会提供一个接口请求报文和响应片段。请结合请求中的路径、查询参数、请求语义与响应内容，判断该未授权访问候选是否应当作为误报过滤。

判断为 TRUE（应过滤）的情况：
1. 响应核心语义是未登录、未授权、权限不足、token失效、认证失败、禁止访问、统一网关拒绝
2. 响应只是通用错误壳子，业务数据为空且没有真实业务字段含义
3. 响应明显是平台统一封装的拦截结果，而不是该接口自己的业务结果
4. 请求路径和响应片段共同表明这是无需登录即可调用的公共接口/能力，例如图形验证码、滑块/人机挑战、验证码会话或 challenge、登录/注册/找回密码前的短信或邮箱验证码发送、公开健康检查或公开基础配置。即使响应是 JSON，只要其业务语义是生成验证码、挑战令牌、验证码标识或临时校验材料，也应过滤。

判断为 FALSE（保留为未授权候选）的情况：
1. 响应明确表示 success / code=0 / ok=true / 查询成功 等正常业务语义
2. 响应中包含真实业务字段、业务对象、列表、统计值、配置项，即使 data 为空数组也仍可能是正常查询结果
3. 请求和响应可以对上真实业务接口语义，而不是统一的权限拒绝
4. 仅凭模糊路径或单个字段无法确认是公共能力时，优先返回 false，避免误伤真实业务数据

只输出 JSON，不要输出其他任何内容，格式固定为：
{"is_deny_template": true/false, "reason": "简短原因"}`

	if len(requestPreview) > 2000 {
		requestPreview = requestPreview[:2000] + "...(请求已截断)"
	}
	if len(responsePreview) > 3000 {
		responsePreview = responsePreview[:3000] + "...(响应已截断)"
	}

	reply, err := c.chatComplete(
		systemPrompt,
		fmt.Sprintf("请判断以下未授权访问候选是否应过滤。务必结合请求路径与响应片段识别公共接口/能力。\n\n请求报文：\n%s\n\n响应报文：\n%s", requestPreview, responsePreview),
		0.1,
		180,
	)
	if err != nil {
		return false, "", err
	}

	var result struct {
		IsDenyTemplate bool   `json:"is_deny_template"`
		Reason         string `json:"reason"`
	}

	jsonStart := strings.Index(reply, "{")
	jsonEnd := strings.LastIndex(reply, "}")
	if jsonStart != -1 && jsonEnd != -1 && jsonEnd > jsonStart {
		jsonStr := reply[jsonStart : jsonEnd+1]
		if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
			return result.IsDenyTemplate, strings.TrimSpace(result.Reason), nil
		}
	}

	replyLower := strings.ToLower(reply)
	if strings.Contains(replyLower, `"is_deny_template":true`) || strings.Contains(replyLower, `"is_deny_template": true`) {
		return true, "", nil
	}
	if strings.Contains(replyLower, `"is_deny_template":false`) || strings.Contains(replyLower, `"is_deny_template": false`) {
		return false, "", nil
	}

	return false, "", fmt.Errorf("failed to parse deny template judgement: %s", strings.TrimSpace(reply))
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

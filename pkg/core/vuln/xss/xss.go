package xss

import (
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	htmlparser "golang.org/x/net/html"
)

// XSSContext 表示payload在响应中的上下文类型
type XSSContext int

const (
	ContextHTMLText         XSSContext = iota // HTML文本节点
	ContextHTMLAttribute                      // HTML属性值
	ContextJavaScriptString                   // JavaScript字符串字面量
	ContextJavaScriptCode                     // JavaScript代码
	ContextCSS                                // CSS上下文
	ContextURL                                // URL上下文
	ContextHTMLComment                        // HTML注释
	ContextSafeTag                            // 安全标签（textarea, pre等）
)

// ContextInfo 表示上下文信息
type ContextInfo struct {
	ContextType   XSSContext
	TagName       string // 标签名（如果有）
	AttributeName string // 属性名（如果有）
	QuoteType     string // 引号类型（单引号、双引号、反引号或无）
	IsEscaped     bool   // 是否被转义
	Position      int    // payload在响应中的位置
	LocalContext  string // 局部上下文（用于转义判断）
}

// XSSResult 表示 XSS 测试结果
type XSSResult struct {
	Vulnerable        bool   `json:"vulnerable"`
	Payload           string `json:"payload"`
	Response          string `json:"response"`
	Reason            string `json:"reason"`
	Type              string `json:"type"` // 漏洞类型：reflected（仅支持反射型XSS检测）
	Confidence        string `json:"confidence,omitempty"`
	ConfidenceReason  string `json:"confidence_reason,omitempty"`
	ExecutionVerified bool   `json:"execution_verified,omitempty"`
}

type xssExecutionVerifier func(apiReq structs.APIRequest, payload, responseBody string) bool

var browserXSSVerifier xssExecutionVerifier = verifyReflectedXSSExecutionInBrowser

// TestXSS 测试跨站脚本攻击漏洞
// apiReq: 原始 API 请求
// cfg: XSS配置（包含payloads、匹配关键词）
// returns: XSSResult 测试结果
func TestXSS(apiReq structs.APIRequest, cfg config.XSSConfig) (*XSSResult, error) {
	if !cfg.Enabled {
		return &XSSResult{
			Vulnerable: false,
			Reason:     "XSS检测未启用",
			Confidence: "low",
		}, nil
	}

	paramNames := make([]string, 0, len(apiReq.Params))
	for paramName := range apiReq.Params {
		paramNames = append(paramNames, paramName)
	}
	if len(paramNames) == 0 {
		return nil, nil
	}

	rules := cfg.Rules
	if len(rules) == 0 {
		payloads := cfg.Payloads
		if len(payloads) == 0 {
			marker := buildExecutionMarker("default")
			snippet := buildExecutionSnippet(marker)
			payloads = []string{
				"<script>" + snippet + "</script>",
				"<img src=x onerror=\"" + snippet + "\">",
				"<svg onload=\"" + snippet + "\">",
				"javascript:" + snippet,
				"'><script>" + snippet + "</script>",
				"\"><script>" + snippet + "</script>",
				"<body onload=\"" + snippet + "\">",
				"<iframe src=\"javascript:" + snippet + "\">",
			}
		}
		for _, p := range payloads {
			rules = append(rules, config.XSSPayloadRule{
				Payloads: []string{p},
				Type:     "reflected",
			})
		}
	}

	for _, paramName := range paramNames {
		probeReq := apiReq
		if probeReq.Params == nil {
			probeReq.Params = make(map[string][]string)
		}
		probePayload := "XSS_PROBE_TRAILBLAZER_" + paramName
		probeReq.Params[paramName] = []string{probePayload}

		resp, err := vuln.SendAPIRequest(probeReq, false)
		if err != nil {
			continue
		}

		body := string(resp.Body())
		if !isLikelyRenderableHTMLResponse(resp.Header().Get("Content-Type"), body) {
			continue
		}
		if !strings.Contains(body, probePayload) {
			continue
		}

		contextInfo := analyzeContext(body, probePayload)
		if contextInfo.ContextType == ContextHTMLComment ||
			contextInfo.ContextType == ContextSafeTag ||
			contextInfo.IsEscaped {
			continue
		}

		payloadList := make([]string, 0, len(rules)+4)
		contextualPayloads := generateContextualPayloads(contextInfo)
		if len(contextualPayloads) > 0 {
			payloadList = append(payloadList, contextualPayloads...)
		}
		for _, rule := range rules {
			if len(rule.Payloads) > 0 {
				payloadList = append(payloadList, rule.Payloads...)
			} else if rule.Payload != "" {
				payloadList = append(payloadList, rule.Payload)
			}
		}
		if len(payloadList) == 0 {
			marker := buildExecutionMarker(paramName)
			snippet := buildExecutionSnippet(marker)
			payloadList = []string{
				"<script>" + snippet + "</script>",
				"<img src=x onerror=\"" + snippet + "\">",
				"<svg onload=\"" + snippet + "\">",
			}
		}

		for _, payload := range payloadList {
			testReq := apiReq
			if testReq.Params == nil {
				testReq.Params = make(map[string][]string)
			}
			for key, values := range apiReq.Params {
				testReq.Params[key] = append([]string(nil), values...)
			}
			testReq.Params[paramName] = []string{payload}

			resp, err := vuln.SendAPIRequest(testReq, false)
			if err != nil {
				continue
			}
			testBody := string(resp.Body())
			if !isLikelyRenderableHTMLResponse(resp.Header().Get("Content-Type"), testBody) {
				continue
			}

			vulnerable := isReflectedXSSAdvanced(testBody, payload, contextInfo)
			if !vulnerable {
				continue
			}

			verified := false
			if browserXSSVerifier != nil {
				verified = browserXSSVerifier(testReq, payload, testBody)
			}
			if !verified {
				continue
			}

			confidence, confidenceReason := assessXSSConfidence(contextInfo, payload, verified)
			return &XSSResult{
				Vulnerable:        true,
				Payload:           payload,
				Response:          vuln.TruncateResponse(testBody),
				Reason:            fmt.Sprintf("检测到反射型XSS漏洞 (参数: %s, 上下文: %s)", paramName, getContextName(contextInfo.ContextType)),
				Type:              "reflected",
				Confidence:        confidence,
				ConfidenceReason:  confidenceReason,
				ExecutionVerified: verified,
			}, nil
		}
	}

	return &XSSResult{
		Vulnerable: false,
		Payload:    "",
		Response:   "",
		Reason:     "未检测到XSS漏洞",
		Type:       "",
		Confidence: "low",
	}, nil
}

// analyzeContext 分析payload在响应中的上下文（改进版：使用HTML解析器+局部转义判断）
func analyzeContext(body, payload string) ContextInfo {
	info := ContextInfo{
		ContextType: ContextHTMLText,
		Position:    strings.Index(body, payload),
	}

	if info.Position == -1 {
		return info
	}

	// 提取局部上下文（前后各500字符，用于转义判断）
	start := max(info.Position-500, 0)
	end := info.Position + len(payload) + 500
	if end > len(body) {
		end = len(body)
	}
	info.LocalContext = body[start:end]
	contextBefore := body[start:info.Position]
	contextAfter := body[info.Position+len(payload) : end]

	// 改进的转义判断：只在局部上下文中检查
	info.IsEscaped = checkLocalEscaping(info.LocalContext, payload)

	// 首先尝试使用HTML解析器进行精确识别
	if htmlInfo := analyzeContextWithHTMLParser(body, payload, info.Position); htmlInfo.ContextType != ContextHTMLText || htmlInfo.TagName != "" {
		htmlInfo.Position = info.Position
		htmlInfo.LocalContext = info.LocalContext
		htmlInfo.IsEscaped = info.IsEscaped
		return htmlInfo
	}

	// 如果HTML解析器无法识别，回退到启发式方法
	contextLower := strings.ToLower(contextBefore + contextAfter)
	payloadLower := strings.ToLower(payload)

	// 检查是否在HTML注释中
	if isInHTMLComment(contextBefore, contextAfter) {
		info.ContextType = ContextHTMLComment
		return info
	}

	// 检查是否在安全标签中
	if isInSafeTag(contextBefore, contextAfter) {
		info.ContextType = ContextSafeTag
		return info
	}

	// 改进的JavaScript字符串检测（支持反引号、转义字符）
	if jsInfo := analyzeJavaScriptContext(contextBefore, contextAfter, payload); jsInfo.ContextType != ContextHTMLText {
		jsInfo.Position = info.Position
		jsInfo.LocalContext = info.LocalContext
		jsInfo.IsEscaped = info.IsEscaped
		return jsInfo
	}

	// 检查是否在HTML属性中（改进：统一大小写处理）
	payloadPrefix := payloadLower[:min(10, len(payloadLower))]
	attrPattern := regexp.MustCompile(`(?i)<(\w+)[^>]*\s+(\w+)\s*=\s*([^"'>\s]*?)` + regexp.QuoteMeta(payloadPrefix))
	if match := attrPattern.FindStringSubmatch(contextBefore + contextAfter); len(match) > 3 {
		info.ContextType = ContextHTMLAttribute
		info.TagName = strings.ToLower(match[1])
		info.AttributeName = strings.ToLower(match[2])
		// 检测引号类型
		attrValue := match[3]
		if strings.Contains(attrValue, `"`) {
			info.QuoteType = `"`
		} else if strings.Contains(attrValue, `'`) {
			info.QuoteType = `'`
		} else if strings.Contains(attrValue, "`") {
			info.QuoteType = "`"
		}
		return info
	}

	// 检查是否在URL中（改进：统一大小写处理）
	urlPattern := regexp.MustCompile(`(?i)(href|src|action|url)\s*=\s*[^"'>]*` + regexp.QuoteMeta(payloadPrefix))
	if urlPattern.MatchString(contextLower) {
		info.ContextType = ContextURL
		return info
	}

	// 检查是否在JavaScript代码中（不在字符串中）
	jsCodePattern := regexp.MustCompile(`(?i)<script[^>]*>.*?` + regexp.QuoteMeta(payloadPrefix))
	if jsCodePattern.MatchString(contextLower) {
		info.ContextType = ContextJavaScriptCode
		return info
	}

	return info
}

// generateContextualPayloads 根据上下文生成针对性的payload（改进：使用唯一标记替代alert）
func generateContextualPayloads(context ContextInfo) []string {
	marker := buildExecutionMarker(context.AttributeName + context.TagName + getContextName(context.ContextType))
	snippet := buildExecutionSnippet(marker)
	payloads := []string{}

	switch context.ContextType {
	case ContextHTMLText:
		// HTML文本节点：可以使用各种标签
		payloads = append(payloads,
			"<script>"+snippet+"</script>",
			"<img src=x onerror=\""+snippet+"\">",
			"<svg onload=\""+snippet+"\">",
			"<body onload=\""+snippet+"\">",
			"<iframe src=\"javascript:"+snippet+"\">",
		)

	case ContextHTMLAttribute:
		// HTML属性：需要闭合引号和标签
		quote := context.QuoteType
		if quote == "" {
			quote = `"`
		}
		// 针对不同属性生成不同的payload
		if context.AttributeName == "href" || context.AttributeName == "src" || context.AttributeName == "action" {
			// URL属性：使用javascript:伪协议
			payloads = append(payloads,
				"javascript:"+snippet,
			)
		} else {
			// 其他属性：闭合引号并添加事件处理器
			payloads = append(payloads,
				quote+" onmouseover=\""+snippet+"\" x="+quote,
				quote+" onclick=\""+snippet+"\" x="+quote,
				quote+"><script>"+snippet+"</script>"+quote,
			)
		}

	case ContextJavaScriptString:
		// JavaScript字符串：需要闭合字符串并执行代码（支持单引号、双引号、反引号）
		quote := context.QuoteType
		if quote == "" {
			// 尝试单引号、双引号和反引号
			payloads = append(payloads,
				"';"+snippet+";//",
				"\";"+snippet+";//",
				"`;"+snippet+";//",
				"'-"+snippet+"-'",
				`"-`+snippet+`-"`,
				"`-"+snippet+"-`",
			)
		} else {
			payloads = append(payloads,
				quote+";"+snippet+";//",
				quote+"-"+snippet+"-"+quote,
			)
		}

	case ContextJavaScriptCode:
		// JavaScript代码：可以直接执行
		payloads = append(payloads,
			snippet,
			"("+snippet+")",
			"eval("+strconv.Quote(snippet)+")",
		)

	case ContextURL:
		// URL上下文：使用javascript:伪协议
		payloads = append(payloads,
			"javascript:"+snippet,
		)

	default:
		// 默认payload
		payloads = append(payloads,
			"<script>"+snippet+"</script>",
			"<img src=x onerror=\""+snippet+"\">",
		)
	}

	return payloads
}

// isReflectedXSSAdvanced 改进的反射型XSS检测，基于上下文信息（改进：使用局部转义判断+编码检测）
func isReflectedXSSAdvanced(body, payload string, context ContextInfo) bool {
	// 检查payload是否在响应中（支持多种编码形式）
	if !containsPayloadInAnyForm(body, payload) {
		return false
	}

	// 改进的转义判断：使用局部上下文
	if context.LocalContext != "" {
		if checkLocalEscaping(context.LocalContext, payload) {
			return false
		}
	} else {
		// 回退到全局检查
		escapedPayload := html.EscapeString(payload)
		if strings.Contains(body, escapedPayload) {
			originalCount := strings.Count(body, payload)
			escapedCount := strings.Count(body, escapedPayload)
			if originalCount <= escapedCount {
				return false
			}
		}
	}

	// 根据上下文类型进行更精确的检测
	switch context.ContextType {
	case ContextHTMLText:
		// HTML文本：检查是否在可执行的标签中
		return containsExecutablePattern(body, payload)

	case ContextHTMLAttribute:
		// HTML属性：检查是否成功闭合引号并添加了事件处理器
		return checkAttributeXSS(body, payload, context)

	case ContextJavaScriptString:
		// JavaScript字符串：检查是否成功闭合字符串并执行代码
		return checkJSStringXSS(body, payload, context)

	case ContextJavaScriptCode:
		// JavaScript代码：检查是否成功执行
		return checkJSCodeXSS(body, payload)

	case ContextURL:
		// URL：检查是否包含javascript:协议
		return checkURLXSS(body, payload)

	default:
		// 默认检测
		return containsExecutablePattern(body, payload)
	}
}

// checkAttributeXSS 检查属性中的XSS
func checkAttributeXSS(body, payload string, context ContextInfo) bool {
	marker := extractExecutionMarker(payload)
	if marker == "" {
		return false
	}

	// 检查payload是否包含事件处理器或闭合引号
	payloadLower := strings.ToLower(payload)
	if strings.Contains(payloadLower, "on") && strings.Contains(payloadLower, "=") {
		// 检查是否匹配事件处理器模式
		pattern := regexp.MustCompile(`(?i)on\w+\s*=\s*["'][^"']*__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"][^"']*["']`)
		return pattern.MatchString(body)
	}
	// 检查是否闭合了引号
	if strings.Contains(payload, `">`) || strings.Contains(payload, `'>`) {
		return containsExecutablePattern(body, payload)
	}
	return false
}

// checkJSStringXSS 检查JavaScript字符串中的XSS（改进：使用唯一标记检测）
func checkJSStringXSS(body, payload string, context ContextInfo) bool {
	marker := extractExecutionMarker(payload)
	if marker == "" {
		return false
	}

	// 检查是否闭合了字符串并执行了代码
	if strings.Contains(payload, ";") || strings.Contains(payload, "//") {
		pattern := regexp.MustCompile(`(?s)<script[^>]*>.*?__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"].*?</script>`)
		return pattern.MatchString(body)
	}
	return false
}

// checkJSCodeXSS 检查JavaScript代码中的XSS（改进：使用唯一标记检测）
func checkJSCodeXSS(body, payload string) bool {
	marker := extractExecutionMarker(payload)
	if marker == "" {
		return false
	}
	pattern := regexp.MustCompile(`(?s)<script[^>]*>.*?__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"].*?</script>`)
	return pattern.MatchString(body)
}

// checkURLXSS 检查URL中的XSS（改进：使用唯一标记检测）
func checkURLXSS(body, payload string) bool {
	// 检查是否包含javascript:协议
	if strings.Contains(strings.ToLower(payload), "javascript:") {
		marker := extractExecutionMarker(payload)
		if marker == "" {
			return false
		}
		pattern := regexp.MustCompile(`(?i)javascript\s*:[^"'>]*__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"][^"'>]*`)
		return pattern.MatchString(body)
	}
	return false
}

// getContextName 获取上下文名称
func getContextName(ctx XSSContext) string {
	switch ctx {
	case ContextHTMLText:
		return "HTML文本"
	case ContextHTMLAttribute:
		return "HTML属性"
	case ContextJavaScriptString:
		return "JavaScript字符串"
	case ContextJavaScriptCode:
		return "JavaScript代码"
	case ContextCSS:
		return "CSS"
	case ContextURL:
		return "URL"
	case ContextHTMLComment:
		return "HTML注释"
	case ContextSafeTag:
		return "安全标签"
	default:
		return "未知"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isInHTMLComment 检查payload是否在HTML注释中
func isInHTMLComment(before, after string) bool {
	// 检查前面是否有 <!-- 且后面没有对应的 -->
	beforeLower := strings.ToLower(before)
	afterLower := strings.ToLower(after)

	// 查找最近的一个 <!--
	lastCommentStart := strings.LastIndex(beforeLower, "<!--")
	if lastCommentStart != -1 {
		// 检查是否有对应的 -->
		commentEnd := strings.Index(afterLower, "-->")
		if commentEnd == -1 {
			// 没有找到对应的结束标签，说明payload在注释中
			return true
		}
	}

	return false
}

// isInSafeTag 检查payload是否在安全的HTML标签中（如textarea、pre等）
func isInSafeTag(before, after string) bool {
	safeTags := []string{"textarea", "pre", "code", "style"}
	beforeLower := strings.ToLower(before)
	afterLower := strings.ToLower(after)

	for _, tag := range safeTags {
		// 检查是否有未闭合的 <textarea> 等标签
		openTag := "<" + tag
		closeTag := "</" + tag + ">"

		lastOpen := strings.LastIndex(beforeLower, openTag)
		if lastOpen != -1 {
			// 检查在openTag之后是否有对应的closeTag
			closePos := strings.Index(afterLower, closeTag)
			if closePos == -1 {
				// 没有找到闭合标签，说明在安全标签内
				return true
			}
		}
	}

	return false
}

// containsExecutablePattern 检查payload的关键部分是否以可执行的形式出现
func containsExecutablePattern(body, payload string) bool {
	// 提取payload中的关键结构
	payloadLower := strings.ToLower(payload)
	marker := extractExecutionMarker(payload)
	if marker == "" {
		return false
	}

	// 检查常见的可执行模式（改进：使用唯一标记）
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?is)<script[^>]*>[^<]*__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"][^<]*</script>`),
		regexp.MustCompile(`(?i)on\w+\s*=\s*["'][^"']*__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"][^"']*["']`),
		// javascript: 伪协议
		regexp.MustCompile(`(?i)javascript\s*:[^"'>]*__TB_XSS_HIT__\s*=\s*['"]` + regexp.QuoteMeta(marker) + `['"][^"'>]*`),
	}

	// 检查payload是否包含这些模式的关键词
	hasScript := strings.Contains(payloadLower, "<script") || strings.Contains(payloadLower, "onerror") ||
		strings.Contains(payloadLower, "onload") || strings.Contains(payloadLower, "javascript:") ||
		strings.Contains(payloadLower, "<img") || strings.Contains(payloadLower, "<svg") ||
		strings.Contains(payloadLower, "<body") || strings.Contains(payloadLower, "<iframe") ||
		strings.Contains(payloadLower, "__tb_xss_hit__")

	if !hasScript {
		return false
	}

	for _, pattern := range patterns {
		matches := pattern.FindAllString(body, -1)
		for _, match := range matches {
			if strings.Contains(match, marker) {
				return true
			}
		}
	}

	return false
}

func buildExecutionMarker(seed string) string {
	normalized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, seed)
	if normalized == "" {
		normalized = "default"
	}
	return "TBXSS" + normalized + "HIT"
}

func buildExecutionSnippet(marker string) string {
	if marker == "" {
		marker = buildExecutionMarker("default")
	}
	return "window.__TB_XSS_HIT__=" + strconv.Quote(marker) + ";" +
		"document.documentElement.setAttribute('data-tb-xss-hit'," + strconv.Quote(marker) + ");"
}

func extractExecutionMarker(payload string) string {
	re := regexp.MustCompile(`__TB_XSS_HIT__\s*=\s*['"]([A-Za-z0-9]+)['"]`)
	match := re.FindStringSubmatch(payload)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

func isLikelyRenderableHTMLResponse(contentType, body string) bool {
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	bodyLower := strings.ToLower(strings.TrimSpace(body))

	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/json") ||
		strings.Contains(contentType, "application/javascript") ||
		strings.Contains(contentType, "text/javascript") ||
		strings.Contains(contentType, "text/plain") ||
		strings.Contains(contentType, "application/octet-stream") {
		return false
	}

	if strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/xhtml+xml") {
		return true
	}

	if strings.HasPrefix(bodyLower, "{") || strings.HasPrefix(bodyLower, "[") {
		return false
	}

	return strings.Contains(bodyLower, "<html") ||
		strings.Contains(bodyLower, "<body") ||
		strings.Contains(bodyLower, "<script") ||
		strings.Contains(bodyLower, "<div")
}

func shouldAttemptBrowserVerification(apiReq structs.APIRequest, responseBody string) bool {
	if strings.ToUpper(strings.TrimSpace(apiReq.Method)) != http.MethodGet {
		return false
	}

	if !isLikelyRenderableHTMLResponse("", responseBody) {
		return false
	}

	finalURL, _ := vuln.ResolveAPIRequestTransport(apiReq)
	return strings.HasPrefix(finalURL, "http://") || strings.HasPrefix(finalURL, "https://")
}

func assessXSSConfidence(context ContextInfo, payload string, executionVerified bool) (string, string) {
	if !executionVerified {
		return "low", "仅检测到结构特征，未完成浏览器执行验证"
	}

	reasons := []string{"浏览器执行验证成功"}
	switch context.ContextType {
	case ContextHTMLAttribute, ContextURL, ContextJavaScriptString, ContextJavaScriptCode:
		reasons = append(reasons, "命中高可利用上下文: "+getContextName(context.ContextType))
		return "high", strings.Join(reasons, "；")
	case ContextHTMLText:
		if strings.Contains(strings.ToLower(payload), "<script") ||
			strings.Contains(strings.ToLower(payload), "onerror") ||
			strings.Contains(strings.ToLower(payload), "onload") {
			reasons = append(reasons, "HTML 可执行标签已成功注入")
			return "high", strings.Join(reasons, "；")
		}
		reasons = append(reasons, "HTML 文本上下文执行成功")
		return "medium", strings.Join(reasons, "；")
	default:
		reasons = append(reasons, "上下文类型未完全识别，但执行结果已确认")
		return "medium", strings.Join(reasons, "；")
	}
}

// checkLocalEscaping 检查局部上下文中的转义情况（改进：只在局部范围内检查）
func checkLocalEscaping(localContext, payload string) bool {
	// 如果payload不包含需要转义的HTML特殊字符，不需要检查转义
	hasSpecialChars := strings.ContainsAny(payload, "<>\"'&")
	if !hasSpecialChars {
		return false
	}

	// 检查常见的转义形式
	escapedForms := []string{
		html.EscapeString(payload),                  // HTML实体转义
		strings.ReplaceAll(payload, "<", "\\u003C"), // Unicode转义
		strings.ReplaceAll(payload, "<", "%3C"),     // URL编码
		strings.ReplaceAll(payload, "<", "&lt;"),    // HTML实体
		strings.ReplaceAll(payload, ">", "&gt;"),    // HTML实体
		strings.ReplaceAll(payload, "\"", "&quot;"), // HTML实体
		strings.ReplaceAll(payload, "'", "&#39;"),   // HTML实体
	}

	originalCount := strings.Count(localContext, payload)
	for _, escaped := range escapedForms {
		// 如果转义形式与原始形式相同，跳过（说明没有转义）
		if escaped == payload {
			continue
		}
		escapedCount := strings.Count(localContext, escaped)
		// 如果转义形式的数量大于等于原始形式，说明被转义了
		if escapedCount > 0 && originalCount <= escapedCount {
			return true
		}
	}

	return false
}

// analyzeContextWithHTMLParser 使用HTML解析器分析上下文（改进：精确识别）
func analyzeContextWithHTMLParser(body, payload string, position int) ContextInfo {
	info := ContextInfo{
		ContextType: ContextHTMLText,
		Position:    position,
	}

	// 解析HTML
	doc, err := htmlparser.Parse(strings.NewReader(body))
	if err != nil {
		return info
	}

	// 查找包含payload的节点
	var foundNode *htmlparser.Node
	var foundInAttr string
	var foundTag string

	var walker func(*htmlparser.Node)
	walker = func(n *htmlparser.Node) {
		if foundNode != nil {
			return
		}

		// 检查文本节点
		if n.Type == htmlparser.TextNode && strings.Contains(n.Data, payload) {
			// 检查是否在注释中
			parent := n.Parent
			for parent != nil {
				if parent.Type == htmlparser.CommentNode {
					info.ContextType = ContextHTMLComment
					return
				}
				// 检查是否在安全标签中
				if parent.Type == htmlparser.ElementNode {
					tagName := strings.ToLower(parent.Data)
					if tagName == "textarea" || tagName == "pre" || tagName == "code" || tagName == "style" {
						info.ContextType = ContextSafeTag
						info.TagName = tagName
						return
					}
				}
				parent = parent.Parent
			}
			foundNode = n
			return
		}

		// 检查属性
		if n.Type == htmlparser.ElementNode {
			for _, attr := range n.Attr {
				if strings.Contains(attr.Val, payload) {
					foundNode = n
					foundInAttr = attr.Key
					foundTag = strings.ToLower(n.Data)
					info.ContextType = ContextHTMLAttribute
					info.TagName = foundTag
					info.AttributeName = strings.ToLower(foundInAttr)

					// 检测引号类型
					attrVal := attr.Val
					if strings.HasPrefix(attrVal, `"`) && strings.HasSuffix(attrVal, `"`) {
						info.QuoteType = `"`
					} else if strings.HasPrefix(attrVal, `'`) && strings.HasSuffix(attrVal, `'`) {
						info.QuoteType = `'`
					} else if strings.HasPrefix(attrVal, "`") && strings.HasSuffix(attrVal, "`") {
						info.QuoteType = "`"
					}

					// 检查是否是URL属性
					if foundInAttr == "href" || foundInAttr == "src" || foundInAttr == "action" {
						info.ContextType = ContextURL
					}

					return
				}
			}
		}

		// 检查script标签内容
		if n.Type == htmlparser.ElementNode && strings.ToLower(n.Data) == "script" {
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == htmlparser.TextNode && strings.Contains(c.Data, payload) {
					// 检查是否在字符串字面量中
					jsInfo := analyzeJavaScriptInScript(c.Data, payload)
					if jsInfo.ContextType != ContextHTMLText {
						info = jsInfo
						return
					}
					info.ContextType = ContextJavaScriptCode
					return
				}
			}
		}

		// 递归遍历子节点
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walker(c)
		}
	}

	walker(doc)
	return info
}

// analyzeJavaScriptContext 分析JavaScript上下文（改进：支持反引号、转义字符）
func analyzeJavaScriptContext(before, after, payload string) ContextInfo {
	info := ContextInfo{
		ContextType: ContextHTMLText,
	}

	// 检查是否在 <script>...</script> 标签内
	beforeLower := strings.ToLower(before)
	scriptStart := strings.LastIndex(beforeLower, "<script")
	if scriptStart == -1 {
		return info
	}

	// 检查script标签后的内容
	scriptContent := beforeLower[scriptStart:]
	scriptEnd := strings.LastIndex(scriptContent, "</script>")
	if scriptEnd != -1 {
		// script标签已闭合，不在script内
		return info
	}

	// 在script标签内，使用状态机检测是否在字符串字面量中
	scriptText := before + payload + after
	jsInfo := analyzeJavaScriptInScript(scriptText, payload)
	if jsInfo.ContextType != ContextHTMLText {
		return jsInfo
	}

	// 如果不在字符串中，说明在JavaScript代码中
	info.ContextType = ContextJavaScriptCode
	return info
}

// analyzeJavaScriptInScript 分析script标签内的JavaScript代码（改进：支持反引号、转义字符）
func analyzeJavaScriptInScript(scriptContent, payload string) ContextInfo {
	info := ContextInfo{
		ContextType: ContextHTMLText,
	}

	payloadPos := strings.Index(scriptContent, payload)
	if payloadPos == -1 {
		return info
	}

	// 状态机：检测是否在字符串字面量中
	inString := false
	stringQuote := ""
	escapeNext := false

	for i := 0; i < payloadPos; i++ {
		char := scriptContent[i]

		if escapeNext {
			escapeNext = false
			continue
		}

		if char == '\\' {
			escapeNext = true
			continue
		}

		if !inString {
			// 不在字符串中，检查是否进入字符串
			if char == '"' || char == '\'' || char == '`' {
				inString = true
				stringQuote = string(char)
			}
		} else {
			// 在字符串中，检查是否退出字符串
			if char == stringQuote[0] {
				inString = false
				stringQuote = ""
			}
		}
	}

	if inString {
		info.ContextType = ContextJavaScriptString
		info.QuoteType = stringQuote
	}

	return info
}

// containsPayloadInAnyForm 检查payload是否以任何形式存在于响应中（改进：支持多种编码）
func containsPayloadInAnyForm(body, payload string) bool {
	// 直接匹配
	if strings.Contains(body, payload) {
		return true
	}

	// 检查HTML实体编码
	decoded := html.UnescapeString(body)
	if strings.Contains(decoded, payload) {
		return true
	}

	// 检查URL编码
	if decoded, err := url.QueryUnescape(body); err == nil {
		if strings.Contains(decoded, payload) {
			return true
		}
	}

	// 检查Unicode转义（\u003C等）
	unicodeDecoded := decodeUnicodeEscapes(body)
	if strings.Contains(unicodeDecoded, payload) {
		return true
	}

	return false
}

// decodeUnicodeEscapes 解码Unicode转义序列（如\u003C -> <）
func decodeUnicodeEscapes(s string) string {
	re := regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	return re.ReplaceAllStringFunc(s, func(match string) string {
		hex := match[2:]
		code, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return match
		}
		return string(rune(code))
	})
}

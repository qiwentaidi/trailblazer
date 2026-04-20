package unauth

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"trailblazer/pkg/core/structs"
	"trailblazer/pkg/core/vuln"
	"unicode"
)

var seenHTMLHashes = struct {
	sync.RWMutex
	items map[string]struct{}
}{
	items: make(map[string]struct{}),
}
var responseSignatureTracker = struct {
	sync.Mutex
	counts map[string]int
}{
	counts: make(map[string]int),
}

// 风险等级评估相关常量
const (
	maxAnalysisLength = 50000 // 50KB，风险等级分析时的最大响应体长度
)

type UnauthorizedAssessment struct {
	RiskLevel        string
	Confidence       string
	ConfidenceReason string
}

// 发送请求测试未授权访问
func TestUnauthorizedAccess(homeBody string, apiReq structs.APIRequest, authentication []string) (bool, string, UnauthorizedAssessment, error) {
	// 0. 检查URL路径，排除登录、验证码等本身就无需鉴权的接口
	if shouldSkipUnauthTest(apiReq.URL) {
		return false, "", UnauthorizedAssessment{}, errors.New("跳过测试：该接口本身就无需鉴权")
	}

	resp, err := vuln.SendAPIRequest(apiReq, true)
	if err != nil {
		return false, "", UnauthorizedAssessment{}, err
	}
	body := string(resp.Body())

	// 1. HTTP状态码异常，直接返回
	if resp.StatusCode() > 400 && resp.StatusCode() != 500 {
		return false, "", UnauthorizedAssessment{}, nil
	}

	if isHTMLResponse(body) {
		if !shouldTreatHTMLAsUnauthorized(body, apiReq.URL) {
			return false, "", UnauthorizedAssessment{}, errors.New("HTML响应缺少有效业务内容，疑似登录页、错误页或前端壳页")
		}

		hash := calcHash(body)

		// 如果已经出现过相同 HTML，说明是统一跳转页面（登录/错误），排除
		seenHTMLHashes.RLock()
		_, exists := seenHTMLHashes.items[hash]
		seenHTMLHashes.RUnlock()
		if exists {
			return false, "", UnauthorizedAssessment{}, errors.New("HTML响应与历史页面相同")
		}

		// 记录新的 HTML hash
		seenHTMLHashes.Lock()
		seenHTMLHashes.items[hash] = struct{}{}
		seenHTMLHashes.Unlock()
	}

	// 3. 页面相似度检查
	similarity := jaccardSimilarity(homeBody, body)
	if similarity >= 0.9 {
		return false, "", UnauthorizedAssessment{}, errors.New("页面内容相似度超过90%")
	}

	// 4. 关键词判断
	for _, auth := range authentication {
		if matched, err := regexp.MatchString(auth, body); matched && err == nil {
			return false, "", UnauthorizedAssessment{}, errors.New("检测到鉴权字段: " + auth)
		}
	}

	// 5. 评估风险等级
	riskLevel := assessRiskLevel(body, apiReq.URL)
	confidence, confidenceReason := assessConfidence(resp.StatusCode(), body, apiReq.URL)
	return true, body, UnauthorizedAssessment{
		RiskLevel:        riskLevel,
		Confidence:       confidence,
		ConfidenceReason: confidenceReason,
	}, nil
}

// 将文本分割成 shingle（n-gram 片段），用于计算相似度
func tokenize(text string, n int) map[string]struct{} {
	// 预处理文本，去除空格和标点
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			return r
		}
		return ' '
	}, text)
	words := strings.Fields(cleaned)

	// 生成 n-gram 片段
	tokens := make(map[string]struct{})
	for i := 0; i < len(words)-n+1; i++ {
		token := strings.Join(words[i:i+n], " ")
		tokens[token] = struct{}{}
	}
	return tokens
}

// 计算 Jaccard 相似度
func jaccardSimilarity(text1, text2 string) float64 {
	set1 := tokenize(text1, 3) // 3-gram
	set2 := tokenize(text2, 3)

	// 计算交集大小
	intersection := 0
	for token := range set1 {
		if _, exists := set2[token]; exists {
			intersection++
		}
	}

	// 计算并集大小
	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

func isHTMLResponse(body string) bool {
	bodyLower := strings.ToLower(body)
	return strings.Contains(bodyLower, "<html") || strings.Contains(bodyLower, "<body")
}

func shouldTreatHTMLAsUnauthorized(body, url string) bool {
	if !isHTMLResponse(body) {
		return false
	}

	if isLikelyAuthHTML(body, url) || isLikelyErrorHTML(body) || isLikelySPAShellHTML(body) {
		return false
	}

	return hasMeaningfulHTMLContent(body, url)
}

func isLikelyAuthHTML(body, url string) bool {
	bodyLower := strings.ToLower(body)
	urlLower := strings.ToLower(url)
	signals := []string{
		"login",
		"sign in",
		"signin",
		"log in",
		"password",
		"username",
		"captcha",
		"oauth",
		"sso",
		"unauthorized",
		"未登录",
		"请先登录",
		"登录",
		"验证码",
		"认证",
		"单点登录",
		"用户登录",
	}

	matchCount := 0
	for _, signal := range signals {
		if strings.Contains(bodyLower, signal) || strings.Contains(urlLower, signal) {
			matchCount++
		}
	}

	return matchCount >= 2
}

func isLikelyErrorHTML(body string) bool {
	bodyLower := strings.ToLower(body)
	signals := []string{
		"404",
		"403",
		"500",
		"error",
		"exception",
		"forbidden",
		"access denied",
		"bad request",
		"not found",
		"request rejected",
		"网关",
		"错误",
		"异常",
		"拒绝访问",
		"访问受限",
		"权限不足",
		"无权限",
		"系统错误",
	}

	matchCount := 0
	for _, signal := range signals {
		if strings.Contains(bodyLower, signal) {
			matchCount++
		}
	}

	return matchCount >= 2
}

func isLikelySPAShellHTML(body string) bool {
	bodyLower := strings.ToLower(body)
	visibleText := normalizeHTMLText(body)
	textLength := len([]rune(visibleText))

	rootMarkers := []string{
		`id="app"`,
		`id="root"`,
		`id="__next"`,
		`id="container"`,
		`data-reactroot`,
	}

	hasRoot := false
	for _, marker := range rootMarkers {
		if strings.Contains(bodyLower, marker) {
			hasRoot = true
			break
		}
	}

	scriptCount := strings.Count(bodyLower, "<script")
	hasBundleHint := strings.Contains(bodyLower, "chunk-vendors") ||
		strings.Contains(bodyLower, "/static/js/") ||
		strings.Contains(bodyLower, "webpack") ||
		strings.Contains(bodyLower, "vite") ||
		strings.Contains(bodyLower, "__next")

	return hasRoot && textLength < 120 && (scriptCount >= 1 || hasBundleHint)
}

func hasMeaningfulHTMLContent(body, url string) bool {
	bodyLower := strings.ToLower(body)
	text := normalizeHTMLText(body)
	textLower := strings.ToLower(text)
	textLength := len([]rune(text))

	if containsSensitiveTextPatterns(textLower) {
		return true
	}

	if hasStructuredBusinessHTML(bodyLower) && containsBusinessHTMLKeywords(textLower, url) {
		return true
	}

	if textLength >= 300 && containsBusinessHTMLKeywords(textLower, url) {
		return true
	}

	return false
}

func hasStructuredBusinessHTML(bodyLower string) bool {
	structuralSignals := 0
	for _, marker := range []string{"<table", "<tr", "<td", "<th", "<dl", "<dt", "<dd", "<article", "<section"} {
		if strings.Contains(bodyLower, marker) {
			structuralSignals++
		}
	}
	return structuralSignals >= 2
}

func containsBusinessHTMLKeywords(textLower, url string) bool {
	urlLower := strings.ToLower(url)
	keywords := []string{
		"admin", "dashboard", "console", "management", "backend",
		"user", "member", "customer", "employee", "staff", "account", "profile",
		"order", "invoice", "payment", "billing", "transaction",
		"email", "phone", "mobile", "address",
		"管理员", "后台", "控制台", "管理",
		"用户", "客户", "员工", "账号", "账户", "个人资料",
		"订单", "支付", "账单", "交易",
		"邮箱", "手机", "电话", "地址",
	}

	for _, keyword := range keywords {
		if strings.Contains(textLower, keyword) || strings.Contains(urlLower, keyword) {
			return true
		}
	}
	return false
}

func containsSensitiveTextPatterns(textLower string) bool {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}`),
		regexp.MustCompile(`1[3-9]\d{9}`),
		regexp.MustCompile(`(?i)(token|secret|api[_-]?key|access[_-]?key|password)\s*[:=]\s*[^\s]+`),
	}

	for _, pattern := range patterns {
		if pattern.MatchString(textLower) {
			return true
		}
	}
	return false
}

func normalizeHTMLText(body string) string {
	replacements := []struct {
		pattern *regexp.Regexp
		value   string
	}{
		{regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`), " "},
		{regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`), " "},
		{regexp.MustCompile(`(?is)<!--.*?-->`), " "},
		{regexp.MustCompile(`(?is)<[^>]+>`), " "},
	}

	normalized := body
	for _, item := range replacements {
		normalized = item.pattern.ReplaceAllString(normalized, item.value)
	}

	normalized = strings.ReplaceAll(normalized, "&nbsp;", " ")
	normalized = strings.ReplaceAll(normalized, "&amp;", "&")
	normalized = strings.ReplaceAll(normalized, "&lt;", "<")
	normalized = strings.ReplaceAll(normalized, "&gt;", ">")
	return strings.Join(strings.Fields(normalized), " ")
}

// 计算 hash
func calcHash(s string) string {
	h := sha1.New() // 也可以用 md5
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// shouldSkipUnauthTest 检查是否应该跳过未授权访问测试
// 排除登录、验证码等本身就无需鉴权的接口
func shouldSkipUnauthTest(url string) bool {
	// 将URL转换为小写进行匹配
	urlLower := strings.ToLower(url)

	// 定义需要跳过的路径关键词
	skipPatterns := []string{
		// 登录相关
		"/login",
		"/signin",
		"/oauth",
		"/sso",
		"/cas",
		"/saml",

		// 注册相关
		"/register",
		"/signup",

		// 验证码相关
		"/captcha",
		"/verify",
		"/code",
		"/validate",
		"/checkcode",
		"/vcode",
		"/kaptcha",

		// 公开信息相关
		"/public",
		"/about",
		"/contact",
		"/help",
		"/faq",
		"/terms",
		"/privacy",
		"/policy",

		// 静态资源相关
		"/static",
		"/assets",
		"/css",
		"/js",
		"/images",
		"/img",
		"/fonts",
		"/favicon",

		// 健康检查相关
		"/health",
		"/status",
		"/ping",
		"/heartbeat",
		"/monitor",

		// 版本信息相关
		"/version",
	}

	// 检查URL是否包含任何跳过模式
	for _, pattern := range skipPatterns {
		if strings.Contains(urlLower, pattern) {
			return true
		}
	}

	return false
}

// assessRiskLevel 根据响应体内容和URL评估风险等级
func assessRiskLevel(responseBody, url string) string {
	// 限制响应体长度，避免大量数据造成性能问题
	originalLength := len(responseBody)
	bodyLower := strings.ToLower(responseBody)

	if originalLength > maxAnalysisLength {
		// 检查是否为结构化数据（JSON/XML）
		startLen := int(float64(maxAnalysisLength) * 0.3)  // 15KB
		endLen := int(float64(maxAnalysisLength) * 0.2)    // 10KB
		middleLen := maxAnalysisLength - startLen - endLen // 25KB

		startPart := responseBody[:startLen]
		endPart := responseBody[originalLength-endLen:]
		middlePart := responseBody[startLen : startLen+middleLen]

		bodyLower = startPart + middlePart + endPart
	}

	urlLower := strings.ToLower(url)

	// 高危关键词
	highRiskKeywords := []string{
		// 敏感数据
		"password", "passwd", "pwd", "secret", "token", "key", "api_key", "access_key",
		"private", "confidential", "internal", "admin", "root", "user", "account",
		"credit", "card", "ssn", "social", "security", "bank", "financial",
		"database", "db", "sql", "mysql", "postgres", "oracle", "mongo",
		"config", "configuration", "settings", "env", "environment", "accesskey", "secretkey",

		// 系统信息
		"version", "build", "release", "deployment", "server", "host", "ip",
		"system", "os", "platform", "architecture", "hardware",

		// 业务敏感
		"order", "payment", "transaction", "invoice", "receipt", "billing",
		"customer", "client", "member", "employee", "staff", "personnel",
		"salary", "wage", "income", "revenue", "profit", "loss",

		// 安全相关
		"auth", "authorization", "permission", "role", "privilege", "access",
		"session", "cookie", "jwt", "oauth", "saml", "ldap",
		"firewall", "security", "vulnerability", "exploit", "attack",
	}

	// 中危关键词
	mediumRiskKeywords := []string{
		// 一般信息
		"profile", "personal", "contact", "address", "phone", "email",
		"name", "title", "description", "content", "message", "comment",
		"log", "history", "record", "track", "monitor", "status",
		"file", "document", "attachment", "upload", "download",

		// 业务一般信息
		"product", "service", "item", "category", "tag", "label",
		"news", "article", "post", "blog", "forum", "discussion",
		"event", "activity", "schedule", "calendar", "meeting",
	}

	// 低危关键词
	lowRiskKeywords := []string{
		// 公开信息
		"public", "open", "free", "available", "common", "general",
		"help", "faq", "support", "guide", "manual", "tutorial",
		"about", "company", "team", "organization", "institution",
		"home", "index", "main", "welcome", "intro", "overview",
	}

	// URL路径风险评估
	urlRiskScore := 0
	highRiskPaths := []string{"/admin", "/api/admin", "/management", "/control", "/dashboard", "/console", "/backend"}
	mediumRiskPaths := []string{"/api", "/v1", "/v2", "/user", "/account", "/profile"}
	lowRiskPaths := []string{"/public", "/static", "/assets", "/css", "/js", "/images"}

	for _, path := range highRiskPaths {
		if strings.Contains(urlLower, path) {
			urlRiskScore += 3
			break
		}
	}
	for _, path := range mediumRiskPaths {
		if strings.Contains(urlLower, path) {
			urlRiskScore += 2
			break
		}
	}
	for _, path := range lowRiskPaths {
		if strings.Contains(urlLower, path) {
			urlRiskScore += 1
			break
		}
	}

	// 响应体内容风险评估
	contentRiskScore := 0

	// 检查高危关键词
	for _, keyword := range highRiskKeywords {
		if strings.Contains(bodyLower, keyword) {
			contentRiskScore += 3
			break
		}
	}

	// 检查中危关键词
	if contentRiskScore == 0 {
		for _, keyword := range mediumRiskKeywords {
			if strings.Contains(bodyLower, keyword) {
				contentRiskScore += 2
				break
			}
		}
	}

	// 检查低危关键词
	if contentRiskScore == 0 {
		for _, keyword := range lowRiskKeywords {
			if strings.Contains(bodyLower, keyword) {
				contentRiskScore += 1
				break
			}
		}
	}

	// 响应体长度影响
	responseLength := len(responseBody)
	if responseLength > 10000 {
		contentRiskScore += 1 // 大响应体可能包含更多信息
	} else if responseLength < 100 {
		contentRiskScore -= 1 // 小响应体可能信息有限
	}

	// 检查是否包含错误信息
	if strings.Contains(bodyLower, "error") || strings.Contains(bodyLower, "exception") ||
		strings.Contains(bodyLower, "stack") || strings.Contains(bodyLower, "trace") {
		contentRiskScore += 1
	}

	// 综合评分
	totalScore := urlRiskScore + contentRiskScore

	// 根据总分确定风险等级
	if totalScore >= 5 {
		return "high"
	} else if totalScore >= 3 {
		return "medium"
	} else {
		return "low"
	}
}

func assessConfidence(statusCode int, responseBody, url string) (string, string) {
	score := 100
	reasons := []string{}
	bodyLower := strings.ToLower(strings.TrimSpace(responseBody))
	responseLength := len(responseBody)

	if responseLength <= 0 {
		return "low", "响应内容为空"
	}

	if responseLength < 120 {
		score -= 20
		reasons = append(reasons, "响应体很短，可利用信息有限")
	} else if responseLength < 300 {
		score -= 10
		reasons = append(reasons, "响应体偏短，结果可能更像统一提示")
	}

	if statusCode == 500 {
		score -= 20
		reasons = append(reasons, "响应状态为 500，接口可能只是暴露通用异常")
	}

	if isLikelyGenericErrorResponse(bodyLower) {
		score -= 45
		reasons = append(reasons, "响应内容命中通用错误特征，疑似统一报错或访问限制提示")
	}

	repeatCount := recordResponseSignature(statusCode, responseBody)
	switch {
	case repeatCount >= 10:
		score -= 45
		reasons = append(reasons, fmt.Sprintf("相同响应特征已重复出现 %d 次，批量误报概率较高", repeatCount))
	case repeatCount >= 5:
		score -= 30
		reasons = append(reasons, fmt.Sprintf("相同响应特征已重复出现 %d 次，结果区分度较低", repeatCount))
	case repeatCount >= 3:
		score -= 15
		reasons = append(reasons, fmt.Sprintf("相同响应特征已重复出现 %d 次，需要结合业务复核", repeatCount))
	}

	if containsMeaningfulDataSignals(bodyLower, url) {
		score += 10
		reasons = append(reasons, "响应中包含结构化业务字段，存在真实数据返回迹象")
	}

	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	switch {
	case score >= 75:
		return "high", strings.Join(reasons, "；")
	case score >= 45:
		return "medium", strings.Join(reasons, "；")
	default:
		return "low", strings.Join(reasons, "；")
	}
}

func recordResponseSignature(statusCode int, responseBody string) int {
	signature := buildResponseSignature(statusCode, responseBody)
	responseSignatureTracker.Lock()
	defer responseSignatureTracker.Unlock()
	responseSignatureTracker.counts[signature]++
	return responseSignatureTracker.counts[signature]
}

func buildResponseSignature(statusCode int, responseBody string) string {
	normalized := strings.ToLower(strings.TrimSpace(responseBody))
	normalized = strings.Join(strings.Fields(normalized), " ")
	if len(normalized) > 512 {
		normalized = normalized[:512]
	}
	return fmt.Sprintf("%d:%s", statusCode, normalized)
}

func isLikelyGenericErrorResponse(bodyLower string) bool {
	genericPatterns := []string{
		`"success":false`,
		`"success": false`,
		`"code":"err.common.system.error"`,
		`"code":500`,
		`"status":500`,
		`"error"`,
		`"exception"`,
		`系统错误`,
		`系统异常`,
		`server error`,
		`system error`,
		`internal error`,
		`稍后重试`,
		`forbidden`,
		`not allowed`,
		`无权限`,
		`权限不足`,
		`访问受限`,
	}

	matches := 0
	for _, pattern := range genericPatterns {
		if strings.Contains(bodyLower, pattern) {
			matches++
		}
	}
	return matches >= 2
}

func containsMeaningfulDataSignals(bodyLower, url string) bool {
	signals := []string{
		`"data":[`,
		`"data":{`,
		`"list":[`,
		`"rows":[`,
		`"total":`,
		`"items":[`,
		`"records":[`,
	}

	for _, signal := range signals {
		if strings.Contains(bodyLower, signal) {
			return true
		}
	}

	urlLower := strings.ToLower(url)
	return strings.Contains(urlLower, "/query") && responseHasObjectDensity(bodyLower)
}

func responseHasObjectDensity(bodyLower string) bool {
	return strings.Count(bodyLower, "{") >= 3 && strings.Count(bodyLower, ":") >= 6
}

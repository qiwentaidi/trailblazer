package unauth

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"trailblazer/pkg/core/database"
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
var learnedAuthPatternRegistry = struct {
	sync.RWMutex
	loaded   bool
	patterns []string
	index    map[string]struct{}
}{
	index: make(map[string]struct{}),
}

var learnableAuthPhrasePatterns = []*regexp.Regexp{
	regexp.MustCompile(`请先[^，。；,;\n\r"'\}\]\{]{0,32}(?:登录|认证|鉴权|授权)[^，。；,;\n\r"'\}\]\{]{0,32}`),
	regexp.MustCompile(`未登录[^，。；,;\n\r"'\}\]\{]{0,24}`),
	regexp.MustCompile(`(?:登录|认证|鉴权|授权)(?:已)?(?:失效|过期|失败)[^，。；,;\n\r"'\}\]\{]{0,24}`),
	regexp.MustCompile(`(?:token|session|jwt)[^,\.;\n\r]{0,24}(?:invalid|expired|missing|fail(?:ed)?|error)`),
	regexp.MustCompile(`(?:unauthorized|forbidden|access denied|permission denied)[^,\.;\n\r]{0,24}`),
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

	// 4. 鉴权拦截识别与自学习
	effectiveAuthPatterns := mergeAuthPatterns(authentication, currentLearnedAuthPatterns())
	if reject, reason := shouldRejectAsAuthResponse(resp.StatusCode(), body, apiReq.URL, effectiveAuthPatterns); reject {
		return false, "", UnauthorizedAssessment{}, errors.New(reason)
	}

	if reject, reason := shouldRejectUnauthorizedResponse(resp.StatusCode(), body, apiReq.URL); reject {
		return false, "", UnauthorizedAssessment{}, errors.New(reason)
	}

	// 5. 评估风险等级
	riskLevel := assessRiskLevel(body, apiReq.URL)
	confidence, confidenceReason := evaluateUnauthorizedConfidence(resp.StatusCode(), body, apiReq.URL)
	return true, body, UnauthorizedAssessment{
		RiskLevel:        riskLevel,
		Confidence:       confidence,
		ConfidenceReason: confidenceReason,
	}, nil
}

func mergeAuthPatterns(groups ...[]string) []string {
	merged := make([]string, 0)
	seen := make(map[string]struct{})
	for _, group := range groups {
		for _, pattern := range group {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}
			if _, exists := seen[pattern]; exists {
				continue
			}
			seen[pattern] = struct{}{}
			merged = append(merged, pattern)
		}
	}
	return merged
}

func currentLearnedAuthPatterns() []string {
	ensureLearnedAuthPatternsLoaded()

	learnedAuthPatternRegistry.RLock()
	defer learnedAuthPatternRegistry.RUnlock()
	if len(learnedAuthPatternRegistry.patterns) == 0 {
		return nil
	}

	patterns := make([]string, len(learnedAuthPatternRegistry.patterns))
	copy(patterns, learnedAuthPatternRegistry.patterns)
	return patterns
}

func ensureLearnedAuthPatternsLoaded() {
	learnedAuthPatternRegistry.RLock()
	loaded := learnedAuthPatternRegistry.loaded
	learnedAuthPatternRegistry.RUnlock()
	if loaded {
		return
	}

	patterns, err := database.ListEnabledLearnedAuthPatterns()
	if err != nil {
		return
	}

	learnedAuthPatternRegistry.Lock()
	defer learnedAuthPatternRegistry.Unlock()
	if learnedAuthPatternRegistry.loaded {
		return
	}

	learnedAuthPatternRegistry.patterns = normalizeUniquePatterns(patterns)
	learnedAuthPatternRegistry.index = make(map[string]struct{}, len(learnedAuthPatternRegistry.patterns))
	for _, pattern := range learnedAuthPatternRegistry.patterns {
		learnedAuthPatternRegistry.index[pattern] = struct{}{}
	}
	learnedAuthPatternRegistry.loaded = true
}

func normalizeUniquePatterns(patterns []string) []string {
	normalized := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if _, exists := seen[pattern]; exists {
			continue
		}
		seen[pattern] = struct{}{}
		normalized = append(normalized, pattern)
	}
	return normalized
}

func shouldRejectAsAuthResponse(statusCode int, responseBody, url string, authPatterns []string) (bool, string) {
	for _, auth := range authPatterns {
		if matched, err := regexp.MatchString(auth, responseBody); matched && err == nil {
			learnAuthPatternsFromResponse(statusCode, responseBody, url)
			return true, "检测到鉴权字段: " + auth
		}
	}

	if !isLikelyAuthenticationRequiredResponse(statusCode, responseBody, url) {
		return false, ""
	}

	learned := learnAuthPatternsFromResponse(statusCode, responseBody, url)
	if len(learned) == 0 {
		return true, "响应疑似鉴权拦截内容，判定为未授权误报"
	}
	return true, fmt.Sprintf("响应疑似鉴权拦截内容，已自动学习 %d 条鉴权特征", len(learned))
}

func isLikelyAuthenticationRequiredResponse(statusCode int, responseBody, url string) bool {
	bodyLower := strings.ToLower(strings.TrimSpace(responseBody))
	if bodyLower == "" {
		return false
	}

	if isLikelyAuthHTML(responseBody, url) {
		return true
	}

	if len(extractLearnableAuthPatterns(responseBody)) > 0 && !containsMeaningfulDataSignals(bodyLower, url) {
		return true
	}

	authSignalCount := countAuthenticationSignals(bodyLower, url)
	switch {
	case statusCode == 401 || statusCode == 403:
		return authSignalCount >= 1
	case authSignalCount >= 2 && !containsMeaningfulDataSignals(bodyLower, url):
		return true
	default:
		return false
	}
}

func countAuthenticationSignals(bodyLower, url string) int {
	urlLower := strings.ToLower(url)
	signals := []string{
		"unauthorized",
		"forbidden",
		"access denied",
		"permission denied",
		"login required",
		"sign in",
		"signin",
		"token expired",
		"token invalid",
		"session expired",
		"session invalid",
		"未登录",
		"请先登录",
		"登录后",
		"重新登录",
		"认证失败",
		"身份认证",
		"鉴权失败",
		"未授权",
		"权限不足",
		"拒绝访问",
		"访问受限",
		"令牌无效",
		"令牌过期",
		"会话失效",
	}

	count := 0
	seen := make(map[string]struct{}, len(signals))
	for _, signal := range signals {
		if _, exists := seen[signal]; exists {
			continue
		}
		if strings.Contains(bodyLower, signal) || strings.Contains(urlLower, signal) {
			seen[signal] = struct{}{}
			count++
		}
	}
	return count
}

func learnAuthPatternsFromResponse(statusCode int, responseBody, url string) []string {
	if !isLikelyAuthenticationRequiredResponse(statusCode, responseBody, url) {
		return nil
	}

	candidates := extractLearnableAuthPatterns(responseBody)
	if len(candidates) == 0 {
		return nil
	}

	source := strings.TrimSpace(url)
	learned := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if rememberLearnedAuthPattern(candidate, source) {
			learned = append(learned, candidate)
		}
	}
	return learned
}

func extractLearnableAuthPatterns(responseBody string) []string {
	text := responseBody
	if isHTMLResponse(responseBody) {
		text = normalizeHTMLText(responseBody)
	}
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return nil
	}

	var patterns []string
	seen := make(map[string]struct{})
	for _, matcher := range learnableAuthPhrasePatterns {
		matches := matcher.FindAllString(text, 8)
		for _, match := range matches {
			match = strings.TrimSpace(strings.Trim(match, `"'`))
			if !isGoodLearnableAuthPhrase(match) {
				continue
			}
			pattern := regexp.QuoteMeta(match)
			if _, exists := seen[pattern]; exists {
				continue
			}
			seen[pattern] = struct{}{}
			patterns = append(patterns, pattern)
		}
	}
	return patterns
}

func isGoodLearnableAuthPhrase(phrase string) bool {
	phrase = strings.TrimSpace(phrase)
	if phrase == "" {
		return false
	}
	length := len([]rune(phrase))
	if length < 4 || length > 48 {
		return false
	}

	bodyLower := strings.ToLower(phrase)
	if isLikelyGenericErrorResponse(bodyLower) && countAuthenticationSignals(bodyLower, "") < 2 {
		return false
	}

	return countAuthenticationSignals(bodyLower, "") >= 1
}

func rememberLearnedAuthPattern(pattern, source string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}

	learnedAuthPatternRegistry.Lock()
	if learnedAuthPatternRegistry.index == nil {
		learnedAuthPatternRegistry.index = make(map[string]struct{})
	}
	_, exists := learnedAuthPatternRegistry.index[pattern]
	if !exists {
		learnedAuthPatternRegistry.index[pattern] = struct{}{}
		learnedAuthPatternRegistry.patterns = append(learnedAuthPatternRegistry.patterns, pattern)
	}
	learnedAuthPatternRegistry.loaded = true
	learnedAuthPatternRegistry.Unlock()

	if err := database.UpsertLearnedAuthPattern(pattern, source); err != nil {
		return !exists
	}
	return !exists
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
	return assessConfidenceWithRepeatCount(statusCode, responseBody, url, recordResponseSignature(statusCode, responseBody))
}

func evaluateUnauthorizedConfidence(statusCode int, responseBody, url string) (string, string) {
	repeatCount := responseSignatureTrackerCurrentCount(statusCode, responseBody)
	if repeatCount == 0 {
		repeatCount = recordResponseSignature(statusCode, responseBody)
	}
	return assessConfidenceWithRepeatCount(statusCode, responseBody, url, repeatCount)
}

func shouldRejectUnauthorizedResponse(statusCode int, responseBody, url string) (bool, string) {
	bodyLower := strings.ToLower(strings.TrimSpace(responseBody))
	repeatCount := recordResponseSignature(statusCode, responseBody)

	if isLikelyGenericErrorResponse(bodyLower) {
		return true, "响应内容命中通用错误模板，判定为未授权误报"
	}

	if statusCode == 500 && !containsMeaningfulDataSignals(bodyLower, url) {
		return true, "响应状态为 500 且缺少有效业务数据，判定为未授权误报"
	}

	if repeatCount >= 3 && !containsMeaningfulDataSignals(bodyLower, url) {
		return true, fmt.Sprintf("相同响应模板已重复出现 %d 次且缺少有效业务数据，判定为未授权误报", repeatCount)
	}

	return false, ""
}

func responseSignatureTrackerCurrentCount(statusCode int, responseBody string) int {
	signature := buildResponseSignature(statusCode, responseBody)
	responseSignatureTracker.Lock()
	defer responseSignatureTracker.Unlock()
	return responseSignatureTracker.counts[signature]
}

func assessConfidenceWithRepeatCount(statusCode int, responseBody, url string, repeatCount int) (string, string) {
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

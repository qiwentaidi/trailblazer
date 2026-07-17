package unauth

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"mime"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
var responseTemplateTracker = struct {
	sync.Mutex
	clusters map[string][]responseTemplateCluster
}{
	clusters: make(map[string][]responseTemplateCluster),
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
	maxAnalysisLength             = 50000 // 50KB，风险等级分析时的最大响应体长度
	similarTemplateRejectCount    = 3
	similarTemplateJaccardMinimum = 0.88
)

type UnauthorizedAssessment struct {
	RiskLevel        string
	Confidence       string
	ConfidenceReason string
	DataExposure     string
	ExposureReason   string
	ResponseType     string
}

type responseRepeatObservation struct {
	ExactCount          int
	SimilarCount        int
	MatchedBySimilarity bool
}

type responseTemplateCluster struct {
	signature string
	tokens    map[string]struct{}
	count     int
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
	responseType := normalizeUnauthorizedResponseType(resp.Header().Get("Content-Type"))
	if reject, reason := shouldRejectUnauthorizedPayload(body); reject {
		return false, "", UnauthorizedAssessment{}, errors.New(reason)
	}

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
	dataExposure, exposureReason := classifyUnauthorizedExposure(body, apiReq.URL)
	riskLevel = adjustUnauthorizedRiskLevel(riskLevel, dataExposure)
	confidence, confidenceReason := evaluateUnauthorizedConfidence(resp.StatusCode(), body, apiReq.URL)
	return true, body, UnauthorizedAssessment{
		RiskLevel:        riskLevel,
		Confidence:       confidence,
		ConfidenceReason: confidenceReason,
		DataExposure:     dataExposure,
		ExposureReason:   exposureReason,
		ResponseType:     responseType,
	}, nil
}

// shouldRejectUnauthorizedPayload enforces the minimum evidence required for an
// unauthorized-access finding: the response must contain a non-trivial JSON or
// XML document. Binary, HTML, and plain-text responses are treated as false
// positives before any risk is recorded or sent to AI for review.
func shouldRejectUnauthorizedPayload(body string) (bool, string) {
	trimmed := strings.TrimSpace(body)
	if len([]byte(trimmed)) <= 2 {
		return true, "响应包内容过短，缺少可验证的业务数据"
	}

	if json.Valid([]byte(trimmed)) {
		return false, ""
	}

	if isHTMLResponse(trimmed) {
		return true, "响应包不是 JSON 或 XML 格式"
	}

	var document struct{}
	if err := xml.Unmarshal([]byte(trimmed), &document); err == nil {
		return false, ""
	}

	return true, "响应包不是 JSON 或 XML 格式"
}

func normalizeUnauthorizedResponseType(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	mediaType, _, err := mime.ParseMediaType(raw)
	if err == nil {
		return strings.ToLower(strings.TrimSpace(mediaType))
	}
	return strings.ToLower(raw)
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
func shouldSkipUnauthTest(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	pathRaw := strings.TrimSpace(rawURL)
	pathLower := strings.ToLower(pathRaw)
	if err == nil && parsed != nil {
		pathRaw = parsed.EscapedPath()
		if pathRaw == "" {
			pathRaw = parsed.Path
		}
		pathLower = strings.ToLower(pathRaw)
	}

	if pathLower == "" {
		return false
	}

	frameworkInternalPrefixes := []string{
		"/__next",
		"/__nextjs",
		"/_next",
		"/__vite",
		"/@vite",
		"/webpack-dev-server",
	}
	for _, prefix := range frameworkInternalPrefixes {
		if strings.HasPrefix(pathLower, prefix) {
			return true
		}
	}

	pathPrefixes := []string{
		"/public",
		"/about",
		"/contact",
		"/help",
		"/faq",
		"/terms",
		"/privacy",
		"/policy",
		"/static",
		"/assets",
		"/css",
		"/js",
		"/images",
		"/img",
		"/fonts",
		"/favicon",
		"/health",
		"/status",
		"/ping",
		"/heartbeat",
		"/monitor",
		"/version",
	}
	for _, prefix := range pathPrefixes {
		if pathLower == prefix || strings.HasPrefix(pathLower, prefix+"/") {
			return true
		}
	}

	tokens := extractURLWordTokens(pathRaw)
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}

	if hasAnyUnauthorizedSkipToken(tokenSet,
		"login", "signin", "logout", "signout",
		"oauth", "sso", "cas", "saml",
		"register", "signup", "resetpassword", "forgotpassword",
		"captcha", "kaptcha", "checkcode", "vcode",
	) {
		return true
	}

	if hasAnyUnauthorizedSkipToken(tokenSet, "otp", "totp") {
		return true
	}

	if hasAnyUnauthorizedSkipToken(tokenSet, "sms", "email", "mail") &&
		hasAnyUnauthorizedSkipToken(tokenSet, "code", "otp", "captcha") {
		return true
	}

	if hasAnyUnauthorizedSkipToken(tokenSet, "image", "img", "graphic") &&
		hasAnyUnauthorizedSkipToken(tokenSet, "code", "captcha") {
		return true
	}

	if hasAnyUnauthorizedSkipToken(tokenSet, "auth", "user", "account") &&
		hasAnyUnauthorizedSkipToken(tokenSet, "login", "signin", "register", "signup", "captcha", "otp") {
		return true
	}

	if hasAnyUnauthorizedSkipToken(tokenSet, "send", "get", "generate", "create", "refresh") &&
		hasAnyUnauthorizedSkipToken(tokenSet, "captcha", "otp") {
		return true
	}

	if hasAnyUnauthorizedSkipToken(tokenSet, "send", "get", "generate") &&
		hasAnyUnauthorizedSkipToken(tokenSet, "sms", "email", "mail") &&
		hasAnyUnauthorizedSkipToken(tokenSet, "code") {
		return true
	}

	return false
}

func extractURLWordTokens(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
	tokens := make([]string, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		tokens = append(tokens, splitIdentifierTokens(field)...)
	}
	return tokens
}

func splitIdentifierTokens(raw string) []string {
	if raw == "" {
		return nil
	}

	var tokens []string
	start := 0
	runes := []rune(raw)
	for i := 1; i < len(runes); i++ {
		prev := runes[i-1]
		curr := runes[i]
		nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])

		switch {
		case unicode.IsLower(prev) && unicode.IsUpper(curr):
			tokens = append(tokens, strings.ToLower(string(runes[start:i])))
			start = i
		case unicode.IsDigit(prev) != unicode.IsDigit(curr):
			tokens = append(tokens, strings.ToLower(string(runes[start:i])))
			start = i
		case unicode.IsUpper(prev) && unicode.IsUpper(curr) && nextIsLower:
			tokens = append(tokens, strings.ToLower(string(runes[start:i])))
			start = i
		}
	}
	tokens = append(tokens, strings.ToLower(string(runes[start:])))
	return tokens
}

func hasAnyUnauthorizedSkipToken(tokenSet map[string]struct{}, tokens ...string) bool {
	for _, token := range tokens {
		if _, ok := tokenSet[token]; ok {
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

func classifyUnauthorizedExposure(responseBody, url string) (string, string) {
	bodyLower := strings.ToLower(strings.TrimSpace(responseBody))
	urlLower := strings.ToLower(strings.TrimSpace(url))
	if bodyLower == "" {
		return "internal_business", "响应内容为空，默认按内部业务数据处理"
	}

	sensitiveScore := countUniqueIndicators(bodyLower, []string{
		`"phone"`, `"mobile"`, `"email"`, `"idcard"`, `"id_card"`, `"身份证"`,
		`"password"`, `"passwd"`, `"token"`, `"secret"`, `"apikey"`, `"api_key"`,
		`"accesskey"`, `"access_key"`, `"role"`, `"permission"`, `"user"`, `"username"`,
		`"account"`, `"customer"`, `"employee"`, `"staff"`, `"order"`, `"invoice"`,
		`"amount"`, `"balance"`, `"salary"`, `"bank"`, `"address"`,
	})
	if containsSensitiveTextPatterns(bodyLower) {
		sensitiveScore += 2
	}

	internalBusinessScore := countUniqueIndicators(bodyLower, []string{
		`"department"`, `"project"`, `"task"`, `"workflow"`, `"notice"`, `"record"`,
		`"detail"`, `"content"`, `"title"`, `"status"`, `"comment"`, `"creator"`,
		`"owner"`, `"member"`, `"tenant"`, `"org"`, `"organization"`, `"company"`,
		`"channel"`, `"source"`, `"business"`, `"审批"`, `"工单"`, `"客户"`, `"员工"`,
		`"部门"`, `"项目"`, `"任务"`, `"流程"`, `"租户"`, `"企业"`, `"组织"`,
	})
	if containsMeaningfulDataSignals(bodyLower, url) {
		internalBusinessScore += 2
	}

	dictFieldScore := countUniqueIndicators(bodyLower, []string{
		`"label"`, `"value"`, `"text"`, `"name"`, `"code"`, `"id"`,
		`"parentid"`, `"parent_id"`, `"sort"`, `"children"`, `"dictlabel"`, `"dictvalue"`,
		`"dict_label"`, `"dict_value"`, `"displayname"`, `"display_name"`,
	})
	geoScore := countUniqueIndicators(bodyLower, []string{
		`"city"`, `"province"`, `"district"`, `"county"`, `"region"`, `"street"`,
		`"town"`, `"village"`, `"zipcode"`, `"postal"`, `"lng"`, `"lat"`,
		`"城市"`, `"省"`, `"区"`, `"县"`, `"区域"`, `"街道"`, `"乡镇"`, `"经度"`, `"纬度"`,
	})

	publicPathScore := countUniqueIndicators(urlLower, []string{
		"/public", "/open", "/common", "/region", "/area", "/city", "/province",
		"/district", "/county", "/street", "/geo", "/metadata", "/meta",
	})
	basicPathScore := countUniqueIndicators(urlLower, []string{
		"/config", "/setting", "/lookup", "/list", "/tree", "/category", "/type",
		"/code", "/dictionary", "/dict", "/enum", "/option", "/select",
	})

	hasDictionaryShape := dictFieldScore >= 3 && strings.Count(bodyLower, "{") >= 2
	hasGeoDictionaryShape := (hasDictionaryShape || geoScore >= 3) && strings.Count(bodyLower, "{") >= 2
	publicScore := publicPathScore + geoScore
	basicScore := basicPathScore + dictFieldScore
	if hasDictionaryShape {
		publicScore += 2
		basicScore += 2
	}

	switch {
	case sensitiveScore >= 2:
		return "sensitive_data", "响应命中用户、凭据、资金或权限等敏感字段，按高价值数据暴露处理"
	case publicScore >= 4 && hasGeoDictionaryShape && sensitiveScore == 0:
		return "public_data", "响应更像公开基础地理或公共枚举数据，按公开数据暴露处理"
	case basicScore >= 6 && sensitiveScore == 0 && internalBusinessScore <= 2:
		return "basic_reference", "响应主要由字典、枚举或通用配置字段组成，按基础参考数据处理"
	case internalBusinessScore >= 2 || containsMeaningfulDataSignals(bodyLower, url):
		return "internal_business", "响应包含有效业务结构或内部业务字段，按内部业务数据暴露处理"
	default:
		return "internal_business", "接口返回有效内容但未命中公开数据特征，默认按内部业务数据处理"
	}
}

func adjustUnauthorizedRiskLevel(currentLevel, dataExposure string) string {
	switch strings.TrimSpace(dataExposure) {
	case "public_data":
		return "info"
	case "basic_reference":
		return lowerRiskLevel(currentLevel, "low")
	case "internal_business":
		return raiseRiskLevel(currentLevel, "medium")
	case "sensitive_data":
		return raiseRiskLevel(currentLevel, "high")
	default:
		return normalizeUnauthorizedRiskLevel(currentLevel)
	}
}

func raiseRiskLevel(currentLevel, minimumLevel string) string {
	if unauthorizedRiskLevelRank(currentLevel) >= unauthorizedRiskLevelRank(minimumLevel) {
		return normalizeUnauthorizedRiskLevel(currentLevel)
	}
	return normalizeUnauthorizedRiskLevel(minimumLevel)
}

func lowerRiskLevel(currentLevel, maximumLevel string) string {
	if unauthorizedRiskLevelRank(currentLevel) <= unauthorizedRiskLevelRank(maximumLevel) {
		return normalizeUnauthorizedRiskLevel(currentLevel)
	}
	return normalizeUnauthorizedRiskLevel(maximumLevel)
}

func normalizeUnauthorizedRiskLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(level))
	default:
		return "low"
	}
}

func unauthorizedRiskLevelRank(level string) int {
	switch normalizeUnauthorizedRiskLevel(level) {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	default:
		return 1
	}
}

func countUniqueIndicators(content string, indicators []string) int {
	count := 0
	seen := make(map[string]struct{}, len(indicators))
	for _, indicator := range indicators {
		if indicator == "" {
			continue
		}
		if _, exists := seen[indicator]; exists {
			continue
		}
		seen[indicator] = struct{}{}
		if strings.Contains(content, indicator) {
			count++
		}
	}
	return count
}

func assessConfidence(statusCode int, responseBody, url string) (string, string) {
	observation := recordResponseObservation(statusCode, responseBody, url)
	return assessConfidenceWithRepeatCount(statusCode, responseBody, url, observation)
}

func evaluateUnauthorizedConfidence(statusCode int, responseBody, url string) (string, string) {
	observation := responseObservationCurrentCount(statusCode, responseBody, url)
	if observation.ExactCount == 0 && observation.SimilarCount == 0 {
		observation = recordResponseObservation(statusCode, responseBody, url)
	}
	return assessConfidenceWithRepeatCount(statusCode, responseBody, url, observation)
}

func shouldRejectUnauthorizedResponse(statusCode int, responseBody, url string) (bool, string) {
	bodyLower := strings.ToLower(strings.TrimSpace(responseBody))
	observation := recordResponseObservation(statusCode, responseBody, url)

	if statusCode >= 400 && statusCode < 500 && !containsMeaningfulDataSignals(bodyLower, url) {
		return true, fmt.Sprintf("响应状态为 %d 且缺少有效业务数据，判定为未授权误报", statusCode)
	}

	if isLikelyGenericErrorResponse(bodyLower) {
		return true, "响应内容命中通用错误模板，判定为未授权误报"
	}

	if statusCode == 500 && !containsMeaningfulDataSignals(bodyLower, url) {
		return true, "响应状态为 500 且缺少有效业务数据，判定为未授权误报"
	}

	if observation.ExactCount >= similarTemplateRejectCount && !containsMeaningfulDataSignals(bodyLower, url) {
		return true, fmt.Sprintf("相同响应模板已重复出现 %d 次且缺少有效业务数据，判定为未授权误报", observation.ExactCount)
	}

	if observation.SimilarCount >= similarTemplateRejectCount &&
		observation.SimilarCount > observation.ExactCount &&
		!containsMeaningfulDataSignals(bodyLower, url) {
		return true, fmt.Sprintf("同目标相似响应模板已重复出现 %d 次且缺少有效业务数据，判定为未授权误报", observation.SimilarCount)
	}

	return false, ""
}

func responseSignatureTrackerCurrentCount(statusCode int, responseBody string) int {
	signature := buildResponseSignature(statusCode, responseBody)
	responseSignatureTracker.Lock()
	defer responseSignatureTracker.Unlock()
	return responseSignatureTracker.counts[signature]
}

func assessConfidenceWithRepeatCount(statusCode int, responseBody, url string, observation responseRepeatObservation) (string, string) {
	score := 100
	bodyLower := strings.ToLower(strings.TrimSpace(responseBody))
	responseLength := len(responseBody)

	if responseLength <= 0 {
		return "low", buildUnauthorizedConfidenceStatement("low")
	}

	if responseLength < 120 {
		score -= 20
	} else if responseLength < 300 {
		score -= 10
	}

	if statusCode == 500 {
		score -= 20
	}

	if isLikelyGenericErrorResponse(bodyLower) {
		score -= 45
	}

	repeatCount := observation.ExactCount
	if observation.SimilarCount > repeatCount {
		repeatCount = observation.SimilarCount
	}

	switch {
	case repeatCount >= 10:
		score -= 45
	case repeatCount >= 5:
		score -= 30
	case repeatCount >= 3:
		score -= 15
	}

	if containsMeaningfulDataSignals(bodyLower, url) {
		score += 10
	}

	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	switch {
	case score >= 75:
		return "high", buildUnauthorizedConfidenceStatement("high")
	case score >= 45:
		return "medium", buildUnauthorizedConfidenceStatement("medium")
	default:
		return "low", buildUnauthorizedConfidenceStatement("low")
	}
}

func buildUnauthorizedConfidenceStatement(confidence string) string {
	switch normalizeUnauthorizedRiskLevel(confidence) {
	case "high":
		return "高置信：响应包含明确业务数据返回"
	case "medium":
		return "中置信：存在数据返回，但与公开接口仍需区分"
	default:
		return "低置信：结果更像相似拒绝模板或通用错误响应"
	}
}

func recordResponseSignature(statusCode int, responseBody string) int {
	signature := buildResponseSignature(statusCode, responseBody)
	responseSignatureTracker.Lock()
	defer responseSignatureTracker.Unlock()
	responseSignatureTracker.counts[signature]++
	return responseSignatureTracker.counts[signature]
}

func responseObservationCurrentCount(statusCode int, responseBody, rawURL string) responseRepeatObservation {
	exactCount := responseSignatureTrackerCurrentCount(statusCode, responseBody)
	similarCount, matchedBySimilarity := responseTemplateTrackerCurrentCount(statusCode, responseBody, rawURL)
	return responseRepeatObservation{
		ExactCount:          exactCount,
		SimilarCount:        similarCount,
		MatchedBySimilarity: matchedBySimilarity,
	}
}

func recordResponseObservation(statusCode int, responseBody, rawURL string) responseRepeatObservation {
	exactCount := recordResponseSignature(statusCode, responseBody)
	similarCount, matchedBySimilarity := recordSimilarResponseTemplate(statusCode, responseBody, rawURL)
	return responseRepeatObservation{
		ExactCount:          exactCount,
		SimilarCount:        similarCount,
		MatchedBySimilarity: matchedBySimilarity,
	}
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

func responseTemplateTrackerCurrentCount(statusCode int, responseBody, rawURL string) (int, bool) {
	scope := buildResponseTemplateScope(statusCode, rawURL)
	signature := buildSimilarResponseSignature(responseBody)
	if signature == "" {
		return 0, false
	}

	tokens := tokenize(signature, 2)
	if len(tokens) == 0 {
		tokens = tokenize(signature, 1)
	}

	responseTemplateTracker.Lock()
	defer responseTemplateTracker.Unlock()

	clusters := responseTemplateTracker.clusters[scope]
	bestIndex := -1
	bestSimilarity := 0.0
	for index := range clusters {
		similarity := templateTokenSimilarity(tokens, clusters[index].tokens)
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestIndex = index
		}
	}

	if bestIndex == -1 || bestSimilarity < similarTemplateJaccardMinimum {
		return 0, false
	}
	return clusters[bestIndex].count, true
}

func recordSimilarResponseTemplate(statusCode int, responseBody, rawURL string) (int, bool) {
	scope := buildResponseTemplateScope(statusCode, rawURL)
	signature := buildSimilarResponseSignature(responseBody)
	if signature == "" {
		return 0, false
	}

	tokens := tokenize(signature, 2)
	if len(tokens) == 0 {
		tokens = tokenize(signature, 1)
	}

	responseTemplateTracker.Lock()
	defer responseTemplateTracker.Unlock()

	clusters := responseTemplateTracker.clusters[scope]
	bestIndex := -1
	bestSimilarity := 0.0
	for index := range clusters {
		cluster := &clusters[index]
		if cluster.signature == signature {
			cluster.count++
			return cluster.count, false
		}

		similarity := templateTokenSimilarity(tokens, cluster.tokens)
		if similarity > bestSimilarity {
			bestSimilarity = similarity
			bestIndex = index
		}
	}

	if bestIndex != -1 && bestSimilarity >= similarTemplateJaccardMinimum {
		clusters[bestIndex].count++
		return clusters[bestIndex].count, true
	}

	responseTemplateTracker.clusters[scope] = append(clusters, responseTemplateCluster{
		signature: signature,
		tokens:    tokens,
		count:     1,
	})
	return 1, false
}

func templateTokenSimilarity(left, right map[string]struct{}) float64 {
	if len(left) == 0 || len(right) == 0 {
		return 0
	}

	intersection := 0
	for token := range left {
		if _, ok := right[token]; ok {
			intersection++
		}
	}
	union := len(left) + len(right) - intersection
	if union <= 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

func buildResponseTemplateScope(statusCode int, rawURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return fmt.Sprintf("%d:%s", statusCode, strings.ToLower(strings.TrimSpace(rawURL)))
	}
	return fmt.Sprintf("%d:%s", statusCode, strings.ToLower(parsed.Host))
}

func buildSimilarResponseSignature(responseBody string) string {
	trimmed := strings.TrimSpace(responseBody)
	if trimmed == "" {
		return ""
	}

	var data any
	if err := json.Unmarshal([]byte(trimmed), &data); err == nil {
		return canonicalizeSimilarResponseValue("", data)
	}

	return normalizeSimilarResponseString(trimmed)
}

func canonicalizeSimilarResponseValue(key string, value any) string {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for item := range typed {
			keys = append(keys, item)
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(keys))
		for _, item := range keys {
			normalizedKey := strings.ToLower(strings.TrimSpace(item))
			switch {
			case isSimilarResponseVolatileKey(normalizedKey):
				parts = append(parts, strconv.Quote(normalizedKey)+`:"<volatile>"`)
			case isRouteLikeKey(normalizedKey):
				parts = append(parts, strconv.Quote(normalizedKey)+`:"<route>"`)
			default:
				parts = append(parts, strconv.Quote(normalizedKey)+":"+canonicalizeSimilarResponseValue(normalizedKey, typed[item]))
			}
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		if len(typed) == 0 {
			return "[]"
		}
		if len(typed) > 3 {
			typed = typed[:3]
		}
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, canonicalizeSimilarResponseValue(key, item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		return strconv.Quote(normalizeSimilarStringValue(key, typed))
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func normalizeSimilarStringValue(key, value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.Join(strings.Fields(normalized), " ")
	if normalized == "" {
		return normalized
	}

	switch {
	case isRouteLikeKey(key), looksLikeURLValue(normalized), looksLikeRouteValue(normalized):
		return "<route>"
	case looksLikeOpaqueToken(normalized):
		return "<token>"
	default:
		return normalizeSimilarResponseString(normalized)
	}
}

func normalizeSimilarResponseString(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.Join(strings.Fields(normalized), " ")
	if normalized == "" {
		return ""
	}

	replacements := []struct {
		pattern *regexp.Regexp
		value   string
	}{
		{regexp.MustCompile(`https?://[^\s"']+`), "<url>"},
		{regexp.MustCompile(`(?:^|[\s:=,])/[a-z0-9._/\-]+`), " <route>"},
		{regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f-]{27,}`), "<uuid>"},
		{regexp.MustCompile(`\b[0-9]{6,}\b`), "<number>"},
		{regexp.MustCompile(`\b[a-z0-9]{24,}\b`), "<token>"},
	}
	for _, replacement := range replacements {
		normalized = replacement.pattern.ReplaceAllString(normalized, replacement.value)
	}
	return strings.Join(strings.Fields(normalized), " ")
}

func isSimilarResponseVolatileKey(key string) bool {
	if key == "" {
		return false
	}
	if isRouteLikeKey(key) {
		return false
	}
	return strings.Contains(key, "trace") ||
		strings.Contains(key, "request") ||
		strings.Contains(key, "nonce") ||
		strings.Contains(key, "timestamp") ||
		strings.Contains(key, "token") ||
		strings.Contains(key, "session") ||
		strings.Contains(key, "captcha") ||
		strings.Contains(key, "sign") ||
		strings.Contains(key, "rand") ||
		strings.Contains(key, "error_hint")
}

func isRouteLikeKey(key string) bool {
	return strings.Contains(key, "route") ||
		strings.Contains(key, "path") ||
		strings.Contains(key, "url") ||
		strings.Contains(key, "uri") ||
		strings.Contains(key, "redirect") ||
		strings.Contains(key, "return")
}

func looksLikeURLValue(value string) bool {
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func looksLikeRouteValue(value string) bool {
	if strings.HasPrefix(value, "/") {
		return strings.Count(value, "/") >= 1
	}
	return strings.Contains(value, "/api/") || strings.Contains(value, "/rest/") || strings.Contains(value, "/gateway/")
}

func looksLikeOpaqueToken(value string) bool {
	if len(value) < 24 {
		return false
	}
	tokenLike := regexp.MustCompile(`^[a-z0-9+/_=-]{24,}$`)
	return tokenLike.MatchString(value)
}

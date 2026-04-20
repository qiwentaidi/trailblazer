package crawl

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"

	arrayutil "github.com/qiwentaidi/utils/array"
)

type Filter struct{}

var (
	// 错误的API后缀名
	invalidApiExtension = []string{".vue", ".jpeg", ".png", ".jpeg", ".gif", ".css", ".svg", ".scss", ".eot", ".ttf", ".woff", ".js", ".ts", ".tsx", ".ico", ".less", ".webp", ".jpg"}
	// 静态文件后缀名，主要给动态加载的链接进行过滤
	// staticResExtension = []string{".vue", ".jpeg", ".png", ".jpeg", ".gif", ".css", ".svg", ".scss", ".eot", ".ttf", ".woff", ".ico", ".less", ".webp", ".jpg", ".html"}
	captchaKeywords = []string{"captcha", "randomimage", "verify", "imgcode", "yzm", "geetest", "vcode"}
)

var (
	// 直接允许的简单根（仍然保留）
	allowSimple = regexp.MustCompile(`(?i)^/(?:api(?:[-_/].*)?|v\d+|rest|service|backend|graphql)(/)?$`)

	// 匹配含有 api 的 segment（更严格，避免像 capillary 之类的误判）
	segmentApiRe = regexp.MustCompile(`(?i)^(?:api|[a-z0-9]+[-_]?api|api[-_a-z0-9]+)$`)

	// 版本段判断，如 v1, v2, 1, 2
	versionRe = regexp.MustCompile(`(?i)^v?\d+$`)

	windowsDrivePathRe = regexp.MustCompile(`(?i)^[a-z]:\\`)
)

var systemPathIndicators = []string{
	"etc/hosts",
	"etc/passwd",
	"system32/drivers/etc",
	"windows/system32",
}

var obviousPagePrefixes = []string{
	"/pages/",
	"/page/",
	"/views/",
	"/view/",
	"/components/",
	"/component/",
	"/layouts/",
	"/layout/",
	"/router/",
	"/routes/",
}

var obviousPageExact = []string{
	"/404",
	"/403",
}

var obviousAssetPathKeywords = []string{
	"/static/",
	"/assets/",
	"/images/",
	"/img/",
	"/fonts/",
}

// 过滤输入目标中以 .js 结尾的链接
func (*Filter) JSLinks(urls []string) []string {
	var jsLinks []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}

		// 判断路径是否以 .js 结尾
		if strings.HasSuffix(strings.ToLower(parsed.Path), ".js") {
			jsLinks = append(jsLinks, u)
		}
	}
	return jsLinks
}

// 获取headless模式下，大概率正确的API
// 在排出黑名单域名的前提下，筛选比如验证码，或者路径中带有api关键词的API
func (f *Filter) Api(urls, blackDomain []string) []string {
	var result []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		if f.IsBlacklist(u, blackDomain) {
			continue
		}
		matched := false
		// 直接匹配常见 API 根
		if allowSimple.MatchString(parsed.Path) {
			matched = true
		}

		// 拆分路径段，检查是否含有 api 关键字
		segs := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for _, seg := range segs {
			if segmentApiRe.MatchString(seg) {
				matched = true
				break
			}
		}
		for _, keyword := range captchaKeywords {
			if strings.Contains(strings.ToLower(parsed.Path), keyword) {
				matched = true
				break
			}
		}
		if matched {
			result = append(result, u)
		}
	}
	return arrayutil.RemoveDuplicates(result)
}

// 从获取到的APIRouter中过滤可能性最高的跟路径API

func (*Filter) APIRoots(paths []string, minFreq int) []string {
	blacklist := []string{
		"proxy", "jsonp", "callback", "tk", "map", "military", "static", "resource", "google", "baidu",
	}

	// 结果频次统计
	freq := map[string]int{}

	for _, raw := range paths {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue
		}
		// 只处理以 / 开头的路径片段
		if !strings.HasPrefix(p, "/") {
			continue
		}
		// 跳过带 query 的
		if strings.Contains(p, "?") {
			continue
		}
		// 长度限制，避免非常短或过长的噪声
		if len(p) < 3 || len(p) > 120 {
			continue
		}

		low := strings.ToLower(strings.TrimSpace(p))
		// 去掉末尾斜杠，后面会统一加回
		low = strings.TrimSuffix(low, "/")

		// 黑名单关键词过滤
		skip := false
		for _, kw := range blacklist {
			if strings.Contains(low, kw) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// 1) 如果直接匹配简单允许模式，直接当根路径
		if allowSimple.MatchString("/" + low) {
			normalized := ensureTrailingSlash("/" + low)
			freq[normalized]++
			continue
		}

		// 2) 逐段分析，寻找包含 api 的 segment
		segs := strings.Split(strings.Trim(low, "/"), "/")
		if len(segs) == 0 {
			continue
		}

		foundIdx := -1
		for i, seg := range segs {
			if segmentApiRe.MatchString(seg) {
				foundIdx = i
				break
			}
		}
		if foundIdx == -1 {
			// 没找到含 api 的段，继续下一个
			continue
		}

		// 构造根路径：至少包含 api 段
		rootSeg := segs[foundIdx]
		root := "/" + rootSeg + "/"

		// 如果紧接着有版本号（v1 或 1），把版本也包含进去
		if foundIdx+1 < len(segs) && versionRe.MatchString(segs[foundIdx+1]) {
			root = "/" + rootSeg + "/" + segs[foundIdx+1] + "/"
		}
		freq[root]++
	}

	// 把频次 >= minFreq 的 root 收集并排序返回
	var result []string
	for r, c := range freq {
		if c >= minFreq {
			result = append(result, r)
		}
	}
	sort.Strings(result)
	return result
}

func ensureTrailingSlash(s string) string {
	if strings.HasSuffix(s, "/") {
		return s
	}
	return s + "/"
}

// 矫正由于错误正则提取到的错误API链接
func (*Filter) InvalidApi(apis []string) []string {
	var result []string
	for _, item := range apis {
		for _, ext := range invalidApiExtension {
			if strings.HasSuffix(strings.ToLower(item), ext) {
				result = append(result, item)
			}
		}
	}
	return result
}

func (f *Filter) FilterAPIRoutes(routes []string) []string {
	uniqueRoutes := arrayutil.RemoveDuplicates(routes)
	accepted := make([]string, 0, len(uniqueRoutes))

	for _, route := range uniqueRoutes {
		if f.shouldKeepAPIRoute(route) {
			accepted = append(accepted, route)
		}
	}

	return arrayutil.RemoveDuplicates(accepted)
}

func (f *Filter) shouldKeepAPIRoute(raw string) bool {
	route := strings.TrimSpace(raw)
	if route == "" {
		return false
	}

	lower := strings.ToLower(route)
	pathOnly := routeCandidatePath(route)

	for _, keyword := range obviousAssetPathKeywords {
		if strings.Contains(lower, keyword) {
			return false
		}
	}

	for _, prefix := range obviousPagePrefixes {
		if strings.HasPrefix(lower, prefix) || strings.Contains(lower, prefix) {
			return false
		}
	}

	for _, exact := range obviousPageExact {
		if lower == exact {
			return false
		}
	}

	for _, ext := range invalidApiExtension {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}

	if hasDotPathTraversalSegment(pathOnly) {
		return false
	}

	if hasSuspiciousLocalizedSlug(pathOnly) {
		return false
	}

	return true
}

func routeCandidatePath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Path != "" {
		return parsed.Path
	}

	if idx := strings.IndexAny(trimmed, "?#"); idx >= 0 {
		return trimmed[:idx]
	}
	return trimmed
}

func hasDotPathTraversalSegment(path string) bool {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return false
	}

	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Path != "" {
		trimmed = parsed.Path
	}

	for _, segment := range strings.Split(strings.Trim(trimmed, "/"), "/") {
		if segment == "" {
			continue
		}
		decoded, err := url.PathUnescape(segment)
		if err == nil {
			segment = decoded
		}
		if segment == "." || segment == ".." {
			return true
		}
	}

	return false
}

func hasSuspiciousLocalizedSlug(path string) bool {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return false
	}

	segments := strings.Split(trimmed, "/")
	afterAPIBase := false
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			continue
		}
		if segmentApiRe.MatchString(segment) {
			afterAPIBase = true
			continue
		}
		if !afterAPIBase || versionRe.MatchString(segment) {
			continue
		}
		if isSuspiciousLocalizedSegment(segment) {
			return true
		}
	}

	return false
}

func isSuspiciousLocalizedSegment(segment string) bool {
	decoded, err := url.PathUnescape(segment)
	if err == nil {
		segment = decoded
	}
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return false
	}

	hasNonASCII := false
	hasASCIIAlphaNum := false
	hasDigit := false
	hasHan := false
	hasOtherScriptLetter := false

	for _, r := range segment {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case r <= unicode.MaxASCII && (unicode.IsLetter(r) || unicode.IsNumber(r)):
			hasASCIIAlphaNum = true
		case unicode.Is(unicode.Han, r):
			hasHan = true
			hasNonASCII = true
		case unicode.IsLetter(r):
			hasOtherScriptLetter = true
			hasNonASCII = true
		case unicode.IsMark(r):
			hasNonASCII = true
		case r == '-' || r == '_' || r == '.' || r == '~':
			continue
		default:
			return false
		}
	}

	if hasDigit || hasASCIIAlphaNum || hasHan {
		return false
	}

	return hasNonASCII && hasOtherScriptLetter
}

func (*Filter) Blacklist(urls []string, blackDomains []string) []string {
	var result []string
	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		blacklisted := false
		for _, domain := range blackDomains {
			if strings.Contains(parsed.Host, domain) {
				blacklisted = true
				break
			}
		}
		if !blacklisted {
			result = append(result, u)
		}
	}
	return result
}

func (*Filter) IsBlacklist(target string, blackDomains []string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	for _, domain := range blackDomains {
		if strings.Contains(parsed.Host, domain) {
			return true
		}
	}
	return false
}

// 判断是否是数字或小数
func isNumericPath(path string) bool {
	// 只包含数字/点号
	re := regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)
	return re.MatchString(path)
}

// 判断是否是MIME类型
func isMimeType(s string) bool {
	return strings.Contains(s, "/") &&
		(strings.HasPrefix(s, "application/") ||
			strings.HasPrefix(s, "text/") ||
			strings.HasPrefix(s, "image/") ||
			strings.HasPrefix(s, "video/") ||
			strings.HasPrefix(s, "audio/"))
}

// 判断是否是时间/日期格式
func isDateLike(s string) bool {
	lower := strings.ToLower(s)

	// 检查常见的时间/日期占位符，要求以非字母数字分隔，避免匹配到普通单词
	placeholderTokens := []string{"yyyy", "yyy", "yy", "mm", "dd", "hh", "ss"}
	for _, token := range placeholderTokens {
		pattern := `(?i)(^|[^a-z0-9])` + token + `([^a-z0-9]|$)`
		if regexp.MustCompile(pattern).MatchString(lower) {
			return true
		}
	}

	// 匹配类似 yyyy-mm-dd、dd/mm/yyyy 等结构
	if regexp.MustCompile(`(?i)\d{2,4}[-/]\d{1,2}([-/]\d{1,4})?`).MatchString(lower) {
		return true
	}

	return false
}

func isInvalidApiExtension(s string) bool {
	for _, ext := range invalidApiExtension {
		if strings.Contains(s, ext) {
			return true
		}
	}
	return false
}

func isSystemPath(s string) bool {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return false
	}
	if windowsDrivePathRe.MatchString(trimmed) {
		return true
	}

	lower := strings.ToLower(trimmed)
	normalized := strings.ReplaceAll(lower, "\\", "/")
	for _, indicator := range systemPathIndicators {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}

	if strings.HasPrefix(normalized, "/etc/") || strings.HasPrefix(normalized, "etc/") {
		return true
	}

	return false
}

// API统一过滤器
func (*Filter) IsGarbage(s string) bool {
	return isNumericPath(s) || isMimeType(s) || isDateLike(s) || isInvalidApiExtension(s) || isSystemPath(s)
}

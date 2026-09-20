package crawl

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/protocoltool"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	lfi "github.com/qiwentaidi/trailblazer/pkg/core/vuln/lfi"
	redirect "github.com/qiwentaidi/trailblazer/pkg/core/vuln/redirect"
	sqli "github.com/qiwentaidi/trailblazer/pkg/core/vuln/sqli"
	ssrf "github.com/qiwentaidi/trailblazer/pkg/core/vuln/ssrf"
	unauth "github.com/qiwentaidi/trailblazer/pkg/core/vuln/unauth"
	upload "github.com/qiwentaidi/trailblazer/pkg/core/vuln/upload"
	xss "github.com/qiwentaidi/trailblazer/pkg/core/vuln/xss"

	"github.com/google/uuid"
	"github.com/panjf2000/ants/v2"
	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
	httputil "github.com/qiwentaidi/utils/http"
)

const maxResponseSize = 500 * 1024 // 500KB

var (
	Sensitive                            = regexp.MustCompile(`\b(access.{0,3}key|access.{0,3}Key|access.{0,3}Id|access.{0,3}id|access.{0,3}Secret|access.{0,3}secret|bucket|Bucket|endpoint|Endpoint|.{0,5}密码|.{0,5}账号|默认.{0,5}密码|password|username)\s*[:=]\s*["']?([^"'\s]+)["']?|\b((ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,}))\b`)
	Phone                                = regexp.MustCompile(`(^|[^0-9a-zA-Z.])(13[0-9]|14[01456879]|15[0-35-9]|16[2567]|17[0-8]|18[0-9]|19[0-35-9])\d{8}([^0-9a-zA-Z]|$)`)
	IDCard                               = regexp.MustCompile(`(^|[^0-9a-zA-Z])((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))([^0-9a-zA-Z]|$)`)
	Email                                = regexp.MustCompile(`\w+([-+.]\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*`)
	Link                                 = regexp.MustCompile(`(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:\w)(?:[\?|#][^"|']{0,}|)))(?:"|')`)
	IP_PORT                              = regexp.MustCompile(`((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}:\d{1,5}`)
	unauthorizedAPIVersionSegmentPattern = regexp.MustCompile(`^v\d+(?:[._-]?\d+)?$`)
	staticVariableTokenPattern           = regexp.MustCompile(`[A-Za-z_$]`)
)

func printAPITestProgress(index, total int, message string) {
	if total <= 1 {
		fmt.Printf("[信息] 接口测试 %d/%d %s\n", index, total, message)
		return
	}
	fmt.Printf("\r[信息] 接口测试 %d/%d %s", index, total, message)
}

func finalizeAPITestProgress(total int) {
	if total > 1 {
		fmt.Print("\n")
	}
}

// FindInfo 使用线程池处理单个 URL 的信息提取
func FindInfo(url string, aiChecker *SensitiveInfoChecker) *structs.FindSomething {
	var fs = &structs.FindSomething{}
	resp, err := clients.SimpleGet(url, clients.DefaultRestyClient())
	if err != nil {
		fmt.Printf("[错误] 抓取 URL 失败: %s，原因: %v\n", url, err)
		return fs
	}
	content := string(resp.Body())
	links := arrayutil.RemoveDuplicates(Link.FindAllString(content, -1))
	// 提取信息
	urls, apis := urlInfoSeparate(links)
	// fs.JS = *AppendSource(url, js)
	fs.APIRoute = *AppendSource(url, apis)
	fs.IP_URL = *AppendSource(url, append(IP_PORT.FindAllString(content, -1), urls...))

	// 提取敏感信息（不在此处进行AI过滤，在Scan函数统一去重后再过滤）
	idCardMatches := clean(IDCard.FindAllString(content, -1))
	phoneMatches := clean(Phone.FindAllString(content, -1))
	sensitiveMatches := Sensitive.FindAllString(content, -1)

	fs.IDCard = *AppendSource(url, idCardMatches)
	fs.Phone = *AppendSource(url, phoneMatches)
	fs.Sensitive = *AppendSource(url, sensitiveMatches)
	fs.Email = *AppendSource(url, Email.FindAllString(content, -1))
	return fs
}

// 对还原出来的 SourceMap 目录提取信息
func ExtractFromSourceMapDir(dirPath string) *structs.FindSomething {
	var fsResult = &structs.FindSomething{}

	filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 忽略错误继续
		}
		if d.IsDir() {
			return nil
		}

		// 只处理 .js .vue .ts .tsx 文件
		if !(strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".vue") || strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx")) {
			return nil
		}

		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(contentBytes)
		links := arrayutil.RemoveDuplicates(Link.FindAllString(content, -1))
		// 提取
		urls, apis := urlInfoSeparate(links)

		fsResult.APIRoute = append(fsResult.APIRoute, *AppendSource(path, apis)...)
		fsResult.IP_URL = append(fsResult.IP_URL, *AppendSource(path, append(IP_PORT.FindAllString(content, -1), urls...))...)
		fsResult.IDCard = append(fsResult.IDCard, *AppendSource(path, clean(IDCard.FindAllString(content, -1)))...)
		fsResult.Phone = append(fsResult.Phone, *AppendSource(path, clean(Phone.FindAllString(content, -1)))...)
		fsResult.Sensitive = append(fsResult.Sensitive, *AppendSource(path, Sensitive.FindAllString(content, -1))...)
		fsResult.Email = append(fsResult.Email, *AppendSource(path, Email.FindAllString(content, -1))...)

		return nil
	})

	// 去重
	fsResult.APIRoute = RemoveDuplicatesInfoSource(fsResult.APIRoute)
	fsResult.IP_URL = RemoveDuplicatesInfoSource(fsResult.IP_URL)
	fsResult.IDCard = RemoveDuplicatesInfoSource(fsResult.IDCard)
	fsResult.Phone = RemoveDuplicatesInfoSource(fsResult.Phone)
	fsResult.Sensitive = RemoveDuplicatesInfoSource(fsResult.Sensitive)

	return fsResult
}

func Scan(target string, jsLinks []string, aiChecker *SensitiveInfoChecker) structs.FindSomething {
	startedAt := time.Now()
	fmt.Printf("[信息] 开始分析 JS 资源: %s（JS 链接数: %d）\n", target, len(jsLinks))

	var fs = structs.FindSomething{}
	var mu sync.Mutex // 用于保护 fs 的并发写操作
	var wg sync.WaitGroup
	var visited sync.Map // 并发安全的去重 map
	// 创建线程池
	pool, _ := ants.NewPoolWithFunc(10, func(data interface{}) {
		defer wg.Done()
		jslink := data.(string)
		newURL := formatURL(target, jslink)
		// 判断是否已访问
		if _, loaded := visited.LoadOrStore(newURL, struct{}{}); loaded {
			// 已处理过，跳过
			return
		}
		fs2 := FindInfo(newURL, aiChecker)
		// 加锁以安全地更新共享资源
		mu.Lock()
		fs.IP_URL = append(fs.IP_URL, fs2.IP_URL...)
		fs.IDCard = append(fs.IDCard, fs2.IDCard...)
		fs.Phone = append(fs.Phone, fs2.Phone...)
		fs.Email = append(fs.Email, fs2.Email...)
		fs.Sensitive = append(fs.Sensitive, fs2.Sensitive...)
		fs.APIRoute = append(fs.APIRoute, fs2.APIRoute...)
		mu.Unlock()
	})
	defer pool.Release()
	wg.Add(1) // 确保 target 任务计入 WaitGroup

	// 提交主目标任务
	pool.Invoke(target)

	// 提交 JS 链接任务
	for _, jslink := range jsLinks {
		wg.Add(1)
		pool.Invoke(jslink)
	}

	// 等待所有任务完成
	wg.Wait()
	fmt.Printf("[信息] JS 内容扫描完成: %s，耗时: %s\n", target, time.Since(startedAt).Round(time.Millisecond))

	// 进行webpack检测
	sourceMapStartedAt := time.Now()
	sourceMapHitCount := 0
	for _, jslink := range jsLinks {
		mapURL := formatURL(target, jslink) + ".map"
		resp, err := clients.SimpleGet(mapURL, clients.NewRestyClient(nil, true))
		if err == nil && resp.StatusCode() == 200 {
			sourceMapHitCount++
			// 检测到 .map 泄漏，尝试还原
			fp, err := RestoreWebpack(mapURL)
			if err == nil {
				fmt.Printf("[信息] 发现JS SourceMap泄漏: %s，恢复webpack成功: %s\n", mapURL, fp)
			}
			sourceMapInfo := ExtractFromSourceMapDir(fp)
			mu.Lock()
			fs.IP_URL = append(fs.IP_URL, sourceMapInfo.IP_URL...)
			fs.IDCard = append(fs.IDCard, sourceMapInfo.IDCard...)
			fs.Phone = append(fs.Phone, sourceMapInfo.Phone...)
			fs.Email = append(fs.Email, sourceMapInfo.Email...)
			fs.Sensitive = append(fs.Sensitive, sourceMapInfo.Sensitive...)
			fs.APIRoute = append(fs.APIRoute, sourceMapInfo.APIRoute...)
			mu.Unlock()
		}
	}
	fmt.Printf("[信息] SourceMap 分析完成: %s，耗时: %s，命中: %d\n", target, time.Since(sourceMapStartedAt).Round(time.Millisecond), sourceMapHitCount)

	// 去重处理
	fs.APIRoute = RemoveDuplicatesInfoSource(fs.APIRoute)
	fs.IDCard = RemoveDuplicatesInfoSource(fs.IDCard)
	fs.Phone = RemoveDuplicatesInfoSource(fs.Phone)
	fs.Email = RemoveDuplicatesInfoSource(fs.Email)
	fs.Sensitive = RemoveDuplicatesInfoSource(fs.Sensitive)
	fs.IP_URL = RemoveDuplicatesInfoSource(fs.IP_URL)

	// 如果启用了AI检测，只对敏感关键词进行过滤（避免重复分析相同内容）
	// 手机号和身份证的正则已经很准确，不需要AI验证
	if aiChecker != nil {
		aiStartedAt := time.Now()

		fmt.Printf("[信息] 开始使用 AI 辅助过滤敏感关键字（候选数: %d）\n", len(fs.Sensitive))
		fs.Sensitive = filterInfoSourceWithAI(aiChecker, fs.Sensitive)

		fmt.Printf("[信息] AI 敏感关键字过滤完成，剩余 %d 项，耗时: %s\n", len(fs.Sensitive), time.Since(aiStartedAt).Round(time.Millisecond))
	}

	fmt.Printf(
		"[INFO] JS analysis completed for %s in %s (api_routes=%d, ip_url=%d, email=%d, sensitive=%d, phone=%d, idcard=%d)\n",
		target,
		time.Since(startedAt).Round(time.Millisecond),
		len(fs.APIRoute),
		len(fs.IP_URL),
		len(fs.Email),
		len(fs.Sensitive),
		len(fs.Phone),
		len(fs.IDCard),
	)

	return fs
}

// 对URL 和 JS 链接进行格式化
func formatURL(url string, jslink string) string {
	return ResolveResourceURL(url, jslink)
}

// clean 去除手机号和身份证中的其他字符，保留数字、+ 和 X
func clean(filed []string) (news []string) {
	// 定义只保留数字、+ 和 X 的正则表达式
	cleanRegex := regexp.MustCompile(`[^\d+X]`)
	for _, p := range filed {
		news = append(news, cleanRegex.ReplaceAllString(p, ""))
	}
	return
}

// filterWithAI 使用AI过滤误报（变量名、占位符等）
func filterWithAI(checker *SensitiveInfoChecker, items []string) []string {
	if checker == nil {
		return items
	}

	// 跳过空列表
	if len(items) == 0 {
		return items
	}

	var filtered []string
	var confirmed, rejected, failed int

	for _, item := range items {
		if item == "" {
			continue
		}

		isSensitive, err := checker.Check(item)
		if err != nil {
			// AI检测失败时保留原结果，确保不漏报
			fmt.Printf("[警告] AI 检测失败，保留原始项: %s，原因: %v\n", item, err)
			filtered = append(filtered, item)
			failed++
			continue
		}

		if isSensitive {
			filtered = append(filtered, item)
			confirmed++
			fmt.Printf("[信息] AI 确认为敏感项: %s\n", truncateString(item, 50))
		} else {
			rejected++
			fmt.Printf("[信息] AI 判定为非敏感项: %s\n", truncateString(item, 50))
		}
	}

	if confirmed > 0 || rejected > 0 {
		fmt.Printf("[信息] AI 过滤结果: 确认 %d 项，排除 %d 项，异常 %d 项（总计 %d 项）\n",
			confirmed, rejected, failed, len(items))
	}

	return filtered
}

func filterInfoSourceWithAI(checker *SensitiveInfoChecker, sources []structs.InfoSource) []structs.InfoSource {
	if checker == nil {
		return sources
	}

	if len(sources) == 0 {
		return sources
	}

	filtered := make([]structs.InfoSource, 0, len(sources))
	var confirmed, rejected, failed int

	for _, item := range sources {
		if item.Filed == "" {
			continue
		}

		if shouldRejectSensitiveCandidate(item.Filed) {
			rejected++
			fmt.Printf("[信息] 本地规则排除: %s\n", truncateString(item.Filed, 50))
			continue
		}
		if shouldConfirmSensitiveCandidate(item.Filed) {
			item.AIVerified = true
			filtered = append(filtered, item)
			confirmed++
			fmt.Printf("[信息] 本地规则确认: %s\n", truncateString(item.Filed, 50))
			continue
		}

		isSensitive, err := checker.Check(item.Filed)
		if err != nil {
			fmt.Printf("[警告] AI 检测失败，保留原始项: %s，原因: %v\n", item.Filed, err)
			item.AIVerified = false
			filtered = append(filtered, item)
			failed++
			continue
		}

		if isSensitive {
			item.AIVerified = true
			filtered = append(filtered, item)
			confirmed++
			fmt.Printf("[信息] AI 确认为敏感项: %s\n", truncateString(item.Filed, 50))
		} else {
			rejected++
			fmt.Printf("[信息] AI 判定为非敏感项: %s\n", truncateString(item.Filed, 50))
		}
	}

	if confirmed > 0 || rejected > 0 {
		fmt.Printf("[信息] AI 过滤结果: 确认 %d 项，排除 %d 项，异常 %d 项（总计 %d 项）\n",
			confirmed, rejected, failed, len(sources))
	}

	return filtered
}

func shouldRejectSensitiveCandidate(candidate string) bool {
	key, value, ok := splitSensitiveAssignmentCandidate(candidate)
	if !ok {
		return false
	}
	if key == "" || value == "" {
		return false
	}
	return isCodeLikeSensitiveValue(value)
}

func shouldConfirmSensitiveCandidate(candidate string) bool {
	key, value, ok := splitSensitiveAssignmentCandidate(candidate)
	if !ok {
		return false
	}
	if !isCredentialLikeSensitiveKey(key) {
		return false
	}
	if !isLikelyLiteralCredentialValue(value) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "admin", "administrator", "root", "test", "guest", "admin123", "admin123456", "123456", "12345678", "password", "passwd", "qwerty":
		return true
	default:
		return false
	}
}

func splitSensitiveAssignmentCandidate(candidate string) (string, string, bool) {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", "", false
	}
	idx := strings.IndexAny(candidate, ":=")
	if idx <= 0 || idx >= len(candidate)-1 {
		return "", "", false
	}
	key := strings.TrimSpace(candidate[:idx])
	value := strings.TrimSpace(candidate[idx+1:])
	value = strings.Trim(value, `"'`)
	if key == "" || value == "" {
		return "", "", false
	}
	return key, value, true
}

func isCredentialLikeSensitiveKey(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	switch key {
	case "username", "user", "account", "login", "password", "passwd", "pwd":
		return true
	default:
		return false
	}
}

func isLikelyLiteralCredentialValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 {
		return false
	}
	if isCodeLikeSensitiveValue(value) {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n,;{}[]") {
		return false
	}
	literalPattern := regexp.MustCompile(`^[A-Za-z0-9@._!#$%^-]+$`)
	return literalPattern.MatchString(value)
}

func isCodeLikeSensitiveValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	codeFragments := []string{
		"===",
		"!==",
		"&&",
		"||",
		"void",
		"function(",
		"=>",
		"),",
		"},{",
		"[{",
		"}]",
		"required:!0",
	}
	for _, fragment := range codeFragments {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	if strings.Contains(value, ",") && strings.Contains(value, ":") {
		return true
	}
	if strings.Contains(value, "(") && strings.Contains(value, ")") {
		return true
	}
	if strings.ContainsAny(value, "{}[]") {
		return true
	}
	return false
}

// truncateString 截断字符串用于日志显示
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func AppendSource(source string, filed []string) *[]structs.InfoSource {
	is := []structs.InfoSource{}
	for _, f := range filed {
		is = append(is, structs.InfoSource{Filed: f, Source: source, AIVerified: false})
	}
	return &is
}

func RemoveDuplicatesInfoSource(iss []structs.InfoSource) []structs.InfoSource {
	encountered := map[string]bool{}
	result := []structs.InfoSource{}
	for _, is := range iss {
		if !encountered[is.Filed] {
			encountered[is.Filed] = true
			result = append(result, is)
		}
	}
	return result
}

// extractFields 从InfoSource列表中提取字段值
func extractFields(sources []structs.InfoSource) []string {
	fields := make([]string, 0, len(sources))
	for _, s := range sources {
		fields = append(fields, s.Filed)
	}
	return fields
}

// filterInfoSourceByFields 根据保留的字段值过滤InfoSource列表
func filterInfoSourceByFields(sources []structs.InfoSource, keepFields []string) []structs.InfoSource {
	// 创建保留字段的map，快速查找
	keepMap := make(map[string]bool)
	for _, field := range keepFields {
		keepMap[field] = true
	}

	// 过滤
	filtered := make([]structs.InfoSource, 0)
	for _, s := range sources {
		if keepMap[s.Filed] {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

// 处理静态提取到的链接，转换成apis和urls
func urlInfoSeparate(links []string) (urls, apis []string) {
	filter := Filter{}
	for _, link := range links {
		link = strings.Trim(link, "\"")
		link = strings.Trim(link, "'")
		// 如果为.开头的API可能是提取到了VUE文件链接了，忽略
		if strings.HasPrefix(link, ".") || link == "" || link == "/" {
			continue
		}

		// 判断是否是 URL，如果是URL的话需要将URL中的链接进行API提取
		if strings.HasPrefix(link, "http") || strings.HasPrefix(link, "ws") || strings.HasPrefix(link, "//") {
			urls = append(urls, link)
			// 提取路径 + 参数，加入到 apis
			u, err := url.Parse(link)
			if err != nil {
				continue
			}
			// 过滤垃圾域名
			if strings.Contains(u.Host, "www.w3.org") {
				continue
			}
			apiPath := u.Path
			if u.RawQuery != "" {
				apiPath += "?" + u.RawQuery
			}

			// 过滤敏感字段
			skip := false
			for _, filter := range invalidApiExtension {
				if strings.Contains(apiPath, filter) {
					skip = true
					break
				}
			}
			if !skip {
				apis = append(apis, apiPath)
			}
			continue // 直接进入下一次循环
		}
		// 对链接进行过滤器拦截
		if !filter.IsGarbage(link) {
			apis = append(apis, link)
		}
	}
	return urls, apis
}

// 全局去重 map，记录已经测试过的 URL（按 TaskID 分组）
var (
	testedURLs      = make(map[string]map[string]bool) // taskID -> URL -> tested
	testedURLsMutex sync.RWMutex
)

// 检查 URL 是否已经测试过
func isURLTested(taskID, url string) bool {
	testedURLsMutex.RLock()
	defer testedURLsMutex.RUnlock()

	if urls, ok := testedURLs[taskID]; ok {
		return urls[url]
	}
	return false
}

// 标记 URL 已测试
func markURLTested(taskID, url string) {
	testedURLsMutex.Lock()
	defer testedURLsMutex.Unlock()

	if testedURLs[taskID] == nil {
		testedURLs[taskID] = make(map[string]bool)
	}
	testedURLs[taskID][url] = true
}

// 清理任务的内存去重缓存（任务完成后调用，避免内存泄漏）
func ClearTestedURLs(taskID string) {
	testedURLsMutex.Lock()
	defer testedURLsMutex.Unlock()

	delete(testedURLs, taskID)
	fmt.Printf("[信息] 已清理任务 %s 的内存去重缓存（非历史版本数据）\n", taskID)
}

// VulnCollector 漏洞收集器接口（用于CLI模式）
type VulnCollector interface {
	Collect(vuln database.VulnRecord)
}

// 处理 API 逻辑
func AnalyzeAPI(o structs.JSFindOptions) {
	AnalyzeAPIWithCollector(o, nil)
}

// AnalyzeAPIWithCollector 处理 API 逻辑，支持可选的漏洞收集器（用于CLI模式）
func AnalyzeAPIWithCollector(o structs.JSFindOptions, collector VulnCollector) {
	resp, err := clients.SimpleGet(o.HomeURL, clients.NewRestyClient(nil, true))
	if err != nil {
		fmt.Printf("[错误] 请求首页失败，无法开始接口测试: %s，原因: %v\n", o.HomeURL, err)
		return
	}
	homeBody := string(resp.Body())
	apiResourceIndex := loadUnauthorizedAPIResourceIndex(o)
	protocolTraceIndex := loadUnauthorizedProtocolTraceIndex(o)
	var unauthorizedNamer unauthorizedFindingNamer
	if namer, ok := o.AIChecker.(unauthorizedFindingNamer); ok {
		unauthorizedNamer = namer
	}
	totalAPIs := len(o.ApiList)
	fmt.Printf("[信息] 开始进行接口测试: 首页=%s，根路径=%s，接口数=%d\n", o.HomeURL, o.ApiRoot, totalAPIs)
	var wg sync.WaitGroup
	var progressMu sync.Mutex
	completedCount := 0
	pool, _ := ants.NewPoolWithFunc(10, func(data interface{}) {
		defer wg.Done()
		api := data.(string)
		progressMu.Lock()
		currentIndex := completedCount + 1
		printAPITestProgress(currentIndex, totalAPIs, fmt.Sprintf("准备测试: %s", api))
		progressMu.Unlock()

		// 为每个 API 独立生成 fullURL 和 headers 副本
		fullURL := buildFullURL(o.HomeURL, o.ApiRoot, api, o.Placeholder)
		if hasDotPathTraversalSegment(fullURL) {
			progressMu.Lock()
			completedCount++
			printAPITestProgress(completedCount, totalAPIs, fmt.Sprintf("已跳过（命中点段路径）: %s", fullURL))
			progressMu.Unlock()
			return
		}

		// 去重检查：如果该 URL 已经测试过，跳过
		if o.TaskID != "" && isURLTested(o.TaskID, fullURL) {
			progressMu.Lock()
			completedCount++
			printAPITestProgress(completedCount, totalAPIs, fmt.Sprintf("已跳过（已测试）: %s", fullURL))
			progressMu.Unlock()
			return
		}

		markURLTested(o.TaskID, fullURL)

		// 拷贝 headers，避免竞争
		apiHeaders := make(map[string]string)
		maps.Copy(apiHeaders, o.Headers)
		applyStaticHeaderHints(api, apiHeaders, o.StaticHeaderHints)

		method, usedStaticMethodHint := resolveStaticProbeMethod(api, o.StaticMethodHints)
		if !usedStaticMethodHint {
			// 检测请求方法
			var err error
			method, err = detectMethod(fullURL, apiHeaders)
			if err != nil {
				return
			}
		}
		u, _ := url.Parse(fullURL)
		param := url.Values{}
		// 如果提取到的API链接参数不为空则要让参数清空，不然会在completeParameters的后续处理中重复添加
		if u.RawQuery != "" {
			param, _ = url.ParseQuery(u.RawQuery)
			u.RawQuery = ""
			fullURL = u.String()
		}
		param = applyStaticConstantParams(method, fullURL, param, o.StaticConstantParams)
		// 补全参数
		param = completeParameters(method, fullURL, param)
		// 构建请求对象
		apiReq := structs.APIRequest{
			URL:     fullURL,
			Method:  method,
			Headers: apiHeaders,
			Params:  param,
		}
		applyStaticRequestPayloadHint(&apiReq, o.StaticRequestPayloadHints, o.Placeholder)
		verifyAndFixStaticGETPayloadHint(&apiReq)
		// 仅在静态载荷提示缺失时再走动态探测兜底
		if method == http.MethodPost && apiReq.PayloadFormat == "" && apiReq.PayloadCarrier == "" {
			if contentType := detectContentType(fullURL, apiHeaders, len(apiReq.Params) > 0); contentType != "" {
				apiReq.Headers["Content-Type"] = contentType
			}
		}

		// 检查高风险路由，直接跳过测试
		for _, router := range o.HighRiskRouter {
			if strings.Contains(strings.ToLower(apiReq.URL), router) {
				progressMu.Lock()
				completedCount++
				printAPITestProgress(completedCount, totalAPIs, fmt.Sprintf("已跳过（高风险关键字 %s）: %s", router, fullURL))
				progressMu.Unlock()
				return
			}
		}
		progressMu.Lock()
		printAPITestProgress(currentIndex, totalAPIs, fmt.Sprintf("测试中: %s %s", method, apiReq.URL))
		progressMu.Unlock()

		// 创建深拷贝函数，避免检测函数修改原始请求对象
		cloneAPIRequest := func(req structs.APIRequest) structs.APIRequest {
			return cloneUnauthorizedAPIRequest(req)
		}

		if o.SkipVulnScan {
			progressMu.Lock()
			completedCount++
			printAPITestProgress(completedCount, totalAPIs, fmt.Sprintf("已完成（仅探测接口）: %s %s", method, apiReq.URL))
			progressMu.Unlock()
			return
		}

		// 继续进行其他漏洞检测
		detectedVuln := false
		// LFI 检测
		if o.LFIConfig != nil {
			if lfiCfg, ok := o.LFIConfig.(config.LFIConfig); ok && lfiCfg.Enabled {
				lfiResult, err := lfi.TestLocalFileInclusion(cloneAPIRequest(apiReq), lfiCfg)
				if err != nil {
					fmt.Printf("\n[错误] LFI 检测失败: %v\n", err)
				} else if lfiResult.Vulnerable {
					fmt.Printf("\n[信息] 发现 LFI 漏洞: %s（Payload: %s）\n", fullURL, lfiResult.Payload)

					// 保存 LFI 漏洞到数据库或收集器
					vulnID := uuid.New().String()
					vulnRecord := database.VulnRecord{
						TaskID:         o.TaskID,
						Version:        o.Version,
						VulnID:         vulnID,
						Title:          "任意文件读取(LFI)",
						Level:          "high",
						Type:           "LFI",
						URL:            fullURL,
						Method:         method,
						Request:        vuln.BuildRawRequest(apiReq),
						Response:       lfiResult.Response,
						ResponseLength: len(lfiResult.Response), // 保存响应长度
						Description:    fmt.Sprintf("发现任意文件读取漏洞，Payload: %s，原因: %s", lfiResult.Payload, lfiResult.Reason),
						AIVerified:     false,
						CreatedAt:      time.Now(),
					}
					if collector != nil {
						collector.Collect(vulnRecord)
					} else if database.DB != nil {
						if err := database.SaveVuln(vulnRecord); err != nil {
							fmt.Printf("\n[错误] 保存 LFI 漏洞失败: %v\n", err)
						}
					}
					detectedVuln = true
				}
			}
		}

		// SSRF 检测
		if o.SSRFConfig != nil {
			if ssrfCfg, ok := o.SSRFConfig.(config.SSRFConfig); ok && ssrfCfg.Enabled {
				ssrfResult, err := ssrf.TestServerSideRequestForgery(cloneAPIRequest(apiReq), ssrfCfg)
				if err != nil {
					fmt.Printf("\n[错误] SSRF 检测失败: %v\n", err)
				} else if ssrfResult.Vulnerable {
					fmt.Printf("\n[信息] 发现 SSRF 漏洞: %s（Payload: %s）\n", fullURL, ssrfResult.Payload)

					// 保存 SSRF 漏洞到数据库或收集器
					vulnID := uuid.New().String()
					vulnRecord := database.VulnRecord{
						TaskID:         o.TaskID,
						Version:        o.Version,
						VulnID:         vulnID,
						Title:          "服务端请求伪造(SSRF)",
						Level:          "high",
						Type:           "SSRF",
						URL:            fullURL,
						Method:         method,
						Request:        vuln.BuildRawRequest(apiReq),
						Response:       ssrfResult.Response,
						ResponseLength: len(ssrfResult.Response),
						Description:    fmt.Sprintf("发现服务端请求伪造漏洞，Payload: %s，原因: %s", ssrfResult.Payload, ssrfResult.Reason),
						AIVerified:     false,
						CreatedAt:      time.Now(),
					}
					if collector != nil {
						collector.Collect(vulnRecord)
					} else if database.DB != nil {
						if err := database.SaveVuln(vulnRecord); err != nil {
							fmt.Printf("\n[错误] 保存 SSRF 漏洞失败: %v\n", err)
						}
					}
					detectedVuln = true
				}
			}
		}

		// 重定向检测
		if o.RedirectConfig != nil {
			if redirectCfg, ok := o.RedirectConfig.(config.RedirectConfig); ok && redirectCfg.Enabled {
				redirectResult, err := redirect.TestRedirectVulnerability(cloneAPIRequest(apiReq), redirectCfg)
				if err != nil {
					fmt.Printf("\n[错误] 重定向漏洞检测失败: %v\n", err)
				} else if redirectResult.Vulnerable {
					fmt.Printf("\n[信息] 发现重定向漏洞: %s（Payload: %s）\n", fullURL, redirectResult.Payload)

					// 保存重定向漏洞到数据库或收集器
					vulnID := uuid.New().String()
					vulnRecord := database.VulnRecord{
						TaskID:         o.TaskID,
						Version:        o.Version,
						VulnID:         vulnID,
						Title:          "开放重定向",
						Level:          "medium",
						Type:           "REDIRECT",
						URL:            fullURL,
						Method:         method,
						Request:        vuln.BuildRawRequest(apiReq),
						Response:       redirectResult.Response,
						ResponseLength: len(redirectResult.Response),
						Description:    fmt.Sprintf("发现开放重定向漏洞，Payload: %s，原因: %s", redirectResult.Payload, redirectResult.Reason),
						AIVerified:     false,
						CreatedAt:      time.Now(),
					}
					if collector != nil {
						collector.Collect(vulnRecord)
					} else if database.DB != nil {
						if err := database.SaveVuln(vulnRecord); err != nil {
							fmt.Printf("\n[错误] 保存重定向漏洞失败: %v\n", err)
						}
					}
					detectedVuln = true
				}
			}
		}

		// SQL注入检测
		if o.SQLInjConfig != nil {
			if sqlCfg, ok := o.SQLInjConfig.(config.SQLInjectionConfig); ok && sqlCfg.Enabled {
				sqlResult, err := sqli.TestSQLInjection(cloneAPIRequest(apiReq), sqlCfg)
				if err != nil {
					fmt.Printf("\n[错误] SQL 注入检测失败: %v\n", err)
				} else if sqlResult != nil && sqlResult.Vulnerable {
					fmt.Printf("\n[信息] 发现 SQL 注入漏洞: %s（Payload: %s，类型: %s）\n", fullURL, sqlResult.Payload, sqlResult.Type)

					// 保存 SQL注入漏洞到数据库或收集器
					vulnID := uuid.New().String()
					vulnRecord := database.VulnRecord{
						TaskID:         o.TaskID,
						Version:        o.Version,
						VulnID:         vulnID,
						Title:          fmt.Sprintf("SQL注入漏洞 (%s)", sqlResult.Type),
						Level:          "high",
						Type:           "SQL_INJECTION",
						URL:            fullURL,
						Method:         method,
						Request:        vuln.BuildRawRequest(apiReq),
						Response:       sqlResult.Response,
						ResponseLength: sqlResult.ResponseLength,
						Description:    fmt.Sprintf("发现SQL注入漏洞，类型: %s，Payload: %s，原因: %s", sqlResult.Type, sqlResult.Payload, sqlResult.Reason),
						AIVerified:     false,
						CreatedAt:      time.Now(),
					}
					if collector != nil {
						collector.Collect(vulnRecord)
					} else if database.DB != nil {
						if err := database.SaveVuln(vulnRecord); err != nil {
							fmt.Printf("\n[错误] 保存 SQL 注入漏洞失败: %v\n", err)
						}
					}
					detectedVuln = true
				}
			}
		}

		// XSS 检测
		if o.XSSConfig != nil {
			if xssCfg, ok := o.XSSConfig.(config.XSSConfig); ok && xssCfg.Enabled {
				xssResult, err := xss.TestXSS(cloneAPIRequest(apiReq), xssCfg)
				if err != nil {
					fmt.Printf("\n[错误] XSS 检测失败: %v\n", err)
				} else if xssResult != nil && xssResult.Vulnerable {
					fmt.Printf("\n[信息] 发现 XSS 漏洞: %s（Payload: %s，类型: %s）\n", fullURL, xssResult.Payload, xssResult.Type)

					// 保存 XSS漏洞到数据库或收集器
					vulnID := uuid.New().String()
					vulnRecord := database.VulnRecord{
						TaskID:           o.TaskID,
						Version:          o.Version,
						VulnID:           vulnID,
						Title:            fmt.Sprintf("跨站脚本攻击漏洞 (%s)", xssResult.Type),
						Level:            "high",
						Type:             "XSS",
						URL:              fullURL,
						Method:           method,
						Request:          vuln.BuildRawRequest(apiReq),
						Response:         xssResult.Response,
						ResponseLength:   len(xssResult.Response),
						Confidence:       xssResult.Confidence,
						ConfidenceReason: xssResult.ConfidenceReason,
						Description:      fmt.Sprintf("发现XSS漏洞，类型: %s，Payload: %s，原因: %s", xssResult.Type, xssResult.Payload, xssResult.Reason),
						AIVerified:       false,
						CreatedAt:        time.Now(),
					}
					if collector != nil {
						collector.Collect(vulnRecord)
					} else if database.DB != nil {
						if err := database.SaveVuln(vulnRecord); err != nil {
							fmt.Printf("\n[错误] 保存 XSS 漏洞失败: %v\n", err)
						}
					}
					detectedVuln = true
				}
			}
		}

		// 文件上传检测
		if o.UploadConfig != nil {
			if uploadCfg, ok := o.UploadConfig.(config.UploadConfig); ok && uploadCfg.Enabled {
				// 将AIChecker转换为FileUploadAIChecker接口
				var aiChecker upload.FileUploadAIChecker
				if o.AIChecker != nil {
					if checker, ok := o.AIChecker.(*SensitiveInfoChecker); ok {
						aiChecker = checker
					}
				}
				uploadResult, err := upload.TestFileUpload(cloneAPIRequest(apiReq), uploadCfg, aiChecker)
				if err != nil {
					fmt.Printf("\n[错误] 文件上传漏洞检测失败: %v\n", err)
				} else if uploadResult != nil {
					if uploadResult.Vulnerable {
						fmt.Printf("\n[信息] 发现文件上传漏洞: %s（Payload: %s）\n", fullURL, uploadResult.Payload)

						// 保存文件上传漏洞到数据库或收集器
						vulnID := uuid.New().String()
						rawRequest := uploadResult.RawRequest
						if rawRequest == "" {
							rawRequest = vuln.BuildRawRequest(apiReq)
						}
						description := fmt.Sprintf("发现文件上传漏洞，Payload: %s，原因: %s", uploadResult.Payload, uploadResult.Reason)
						if uploadResult.UploadURL != "" {
							description += fmt.Sprintf("，上传文件URL: %s", uploadResult.UploadURL)
						}
						vulnRecord := database.VulnRecord{
							TaskID:         o.TaskID,
							Version:        o.Version,
							VulnID:         vulnID,
							Title:          "文件上传漏洞",
							Level:          "high",
							Type:           "FILE_UPLOAD",
							URL:            fullURL,
							Method:         method,
							Request:        rawRequest,
							Response:       uploadResult.Response,
							ResponseLength: len(uploadResult.Response),
							Description:    description,
							AIVerified:     false,
							CreatedAt:      time.Now(),
						}
						if collector != nil {
							collector.Collect(vulnRecord)
						} else if database.DB != nil {
							if err := database.SaveVuln(vulnRecord); err != nil {
								fmt.Printf("\n[错误] 保存文件上传漏洞失败: %v\n", err)
							}
						}
						detectedVuln = true
					}
				} else {
					fmt.Printf("\n[调试] 文件上传检测未返回结果: %s\n", fullURL)
				}
			}
		}

		// 如果已检测到其他漏洞，则不再检测未授权访问
		if detectedVuln {
			return
		}

		unauthorizedProbeReq, replayDetail := prepareUnauthorizedProbeRequest(
			cloneAPIRequest(apiReq),
			apiResourceIndex,
			protocolTraceIndex,
		)

		var (
			probeProtocolContext          unauthorizedProtocolContext
			rawUnauthorizedResponse       string
			plaintextUnauthorizedResponse string
		)
		responseDecoder := unauth.ResponseDecoder(func(rawBody string) (string, bool, error) {
			rawUnauthorizedResponse = rawBody
			decodedBody := rawBody
			context := resolveUnauthorizedProtocolContext(apiReq, rawBody, apiResourceIndex, protocolTraceIndex)
			probeProtocolContext = context

			// Only an observed response-level encryption envelope warrants decoding
			// or JS analysis. Plain Base64/Hex-looking business values are not
			// encryption evidence and must be left untouched.
			if !context.ResponseEncrypted {
				return decodedBody, false, nil
			}

			if plaintext, encoding, ok := tryDirectResponseDecoding(rawBody, context.ResponseCiphertext); ok {
				context.ResponsePlaintext = plaintext
				context.DecryptionStatus = "decoded_" + encoding
				context.DecryptionDetail = strings.TrimSpace(context.DecryptionDetail + "；已确认响应加密包装，内容可直接按 " + encoding + " 解码为 JSON，无需静态加解密分析")
				probeProtocolContext = context
				plaintextUnauthorizedResponse = plaintext
				return plaintext, true, nil
			}

			reviewedContext, reviewErr := reviewUncapturedEncryptedResponse(context)
			probeProtocolContext = reviewedContext
			if reviewErr != nil {
				var encryptedResponseErr *uncapturedEncryptedResponseError
				if errors.As(reviewErr, &encryptedResponseErr) {
					return "", true, reviewErr
				}
				fmt.Printf("[警告] 响应加密包装的 AI 解密链路线索复核失败，继续按原响应处理 %s %s: %v\n", apiReq.Method, apiReq.URL, reviewErr)
			}
			return decodedBody, false, nil
		})

		// 未授权访问由授权开关控制。关闭时保留接口发现与其他漏洞检测，
		// 不再把“匿名请求返回 200”当作漏洞证据。
		if o.SkipUnauthorizedScan {
			return
		}

		// 测试未授权访问
		vulnerable, body, assessment, err := unauth.TestUnauthorizedAccessWithDecoder(homeBody, unauthorizedProbeReq, o.Authentication, responseDecoder)
		if err != nil {
			var encryptedResponseErr *uncapturedEncryptedResponseError
			if errors.As(err, &encryptedResponseErr) {
				recordUncapturedEncryptedResponseFinding(o, collector, unauthorizedProbeReq, rawUnauthorizedResponse, probeProtocolContext)
			}
			return
		}

		if vulnerable && len(body) > 0 {
			if rawUnauthorizedResponse == "" {
				rawUnauthorizedResponse = body
			}
			if plaintextUnauthorizedResponse == "" && probeProtocolContext.DecryptionStatus == "decrypted" {
				plaintextUnauthorizedResponse = body
			}

			// 存在未授权，记录漏洞信息
			result := structs.JSFindResult{
				VulType:  "未授权访问",
				Severity: assessment.RiskLevel,
				Method:   method,
				Request:  vuln.BuildRawRequest(unauthorizedProbeReq),
				Source:   fullURL,
				Response: httputil.LimitResponse(rawUnauthorizedResponse, maxResponseSize, "响应包长度过大，请手动打开链接查看。"),
				Length:   len(rawUnauthorizedResponse),
			}
			name := ClassifyUnauthorizedFinding(fullURL, method, firstNonEmpty(plaintextUnauthorizedResponse, body), assessment.DataExposure)
			if unauthorizedNamer != nil {
				if aiName, err := unauthorizedNamer.NameUnauthorizedFinding(fullURL, method, result.Request, firstNonEmpty(plaintextUnauthorizedResponse, body), assessment.DataExposure); err == nil {
					name = normalizeUnauthorizedFindingName(aiName, fullURL, method, firstNonEmpty(plaintextUnauthorizedResponse, body), assessment.DataExposure)
				}
			}

			fmt.Printf("[+] %s | %s | %s | 风险等级: %s | 响应长度: %d\n",
				result.VulType, result.Method, result.Source, result.Severity, result.Length)

			// 保存未授权漏洞到数据库或收集器
			vulnID := uuid.New().String()
			vulnRecord := database.VulnRecord{
				TaskID:             o.TaskID,
				Version:            o.Version,
				VulnID:             vulnID,
				Title:              name.Title,
				Level:              assessment.RiskLevel,
				Type:               "未授权访问",
				Category:           name.Category,
				Subcategory:        name.Subcategory,
				BusinessObject:     name.BusinessObject,
				NamingSource:       name.Source,
				URL:                fullURL,
				Method:             method,
				Request:            result.Request,
				Response:           rawUnauthorizedResponse,
				ResponsePlaintext:  plaintextUnauthorizedResponse,
				ResponseType:       assessment.ResponseType,
				TraceID:            probeProtocolContext.TraceID,
				HasProtocolTrace:   probeProtocolContext.HasProtocolTrace,
				ResponseCiphertext: probeProtocolContext.ResponseCiphertext,
				DecryptionStatus:   probeProtocolContext.DecryptionStatus,
				DecryptionDetail:   probeProtocolContext.DecryptionDetail,
				ResponseLength:     len(rawUnauthorizedResponse),
				Confidence:         assessment.Confidence,
				ConfidenceReason:   assessment.ConfidenceReason,
				DataExposure:       assessment.DataExposure,
				ExposureReason:     assessment.ExposureReason,
				Description:        buildUnauthorizedVulnDescription(assessment.RiskLevel, assessment.Confidence, assessment.DataExposure, result.Length, replayDetail, assessment.ConfidenceReason, assessment.ExposureReason),
				AIVerified:         false,
				CreatedAt:          time.Now(),
			}
			if collector != nil {
				collector.Collect(vulnRecord)
			} else if database.DB != nil {
				if err := database.SaveVuln(vulnRecord); err != nil {
					fmt.Printf("\n[错误] 保存未授权漏洞失败: %v\n", err)
				}
			}
		}

		progressMu.Lock()
		completedCount++
		printAPITestProgress(completedCount, totalAPIs, fmt.Sprintf("已完成: %s %s", method, apiReq.URL))
		progressMu.Unlock()
	})
	defer pool.Release()

	// 提交任务
	for _, api := range o.ApiList {
		wg.Add(1)
		pool.Invoke(api)
	}

	wg.Wait()
	finalizeAPITestProgress(totalAPIs)
}

func applyStaticConstantParams(method, fullURL string, params url.Values, hints map[string]url.Values) url.Values {
	if len(hints) == 0 {
		return params
	}
	if params == nil {
		params = url.Values{}
	}

	parsed, err := url.Parse(strings.TrimSpace(fullURL))
	if err != nil {
		return params
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	path := strings.TrimSpace(parsed.Path)
	if method == "" || path == "" {
		return params
	}

	key := method + "\x00" + path
	constantParams, ok := hints[key]
	if !ok || len(constantParams) == 0 {
		return params
	}

	for paramName, values := range constantParams {
		if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
			continue
		}
		if _, exists := params[paramName]; exists {
			continue
		}
		params[paramName] = []string{values[0]}
	}

	return params
}

func shouldSkipStaticRouteRootCombination(api, apiRoot string, hints map[string][]string) bool {
	if len(hints) == 0 {
		return false
	}

	pathKey := normalizeStaticRouteRootAPIPath(api)
	if pathKey == "" {
		return false
	}

	boundRoots := hints[pathKey]
	if len(boundRoots) == 0 {
		return false
	}

	currentRoot := normalizeStaticBoundRoot(apiRoot)
	if currentRoot == "" {
		return false
	}

	for _, boundRoot := range boundRoots {
		if normalizeStaticBoundRoot(boundRoot) == currentRoot {
			return false
		}
	}

	fmt.Printf("[调试] 跳过接口 %s（根路径 %s），原因: 命中静态绑定根路径 %v\n", api, apiRoot, boundRoots)
	return true
}

func normalizeStaticRouteRootAPIPath(api string) string {
	api = strings.TrimSpace(api)
	if api == "" {
		return ""
	}

	if parsed, err := url.Parse(api); err == nil && parsed != nil && parsed.Path != "" {
		api = parsed.Path
	}

	if !strings.HasPrefix(api, "/") {
		api = "/" + strings.TrimLeft(api, "/")
	}
	return strings.TrimRight(api, "/")
}

func resolveStaticProbeMethod(api string, hints map[string]string) (string, bool) {
	if len(hints) == 0 {
		return "", false
	}

	path := normalizeStaticRouteRootAPIPath(api)
	if path == "" {
		return "", false
	}

	method := strings.ToUpper(strings.TrimSpace(hints[path]))
	switch method {
	case http.MethodGet, http.MethodPost:
		return method, true
	default:
		return "", false
	}
}

func applyStaticRequestPayloadHint(apiReq *structs.APIRequest, hints map[string]structs.StaticRequestPayloadHint, placeholder map[string]string) {
	if apiReq == nil || len(hints) == 0 {
		return
	}

	parsed, err := url.Parse(strings.TrimSpace(apiReq.URL))
	if err != nil {
		return
	}
	method := strings.ToUpper(strings.TrimSpace(apiReq.Method))
	path := strings.TrimSpace(parsed.Path)
	if method == "" || path == "" {
		return
	}

	hint, ok := hints[method+"\x00"+path]
	if !ok {
		return
	}

	apiReq.PayloadCarrier = strings.TrimSpace(hint.Carrier)
	apiReq.PayloadFormat = strings.TrimSpace(hint.Format)

	if apiReq.Headers == nil {
		apiReq.Headers = make(map[string]string)
	}

	switch apiReq.PayloadFormat {
	case "json":
		setHeaderIfMissing(apiReq.Headers, "Content-Type", "application/json")
		if strings.TrimSpace(apiReq.Body) == "" {
			if normalizedBody := buildStaticPayloadBody(hint.Preview, apiReq.Params, placeholder); normalizedBody != "" {
				apiReq.Body = normalizedBody
			}
		}
	case "query":
		apiReq.PayloadCarrier = "params"
	case "unknown":
		if apiReq.PayloadCarrier == "body" || apiReq.PayloadCarrier == "data" {
			setHeaderIfMissing(apiReq.Headers, "Content-Type", "application/x-www-form-urlencoded")
		}
	}
}

func verifyAndFixStaticGETPayloadHint(apiReq *structs.APIRequest) {
	if apiReq == nil {
		return
	}
	if strings.ToUpper(strings.TrimSpace(apiReq.Method)) != http.MethodGet {
		return
	}

	carrier := strings.ToLower(strings.TrimSpace(apiReq.PayloadCarrier))
	format := strings.ToLower(strings.TrimSpace(apiReq.PayloadFormat))
	if carrier != "body" && carrier != "data" && format != "json" {
		return
	}
	if len(apiReq.Params) == 0 && strings.TrimSpace(apiReq.Body) == "" {
		return
	}
	backfillStaticGETQueryParamsFromBody(apiReq)
	apiReq.PayloadCarrier = "params"
	apiReq.PayloadFormat = "query"
	if apiReq.Headers == nil {
		apiReq.Headers = make(map[string]string)
	}
	setHeaderIfMissing(apiReq.Headers, "Content-Type", "application/json")
	if strings.TrimSpace(apiReq.Body) == "" {
		if normalizedBody := buildStaticPayloadBody("", apiReq.Params, nil); normalizedBody != "" {
			apiReq.Body = normalizedBody
		}
	}
}

func backfillStaticGETQueryParamsFromBody(apiReq *structs.APIRequest) {
	if apiReq == nil {
		return
	}
	body := strings.TrimSpace(apiReq.Body)
	if body == "" || !json.Valid([]byte(body)) {
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return
	}
	if len(payload) == 0 {
		return
	}
	if apiReq.Params == nil {
		apiReq.Params = make(url.Values)
	}

	for key, value := range payload {
		key = strings.TrimSpace(key)
		if key == "" || len(apiReq.Params[key]) > 0 {
			continue
		}
		switch typed := value.(type) {
		case string:
			apiReq.Params.Set(key, typed)
		case float64:
			apiReq.Params.Set(key, strconv.FormatFloat(typed, 'f', -1, 64))
		case bool:
			apiReq.Params.Set(key, strconv.FormatBool(typed))
		case nil:
			apiReq.Params.Set(key, "")
		case []interface{}:
			for _, item := range typed {
				apiReq.Params.Add(key, stringifyStaticPayloadParamValue(item))
			}
		default:
			apiReq.Params.Set(key, stringifyStaticPayloadParamValue(typed))
		}
	}
}

func stringifyStaticPayloadParamValue(value interface{}) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(typed)
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

func buildStaticPayloadBody(preview string, params url.Values, placeholder map[string]string) string {
	trimmed := strings.TrimSpace(preview)
	if trimmed != "" {
		if json.Valid([]byte(trimmed)) {
			return trimmed
		}
		if value, ok := normalizeStaticPayloadValue("", trimmed, params, placeholder); ok {
			if body, err := json.Marshal(value); err == nil {
				return string(body)
			}
		}
	}

	if len(params) == 0 {
		return ""
	}

	payload := make(map[string]interface{}, len(params))
	for key, values := range params {
		if key == "" || len(values) == 0 {
			continue
		}
		payload[key] = values[0]
	}
	if len(payload) == 0 {
		return ""
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(body)
}

func normalizeStaticPayloadValue(fieldName, raw string, params url.Values, placeholder map[string]string) (interface{}, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		if fieldName == "" {
			return nil, false
		}
		return defaultStaticPayloadValue(fieldName, placeholder), true
	}

	if strings.HasPrefix(trimmed, "JSON.stringify(") {
		if inner, _, ok := extractBalancedJS(trimmed, len("JSON.stringify"), '(', ')'); ok {
			return normalizeStaticPayloadValue(fieldName, inner, params, placeholder)
		}
	}

	if literal := parseStringLiteral(trimmed); literal != "" {
		return literal, true
	}

	switch strings.ToLower(trimmed) {
	case "true":
		return true, true
	case "false":
		return false, true
	case "null":
		return nil, true
	}

	if integer, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
		return integer, true
	}
	if number, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return number, true
	}

	if fields := extractTopLevelObjectFields(trimmed); len(fields) > 0 {
		payload := make(map[string]interface{}, len(fields))
		for key, value := range fields {
			normalized, ok := normalizeStaticPayloadValue(key, value, params, placeholder)
			if !ok {
				normalized = defaultStaticPayloadValue(key, placeholder)
			}
			payload[key] = normalized
		}
		return payload, true
	}

	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
		if inner == "" {
			return []interface{}{}, true
		}
		parts := splitTopLevelCSV(inner)
		items := make([]interface{}, 0, len(parts))
		for _, part := range parts {
			normalized, ok := normalizeStaticPayloadValue(fieldName, part, params, placeholder)
			if !ok {
				normalized = defaultStaticPayloadValue(fieldName, placeholder)
			}
			items = append(items, normalized)
		}
		return items, true
	}

	if fieldName != "" {
		if value := strings.TrimSpace(params.Get(fieldName)); value != "" {
			return value, true
		}
	}

	if isStaticVariableExpression(trimmed) {
		return defaultStaticPayloadValue(fieldName, placeholder), true
	}

	var generic interface{}
	if json.Unmarshal([]byte(trimmed), &generic) == nil {
		return generic, true
	}

	if fieldName == "" {
		return nil, false
	}
	return defaultStaticPayloadValue(fieldName, placeholder), true
}

func isStaticVariableExpression(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return false
	}
	if identifierPattern.MatchString(expr) {
		return true
	}
	return staticVariableTokenPattern.MatchString(expr)
}

func defaultStaticPayloadValue(fieldName string, placeholder map[string]string) interface{} {
	field := strings.ToLower(strings.TrimSpace(fieldName))

	if field != "" {
		if value, ok := lookupPlaceholderValue(field, placeholder); ok {
			return value
		}
	}

	switch {
	case strings.HasPrefix(field, "is"), strings.HasPrefix(field, "has"), strings.HasSuffix(field, "flag"), strings.HasSuffix(field, "enabled"):
		return false
	case strings.HasSuffix(field, "ids"):
		return []string{}
	case strings.HasSuffix(field, "list"), strings.HasSuffix(field, "items"):
		return []string{}
	default:
		return ""
	}
}

func lookupPlaceholderValue(field string, rules map[string]string) (string, bool) {
	field = strings.ToLower(strings.TrimSpace(field))
	if field == "" || len(rules) == 0 {
		return "", false
	}

	for key, value := range rules {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" || normalizedKey == "default" {
			continue
		}
		if strings.Contains(field, normalizedKey) {
			return value, true
		}
	}

	if value, ok := rules["default"]; ok {
		return value, true
	}
	return "", false
}

func applyStaticHeaderHints(apiPath string, headers map[string]string, hints map[string]map[string]string) {
	if len(hints) == 0 {
		return
	}
	path := normalizeStaticRouteRootAPIPath(apiPath)
	if path == "" {
		return
	}

	for _, endpointHeaders := range []map[string]string{
		hints["GET\x00"+path],
		hints["POST\x00"+path],
		hints["PUT\x00"+path],
		hints["DELETE\x00"+path],
		hints["PATCH\x00"+path],
	} {
		for key, value := range endpointHeaders {
			if !isReusableStaticProbeHeader(key, value) {
				continue
			}
			setHeaderIfMissing(headers, key, value)
		}
	}
}

type unauthorizedProtocolContext struct {
	TraceID            string
	HasProtocolTrace   bool
	ResponsePlaintext  string
	ResponseCiphertext string
	ResponseEncrypted  bool
	DecryptionStatus   string
	DecryptionDetail   string
}

type uncapturedEncryptedResponseError struct {
	detail string
}

func (e *uncapturedEncryptedResponseError) Error() string {
	return e.detail
}

type unauthorizedAPIResourceIndex struct {
	byFullURL       map[string][]database.APIResource
	byPathOnly      map[string][]database.APIResource
	byRouteTemplate map[string][]database.APIResource
}

type unauthorizedProtocolTraceIndex struct {
	byTraceID map[string]database.ProtocolTraceRecord
	traces    []database.ProtocolTraceRecord
}

type unauthorizedURLMeta struct {
	NormalizedURL string
	PathOnly      string
	RouteTemplate string
	Host          string
	APIBasePath   string
	QueryKeys     map[string]struct{}
}

func loadUnauthorizedAPIResourceIndex(o structs.JSFindOptions) *unauthorizedAPIResourceIndex {
	if strings.TrimSpace(o.TaskID) == "" {
		return nil
	}
	store := o.DataStore
	if store == nil {
		store = database.GetScanDataStore()
	}
	if store == nil {
		return nil
	}

	var (
		apiResources []database.APIResource
		err          error
	)
	if o.Version > 0 {
		apiResources, err = store.ListAPIResources(o.TaskID, o.Version)
	} else {
		apiResources, err = store.ListAPIResources(o.TaskID)
	}
	if err != nil {
		fmt.Printf("[警告] 加载任务 %s 的 API 记录失败，未授权漏洞将缺少协议轨迹关联: %v\n", o.TaskID, err)
		return nil
	}

	return buildUnauthorizedAPIResourceIndex(apiResources)
}

func loadUnauthorizedProtocolTraceIndex(o structs.JSFindOptions) *unauthorizedProtocolTraceIndex {
	if strings.TrimSpace(o.TaskID) == "" {
		return nil
	}
	store := o.DataStore
	if store == nil {
		store = database.GetScanDataStore()
	}
	if store == nil {
		return nil
	}

	var (
		protocolTraces []database.ProtocolTraceRecord
		err            error
	)
	if o.Version > 0 {
		protocolTraces, err = store.ListProtocolTraces(o.TaskID, o.Version)
	} else {
		protocolTraces, err = store.ListProtocolTraces(o.TaskID)
	}
	if err != nil {
		fmt.Printf("[警告] 加载任务 %s 的协议轨迹失败，未授权漏洞将无法自动复用加密链路: %v\n", o.TaskID, err)
		return nil
	}

	index := &unauthorizedProtocolTraceIndex{
		byTraceID: make(map[string]database.ProtocolTraceRecord, len(protocolTraces)),
		traces:    make([]database.ProtocolTraceRecord, 0, len(protocolTraces)),
	}
	for _, trace := range protocolTraces {
		traceID := strings.TrimSpace(trace.TraceID)
		if traceID == "" {
			continue
		}
		index.byTraceID[traceID] = trace
		index.traces = append(index.traces, trace)
	}
	return index
}

func reviewUncapturedEncryptedResponse(context unauthorizedProtocolContext) (unauthorizedProtocolContext, error) {
	if context.ResponseCiphertext == "" {
		return context, nil
	}

	markForRuntimeCapture := func(detail string) (unauthorizedProtocolContext, error) {
		context.DecryptionStatus = "needs_runtime_capture"
		context.DecryptionDetail = strings.TrimSpace(context.DecryptionDetail + "；" + detail + "；未捕获可执行运行期解密链路，已保留密文并建议补充运行期捕获")
		return context, &uncapturedEncryptedResponseError{detail: "检测到响应级加密包装但未捕获运行期解密链路"}
	}

	// A response-level envelope is deterministic evidence. It must be kept out
	// of unauthorized-access evaluation even when a historical trace cannot be
	// found or the AI service is unavailable.
	if context.ResponseEncrypted {
		return markForRuntimeCapture("本地结构化判定为响应加密包装")
	}

	// AI is deliberately not an encryption classifier. A response that does not
	// satisfy the local, response-level envelope rule remains an ordinary
	// business response/unknown response and must not be promoted by a model.
	return context, nil
}

func buildUnauthorizedAPIResourceIndex(apiResources []database.APIResource) *unauthorizedAPIResourceIndex {
	index := &unauthorizedAPIResourceIndex{
		byFullURL:       make(map[string][]database.APIResource, len(apiResources)),
		byPathOnly:      make(map[string][]database.APIResource, len(apiResources)),
		byRouteTemplate: make(map[string][]database.APIResource, len(apiResources)),
	}
	for _, resource := range apiResources {
		meta := buildUnauthorizedURLMeta(resource.URL)
		if key := buildUnauthorizedLookupKey(resource.Method, meta.NormalizedURL); key != "" {
			index.byFullURL[key] = append(index.byFullURL[key], resource)
		}
		if key := buildUnauthorizedLookupKey(resource.Method, meta.PathOnly); key != "" {
			index.byPathOnly[key] = append(index.byPathOnly[key], resource)
		}
		if key := buildUnauthorizedLookupKey(resource.Method, meta.RouteTemplate); key != "" {
			index.byRouteTemplate[key] = append(index.byRouteTemplate[key], resource)
		}
	}
	return index
}

func resolveUnauthorizedProtocolContext(apiReq structs.APIRequest, responseBody string, apiResourceIndex *unauthorizedAPIResourceIndex, traceIndex *unauthorizedProtocolTraceIndex) unauthorizedProtocolContext {
	context := unauthorizedProtocolContext{}
	resource, matchStrategy, matched := lookupUnauthorizedAPIResource(apiReq.Method, apiReq.URL, apiResourceIndex)
	if matched {
		context.TraceID = strings.TrimSpace(resource.TraceID)
		context.HasProtocolTrace = resource.HasProtocolTrace || context.TraceID != ""
	}
	if !context.HasProtocolTrace {
		if protocolTrace, fallbackStrategy, ok := findReusableUnauthorizedProtocolTrace(apiReq, traceIndex); ok && protocolTrace != nil {
			context.TraceID = strings.TrimSpace(protocolTrace.TraceID)
			context.HasProtocolTrace = context.TraceID != ""
			if context.HasProtocolTrace {
				matchStrategy = fallbackStrategy
			}
		}
	}

	ciphertext, ciphertextSource, encryptedEnvelope := pickUnauthorizedCiphertext(responseBody, resource, matched)
	if ciphertext == "" {
		return context
	}

	context.ResponseCiphertext = ciphertext
	context.ResponseEncrypted = encryptedEnvelope
	context.DecryptionStatus = "not_tried"
	switch {
	case encryptedEnvelope:
		context.DecryptionDetail = buildUnauthorizedCiphertextDetail(ciphertextSource, "响应包含加密包装标记（如 useGlobalEnc / enc）")
	case context.HasProtocolTrace:
		context.DecryptionDetail = buildUnauthorizedDecryptionDetail(matchStrategy, buildUnauthorizedCiphertextDetail(ciphertextSource, "已关联协议轨迹，可先尝试离线解密，失败后可继续尝试在线 runtime 解密"))
	case matched:
		context.DecryptionDetail = buildUnauthorizedDecryptionDetail(matchStrategy, buildUnauthorizedCiphertextDetail(ciphertextSource, "已命中 API 记录，但该记录尚未关联协议轨迹"))
	default:
		context.DecryptionDetail = buildUnauthorizedCiphertextDetail(ciphertextSource, "已捕获疑似密文，但当前未命中可复用的协议轨迹")
	}

	return context
}

func pickUnauthorizedCiphertext(responseBody string, resource database.APIResource, matched bool) (string, string, bool) {
	if ciphertext := normalizeUnauthorizedCiphertext(responseBody); ciphertext != "" {
		return ciphertext, "unauth_probe_response", isLikelyEncryptedResponseEnvelope(responseBody)
	}

	if matched {
		if ciphertext := normalizeUnauthorizedCiphertext(resource.ResponseBody); ciphertext != "" {
			return ciphertext, "api_record_response", isLikelyEncryptedResponseEnvelope(resource.ResponseBody)
		}
	}

	return "", "", false
}

func buildUnauthorizedCiphertextDetail(source, detail string) string {
	detail = strings.TrimSpace(detail)
	if source == "" {
		return detail
	}

	sourceLabel := map[string]string{
		"api_record_response":   "密文来源: 已匹配 API 记录响应",
		"unauth_probe_response": "密文来源: 当前未授权探测响应",
	}[source]
	if sourceLabel == "" {
		sourceLabel = "密文来源: " + source
	}

	if detail == "" {
		return sourceLabel
	}
	return sourceLabel + "；" + detail
}

func prepareUnauthorizedProbeRequest(apiReq structs.APIRequest, apiResourceIndex *unauthorizedAPIResourceIndex, traceIndex *unauthorizedProtocolTraceIndex) (structs.APIRequest, string) {
	resource, matchStrategy, matched := lookupUnauthorizedAPIResource(apiReq.Method, apiReq.URL, apiResourceIndex)
	var (
		protocolTrace *database.ProtocolTraceRecord
		ok            bool
	)
	if matched {
		protocolTrace, ok = findUnauthorizedProtocolTrace(resource.TraceID, traceIndex)
	}
	if !ok {
		protocolTrace, matchStrategy, ok = findReusableUnauthorizedProtocolTrace(apiReq, traceIndex)
	}
	if !ok || protocolTrace == nil {
		return apiReq, ""
	}

	replayedRequest, replayDetail, err := buildUnauthorizedProtocolReplayRequest(apiReq, protocolTrace)
	if err != nil {
		fmt.Printf("[调试] 未授权探测复用协议轨迹失败 %s %s: %v\n", apiReq.Method, apiReq.URL, err)
		return apiReq, ""
	}

	detail := buildUnauthorizedDecryptionDetail(
		matchStrategy,
		"请求构造: 已复用协议轨迹自动生成新的密文请求体与动态请求头；"+replayDetail,
	)
	return replayedRequest, detail
}

func findUnauthorizedProtocolTrace(traceID string, traceIndex *unauthorizedProtocolTraceIndex) (*database.ProtocolTraceRecord, bool) {
	if traceIndex == nil {
		return nil, false
	}

	trace, ok := traceIndex.byTraceID[strings.TrimSpace(traceID)]
	if !ok {
		return nil, false
	}
	return &trace, true
}

func findReusableUnauthorizedProtocolTrace(apiReq structs.APIRequest, traceIndex *unauthorizedProtocolTraceIndex) (*database.ProtocolTraceRecord, string, bool) {
	if traceIndex == nil || len(traceIndex.traces) == 0 {
		return nil, "", false
	}

	requestMeta := buildUnauthorizedURLMeta(apiReq.URL)
	bestScore := -1
	bestStrategy := ""
	var bestTrace *database.ProtocolTraceRecord
	for idx := range traceIndex.traces {
		trace := &traceIndex.traces[idx]
		if !isReusableUnauthorizedProtocolTrace(trace) {
			continue
		}
		score, strategy := scoreReusableUnauthorizedProtocolTrace(apiReq, requestMeta, trace)
		if score < 0 {
			continue
		}
		if score > bestScore || (score == bestScore && bestTrace != nil && trace.CreatedAt.After(bestTrace.CreatedAt)) {
			bestScore = score
			bestStrategy = strategy
			bestTrace = trace
		}
	}
	if bestTrace == nil {
		return nil, "", false
	}
	return bestTrace, bestStrategy, true
}

func isReusableUnauthorizedProtocolTrace(trace *database.ProtocolTraceRecord) bool {
	if trace == nil {
		return false
	}
	if strings.TrimSpace(trace.RequestURL) == "" {
		return false
	}
	if strings.TrimSpace(trace.RequestBeforeTransform) == "" && strings.TrimSpace(trace.FinalRequestBody) == "" {
		return false
	}
	sessionMaterials := trace.SessionMaterials
	return strings.TrimSpace(sessionMaterials["sm4_key_hex"]) != "" &&
		strings.TrimSpace(firstNonEmpty(
			trace.RequestHeaders[protocoltool.HeaderKeyExchange],
			trace.RequestHeaders[strings.ToLower(protocoltool.HeaderKeyExchange)],
			sessionMaterials["key_exchange_header"],
		)) != ""
}

func scoreReusableUnauthorizedProtocolTrace(apiReq structs.APIRequest, requestMeta unauthorizedURLMeta, trace *database.ProtocolTraceRecord) (int, string) {
	if trace == nil {
		return -1, ""
	}

	traceMeta := buildUnauthorizedURLMeta(trace.RequestURL)
	score := -1
	strategy := ""
	switch {
	case requestMeta.Host != "" && traceMeta.Host != "" && requestMeta.Host == traceMeta.Host:
		score = 100
		strategy = "same_host_protocol"
	case requestMeta.APIBasePath != "" &&
		traceMeta.APIBasePath != "" &&
		requestMeta.APIBasePath == traceMeta.APIBasePath:
		score = 88
		strategy = "same_api_base_protocol"
	default:
		return -1, ""
	}
	requestMethod := strings.ToUpper(strings.TrimSpace(apiReq.Method))
	traceMethod := strings.ToUpper(strings.TrimSpace(trace.Method))
	if requestMethod != "" && traceMethod != "" {
		if requestMethod == traceMethod {
			score += 20
		} else if requestMethod == http.MethodPost && traceMethod == http.MethodPost {
			score += 10
		}
	}
	if requestMeta.PathOnly != "" && traceMeta.PathOnly != "" {
		if requestMeta.PathOnly == traceMeta.PathOnly {
			score += 12
			if strategy == "same_host_protocol" {
				strategy = "same_host_same_path_protocol"
			} else {
				strategy = "same_api_base_same_path_protocol"
			}
		} else if requestMeta.RouteTemplate != "" && requestMeta.RouteTemplate == traceMeta.RouteTemplate {
			score += 8
			if strategy == "same_host_protocol" {
				strategy = "same_host_route_template_protocol"
			} else {
				strategy = "same_api_base_route_template_protocol"
			}
		}
	}
	if len(trace.Algorithms) > 0 {
		score += 6
	}
	if trace.CreatedAt.After(time.Time{}) {
		score += 1
	}
	return score, strategy
}

func buildUnauthorizedProtocolReplayRequest(apiReq structs.APIRequest, trace *database.ProtocolTraceRecord) (structs.APIRequest, string, error) {
	if trace == nil {
		return apiReq, "", fmt.Errorf("missing protocol trace")
	}

	method := strings.ToUpper(strings.TrimSpace(firstNonEmpty(apiReq.Method, trace.Method)))
	if method == "" {
		return apiReq, "", fmt.Errorf("missing request method")
	}
	if method == http.MethodGet {
		return apiReq, "", fmt.Errorf("GET 请求无需复用加密链路")
	}

	plaintext := pickUnauthorizedReplayPlaintext(apiReq, trace)
	if plaintext == "" {
		return apiReq, "", fmt.Errorf("missing replay plaintext")
	}

	traceCopy := *trace
	traceCopy.RequestHeaders = cloneStringMap(trace.RequestHeaders)
	traceCopy.SessionMaterials = cloneStringMap(trace.SessionMaterials)
	deleteProtocolReplayAuth(traceCopy.RequestHeaders)
	deleteProtocolReplayAuth(traceCopy.SessionMaterials)

	encryptResult, err := protocoltool.EncryptWithTrace(&traceCopy, "", plaintext, "", "", "", "", "")
	if err != nil {
		return apiReq, "", err
	}

	replayedRequest := cloneUnauthorizedAPIRequest(apiReq)
	replayedRequest.Method = method
	if replayedRequest.Headers == nil {
		replayedRequest.Headers = make(map[string]string)
	}
	if _, exists := replayedRequest.Headers["Content-Type"]; !exists {
		replayedRequest.Headers["Content-Type"] = firstNonEmpty(
			trace.RequestHeaders["Content-Type"],
			trace.RequestHeaders["content-type"],
			"application/x-www-form-urlencoded",
		)
	}
	deleteProtocolReplayAuth(replayedRequest.Headers)
	for key, value := range encryptResult.Headers {
		replayedRequest.Headers[key] = value
	}
	deleteProtocolReplayAuth(replayedRequest.Headers)
	replayedRequest.Body = encryptResult.Ciphertext

	detail := fmt.Sprintf(
		"trace=%s；nonce=%s；timestamp=%s；保留 6zzbinypyphq，移除 x-access-token",
		strings.TrimSpace(trace.TraceID),
		encryptResult.Nonce,
		encryptResult.Timestamp,
	)
	return replayedRequest, detail, nil
}

func pickUnauthorizedReplayPlaintext(apiReq structs.APIRequest, trace *database.ProtocolTraceRecord) string {
	requestBody := strings.TrimSpace(apiReq.Body)
	tracePlaintext := strings.TrimSpace(trace.RequestBeforeTransform)
	switch {
	case tracePlaintext != "" && (requestBody == "" || requestBody == "{}"):
		return tracePlaintext
	case requestBody != "":
		return requestBody
	default:
		return tracePlaintext
	}
}

func cloneUnauthorizedAPIRequest(req structs.APIRequest) structs.APIRequest {
	cloned := structs.APIRequest{
		URL:            req.URL,
		Method:         req.Method,
		Body:           req.Body,
		PayloadCarrier: req.PayloadCarrier,
		PayloadFormat:  req.PayloadFormat,
	}
	cloned.Headers = cloneStringMap(req.Headers)
	cloned.Params = make(url.Values)
	for key, values := range req.Params {
		cloned.Params[key] = append([]string(nil), values...)
	}
	return cloned
}

func setHeaderIfMissing(headers map[string]string, key, value string) {
	for existingKey := range headers {
		if strings.EqualFold(existingKey, key) {
			return
		}
	}
	headers[key] = value
}

func isReusableStaticProbeHeader(key, value string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return false
	}

	switch key {
	case "authorization", "cookie", "x-access-token", "proxy-authorization":
		return false
	}
	return true
}

func cloneStringMap(source map[string]string) map[string]string {
	if len(source) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(source))
	maps.Copy(cloned, source)
	return cloned
}

func deleteProtocolReplayAuth(headers map[string]string) {
	for key := range headers {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "x-access-token", "authorization", "cookie":
			delete(headers, key)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func buildUnauthorizedVulnDescription(riskLevel, confidence, dataExposure string, responseLength int, replayDetail, confidenceReason, exposureReason string) string {
	description := fmt.Sprintf("发现未授权访问漏洞，风险等级: %s，置信度: %s，数据暴露评级: %s，响应长度: %d", riskLevel, confidence, dataExposure, responseLength)
	if strings.TrimSpace(confidenceReason) != "" {
		description += "；置信度说明: " + strings.TrimSpace(confidenceReason)
	}
	if strings.TrimSpace(exposureReason) != "" {
		description += "；暴露评级说明: " + strings.TrimSpace(exposureReason)
	}
	if strings.TrimSpace(replayDetail) == "" {
		return description
	}
	return description + "；" + strings.TrimSpace(replayDetail)
}

func recordUncapturedEncryptedResponseFinding(o structs.JSFindOptions, collector VulnCollector, apiReq structs.APIRequest, rawResponse string, context unauthorizedProtocolContext) {
	if strings.TrimSpace(context.ResponseCiphertext) == "" || context.DecryptionStatus != "needs_runtime_capture" {
		return
	}
	description := "检测到接口响应加密包装，但本次运行未捕获可执行的响应解密链路。该记录不是未授权访问漏洞，需补充浏览器运行期捕获后再验证响应明文。"
	record := database.VulnRecord{
		TaskID:             o.TaskID,
		Version:            o.Version,
		VulnID:             uuid.New().String(),
		Title:              "接口加密响应待分析",
		Level:              "info",
		Type:               "加密响应待分析",
		URL:                apiReq.URL,
		Method:             apiReq.Method,
		Request:            vuln.BuildRawRequest(apiReq),
		Response:           rawResponse,
		TraceID:            context.TraceID,
		HasProtocolTrace:   context.HasProtocolTrace,
		ResponseCiphertext: context.ResponseCiphertext,
		DecryptionStatus:   context.DecryptionStatus,
		DecryptionDetail:   context.DecryptionDetail,
		ResponseLength:     len(rawResponse),
		Confidence:         "medium",
		ConfidenceReason:   "本地结构化规则已确认响应级加密包装；尚未获得运行期解密明文",
		Description:        description,
		AIVerified:         false,
		CreatedAt:          time.Now(),
	}
	if collector != nil {
		collector.Collect(record)
		return
	}
	if database.DB != nil {
		if err := database.SaveVuln(record); err != nil {
			fmt.Printf("\n[错误] 保存加密响应待分析记录失败: %v\n", err)
		}
	}
}

func lookupUnauthorizedAPIResource(method, rawURL string, apiResourceIndex *unauthorizedAPIResourceIndex) (database.APIResource, string, bool) {
	if apiResourceIndex == nil {
		return database.APIResource{}, "", false
	}

	requestMeta := buildUnauthorizedURLMeta(rawURL)
	bestResource := database.APIResource{}
	bestScore := -1
	bestStrategy := ""

	consider := func(resources []database.APIResource, strategy string) {
		for _, candidate := range resources {
			score := scoreUnauthorizedAPIResourceMatch(requestMeta, buildUnauthorizedURLMeta(candidate.URL), candidate, strategy)
			if score < 0 {
				continue
			}
			if score > bestScore || (score == bestScore && shouldPreferUnauthorizedAPIResource(candidate, bestResource)) {
				bestScore = score
				bestResource = candidate
				bestStrategy = strategy
			}
		}
	}

	if key := buildUnauthorizedLookupKey(method, requestMeta.NormalizedURL); key != "" {
		consider(apiResourceIndex.byFullURL[key], "exact_url")
	}
	if key := buildUnauthorizedLookupKey(method, requestMeta.PathOnly); key != "" {
		consider(apiResourceIndex.byPathOnly[key], "same_path")
	}
	if key := buildUnauthorizedLookupKey(method, requestMeta.RouteTemplate); key != "" {
		consider(apiResourceIndex.byRouteTemplate[key], "route_template")
	}

	if bestScore < 0 {
		return database.APIResource{}, "", false
	}
	return bestResource, bestStrategy, true
}

func buildUnauthorizedLookupKey(method, normalizedURL string) string {
	if normalizedURL == "" {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(method)) + " " + normalizedURL
}

func normalizeUnauthorizedAPIResourceURL(rawURL string, dropQuery bool) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Host == "" {
		if dropQuery {
			if idx := strings.Index(trimmed, "?"); idx >= 0 {
				trimmed = trimmed[:idx]
			}
		}
		return strings.TrimRight(trimmed, "/")
	}

	if dropQuery {
		parsed.RawQuery = ""
	} else if parsed.RawQuery != "" {
		queryValues := parsed.Query()
		parsed.RawQuery = queryValues.Encode()
	}

	normalized := parsed.String()
	if parsed.RawQuery == "" {
		normalized = strings.TrimRight(normalized, "/")
	}
	return normalized
}

func buildUnauthorizedURLMeta(rawURL string) unauthorizedURLMeta {
	meta := unauthorizedURLMeta{
		NormalizedURL: normalizeUnauthorizedAPIResourceURL(rawURL, false),
		PathOnly:      normalizeUnauthorizedAPIResourceURL(rawURL, true),
		QueryKeys:     make(map[string]struct{}),
	}

	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return meta
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		meta.RouteTemplate = buildUnauthorizedPathTemplate(trimmed)
		return meta
	}

	meta.Host = strings.ToLower(strings.TrimSpace(parsed.Host))
	path := parsed.EscapedPath()
	if path == "" {
		path = parsed.Path
	}
	meta.APIBasePath = buildUnauthorizedAPIBasePath(path)
	meta.RouteTemplate = strings.TrimRight(meta.Host+buildUnauthorizedPathTemplate(path), "/")
	for key := range parsed.Query() {
		meta.QueryKeys[key] = struct{}{}
	}
	return meta
}

func buildUnauthorizedAPIBasePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" || trimmed == "/" {
		return ""
	}
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) == 0 {
		return ""
	}

	for idx, part := range parts {
		if !strings.EqualFold(strings.TrimSpace(part), "api") {
			continue
		}
		baseParts := parts[:idx+1]
		if idx+1 < len(parts) && unauthorizedAPIVersionSegmentPattern.MatchString(parts[idx+1]) {
			baseParts = parts[:idx+2]
		}
		return "/" + strings.Join(baseParts, "/")
	}

	if strings.HasPrefix(strings.ToLower(trimmed), "/api") {
		return "/api"
	}
	return ""
}

func buildUnauthorizedPathTemplate(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	parts := strings.Split(trimmed, "/")
	for idx, part := range parts {
		if part == "" {
			continue
		}
		if isDynamicUnauthorizedPathSegment(part) {
			parts[idx] = ":var"
		}
	}
	return strings.TrimRight(strings.Join(parts, "/"), "/")
}

func isDynamicUnauthorizedPathSegment(segment string) bool {
	trimmed := strings.TrimSpace(segment)
	if trimmed == "" {
		return false
	}
	trimmed = strings.Trim(trimmed, "{}")
	if len(trimmed) <= 2 {
		return false
	}
	if isDigitsOnly(trimmed) {
		return true
	}
	if isUUIDLike(trimmed) {
		return true
	}
	if len(trimmed) >= 24 && isHexString(trimmed) {
		return true
	}
	return false
}

func isDigitsOnly(value string) bool {
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return value != ""
}

func isUUIDLike(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 5 {
		return false
	}
	for _, part := range parts {
		if part == "" || !isHexString(part) {
			return false
		}
	}
	return true
}

func scoreUnauthorizedAPIResourceMatch(requestMeta, candidateMeta unauthorizedURLMeta, candidate database.APIResource, strategy string) int {
	if requestMeta.PathOnly == "" || candidateMeta.PathOnly == "" {
		return -1
	}

	score := -1
	switch strategy {
	case "exact_url":
		if requestMeta.NormalizedURL != "" && requestMeta.NormalizedURL == candidateMeta.NormalizedURL {
			score = 180
		}
	case "same_path":
		if requestMeta.PathOnly == candidateMeta.PathOnly {
			score = 140
		}
	case "route_template":
		if requestMeta.RouteTemplate != "" && requestMeta.RouteTemplate == candidateMeta.RouteTemplate {
			score = 110
		}
	}
	if score < 0 {
		return -1
	}

	sharedQueryKeys := countUnauthorizedSharedQueryKeys(requestMeta.QueryKeys, candidateMeta.QueryKeys)
	if len(requestMeta.QueryKeys) > 0 {
		score += sharedQueryKeys * 8
		if sharedQueryKeys == 0 && strategy != "exact_url" {
			score -= 12
		}
	}
	if candidate.HasProtocolTrace || strings.TrimSpace(candidate.TraceID) != "" {
		score += 25
	}
	if strings.TrimSpace(candidate.ResponseBody) != "" {
		score += 5
	}
	return score
}

func countUnauthorizedSharedQueryKeys(left, right map[string]struct{}) int {
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	shared := 0
	for key := range left {
		if _, ok := right[key]; ok {
			shared++
		}
	}
	return shared
}

func buildUnauthorizedDecryptionDetail(matchStrategy, suffix string) string {
	prefix := ""
	switch matchStrategy {
	case "exact_url":
		prefix = "已通过相同 method + 完整 URL 命中历史 API 记录"
	case "same_path":
		prefix = "已通过相同 method + 路径命中历史 API 记录"
	case "route_template":
		prefix = "已通过相同 method + 路由模板命中历史 API 记录"
	case "same_host_protocol":
		prefix = "已通过同站点协议轨迹复用历史加密链路"
	case "same_host_same_path_protocol":
		prefix = "已通过同站点相同路径的协议轨迹复用历史加密链路"
	case "same_host_route_template_protocol":
		prefix = "已通过同站点相同路由模板的协议轨迹复用历史加密链路"
	case "same_api_base_protocol":
		prefix = "已通过同 API Base 协议轨迹复用历史加密链路"
	case "same_api_base_same_path_protocol":
		prefix = "已通过同 API Base 相同路径的协议轨迹复用历史加密链路"
	case "same_api_base_route_template_protocol":
		prefix = "已通过同 API Base 相同路由模板的协议轨迹复用历史加密链路"
	}
	if prefix == "" {
		return suffix
	}
	if strings.TrimSpace(suffix) == "" {
		return prefix
	}
	return prefix + "，" + suffix
}

func shouldPreferUnauthorizedAPIResource(candidate, current database.APIResource) bool {
	if (candidate.HasProtocolTrace || strings.TrimSpace(candidate.TraceID) != "") !=
		(current.HasProtocolTrace || strings.TrimSpace(current.TraceID) != "") {
		return candidate.HasProtocolTrace || strings.TrimSpace(candidate.TraceID) != ""
	}
	if (strings.TrimSpace(candidate.ResponseBody) != "") != (strings.TrimSpace(current.ResponseBody) != "") {
		return strings.TrimSpace(candidate.ResponseBody) != ""
	}
	if candidate.FetchedAt.Equal(current.FetchedAt) {
		return false
	}
	return candidate.FetchedAt.After(current.FetchedAt)
}

func normalizeUnauthorizedCiphertext(body string) string {
	if direct := normalizeUnauthorizedCiphertextValue(body); direct != "" {
		return direct
	}
	if isLikelyEncryptedResponseEnvelope(body) {
		var response map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &response); err == nil {
			payload, _ := lookupInsensitiveJSONString(response, "data", "payload", "ciphertext", "content", "result")
			return normalizeUnauthorizedCiphertextValue(payload)
		}
	}

	// Never recursively mine JSON business fields for random-looking strings.
	// A JSON response is treated as ciphertext only when it satisfies the
	// response-envelope contract above. This prevents values such as card_id,
	// request_id, token, or UUID from becoming "encrypted response" findings.
	return ""
}

func isLikelyEncryptedResponseEnvelope(body string) bool {
	var response map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &response); err != nil {
		return false
	}

	globalEncryption, _ := lookupInsensitiveJSONBool(response, "useGlobalEnc", "use_global_enc", "globalEncryption")
	if !globalEncryption {
		return false
	}
	algorithm, _ := lookupInsensitiveJSONString(response, "enc", "encryption", "cipher", "algorithm")
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	if algorithm == "" || algorithm == "none" || algorithm == "plain" || algorithm == "plaintext" {
		return false
	}
	payload, _ := lookupInsensitiveJSONString(response, "data", "payload", "ciphertext", "content", "result")
	if normalizeUnauthorizedCiphertextValue(payload) == "" {
		return false
	}

	return true
}

func lookupInsensitiveJSONString(values map[string]any, keys ...string) (string, bool) {
	for key, value := range values {
		for _, expected := range keys {
			if !strings.EqualFold(strings.TrimSpace(key), expected) {
				continue
			}
			stringValue, ok := value.(string)
			return strings.TrimSpace(stringValue), ok
		}
	}
	return "", false
}

func lookupInsensitiveJSONBool(values map[string]any, keys ...string) (bool, bool) {
	for key, value := range values {
		for _, expected := range keys {
			if !strings.EqualFold(strings.TrimSpace(key), expected) {
				continue
			}
			boolValue, ok := value.(bool)
			return boolValue, ok
		}
	}
	return false, false
}

func normalizeUnauthorizedCiphertextValue(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}

	var asJSONString string
	if err := json.Unmarshal([]byte(trimmed), &asJSONString); err == nil {
		trimmed = strings.TrimSpace(asJSONString)
	}

	trimmed = strings.TrimSpace(strings.Trim(trimmed, "\"'"))
	if trimmed == "" || strings.ContainsAny(trimmed, "{}[]") {
		return ""
	}

	if isHexString(trimmed) && len(trimmed) >= 32 && len(trimmed)%2 == 0 {
		return trimmed
	}
	if len(trimmed) >= 32 && isBase64Like(trimmed) {
		return trimmed
	}

	return ""
}

// buildFullURL 根据 ApiRoot 和 API 路径生成完整 URL
func buildFullURL(homeURL, apiRoot, api string, placeholder map[string]string) string {
	originalAPI := api

	// 规范化homeURL，去除fragment和query参数
	homeURLParsed, err := url.Parse(homeURL)
	if err == nil {
		homeURLParsed.Fragment = ""
		homeURLParsed.RawQuery = ""
		homeURL = homeURLParsed.String()
	}

	// 如果 api 已经是完整 URL，直接返回原始API（不进行占位符替换）
	if strings.HasPrefix(api, "http://") || strings.HasPrefix(api, "https://") {
		return originalAPI
	}

	// 对于非完整URL，进行占位符替换
	api = replacePlaceholders(api, placeholder)

	// 获取 homeURL 的 scheme://host 部分
	u, err := url.Parse(homeURL)
	if err != nil {
		return api // 出错就退化
	}

	baseURL := u.Scheme + "://" + u.Host

	// ApiRoot 为空时，默认用 homeURL
	if apiRoot == "" {
		api = strings.TrimLeft(api, "/")
		return baseURL + "/" + api
	}

	// 如果 ApiRoot 是完整 URL
	if strings.HasPrefix(apiRoot, "http://") || strings.HasPrefix(apiRoot, "https://") {
		rootURL, err := url.Parse(apiRoot)
		if err != nil {
			return strings.TrimRight(apiRoot, "/") + "/" + strings.TrimLeft(api, "/")
		}
		apiRootPath := strings.TrimRight(rootURL.Path, "/")

		// 如果 api 以 / 开头，说明是完整路径
		if strings.HasPrefix(originalAPI, "/") {
			// 检查 api 是否已经包含了 apiRoot 的路径部分
			if strings.HasPrefix(api, apiRootPath+"/") || api == apiRootPath {
				// api 已经包含完整路径，直接使用
				return baseURL + api
			}
		}

		// 否则正常拼接
		api = strings.TrimLeft(api, "/")
		return strings.TrimRight(apiRoot, "/") + "/" + api
	}

	// 如果 ApiRoot 是相对路径（以 / 开头）
	if strings.HasPrefix(apiRoot, "/") {
		apiRootPath := strings.TrimRight(apiRoot, "/")

		// 如果 api 以 / 开头，说明是完整路径
		if strings.HasPrefix(originalAPI, "/") {
			// 检查 api 是否已经包含了 apiRoot 的路径部分
			if strings.HasPrefix(api, apiRootPath+"/") || api == apiRootPath {
				// api 已经包含完整路径，直接使用
				return baseURL + api
			}
		}

		// 否则正常拼接
		api = strings.TrimLeft(api, "/")
		return baseURL + apiRootPath + "/" + api
	}

	// 其他情况（比如没加 /），直接拼到 homeURL 后面
	api = strings.TrimLeft(api, "/")
	return strings.TrimRight(homeURL, "/") + "/" + strings.TrimLeft(apiRoot, "/") + "/" + api
}

// replacePlaceholders 替换 API 占位符 (:id {id} <id>) 为缺省值
func replacePlaceholders(path string, rules map[string]string) string {
	re := regexp.MustCompile(`[:<{]([a-zA-Z0-9_]+)[>}]?`)
	return re.ReplaceAllStringFunc(path, func(m string) string {
		key := strings.ToLower(strings.Trim(m, ":{}<>"))

		// 遍历规则，模糊匹配 key
		for k, v := range rules {
			if k != "default" && strings.Contains(key, k) {
				return v
			}
		}

		// 默认值
		if def, ok := rules["default"]; ok {
			return def
		}
		return "test"
	})
}

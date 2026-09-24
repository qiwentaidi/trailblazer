// apiasset.go exposes the katana-based API asset capabilities through the
// stable SDK surface: runtime API context capture (APIContext), operation
// dedup/merge (APIStore), Observed API Docs export (OpenAPI 3.1) and the
// authorization comparative experiment.
//
// These entry points run on the forked katana engine (see the go.mod
// module requirement) and are the recommended way for other projects to
// consume "crawl -> API asset -> docs / audit" as a library.
package sdk

import (
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/qiwentaidi/clients"
	"github.com/qiwentaidi/katana/pkg/apiaudit"
	"github.com/qiwentaidi/katana/pkg/apicontext"
	"github.com/qiwentaidi/katana/pkg/engine/hybrid"
	"github.com/qiwentaidi/katana/pkg/output"
	"github.com/qiwentaidi/katana/pkg/types"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"golang.org/x/net/html"
)

type (
	// APIContext 一次观测到的接口完整上下文（方法、路径模板、参数、
	// 请求/响应结构、认证证据、来源证据），凭据保留原文。
	APIContext = apicontext.Context
	// APIParameter 观测参数（位置 in: path/query，含置信度）。
	APIParameter = apicontext.Parameter
	// APIBodySchema 请求体结构（字段类型推断 + 原文示例）。
	APIBodySchema = apicontext.BodySchema
	// APIAuthContext 认证证据（cookie|bearer|custom|none，凭据保存在 Headers 中）。
	APIAuthContext = apicontext.AuthContext
	// APIEvidence 资产来源证据（runtime / js-blueprint）。
	APIEvidence = apicontext.Evidence
	// APIStore 按 operationId 去重合并的接口资产仓库。
	APIStore = apicontext.Store
	// AuthzVerdict 授权对照实验结论（含判定理由，可复核）。
	AuthzVerdict = apiaudit.AuthzVerdict
	// AuthzSender 授权实验的 HTTP 发送器，允许调用方注入自带
	// 代理/Cookie 池/限速的 HTTP 客户端。
	AuthzSender = apiaudit.Sender
)

// APICrawlOptions 基于 katana hybrid（headless）引擎的接口资产采集选项。
// 只暴露与采集相关的参数；漏洞检测参数不在这里。
type APICrawlOptions struct {
	// Context cancels browser capture and recursive JavaScript downloads.
	Context context.Context
	// MaxDepth is used by supplemental Katana crawling only; default 3.
	MaxDepth int
	// Timeout is used by supplemental Katana crawling only; default 10 seconds.
	Timeout int
	// Concurrency is used by supplemental Katana crawling only; default 10.
	Concurrency int
	// RateLimit is used by supplemental Katana crawling only; default 150.
	RateLimit int
	// Proxy 代理地址（可选），如 http://127.0.0.1:8080。
	Proxy string
	// EnableKatana enables Katana as a supplemental crawler. It is off by
	// default because some large/minified bundles can keep the hybrid crawler
	// busy without yielding additional API evidence. Runtime + JS collection
	// remains enabled either way.
	EnableKatana bool
	// Headers are applied to browser, document, JS and Katana requests.
	Headers map[string]string
	// RuntimeTimeout bounds the Trailblazer browser capture, including form
	// triggering. Zero defaults to 35 seconds.
	RuntimeTimeout time.Duration
	// Deprecated: form triggering is enabled by default. Use
	// DisableAutoTriggerForms to opt out.
	AutoTriggerForms        bool
	DisableAutoTriggerForms bool
	// MaxJSResources limits downloaded JavaScript bundles, including recursively
	// referenced modules, for static request extraction. Zero defaults to 512.
	MaxJSResources int
	// OnAPIContext 每观测到一个接口上下文回调一次；返回 false 不中断爬取，
	// 仅跳过该条资产的入库。
	OnAPIContext func(ctx *APIContext) bool
}

// APIAssetResult is the complete, inspectable result of an API asset crawl.
// Store is suitable for OpenAPI export; JSResources and RequestBlueprints
// retain the evidence used for static parameter recognition and completion.
type APIAssetResult struct {
	Store             *APIStore                      `json:"-"`
	SiteTree          []crawl.ElTreeNode             `json:"siteTree"`
	JSResources       []database.JSResource          `json:"jsResources"`
	RequestBlueprints []crawl.RequestBlueprint       `json:"requestBlueprints"`
	AnchorCandidates  []crawl.RequestAnchorCandidate `json:"anchorCandidates,omitempty"`
	// OperationSpecs are persistable interface templates derived from static
	// blueprints; dynamic values are stripped and must come from runtime
	// traffic. ReplayFixture samples are never stored here.
	OperationSpecs []crawl.OperationSpec `json:"operationSpecs,omitempty"`
	RuntimeRecords []crawl.NetworkRecord `json:"runtimeRecords"`
	// APIRootCandidates are inferred API base-path candidates aggregated from
	// static and runtime evidence. They are useful asset-recognition leads, not
	// verified server configuration (for example /api/ or /gateway/api/v1/).
	APIRootCandidates []string `json:"apiRootCandidates,omitempty"`
}

// NewAPIStore 创建空的接口资产仓库。
func NewAPIStore() *APIStore {
	return apicontext.NewStore()
}

// CrawlAPIContexts 以 headless 模式爬取目标并采集接口资产。
//
// 返回的 Store 已完成按 operationId 的去重合并，可直接用于
// ExportOpenAPI 或 RunAuthorizationCheck。
func CrawlAPIContexts(target string, opts *APICrawlOptions) (*APIStore, error) {
	assets, err := CrawlAPIAssets(target, opts)
	if assets == nil {
		return NewAPIStore(), err
	}
	return assets.Store, err
}

// CrawlAPIAssets combines Katana's headless crawl with Trailblazer's runtime
// form-aware capture and static JS extraction. The latter is intentional: a
// page may construct APIs only after a user action, while JavaScript provides
// request method, body and parameter hints even when no request is replayed.
func CrawlAPIAssets(target string, opts *APICrawlOptions) (*APIAssetResult, error) {
	if opts == nil {
		opts = &APICrawlOptions{}
	}
	if err := apiAssetContext(opts).Err(); err != nil {
		return nil, err
	}
	if proxy := strings.TrimSpace(opts.Proxy); proxy != "" {
		parsed, err := url.Parse(proxy)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return nil, fmt.Errorf("apiasset: invalid proxy URL %q", proxy)
		}
	}
	store := apicontext.NewStore()
	assets := &APIAssetResult{Store: store, SiteTree: []crawl.ElTreeNode{}, JSResources: []database.JSResource{}, RequestBlueprints: []crawl.RequestBlueprint{}, RuntimeRecords: []crawl.NetworkRecord{}}

	var katanaURLs []string
	if opts.EnableKatana {
		var err error
		katanaURLs, err = crawlKatanaAPIContexts(target, opts, store)
		if err != nil {
			assets.SiteTree = buildAPIAssetSiteTree(target, katanaURLs)
			return assets, err
		}
	}

	// Katana observes navigation and network activity, but does not submit
	// forms. Reuse the existing bounded browser collector for form-driven API
	// calls, then merge its observations into the same operation store.
	runtimeTimeout := opts.RuntimeTimeout
	if runtimeTimeout <= 0 {
		runtimeTimeout = 35 * time.Second
	}
	networkURLs, records, _, _ := crawl.CaptureNetworkActivityWithOptions(target, crawl.CaptureOptions{
		Context:              apiAssetContext(opts),
		Timeout:              runtimeTimeout,
		ProxyServer:          opts.Proxy,
		Headers:              opts.Headers,
		AutoTriggerForms:     !opts.DisableAutoTriggerForms,
		AutoExploreRoutes:    true,
		MaxExploreRoutes:     8,
		MaxRouteClicks:       8,
		RouteInteractionWait: 2 * time.Second,
	})
	if err := apiAssetContext(opts).Err(); err != nil {
		return assets, err
	}
	assets.SiteTree = buildAPIAssetSiteTree(target, append(katanaURLs, networkURLs...))
	assets.RuntimeRecords = records
	for _, record := range records {
		ctx := apicontext.Build(apicontext.Observation{Method: record.Method, URL: record.URL, PostData: record.RequestBody, ReqHeaders: record.RequestHeaders, RespStatus: record.ResponseCode, RespHeaders: record.ResponseHeaders, RespBody: []byte(record.ResponseBody), ResourceType: record.ResourceType, PageURL: record.PageURL})
		if ctx == nil || (opts.OnAPIContext != nil && !opts.OnAPIContext(ctx)) {
			continue
		}
		store.Add(ctx)
	}

	assets.JSResources = collectAPIAssetJS(target, append(katanaURLs, networkURLs...), opts)
	if err := apiAssetContext(opts).Err(); err != nil {
		return assets, err
	}
	blueprintAnalysis := crawl.AnalyzeJSRequestBlueprints(assets.JSResources)
	assets.RequestBlueprints = prefixAPIAssetBlueprintPaths(supplementAPIAssetUploadActions(blueprintAnalysis.Blueprints, assets.JSResources), assets.RuntimeRecords)
	assets.AnchorCandidates = blueprintAnalysis.AnchorCandidates
	assets.OperationSpecs = crawl.OperationSpecsFromBlueprints(assets.RequestBlueprints, target)
	assets.APIRootCandidates = buildAPIAssetRootCandidates(target, assets.OperationSpecs, assets.RuntimeRecords, assets.Store)
	return assets, nil
}

func apiAssetContext(opts *APICrawlOptions) context.Context {
	if opts != nil && opts.Context != nil {
		return opts.Context
	}
	return context.Background()
}

// Static wrappers often prepend a base path at request time. Infer that path
// only when an observed request ends in the same static operation path.
func prefixAPIAssetBlueprintPaths(blueprints []crawl.RequestBlueprint, records []crawl.NetworkRecord) []crawl.RequestBlueprint {
	counts := make(map[string]int)
	exactMatch := false
	for _, record := range records {
		runtimePath := apiAssetPath(record.URL)
		for _, blueprint := range blueprints {
			staticPath := strings.TrimSpace(blueprint.Path)
			if staticPath == "" || !strings.HasPrefix(staticPath, "/") {
				continue
			}
			if runtimePath == staticPath {
				exactMatch = true
				continue
			}
			if strings.HasSuffix(runtimePath, staticPath) {
				prefix := strings.TrimSuffix(runtimePath, staticPath)
				if strings.HasPrefix(prefix, "/") && prefix != "/" {
					counts[strings.TrimRight(prefix, "/")]++
				}
			}
		}
	}
	if exactMatch || len(counts) == 0 {
		return blueprints
	}
	prefix := ""
	best := 0
	for candidate, count := range counts {
		if count > best {
			prefix, best = candidate, count
		} else if count == best {
			prefix = ""
		}
	}
	if prefix == "" {
		return blueprints
	}
	result := append([]crawl.RequestBlueprint(nil), blueprints...)
	for index := range result {
		path := strings.TrimSpace(result[index].Path)
		if strings.HasPrefix(path, "/") && path != prefix && !strings.HasPrefix(path, prefix+"/") {
			result[index].Path = prefix + path
		}
	}
	return result
}

func buildAPIAssetSiteTree(target string, discovered []string) []crawl.ElTreeNode {
	urls := make([]string, 0, len(discovered)+1)
	seen := make(map[string]struct{}, len(discovered)+1)
	for _, raw := range append([]string{target}, discovered...) {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			continue
		}
		parsed.Fragment = ""
		normalized := parsed.String()
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		urls = append(urls, normalized)
	}
	return crawl.BuildElTree(urls)
}

// buildAPIAssetRootCandidates restores the legacy API Root signal for the separated
// SDK pipeline. API routes may originate from static templates, browser
// runtime capture, or Katana contexts, so all three sources participate in
// root aggregation.
func buildAPIAssetRootCandidates(target string, specs []crawl.OperationSpec, records []crawl.NetworkRecord, store *APIStore) []string {
	routes := make([]string, 0, len(specs)+len(records))
	for _, spec := range specs {
		if path := apiAssetPath(spec.PathTemplate); path != "" {
			routes = append(routes, path)
		}
	}
	for _, record := range records {
		if path := apiAssetPath(record.URL); path != "" {
			routes = append(routes, path)
		}
	}
	if store != nil {
		for _, ctx := range store.List() {
			if ctx == nil {
				continue
			}
			if path := apiAssetPath(ctx.PathTemplate); path != "" {
				routes = append(routes, path)
			}
		}
	}

	filter := crawl.Filter{}
	roots := filter.APIRoots(routes, 1)
	if parsed, err := url.Parse(strings.TrimSpace(target)); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		roots = append(roots, parsed.Scheme+"://"+parsed.Host)
	}
	return dedupeAPIAssetRootCandidates(roots)
}

func apiAssetPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && parsed.Path != "" {
		return parsed.Path
	}
	if strings.HasPrefix(trimmed, "/") {
		if queryIndex := strings.IndexByte(trimmed, '?'); queryIndex >= 0 {
			return trimmed[:queryIndex]
		}
		return trimmed
	}
	return ""
}

func dedupeAPIAssetRootCandidates(roots []string) []string {
	seen := make(map[string]struct{}, len(roots))
	result := make([]string, 0, len(roots))
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		result = append(result, root)
	}
	return result
}

func crawlKatanaAPIContexts(target string, opts *APICrawlOptions, store *APIStore) ([]string, error) {
	var urls []string
	var urlsMu sync.Mutex
	katanaOpts := &types.Options{
		MaxDepth:      intOrDefault(opts.MaxDepth, 3),
		Timeout:       intOrDefault(opts.Timeout, 10),
		Concurrency:   intOrDefault(opts.Concurrency, 10),
		Parallelism:   intOrDefault(opts.Concurrency, 10),
		RateLimit:     intOrDefault(opts.RateLimit, 150),
		FieldScope:    "rdn",
		Strategy:      "depth-first",
		Proxy:         opts.Proxy,
		APICapture:    true,
		XhrExtraction: true,
		OnResult: func(result output.Result) {
			if result.Request != nil && result.Response != nil {
				urlsMu.Lock()
				urls = append(urls, result.Request.URL)
				urlsMu.Unlock()
			}
			if result.Response == nil {
				return
			}
			for _, ctx := range result.Response.APIContexts {
				if ctx == nil {
					continue
				}
				if opts.OnAPIContext != nil && !opts.OnAPIContext(ctx) {
					continue
				}
				store.Add(ctx)
			}
		},
	}
	for k, v := range opts.Headers {
		katanaOpts.CustomHeaders = append(katanaOpts.CustomHeaders, k+": "+v)
	}

	crawlerOptions, err := types.NewCrawlerOptions(katanaOpts)
	if err != nil {
		return urls, fmt.Errorf("apiasset: build crawler options: %w", err)
	}
	defer crawlerOptions.Close()

	crawler, err := hybrid.New(crawlerOptions)
	if err != nil {
		return urls, fmt.Errorf("apiasset: start hybrid crawler: %w", err)
	}
	defer crawler.Close()

	if err := crawler.Crawl(target); err != nil {
		return urls, fmt.Errorf("apiasset: katana crawl %s: %w", target, err)
	}
	return urls, nil
}

// maxJSResourceFetchBytes bounds how much of one JavaScript resource is
// fetched for static analysis. Bundles larger than this are truncated; the
// anchor-slice stage still analyzes the fetched prefix.
const (
	maxJSResourceFetchBytes = 8 * 1024 * 1024
	maxJSResourceTotalBytes = 64 * 1024 * 1024
	defaultMaxJSResources   = 512
)

var relativeJSReferencePattern = regexp.MustCompile("[\"'](\\.{1,2}/[^\"'\\s]+?\\.js(?:\\?[^\"'\\s]*)?)[\"']")
var uploadActionTemplatePattern = regexp.MustCompile("`[^`]{0,256}(/upload/\\$\\{([A-Za-z_$][\\w$.]*)\\})[^`]*`")

// UI upload components submit their action URL through the component rather
// than a fetch/axios call. Preserve a dynamic path as a template when the
// action binding appears alongside the template construction.
func supplementAPIAssetUploadActions(blueprints []crawl.RequestBlueprint, resources []database.JSResource) []crawl.RequestBlueprint {
	result := append([]crawl.RequestBlueprint(nil), blueprints...)
	seen := make(map[string]struct{}, len(result))
	for _, blueprint := range result {
		seen[strings.ToUpper(blueprint.Method)+" "+blueprint.Path] = struct{}{}
	}
	for _, resource := range resources {
		for _, match := range uploadActionTemplatePattern.FindAllStringSubmatchIndex(resource.Content, -1) {
			end := min(len(resource.Content), match[1]+1200)
			if !strings.Contains(resource.Content[match[1]:end], "action:") {
				continue
			}
			expression := resource.Content[match[4]:match[5]]
			param := expression
			if dot := strings.LastIndexByte(param, '.'); dot >= 0 {
				param = param[dot+1:]
			}
			path := "/upload/{" + param + "}"
			key := "POST " + path
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			snippet := resource.Content[match[0]:match[1]]
			hash := sha1.Sum([]byte(key + "\x00" + resource.URL + "\x00" + snippet))
			result = append(result, crawl.RequestBlueprint{
				ID:               fmt.Sprintf("jrb_%x", hash[:8]),
				Path:             path,
				Method:           "POST",
				Client:           "upload-action",
				Source:           crawl.RequestBlueprintSource{File: resource.URL, Snippet: snippet, StartOffset: match[0], EndOffset: match[1]},
				Confidence:       "medium",
				ConfidenceReason: "upload action path template; method inferred from upload component default",
				ExtractionSource: "js-upload-action",
			})
		}
	}
	return result
}

func collectAPIAssetJS(target string, candidates []string, opts *APICrawlOptions) []database.JSResource {
	limit := opts.MaxJSResources
	if limit <= 0 {
		limit = defaultMaxJSResources
	}
	base, err := url.Parse(target)
	if err != nil || base.Host == "" {
		return nil
	}
	client := clients.NewRestyClient(nil, true).GetClient()
	client.Timeout = 10 * time.Second
	if proxy := strings.TrimSpace(opts.Proxy); proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		if transport, ok := client.Transport.(*http.Transport); ok {
			copy := transport.Clone()
			copy.Proxy = http.ProxyURL(proxyURL)
			client.Transport = copy
		}
	}
	client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if !sameAPIAssetOrigin(base, req.URL) {
			return http.ErrUseLastResponse
		}
		return nil
	}
	seen := make(map[string]struct{})
	resources := make([]database.JSResource, 0)
	queue := make([]string, 0, len(candidates)+16)
	enqueue := func(raw string) {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || !sameAPIAssetOrigin(base, parsed) || !strings.EqualFold(parsed.Scheme, base.Scheme) || !strings.HasSuffix(strings.ToLower(parsed.Path), ".js") {
			return
		}
		parsed.Fragment = ""
		if (strings.EqualFold(parsed.Scheme, "https") && parsed.Port() == "443") ||
			(strings.EqualFold(parsed.Scheme, "http") && parsed.Port() == "80") {
			parsed.Host = parsed.Hostname()
		}
		candidate := parsed.String()
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		queue = append(queue, candidate)
	}
	for _, candidate := range candidates {
		enqueue(candidate)
	}
	for _, candidate := range apiAssetDocumentScripts(apiAssetContext(opts), client, base, opts.Headers) {
		enqueue(candidate)
	}
	totalBytes := 0
	for head := 0; head < len(queue) && len(resources) < limit && totalBytes < maxJSResourceTotalBytes; head++ {
		if apiAssetContext(opts).Err() != nil {
			break
		}
		candidate := queue[head]
		req, err := http.NewRequestWithContext(apiAssetContext(opts), http.MethodGet, candidate, nil)
		if err != nil {
			continue
		}
		for name, value := range opts.Headers {
			req.Header.Set(name, value)
		}
		resp, err := client.Do(req)
		if err != nil || resp == nil {
			continue
		}
		// Large application bundles commonly exceed 2MiB; the anchor-slice
		// analysis path bounds extractor work per resource, so fetching up to
		// 8MiB is safe and avoids silently truncating request modules.
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxJSResourceFetchBytes))
		resp.Body.Close()
		if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 ||
			strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
			continue
		}
		if totalBytes+len(body) > maxJSResourceTotalBytes {
			break
		}
		totalBytes += len(body)
		resources = append(resources, database.JSResource{URL: candidate, Content: string(body), ResponseCode: resp.StatusCode, Size: len(body), FetchedAt: time.Now()})
		parent, _ := url.Parse(candidate)
		for _, match := range relativeJSReferencePattern.FindAllStringSubmatch(string(body), -1) {
			ref, err := url.Parse(match[1])
			if err == nil {
				enqueue(parent.ResolveReference(ref).String())
			}
		}
	}
	return resources
}

func apiAssetDocumentScripts(ctx context.Context, client *http.Client, page *url.URL, headers map[string]string) []string {
	requestURL := *page
	requestURL.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	root, err := html.Parse(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return nil
	}
	result := make([]string, 0, 16)
	var visit func(*html.Node)
	visit = func(node *html.Node) {
		if node.Type == html.ElementNode && (node.Data == "script" || node.Data == "link") {
			attr := "src"
			if node.Data == "link" {
				attr = "href"
			}
			for _, item := range node.Attr {
				if item.Key != attr {
					continue
				}
				ref, err := url.Parse(strings.TrimSpace(item.Val))
				if err == nil {
					result = append(result, page.ResolveReference(ref).String())
				}
			}
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	return result
}

func sameAPIAssetOrigin(base, candidate *url.URL) bool {
	if base == nil || candidate == nil ||
		!strings.EqualFold(base.Scheme, candidate.Scheme) ||
		!strings.EqualFold(base.Hostname(), candidate.Hostname()) ||
		base.Hostname() == "" {
		return false
	}
	return apiAssetOriginPort(base) == apiAssetOriginPort(candidate)
}

func apiAssetOriginPort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return "443"
	}
	if strings.EqualFold(parsed.Scheme, "http") {
		return "80"
	}
	return ""
}

// ExportOpenAPI 把接口资产仓库导出为 OpenAPI 3.1 JSON 文档。
// 推断出的字段位于 confidence / evidence 等平名字段中，
// 文档可直接交给 swagger-ui 类工具渲染。
func ExportOpenAPI(store *APIStore, title string) ([]byte, error) {
	doc := apicontext.ToOpenAPI(store, title)
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("apiasset: marshal openapi: %w", err)
	}
	return raw, nil
}

// ExportOpenAPIWithSpecs renders runtime observations plus statically derived
// OperationSpecs into one OpenAPI 3.1 document. A runtime-observed operation
// always wins for its path+method; a spec only fills operations that runtime
// traffic did not capture (for example endpoints behind a login wall).
// Static operations are template-only: dynamic parameters carry no values and
// are marked with dynamic/requiresRuntime fields so consumers know runtime
// traffic must complete them.
func ExportOpenAPIWithSpecs(store *APIStore, specs []crawl.OperationSpec, title string) ([]byte, error) {
	doc := apicontext.ToOpenAPI(store, title)
	mergeOperationSpecsIntoOpenAPI(doc, specs)
	return marshalOpenAPIDocument(doc, nil)
}

// ExportOpenAPIAssets exports a complete crawl result. A shared inferred API
// Root candidate is reflected in the OpenAPI 3.1 server description and base
// URL, so consumers know it requires validation before use.
func ExportOpenAPIAssets(assets *APIAssetResult, title string) ([]byte, error) {
	if assets == nil {
		return nil, fmt.Errorf("apiasset: assets cannot be nil")
	}
	return ExportOpenAPIWithSpecsAndRoots(assets.Store, assets.OperationSpecs, assets.APIRootCandidates, title)
}

// ExportOpenAPIWithSpecsAndRoots is the root-aware variant of
// ExportOpenAPIWithSpecs. It preserves the older function for callers that
// only have a Store and templates.
func ExportOpenAPIWithSpecsAndRoots(store *APIStore, specs []crawl.OperationSpec, roots []string, title string) ([]byte, error) {
	doc := apicontext.ToOpenAPI(store, title)
	mergeOperationSpecsIntoOpenAPI(doc, specs)
	return marshalOpenAPIDocument(doc, roots)
}

func marshalOpenAPIDocument(doc *apicontext.OpenAPIDocument, roots []string) ([]byte, error) {
	if doc == nil {
		return nil, fmt.Errorf("apiasset: OpenAPI document cannot be nil")
	}
	serverURL, basePath := openAPIServerBase(roots, doc.Paths)
	if basePath != "" {
		doc.Paths = rebaseOpenAPIPaths(doc.Paths, basePath)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("apiasset: marshal openapi: %w", err)
	}
	if serverURL == "" && len(roots) == 0 {
		return raw, nil
	}
	var rendered map[string]any
	if err := json.Unmarshal(raw, &rendered); err != nil {
		return nil, fmt.Errorf("apiasset: decode rendered OpenAPI: %w", err)
	}
	if serverURL != "" {
		rendered["servers"] = []map[string]string{{
			"url":         serverURL,
			"description": "Inferred shared API base path; validate before using this server configuration.",
		}}
	}
	return json.MarshalIndent(rendered, "", "  ")
}

// openAPIServerBase selects the most-specific API Root shared by every path.
// Only a shared root can be safely represented as a document-level OpenAPI
// server because server URLs are prepended to every path.
func openAPIServerBase(roots []string, paths map[string]map[string]any) (string, string) {
	origin := ""
	candidates := make([]string, 0, len(roots))
	for _, root := range roots {
		trimmed := strings.TrimSpace(root)
		if trimmed == "" {
			continue
		}
		if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" && parsed.Host != "" {
			if origin == "" {
				origin = parsed.Scheme + "://" + parsed.Host
			}
			if path := normalizeOpenAPIBasePath(parsed.Path); path != "" {
				candidates = append(candidates, path)
			}
			continue
		}
		if path := normalizeOpenAPIBasePath(trimmed); path != "" {
			candidates = append(candidates, path)
		}
	}
	if origin == "" {
		return "", ""
	}
	sort.SliceStable(candidates, func(i, j int) bool { return len(candidates[i]) > len(candidates[j]) })
	for _, candidate := range candidates {
		if openAPIPathsShareBase(paths, candidate) {
			return origin + candidate, candidate
		}
	}
	return origin, ""
}

func normalizeOpenAPIBasePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "/" || !strings.HasPrefix(value, "/") {
		return ""
	}
	return strings.TrimRight(value, "/")
}

func openAPIPathsShareBase(paths map[string]map[string]any, base string) bool {
	if len(paths) == 0 {
		return false
	}
	for path := range paths {
		if path != base && !strings.HasPrefix(path, base+"/") {
			return false
		}
	}
	return true
}

func rebaseOpenAPIPaths(paths map[string]map[string]any, base string) map[string]map[string]any {
	rebased := make(map[string]map[string]any, len(paths))
	for path, item := range paths {
		key := strings.TrimPrefix(path, base)
		if key == "" {
			key = "/"
		}
		if !strings.HasPrefix(key, "/") {
			key = "/" + key
		}
		rebased[key] = item
	}
	return rebased
}

const (
	extStaticSource     = "source"
	extDynamic          = "dynamic"
	extDynamicReason    = "dynamicReason"
	extRequiresRuntime  = "requiresRuntime"
	extUnresolvedSymbol = "unresolvedSymbols"
	extAnalysisStage    = "analysisStage"
)

// mergeOperationSpecsIntoOpenAPI adds spec-derived operations for path+method
// pairs not already observed at runtime.
func mergeOperationSpecsIntoOpenAPI(doc *apicontext.OpenAPIDocument, specs []crawl.OperationSpec) {
	if doc == nil {
		return
	}
	if doc.Paths == nil {
		doc.Paths = make(map[string]map[string]any)
	}
	for _, spec := range specs {
		method := strings.ToLower(strings.TrimSpace(spec.Method))
		path := strings.TrimSpace(spec.PathTemplate)
		if method == "" || path == "" {
			continue
		}
		if doc.Paths[path] == nil {
			doc.Paths[path] = make(map[string]any)
		}
		if _, exists := doc.Paths[path][method]; exists {
			continue // runtime observation wins
		}
		operation := map[string]any{
			"operationId":   spec.ID,
			"summary":       strings.ToUpper(method) + " " + path,
			extStaticSource: "static-js-blueprint",
			apicontext.ExtConfidence: func() string {
				if spec.Confidence == "" {
					return "low"
				}
				return spec.Confidence
			}(),
			"responses": map[string]any{
				"default": map[string]any{"description": "Not observed at runtime; statically derived operation template"},
			},
		}
		if spec.AnalysisStage != "" {
			operation[extAnalysisStage] = spec.AnalysisStage
		}
		if len(spec.UnresolvedSymbols) > 0 {
			operation[extUnresolvedSymbol] = spec.UnresolvedSymbols
		}
		if len(spec.RequiresRuntime) > 0 {
			operation[extRequiresRuntime] = spec.RequiresRuntime
		}
		if params := specOpenAPIParameters(spec.Params); len(params) > 0 {
			operation["parameters"] = params
		}
		if body := specOpenAPIRequestBody(spec); body != nil {
			operation["requestBody"] = body
		}
		if specNeedsAuth(spec) {
			operation["security"] = []any{map[string]any{"bearerAuth": []string{}}}
			ensureSecurityScheme(doc, "bearerAuth", map[string]any{"type": "http", "scheme": "bearer"})
		}
		doc.Paths[path][method] = operation
	}
}

// specOpenAPIParameters converts query/path/header spec params into OpenAPI
// parameters. Dynamic params carry no example value.
func specOpenAPIParameters(params []crawl.OperationSpecParam) []any {
	out := make([]any, 0, len(params))
	for _, param := range params {
		location := strings.ToLower(strings.TrimSpace(param.Location))
		if location == "" {
			location = "query"
		}
		if location != "query" && location != "path" && location != "header" {
			continue
		}
		entry := map[string]any{
			"name":     param.Name,
			"in":       location,
			"required": location == "path",
			"schema":   map[string]any{"type": "string"},
		}
		if param.Value != "" {
			entry["example"] = param.Value
		}
		if param.Dynamic {
			entry[extDynamic] = true
			if param.DynamicReason != "" {
				entry[extDynamicReason] = param.DynamicReason
			}
		}
		if param.Confidence != "" {
			entry[apicontext.ExtConfidence] = param.Confidence
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].(map[string]any), out[j].(map[string]any)
		if a["in"] != b["in"] {
			return a["in"] == "path"
		}
		return a["name"].(string) < b["name"].(string)
	})
	return out
}

// specOpenAPIRequestBody builds a request body template from body-carried
// spec params (json/form). Values are only included when statically safe.
func specOpenAPIRequestBody(spec crawl.OperationSpec) map[string]any {
	bodyParams := make([]crawl.OperationSpecParam, 0, len(spec.Params))
	for _, param := range spec.Params {
		location := strings.ToLower(strings.TrimSpace(param.Location))
		if location == "json" || location == "body" || location == "form" {
			bodyParams = append(bodyParams, param)
		}
	}
	if len(bodyParams) == 0 && strings.TrimSpace(spec.PayloadTemplate) == "" {
		return nil
	}
	contentType := "application/json"
	switch strings.ToLower(strings.TrimSpace(spec.PayloadFormat)) {
	case "form", "formdata", "multipart":
		contentType = "multipart/form-data"
	case "urlencoded", "urlsearchparams":
		contentType = "application/x-www-form-urlencoded"
	}
	properties := make(map[string]any, len(bodyParams))
	for _, param := range bodyParams {
		schema := map[string]any{"type": "string"}
		if param.Dynamic {
			schema[extDynamic] = true
			if param.DynamicReason != "" {
				schema[extDynamicReason] = param.DynamicReason
			}
		}
		properties[param.Name] = schema
	}
	media := map[string]any{}
	if len(properties) > 0 {
		media["schema"] = map[string]any{"type": "object", "properties": properties}
	}
	if contentType == "application/json" {
		if example := staticJSONExample(spec.PayloadTemplate); example != nil {
			media["example"] = example
		}
	}
	return map[string]any{
		"required": true,
		"content":  map[string]any{contentType: media},
	}
}

// staticJSONExample parses a static payload template into an example value.
// Dynamic placeholders are stripped so no credential-shaped material leaks
// into the document.
func staticJSONExample(template string) any {
	template = strings.TrimSpace(template)
	if template == "" || !strings.HasPrefix(template, "{") {
		return nil
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(template), &parsed); err != nil {
		return nil
	}
	for key, value := range parsed {
		if crawl.IsDynamicParamName(key) {
			parsed[key] = "<runtime>"
			continue
		}
		if text, ok := value.(string); ok && len(text) >= 24 {
			parsed[key] = "<runtime>"
		}
	}
	return parsed
}

// specNeedsAuth reports whether the spec marks an authorization header as
// runtime-required.
func specNeedsAuth(spec crawl.OperationSpec) bool {
	for _, requirement := range spec.RequiresRuntime {
		if strings.EqualFold(strings.TrimSpace(requirement), "header:authorization") {
			return true
		}
	}
	for _, header := range spec.Headers {
		if header.Dynamic && strings.EqualFold(strings.TrimSpace(header.Name), "authorization") {
			return true
		}
	}
	return false
}

func ensureSecurityScheme(doc *apicontext.OpenAPIDocument, name string, scheme map[string]any) {
	if doc.Components == nil {
		doc.Components = &apicontext.OpenAPIComponents{}
	}
	if doc.Components.SecuritySchemes == nil {
		doc.Components.SecuritySchemes = make(map[string]any)
	}
	if _, exists := doc.Components.SecuritySchemes[name]; !exists {
		doc.Components.SecuritySchemes[name] = scheme
	}
}

// RunAuthorizationCheck 对单条接口资产执行授权对照实验：
// 复放匿名变体并与爬取期捕获的带凭据基线做状态码 / 响应类型 /
// 业务字段结构三重比对。不做低权限变体（无账号场景无法构造）。
func RunAuthorizationCheck(ctx *APIContext, sender AuthzSender) AuthzVerdict {
	if sender == nil {
		sender = defaultAuthzSender()
	}
	return apiaudit.RunAuthorizationExperiment(ctx, apiaudit.Sender(sender))
}

// defaultAuthzSender 使用标准库 http.Client 执行对照实验请求。
func defaultAuthzSender() AuthzSender {
	client := clients.NewRestyClient(nil, true).GetClient()
	client.Timeout = 10 * time.Second
	return func(req *http.Request) (*http.Response, []byte, error) {
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			resp.Body.Close()
			return nil, nil, readErr
		}
		return resp, body, nil
	}
}

func intOrDefault(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

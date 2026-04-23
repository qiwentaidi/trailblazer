package scanexec

import (
	"crypto/sha1"
	"encoding/json"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/structs"

	"github.com/google/uuid"
	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
)

type Options struct {
	TaskID         string
	Version        int
	BlackDomain    []string
	HighRiskRouter []string
	Authentication []string
	Placeholder    map[string]string
	OpenAI         config.OpenAI
	VulnDetection  config.VulnDetection
	DataStore      database.ScanDataStore
}

type SensitiveItem struct {
	Value      string
	Source     string
	AIVerified bool
}

type AssetInfo struct {
	Email     []SensitiveItem
	IDCard    []SensitiveItem
	Phone     []SensitiveItem
	IPURL     []SensitiveItem
	Sensitive []SensitiveItem
	APIRoutes []string
	APIRoots  []string
}

type RiskItem struct {
	ID          string
	Title       string
	Level       string
	Type        string
	URL         string
	Description string
	CreatedAt   string
}

type TargetResult struct {
	Target           string
	TreeData         []crawl.ElTreeNode
	NetworkURLs      []string
	APIRecords       []crawl.NetworkRecord
	ProtocolTraces   []crawl.ProtocolTraceRecord
	JSResources      []database.JSResource
	StaticHintBundle crawl.StaticEndpointHintBundle
	Assets           AssetInfo
	Risks            []RiskItem
	Vulnerabilities  []database.VulnRecord
}

type vulnSliceCollector struct {
	items []database.VulnRecord
}

func (c *vulnSliceCollector) Collect(vuln database.VulnRecord) {
	c.items = append(c.items, vuln)
}

type compositeScanDataStore struct {
	stores []database.ScanDataStore
}

const denyTemplateMinClusterSize = 3

type denyTemplateAIReviewer interface {
	JudgeDenyTemplate(requestPreview, responsePreview string) (bool, string, error)
}

type denyTemplateAIReviewResult struct {
	confirmed bool
}

type denyTemplateCluster struct {
	id          string
	kind        string
	label       string
	fingerprint string
	items       []*database.VulnRecord
}

var denyTemplateAIReviewCache sync.Map

var volatileResponseKeys = map[string]struct{}{
	"error_hint":   {},
	"hint":         {},
	"trace_id":     {},
	"traceid":      {},
	"request_id":   {},
	"requestid":    {},
	"req_id":       {},
	"reqid":        {},
	"timestamp":    {},
	"time":         {},
	"ts":           {},
	"nonce":        {},
	"sign":         {},
	"signature":    {},
	"rand":         {},
	"random":       {},
	"token":        {},
	"access_token": {},
}

func (s compositeScanDataStore) ListJSResources(taskID string, versions ...int) ([]database.JSResource, error) {
	var combined []database.JSResource
	for _, store := range s.stores {
		if store == nil {
			continue
		}
		items, err := store.ListJSResources(taskID, versions...)
		if err != nil {
			return nil, err
		}
		combined = append(combined, items...)
	}
	return combined, nil
}

func (s compositeScanDataStore) ListAPIResources(taskID string, versions ...int) ([]database.APIResource, error) {
	var combined []database.APIResource
	for _, store := range s.stores {
		if store == nil {
			continue
		}
		items, err := store.ListAPIResources(taskID, versions...)
		if err != nil {
			return nil, err
		}
		combined = append(combined, items...)
	}
	return combined, nil
}

func (s compositeScanDataStore) ListProtocolTraces(taskID string, versions ...int) ([]database.ProtocolTraceRecord, error) {
	var combined []database.ProtocolTraceRecord
	for _, store := range s.stores {
		if store == nil {
			continue
		}
		items, err := store.ListProtocolTraces(taskID, versions...)
		if err != nil {
			return nil, err
		}
		combined = append(combined, items...)
	}
	return combined, nil
}

func RunTarget(targetURL string, options Options) (*TargetResult, error) {
	if _, err := clients.SimpleGet(targetURL, clients.DefaultRestyClient()); err != nil {
		return nil, err
	}

	result := &TargetResult{
		Target:          targetURL,
		Assets:          AssetInfo{},
		Risks:           []RiskItem{},
		Vulnerabilities: []database.VulnRecord{},
	}

	e := crawl.Extract{}
	filter := crawl.Filter{}

	allNetworkURLs, capturedAPIRecords, capturedProtocolTraces := crawl.CaptureNetworkActivity(targetURL)
	for i := range capturedProtocolTraces {
		if strings.TrimSpace(capturedProtocolTraces[i].TaskID) == "" {
			capturedProtocolTraces[i].TaskID = options.TaskID
		}
	}
	mergedAPIRecords := mergeCapturedAPIRecordsWithProtocolTraces(capturedAPIRecords, capturedProtocolTraces)

	result.NetworkURLs = allNetworkURLs
	result.TreeData = crawl.BuildElTree(allNetworkURLs)
	result.APIRecords = mergedAPIRecords
	result.ProtocolTraces = capturedProtocolTraces

	classified := e.ClassifyLinks(allNetworkURLs, options.BlackDomain)

	allJS := mergeJSLinks(targetURL, classified, options.BlackDomain)
	result.JSResources = fetchStaticHintJSResources(options.TaskID, options.Version, targetURL, allJS, options.BlackDomain)
	result.StaticHintBundle = crawl.BuildStaticEndpointHintBundle(result.JSResources)

	var aiChecker *crawl.SensitiveInfoChecker
	if options.OpenAI.Enabled && strings.TrimSpace(options.OpenAI.APIKey) != "" {
		aiChecker = crawl.NewSensitiveInfoChecker(
			options.OpenAI.APIKey,
			options.OpenAI.BaseURL,
			options.OpenAI.Model,
		)
	}

	findSomething := crawl.Scan(targetURL, allJS, aiChecker)
	result.Assets = buildAssetInfo(findSomething)

	apiRouter := buildAPIRoutes(findSomething, classified, mergedAPIRecords, capturedProtocolTraces, filter)
	result.Assets.APIRoutes = apiRouter
	result.Assets.APIRoots = buildAPIRoots(targetURL, apiRouter, classified, filter)

	workingStore := buildWorkingDataStore(options, targetURL, result.JSResources, mergedAPIRecords, capturedProtocolTraces)
	collector := &vulnSliceCollector{}
	for _, root := range result.Assets.APIRoots {
		crawl.AnalyzeAPIWithCollector(buildJSFindOptions(options, targetURL, apiRouter, root, result.StaticHintBundle, aiChecker, workingStore), collector)
	}
	result.Vulnerabilities = dedupeVulnerabilities(collector.items)
	bindStaticContexts(result.Vulnerabilities, result.JSResources)
	result.Vulnerabilities = annotateUnauthorizedNoise(result.Vulnerabilities, aiChecker)
	result.Risks = buildRisks(result.Assets, aiChecker != nil)
	dedupeAssets(&result.Assets)

	return result, nil
}

func buildJSFindOptions(
	options Options,
	targetURL string,
	apiRouter []string,
	root string,
	hintBundle crawl.StaticEndpointHintBundle,
	aiChecker *crawl.SensitiveInfoChecker,
	dataStore database.ScanDataStore,
) structs.JSFindOptions {
	vulnDetection := resolveVulnDetection(options.VulnDetection)
	return structs.JSFindOptions{
		TaskID:                    options.TaskID,
		Version:                   options.Version,
		HomeURL:                   targetURL,
		ApiList:                   apiRouter,
		ApiRoot:                   root,
		StaticMethodHints:         hintBundle.Methods,
		StaticHeaderHints:         hintBundle.Headers,
		StaticConstantParams:      hintBundle.ConstantParams,
		StaticRequestPayloadHints: hintBundle.RequestPayload,
		SkipVulnScan:              !vulnDetection.Enabled,
		HighRiskRouter:            options.HighRiskRouter,
		Authentication:            options.Authentication,
		Placeholder:               options.Placeholder,
		LFIConfig:                 vulnDetection.LFI,
		SSRFConfig:                vulnDetection.SSRF,
		RedirectConfig:            vulnDetection.Redirect,
		SQLInjConfig:              vulnDetection.SQLInjection,
		XSSConfig:                 vulnDetection.XSS,
		UploadConfig:              vulnDetection.Upload,
		AIChecker:                 aiChecker,
		DataStore:                 dataStore,
	}
}

func resolveVulnDetection(options config.VulnDetection) config.VulnDetection {
	if options.Enabled {
		return options
	}

	options.SQLInjection.Enabled = false
	options.LFI.Enabled = false
	options.SSRF.Enabled = false
	options.Redirect.Enabled = false
	options.XSS.Enabled = false
	options.Upload.Enabled = false
	return options
}

func buildWorkingDataStore(
	options Options,
	targetURL string,
	jsResources []database.JSResource,
	apiRecords []crawl.NetworkRecord,
	protocolTraces []crawl.ProtocolTraceRecord,
) database.ScanDataStore {
	memoryStore := database.NewMemoryScanDataStore()
	memoryStore.AddJSResources(options.TaskID, jsResources)

	apiResources := make([]database.APIResource, 0, len(apiRecords))
	for _, record := range apiRecords {
		apiResources = append(apiResources, database.APIResource{
			TaskID:           options.TaskID,
			Version:          options.Version,
			URL:              record.URL,
			Method:           record.Method,
			TraceID:          record.TraceID,
			HasProtocolTrace: record.HasProtocolTrace,
			RequestHeaders:   record.RequestHeaders,
			RequestBody:      record.RequestBody,
			ResponseHeaders:  record.ResponseHeaders,
			ResponseBody:     record.ResponseBody,
			ResponseCode:     record.ResponseCode,
			Headers:          record.ResponseHeaders,
			FetchedAt:        record.FetchedAt,
		})
	}
	memoryStore.AddAPIResources(options.TaskID, apiResources)

	normalizedTraces := make([]database.ProtocolTraceRecord, 0, len(protocolTraces))
	for _, record := range protocolTraces {
		trace := normalizeProtocolTraceForView(record, options.Version, targetURL)
		normalizedTraces = append(normalizedTraces, trace)
	}
	memoryStore.AddProtocolTraces(options.TaskID, normalizedTraces)

	if options.DataStore == nil {
		return memoryStore
	}
	return compositeScanDataStore{stores: []database.ScanDataStore{memoryStore, options.DataStore}}
}

func normalizeProtocolTraceForView(record crawl.ProtocolTraceRecord, version int, targetURL string) database.ProtocolTraceRecord {
	requestSteps := make([]database.ProtocolCryptoStep, 0, len(record.RequestSteps))
	for _, step := range record.RequestSteps {
		requestSteps = append(requestSteps, database.ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}
	responseSteps := make([]database.ProtocolCryptoStep, 0, len(record.ResponseSteps))
	for _, step := range record.ResponseSteps {
		responseSteps = append(responseSteps, database.ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}
	dbTrace := database.ProtocolTraceRecord{
		TaskID:                 record.TaskID,
		Version:                version,
		TargetURL:              targetURL,
		TraceID:                record.TraceID,
		Transport:              record.Transport,
		PageURL:                record.PageURL,
		RequestURL:             record.RequestURL,
		Method:                 record.Method,
		RequestHeaders:         record.RequestHeaders,
		RequestBeforeTransform: record.RequestBeforeTransform,
		FinalRequestBody:       record.FinalRequestBody,
		RequestSteps:           requestSteps,
		ResponseSteps:          responseSteps,
		SignatureFields:        record.SignatureFields,
		DynamicParams:          record.DynamicParams,
		SessionMaterials:       record.SessionMaterials,
		Algorithms:             record.Algorithms,
		Stack:                  record.Stack,
		CreatedAt:              record.CreatedAt,
	}
	dbTrace.NormalizeForView()
	return dbTrace
}

func mergeJSLinks(targetURL string, classified crawl.NetworkLinks, blackDomain []string) []string {
	e := crawl.Extract{}
	filter := crawl.Filter{}

	staticJsLinks := filter.Blacklist(e.StaticJSLink(targetURL), blackDomain)
	classified.Classification.JS = filter.Blacklist(classified.Classification.JS, blackDomain)

	allJS := classified.Classification.JS
	if len(classified.Classification.JS) > 0 {
		for _, static := range staticJsLinks {
			present := false
			for _, dynamic := range classified.Classification.JS {
				if strings.Contains(dynamic, static) || strings.Contains(static, dynamic) {
					present = true
					break
				}
			}
			if !present {
				allJS = append(allJS, static)
			}
		}
	} else {
		allJS = append(allJS, staticJsLinks...)
	}

	return arrayutil.RemoveDuplicates(allJS)
}

func fetchStaticHintJSResources(taskID string, version int, homeURL string, jsLinks []string, blackDomain []string) []database.JSResource {
	const maxStaticHintJS = 40

	filter := crawl.Filter{}
	tempDir, err := os.MkdirTemp("", "trailblazer-shared-js-*")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(tempDir)

	result := make([]database.JSResource, 0, maxStaticHintJS)
	for _, jsURL := range jsLinks {
		if len(result) >= maxStaticHintJS {
			break
		}
		resolvedURL := normalizeJSURL(homeURL, jsURL)
		if strings.TrimSpace(resolvedURL) == "" || filter.IsBlacklist(resolvedURL, blackDomain) {
			continue
		}

		resp, err := clients.SimpleGet(resolvedURL, clients.DefaultRestyClient())
		if err != nil {
			continue
		}

		filePath := filepath.Join(tempDir, buildTempJSFileName(resolvedURL))
		if err := os.WriteFile(filePath, resp.Body(), 0o600); err != nil {
			continue
		}
		fileContent, err := os.ReadFile(filePath)
		_ = os.Remove(filePath)
		if err != nil {
			continue
		}

		result = append(result, database.JSResource{
			TaskID:       taskID,
			Version:      version,
			URL:          resolvedURL,
			Content:      string(fileContent),
			ResponseCode: resp.StatusCode(),
			Size:         len(fileContent),
			FetchedAt:    time.Now(),
		})
	}

	return result
}

func normalizeJSURL(homeURL, jsLink string) string {
	jsLink = strings.TrimSpace(jsLink)
	if jsLink == "" {
		return ""
	}
	if strings.HasPrefix(jsLink, "http://") || strings.HasPrefix(jsLink, "https://") {
		return jsLink
	}

	baseURL := strings.TrimSpace(homeURL)
	if parsed, err := url.Parse(baseURL); err == nil && parsed != nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + "/" + strings.TrimLeft(jsLink, "/")
	}
	return jsLink
}

func buildTempJSFileName(jsURL string) string {
	sum := sha1.Sum([]byte(jsURL))
	extension := filepath.Ext(strings.TrimSpace(jsURL))
	if extension == "" || len(extension) > 10 {
		extension = ".js"
	}
	return hex.EncodeToString(sum[:]) + extension
}

func buildAssetInfo(found structs.FindSomething) AssetInfo {
	result := AssetInfo{}
	for _, item := range found.Email {
		result.Email = append(result.Email, SensitiveItem{Value: item.Filed, Source: item.Source, AIVerified: item.AIVerified})
	}
	for _, item := range found.IDCard {
		result.IDCard = append(result.IDCard, SensitiveItem{Value: item.Filed, Source: item.Source, AIVerified: item.AIVerified})
	}
	for _, item := range found.Phone {
		result.Phone = append(result.Phone, SensitiveItem{Value: item.Filed, Source: item.Source, AIVerified: item.AIVerified})
	}
	for _, item := range found.IP_URL {
		result.IPURL = append(result.IPURL, SensitiveItem{Value: item.Filed, Source: item.Source, AIVerified: item.AIVerified})
	}
	for _, item := range found.Sensitive {
		result.Sensitive = append(result.Sensitive, SensitiveItem{Value: item.Filed, Source: item.Source, AIVerified: item.AIVerified})
	}
	return result
}

func buildAPIRoutes(
	found structs.FindSomething,
	classified crawl.NetworkLinks,
	apiRecords []crawl.NetworkRecord,
	protocolTraces []crawl.ProtocolTraceRecord,
	filter crawl.Filter,
) []string {
	var apiRouter []string
	for _, item := range found.APIRoute {
		if strings.Contains(item.Filed, "[") || strings.Contains(item.Filed, "]") {
			continue
		}
		route := strings.TrimSpace(item.Filed)
		if route != "" {
			apiRouter = append(apiRouter, route)
		}
	}
	for _, route := range classified.Classification.APIRoute {
		trimmedRoute := strings.TrimSpace(route)
		if trimmedRoute != "" {
			apiRouter = append(apiRouter, trimmedRoute)
		}
	}

	apiRouter = mergeRuntimeAPIRoutes(apiRouter, apiRecords, protocolTraces)
	apiRouter = preferAbsoluteRuntimeRoutes(apiRouter)
	apiRouter = arrayutil.RemoveDuplicates(apiRouter)
	apiRouter = filter.FilterAPIRoutes(apiRouter)

	sort.Slice(apiRouter, func(i, j int) bool {
		iIsFullURL := strings.HasPrefix(apiRouter[i], "http://") || strings.HasPrefix(apiRouter[i], "https://")
		jIsFullURL := strings.HasPrefix(apiRouter[j], "http://") || strings.HasPrefix(apiRouter[j], "https://")
		if iIsFullURL && !jIsFullURL {
			return true
		}
		if !iIsFullURL && jIsFullURL {
			return false
		}
		return false
	})

	return apiRouter
}

func buildAPIRoots(targetURL string, apiRouter []string, classified crawl.NetworkLinks, filter crawl.Filter) []string {
	apiRoots := filter.APIRoots(apiRouter, 1)
	allApiRoots := classified.Classification.APIRoot
	for _, item := range classified.Classification.APIRoot {
		for _, v := range apiRoots {
			if !strings.Contains(item, v) {
				allApiRoots = append(allApiRoots, v)
			}
		}
	}
	allApiRoots = append(allApiRoots, apiRoots...)
	allApiRoots = arrayutil.RemoveDuplicates(allApiRoots)

	if parsedURL, err := url.Parse(targetURL); err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
		siteRoot := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		allApiRoots = append(allApiRoots, siteRoot)
		allApiRoots = arrayutil.RemoveDuplicates(allApiRoots)
	}

	if len(allApiRoots) == 0 {
		if parsedURL, err := url.Parse(targetURL); err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
			allApiRoots = append(allApiRoots, fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host))
		}
	}

	return preferAbsoluteAPIRoots(allApiRoots)
}

func buildRisks(assets AssetInfo, aiEnabled bool) []RiskItem {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	var risks []RiskItem

	appendRisk := func(level, title, riskType string, items []SensitiveItem) {
		for _, item := range items {
			risks = append(risks, RiskItem{
				ID:          uuid.New().String(),
				Title:       title,
				Level:       level,
				Type:        riskType,
				URL:         item.Source,
				Description: fmt.Sprintf("发现%s: %s", title, item.Value),
				CreatedAt:   timestamp,
			})
		}
	}

	appendRisk("low", "身份证号码泄露", "敏感信息泄露", assets.IDCard)
	appendRisk("low", "手机号码泄露", "敏感信息泄露", assets.Phone)
	if aiEnabled {
		appendRisk("medium", "敏感关键词泄露", "敏感信息泄露", assets.Sensitive)
	} else {
		appendRisk("medium", "敏感关键词泄露", "敏感信息泄露", assets.Sensitive)
	}

	return risks
}

func dedupeAssets(assets *AssetInfo) {
	if assets == nil {
		return
	}
	assets.Email = dedupeSensitiveItems(assets.Email)
	assets.IDCard = dedupeSensitiveItems(assets.IDCard)
	assets.Phone = dedupeSensitiveItems(assets.Phone)
	assets.IPURL = dedupeSensitiveItems(assets.IPURL)
	assets.Sensitive = dedupeSensitiveItems(assets.Sensitive)
	assets.APIRoutes = arrayutil.RemoveDuplicates(assets.APIRoutes)
	assets.APIRoots = arrayutil.RemoveDuplicates(assets.APIRoots)
}

func dedupeSensitiveItems(items []SensitiveItem) []SensitiveItem {
	seen := make(map[string]int, len(items))
	result := make([]SensitiveItem, 0, len(items))
	for _, item := range items {
		key := strings.TrimSpace(item.Value) + "|" + strings.TrimSpace(item.Source)
		if index, ok := seen[key]; ok {
			result[index].AIVerified = result[index].AIVerified || item.AIVerified
			continue
		}
		seen[key] = len(result)
		result = append(result, item)
	}
	return result
}

func annotateUnauthorizedNoise(vulns []database.VulnRecord, reviewer denyTemplateAIReviewer) []database.VulnRecord {
	if len(vulns) == 0 {
		return vulns
	}

	clusters := map[string]*denyTemplateCluster{}
	for index := range vulns {
		vuln := &vulns[index]
		if !isUnauthorizedVuln(*vuln) {
			continue
		}

		fingerprint, kind, label, ok := buildDenyTemplateFingerprint(*vuln)
		if !ok {
			continue
		}

		clusterID := shortHash(kind + ":" + fingerprint)
		cluster, exists := clusters[clusterID]
		if !exists {
			cluster = &denyTemplateCluster{
				id:          clusterID,
				kind:        kind,
				label:       label,
				fingerprint: fingerprint,
				items:       []*database.VulnRecord{},
			}
			clusters[clusterID] = cluster
		}
		cluster.items = append(cluster.items, vuln)
	}

	for _, cluster := range clusters {
		if len(cluster.items) < denyTemplateMinClusterSize {
			continue
		}

		keep, aiVerified := shouldKeepDenyTemplateCluster(cluster, reviewer)
		if aiVerified {
			for _, vuln := range cluster.items {
				vuln.AIVerified = true
			}
		}
		if !keep {
			continue
		}

		for _, vuln := range cluster.items {
			vuln.DenyTemplateID = cluster.id
			vuln.DenyTemplateKind = cluster.kind
			vuln.DenyTemplateLabel = cluster.label
			vuln.DenyTemplateCount = len(cluster.items)
			vuln.Confidence = "low"

			reason := strings.TrimSpace(vuln.ConfidenceReason)
			clusterReason := fmt.Sprintf("%s，当前模板命中 %d 个接口", cluster.label, len(cluster.items))
			if reason == "" {
				vuln.ConfidenceReason = clusterReason
				continue
			}
			if !strings.Contains(reason, cluster.label) {
				vuln.ConfidenceReason = reason + "；" + clusterReason
			}
		}
	}

	return vulns
}

func isUnauthorizedVuln(vuln database.VulnRecord) bool {
	return vuln.Type == "未授权访问" || vuln.Title == "未授权访问"
}

func shouldKeepDenyTemplateCluster(cluster *denyTemplateCluster, reviewer denyTemplateAIReviewer) (bool, bool) {
	if cluster == nil || len(cluster.items) == 0 {
		return false, false
	}
	if reviewer == nil {
		return true, false
	}

	cacheKey := cluster.kind + ":" + cluster.fingerprint
	if cached, ok := denyTemplateAIReviewCache.Load(cacheKey); ok {
		if result, ok := cached.(denyTemplateAIReviewResult); ok {
			return result.confirmed, true
		}
	}

	sample := pickDenyTemplateRepresentative(cluster.items)
	if sample == nil {
		return true, false
	}

	confirmed, _, err := reviewer.JudgeDenyTemplate(sample.Request, sample.Response)
	if err != nil {
		return true, false
	}

	denyTemplateAIReviewCache.Store(cacheKey, denyTemplateAIReviewResult{confirmed: confirmed})
	return confirmed, true
}

func pickDenyTemplateRepresentative(items []*database.VulnRecord) *database.VulnRecord {
	if len(items) == 0 {
		return nil
	}

	best := items[0]
	bestScore := denyTemplateRepresentativeScore(best)
	for _, item := range items[1:] {
		score := denyTemplateRepresentativeScore(item)
		if score > bestScore {
			best = item
			bestScore = score
		}
	}
	return best
}

func denyTemplateRepresentativeScore(vuln *database.VulnRecord) int {
	if vuln == nil {
		return -1
	}
	return len(strings.TrimSpace(vuln.Request))*2 + len(strings.TrimSpace(vuln.Response))
}

func buildDenyTemplateFingerprint(vuln database.VulnRecord) (string, string, string, bool) {
	normalizedResponse := strings.TrimSpace(vuln.Response)
	if normalizedResponse == "" {
		return "", "", "", false
	}

	shortResponse := len(normalizedResponse) <= 1024
	normalizedBody := normalizeResponseFingerprint(normalizedResponse)
	if normalizedBody == "" {
		return "", "", "", false
	}

	score := 0
	kind := "deny_template"
	label := "疑似统一拒绝模板"

	if shortResponse {
		score += 2
	}
	if vuln.ResponseLength > 0 && vuln.ResponseLength <= 256 {
		score += 2
	}
	if strings.Contains(normalizedBody, `"success":false`) || strings.Contains(normalizedBody, `"ok":false`) {
		score += 2
	}

	authSignalCount := countAuthSignals(normalizedBody)
	if authSignalCount > 0 {
		score += authSignalCount * 2
		kind = "auth_required"
		label = "疑似统一认证拒绝模板"
	}

	if strings.Contains(normalizedBody, `"data":null`) || strings.Contains(normalizedBody, `"result":null`) {
		score += 1
	}

	if strings.Contains(normalizedBody, `"from":"`) && strings.Contains(normalizedBody, `auth`) {
		score += 2
		kind = "auth_required"
		label = "疑似统一认证拒绝模板"
	}

	if score < 4 {
		return "", "", "", false
	}

	fingerprint := normalizedBody
	if len(fingerprint) > 512 {
		fingerprint = fingerprint[:512]
	}

	return fingerprint, kind, label, true
}

func normalizeResponseFingerprint(response string) string {
	trimmed := strings.TrimSpace(response)
	if trimmed == "" {
		return ""
	}

	var data any
	if err := json.Unmarshal([]byte(trimmed), &data); err == nil {
		return canonicalizeJSONValue(data)
	}

	lower := strings.ToLower(trimmed)
	return strings.Join(strings.Fields(lower), " ")
}

func canonicalizeJSONValue(value any) string {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			normalizedKey := strings.ToLower(key)
			if isVolatileResponseKey(normalizedKey) {
				parts = append(parts, strconv.Quote(normalizedKey)+`:"<volatile>"`)
				continue
			}
			parts = append(parts, strconv.Quote(normalizedKey)+":"+canonicalizeJSONValue(typed[key]))
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
			parts = append(parts, canonicalizeJSONValue(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case string:
		normalized := strings.ToLower(strings.TrimSpace(typed))
		normalized = strings.Join(strings.Fields(normalized), " ")
		return strconv.Quote(normalized)
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

func countAuthSignals(body string) int {
	signals := []string{
		"auth", "jwt", "token", "credential", "login", "session", "unauthorized", "forbidden", "permission",
		"凭据", "认证", "鉴权", "登录", "令牌", "未登录", "无权限",
	}

	count := 0
	for _, signal := range signals {
		if strings.Contains(body, signal) {
			count++
		}
	}
	return count
}

func isVolatileResponseKey(key string) bool {
	if _, ok := volatileResponseKeys[key]; ok {
		return true
	}

	return strings.Contains(key, "trace") ||
		strings.Contains(key, "request") ||
		strings.Contains(key, "nonce") ||
		strings.Contains(key, "timestamp") ||
		strings.Contains(key, "error_hint")
}

func shortHash(value string) string {
	sum := sha1.Sum([]byte(value))
	return hex.EncodeToString(sum[:8])
}

func mergeCapturedAPIRecordsWithProtocolTraces(apiRecords []crawl.NetworkRecord, protocolTraces []crawl.ProtocolTraceRecord) []crawl.NetworkRecord {
	merged := make([]crawl.NetworkRecord, 0, len(apiRecords)+len(protocolTraces))
	recordIndex := make(map[string]int, len(apiRecords)+len(protocolTraces))
	traceIndex := make(map[string]int, len(apiRecords)+len(protocolTraces))
	urlMethodIndex := make(map[string]int, len(apiRecords)+len(protocolTraces))

	putRecord := func(record crawl.NetworkRecord) {
		key := strings.TrimSpace(record.Method) + "|" + strings.TrimSpace(record.URL) + "|" + strings.TrimSpace(record.RequestBody)
		urlMethodKey := strings.TrimSpace(record.Method) + "|" + strings.TrimSpace(record.URL)

		idx := -1
		if traceID := strings.TrimSpace(record.TraceID); traceID != "" {
			if existingIdx, ok := traceIndex[traceID]; ok {
				idx = existingIdx
			}
		}
		if idx == -1 {
			if existingIdx, ok := recordIndex[key]; ok {
				idx = existingIdx
			}
		}
		if idx == -1 {
			if existingIdx, ok := urlMethodIndex[urlMethodKey]; ok {
				existing := merged[existingIdx]
				if strings.TrimSpace(existing.RequestBody) == "" || strings.TrimSpace(record.RequestBody) == "" {
					idx = existingIdx
				}
			}
		}

		if idx >= 0 {
			existing := &merged[idx]
			if existing.TraceID == "" {
				existing.TraceID = record.TraceID
			}
			existing.HasProtocolTrace = existing.HasProtocolTrace || record.HasProtocolTrace
			if existing.ResourceType == "" {
				existing.ResourceType = record.ResourceType
			}
			if len(existing.RequestHeaders) == 0 {
				existing.RequestHeaders = record.RequestHeaders
			}
			if existing.RequestBody == "" {
				existing.RequestBody = record.RequestBody
			}
			if len(existing.ResponseHeaders) == 0 {
				existing.ResponseHeaders = record.ResponseHeaders
			}
			if existing.ResponseBody == "" {
				existing.ResponseBody = record.ResponseBody
			}
			if existing.ResponseCode == 0 {
				existing.ResponseCode = record.ResponseCode
			}
			if existing.MIMEType == "" {
				existing.MIMEType = record.MIMEType
			}
			if existing.FetchedAt.IsZero() {
				existing.FetchedAt = record.FetchedAt
			}
			recordIndex[key] = idx
			urlMethodIndex[urlMethodKey] = idx
			if traceID := strings.TrimSpace(existing.TraceID); traceID != "" {
				traceIndex[traceID] = idx
			}
			return
		}

		nextIdx := len(merged)
		recordIndex[key] = nextIdx
		urlMethodIndex[urlMethodKey] = nextIdx
		if traceID := strings.TrimSpace(record.TraceID); traceID != "" {
			traceIndex[traceID] = nextIdx
		}
		merged = append(merged, record)
	}

	for _, record := range apiRecords {
		putRecord(record)
	}

	for _, trace := range protocolTraces {
		requestURL := strings.TrimSpace(trace.RequestURL)
		if requestURL == "" {
			continue
		}

		record := crawl.NetworkRecord{
			URL:              requestURL,
			Method:           trace.Method,
			ResourceType:     trace.Transport,
			TraceID:          trace.TraceID,
			HasProtocolTrace: strings.TrimSpace(trace.TraceID) != "",
			RequestHeaders:   trace.RequestHeaders,
			RequestBody:      trace.FinalRequestBody,
			ResponseBody:     preferTraceResponseBody(trace),
			FetchedAt:        trace.CreatedAt,
		}
		if strings.HasPrefix(strings.TrimSpace(record.ResponseBody), "{") || strings.HasPrefix(strings.TrimSpace(record.ResponseBody), "[") {
			record.MIMEType = "application/json"
		}
		putRecord(record)
	}

	return merged
}

func preferTraceResponseBody(trace crawl.ProtocolTraceRecord) string {
	if body := strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]); body != "" {
		return body
	}
	if body := strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"]); body != "" {
		return body
	}
	return ""
}

func mergeRuntimeAPIRoutes(routes []string, apiRecords []crawl.NetworkRecord, protocolTraces []crawl.ProtocolTraceRecord) []string {
	merged := append([]string{}, routes...)
	for _, record := range apiRecords {
		if value := strings.TrimSpace(record.URL); value != "" {
			merged = append(merged, value)
		}
	}
	for _, trace := range protocolTraces {
		if value := strings.TrimSpace(trace.RequestURL); value != "" {
			merged = append(merged, value)
		}
	}
	return arrayutil.RemoveDuplicates(merged)
}

func preferAbsoluteRuntimeRoutes(routes []string) []string {
	absoluteByPath := make(map[string]bool)
	for _, route := range routes {
		parsed, err := url.Parse(strings.TrimSpace(route))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		absoluteByPath[strings.TrimSpace(parsed.Path)] = true
	}

	result := make([]string, 0, len(routes))
	for _, route := range routes {
		trimmed := strings.TrimSpace(route)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "/") && absoluteByPath[trimmed] {
			continue
		}
		result = append(result, trimmed)
	}
	return arrayutil.RemoveDuplicates(result)
}

func ensureTrailingSlash(value string) string {
	if strings.HasSuffix(value, "/") {
		return value
	}
	return value + "/"
}

func preferAbsoluteAPIRoots(roots []string) []string {
	absoluteByPath := make(map[string]bool)
	for _, root := range roots {
		parsed, err := url.Parse(strings.TrimSpace(root))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		absoluteByPath[ensureTrailingSlash(parsed.Path)] = true
	}

	result := make([]string, 0, len(roots))
	for _, root := range roots {
		trimmed := strings.TrimSpace(root)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "/") && absoluteByPath[ensureTrailingSlash(trimmed)] {
			continue
		}
		result = append(result, trimmed)
	}
	return arrayutil.RemoveDuplicates(result)
}

func dedupeVulnerabilities(vulns []database.VulnRecord) []database.VulnRecord {
	if len(vulns) <= 1 {
		return vulns
	}

	index := make(map[string]int, len(vulns))
	result := make([]database.VulnRecord, 0, len(vulns))
	for _, vuln := range vulns {
		key := vulnerabilityDedupKey(vuln)
		if idx, ok := index[key]; ok {
			result[idx] = choosePreferredVulnerability(result[idx], vuln)
			continue
		}
		index[key] = len(result)
		result = append(result, vuln)
	}
	return result
}

func vulnerabilityDedupKey(vuln database.VulnRecord) string {
	parsed, err := url.Parse(strings.TrimSpace(vuln.URL))
	if err == nil && parsed.Host != "" {
		return strings.ToUpper(strings.TrimSpace(vuln.Method)) + "|" + strings.ToLower(parsed.Host) + "|" + parsed.Path + "|" + strings.TrimSpace(vuln.Type)
	}
	return strings.ToUpper(strings.TrimSpace(vuln.Method)) + "|" + strings.TrimSpace(vuln.URL) + "|" + strings.TrimSpace(vuln.Type)
}

func choosePreferredVulnerability(current, candidate database.VulnRecord) database.VulnRecord {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(candidate.URL)), "https://") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(current.URL)), "https://") {
		return candidate
	}
	if candidate.ResponseLength > current.ResponseLength {
		return candidate
	}
	if len(strings.TrimSpace(candidate.Response)) > len(strings.TrimSpace(current.Response)) {
		return candidate
	}
	return current
}

func bindStaticContexts(vulns []database.VulnRecord, jsResources []database.JSResource) {
	if len(vulns) == 0 || len(jsResources) == 0 {
		return
	}
	for i := range vulns {
		vulns[i].StaticContexts = findStaticContextsForVuln(vulns[i], jsResources)
	}
}

func findStaticContextsForVuln(vuln database.VulnRecord, jsResources []database.JSResource) []database.VulnStaticContext {
	needles := buildStaticContextNeedles(vuln.URL)
	if len(needles) == 0 {
		return nil
	}

	result := make([]database.VulnStaticContext, 0, 3)
	seen := make(map[string]bool)
	for _, resource := range jsResources {
		content := strings.TrimSpace(resource.Content)
		if content == "" {
			continue
		}

		snippet := buildMatchedSnippet(content, needles)
		if snippet == "" {
			continue
		}

		key := strings.TrimSpace(resource.URL) + "|" + snippet
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, database.VulnStaticContext{
			SourceURL: resource.URL,
			Snippet:   snippet,
		})
		if len(result) >= 3 {
			break
		}
	}

	return result
}

func buildStaticContextNeedles(rawURL string) []string {
	normalized := strings.TrimSpace(rawURL)
	if normalized == "" {
		return nil
	}

	needles := make([]string, 0, 4)
	appendNeedle := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range needles {
			if existing == value {
				return
			}
		}
		needles = append(needles, value)
	}

	appendNeedle(normalized)
	if parsed, err := url.Parse(normalized); err == nil {
		appendNeedle(parsed.Path + parsed.RawQuery)
		if parsed.RawQuery != "" {
			appendNeedle(parsed.Path + "?" + parsed.RawQuery)
		}
		appendNeedle(parsed.Path)
	}

	sort.SliceStable(needles, func(i, j int) bool {
		return len(needles[i]) > len(needles[j])
	})
	return needles
}

func buildMatchedSnippet(content string, needles []string) string {
	if len(needles) == 0 {
		return ""
	}

	lowerContent := strings.ToLower(content)
	for _, needle := range needles {
		lowerNeedle := strings.ToLower(strings.TrimSpace(needle))
		if lowerNeedle == "" {
			continue
		}
		start := strings.Index(lowerContent, lowerNeedle)
		if start < 0 {
			continue
		}
		snippetStart := maxInt(0, start-120)
		snippetEnd := minInt(len(content), start+len(needle)+120)
		prefix := ""
		suffix := ""
		if snippetStart > 0 {
			prefix = "..."
		}
		if snippetEnd < len(content) {
			suffix = "..."
		}
		return prefix + content[snippetStart:snippetEnd] + suffix
	}

	return ""
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

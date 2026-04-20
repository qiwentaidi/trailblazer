package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/structs"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
	"gopkg.in/yaml.v3"
)

func resolveWebVulnDetection(options config.VulnDetection) config.VulnDetection {
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

// ScanResult 扫描结果
type ScanResult struct {
	TaskID   string             `json:"taskId"`
	Target   string             `json:"target"`
	TreeData []crawl.ElTreeNode `json:"treeData"`
	Assets   AssetInfo          `json:"assets"`
	Risks    []RiskItem         `json:"risks"`
	APIRoots []string           `json:"apiRoots"`
}

// AssetInfo 资产信息
type AssetInfo struct {
	Email     []SensitiveItem `json:"email"`
	IDCard    []SensitiveItem `json:"idCard"`
	Phone     []SensitiveItem `json:"phone"`
	IPURL     []SensitiveItem `json:"ipUrl"`
	Sensitive []SensitiveItem `json:"sensitive"`
	APIRoutes []string        `json:"apiRoutes"`
}

type SensitiveItem struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

func assetValuesFromSensitiveItems(items []SensitiveItem) []database.AssetValue {
	values := make([]database.AssetValue, 0, len(items))
	for _, item := range items {
		value := strings.TrimSpace(item.Value)
		if value == "" {
			continue
		}
		values = append(values, database.AssetValue{
			Value:  value,
			Source: nonEmptySourceList(item.Source),
		})
	}
	return database.MergeAssetValues(values)
}

func assetValuesFromStrings(items []string, sources ...string) []database.AssetValue {
	return database.NewAssetValues(items, sources...)
}

func buildAPIRootAssetValues(roots []string, routes []string, fallbackSource string) []database.AssetValue {
	values := make([]database.AssetValue, 0, len(roots))
	for _, root := range roots {
		normalizedRoot := strings.TrimSpace(root)
		if normalizedRoot == "" {
			continue
		}

		var matchedSources []string
		for _, route := range routes {
			normalizedRoute := strings.TrimSpace(route)
			if normalizedRoute == "" {
				continue
			}
			if strings.Contains(normalizedRoute, normalizedRoot) {
				matchedSources = append(matchedSources, normalizedRoute)
			}
		}
		if len(matchedSources) == 0 {
			matchedSources = nonEmptySourceList(fallbackSource)
		}

		values = append(values, database.AssetValue{
			Value:  normalizedRoot,
			Source: matchedSources,
		})
	}
	return database.MergeAssetValues(values)
}

func nonEmptySourceList(sources ...string) []string {
	result := make([]string, 0, len(sources))
	for _, source := range sources {
		trimmed := strings.TrimSpace(source)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

type RiskItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Level       string `json:"level"` // high, medium, low, info
	Type        string `json:"type"`
	URL         string `json:"url"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

// startScan 启动完整扫描（异步模式）
func startScan(c *gin.Context) {
	var body struct {
		URLs   []string `json:"urls"`
		TaskId string   `json:"taskId"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	if len(body.URLs) == 0 {
		c.JSON(400, gin.H{"error": "urls array is required and cannot be empty"})
		return
	}

	// 更新任务状态为running
	if body.TaskId != "" {
		task := database.Task{ID: body.TaskId}
		_, err := task.UpdateStatus("running", 0)
		if err != nil {
			fmt.Printf("[ERROR] Failed to update task status to running: %v\n", err)
		} else {
			fmt.Printf("[INFO] Updated task %s status to running\n", body.TaskId)
		}
	}

	// 立即返回响应，启动异步扫描
	c.JSON(200, gin.H{"message": "扫描已启动", "taskId": body.TaskId})

	// 启动异步扫描
	go performAsyncScan(body.URLs, body.TaskId)
}

// performAsyncScan 执行异步扫描
func performAsyncScan(urls []string, taskId string) {
	version := 0

	// 添加defer函数处理扫描失败的情况
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[ERROR] Scan panic recovered: %v\n", r)
			if taskId != "" {
				if version > 0 {
					if err := database.UpdateTaskVersionStatus(taskId, version, "failed", 0); err != nil {
						fmt.Printf("[ERROR] Failed to update task version status to failed: %v\n", err)
					}
				}
				task := database.Task{ID: taskId}
				_, err := task.UpdateStatus("failed", 0)
				if err != nil {
					fmt.Printf("[ERROR] Failed to update task status to failed: %v\n", err)
				} else {
					fmt.Printf("[INFO] Updated task %s status to failed\n", taskId)
				}
			}
		}
	}()

	// 加载配置
	configData, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("[ERROR] Failed to load config: %v\n", err)
		if taskId != "" {
			task := database.Task{ID: taskId}
			task.UpdateStatus("failed", 0)
		}
		return
	}
	var config Config
	if err := yaml.Unmarshal(configData, &config); err != nil {
		fmt.Printf("[ERROR] Failed to parse config: %v\n", err)
		if taskId != "" {
			task := database.Task{ID: taskId}
			task.UpdateStatus("failed", 0)
		}
		return
	}
	resolvedVulnDetection := resolveWebVulnDetection(config.VulnDetection)

	now := time.Now()

	if taskId != "" {
		taskVersion, err := database.CreateTaskVersion(taskId, urls, configData, "manual")
		if err != nil {
			fmt.Printf("[ERROR] Failed to create task version for task %s: %v\n", taskId, err)
			task := database.Task{ID: taskId}
			task.UpdateStatus("failed", 0)
			return
		}
		version = taskVersion.Version
		if err := database.UpdateTaskVersionStatus(taskId, version, "running", 0); err != nil {
			fmt.Printf("[ERROR] Failed to update task version %d status to running: %v\n", version, err)
		}
		fmt.Printf("[INFO] Created task version %d for task %s\n", version, taskId)
	}

	// 存储所有URL的扫描结果
	var allResults []ScanResult
	var allAssets AssetInfo
	var allRisks []RiskItem
	var allAPIRoots []string
	var allTreeData []crawl.ElTreeNode

	// 用于收集所有URL的资产数据
	var allIPURLAssets []database.AssetValue
	var allAPIRouterAssets []database.AssetValue
	var allAPIRootAssets []database.AssetValue

	// 循环处理每个URL
	for i, targetURL := range urls {
		fmt.Printf("[INFO] Processing URL %d/%d: %s\n", i+1, len(urls), targetURL)

		// 存活验证
		_, err = clients.SimpleGet(targetURL, clients.DefaultRestyClient())
		if err != nil {
			fmt.Printf("[WARNING] Target %s is not accessible: %v\n", targetURL, err)
			continue
		}

		result := ScanResult{
			TaskID: taskId,
			Target: targetURL,
			Assets: AssetInfo{},
			Risks:  []RiskItem{},
		}

		e := crawl.Extract{}
		filter := crawl.Filter{}

		// 1. 捕获网络链接和运行时接口请求/响应记录
		allNetworkURLs, capturedAPIRecords, protocolTraces := crawl.CaptureNetworkActivity(targetURL)

		// 2. 生成网站树并保存到ES
		result.TreeData = crawl.BuildElTree(allNetworkURLs)
		if database.ESClient != nil {
			saveTreeToESWithURL(taskId, version, targetURL, result.TreeData, now)
			fmt.Printf("[DEBUG] Saved %d tree nodes to ES for task %s (URL: %s)\n", countTreeNodes(result.TreeData), taskId, targetURL)
		} else {
			fmt.Printf("[DEBUG] ES client is nil, tree not saved\n")
		}

		// 3. 分类链接（使用已捕获的链接）
		classified := e.ClassifyLinks(allNetworkURLs, config.BlackDomain)

		// 4. 静态JS提取 + 合并去重
		var allJS []string
		staticJsLinks := filter.Blacklist(e.StaticJSLink(targetURL), config.BlackDomain)
		classified.Classification.JS = filter.Blacklist(classified.Classification.JS, config.BlackDomain)

		allJS = classified.Classification.JS
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
		allJS = arrayutil.RemoveDuplicates(allJS)
		staticHeaderHints := make(map[string]map[string]string)
		staticMethodHints := make(map[string]string)
		staticConstantParamHints := make(map[string]url.Values)
		staticRequestPayloadHints := make(map[string]structs.StaticRequestPayloadHint)

		const maxStaticHintJS = 40
		filteredHintJS := make([]database.JSResource, 0, maxStaticHintJS)
		for _, jsURL := range allJS {
			if len(filteredHintJS) >= maxStaticHintJS {
				break
			}
			if filter.IsBlacklist(jsURL, config.BlackDomain) {
				continue
			}
			resp, err := clients.SimpleGet(jsURL, clients.DefaultRestyClient())
			if err != nil {
				continue
			}
			filteredHintJS = append(filteredHintJS, database.JSResource{
				TaskID:       taskId,
				Version:      version,
				URL:          jsURL,
				Content:      string(resp.Body()),
				ResponseCode: resp.StatusCode(),
				Size:         len(resp.Body()),
				FetchedAt:    time.Now(),
			})
		}
		hintStartedAt := time.Now()
		hintBundle := crawl.BuildStaticEndpointHintBundle(filteredHintJS)
		if len(hintBundle.ConstantParams) > 0 {
			staticConstantParamHints = hintBundle.ConstantParams
			fmt.Printf("[DEBUG] Built %d static constant-param endpoint hints for %s\n", len(hintBundle.ConstantParams), targetURL)
		}
		if len(hintBundle.Methods) > 0 {
			staticMethodHints = hintBundle.Methods
			fmt.Printf("[DEBUG] Built %d static method endpoint hints for %s\n", len(hintBundle.Methods), targetURL)
		}
		if len(hintBundle.Headers) > 0 {
			staticHeaderHints = hintBundle.Headers
			fmt.Printf("[DEBUG] Built %d static header endpoint hints for %s\n", len(hintBundle.Headers), targetURL)
		}
		if len(hintBundle.RequestPayload) > 0 {
			staticRequestPayloadHints = hintBundle.RequestPayload
			fmt.Printf("[DEBUG] Built %d static payload endpoint hints for %s\n", len(hintBundle.RequestPayload), targetURL)
		}
		fmt.Printf("[INFO] Static endpoint hint analysis finished for %s in %s (js=%d)\n", targetURL, time.Since(hintStartedAt).Round(time.Millisecond), len(filteredHintJS))

		// 保存JS资源到ES（采样保存，避免数据量过大，且过滤黑名单域名）
		if database.ESClient != nil {
			filter := crawl.Filter{}
			savedCount := 0
			for _, jsURL := range allJS {
				if savedCount >= 50 { // 限制最多保存50个JS
					break
				}

				// 黑名单过滤：跳过黑名单域名的JS
				if filter.IsBlacklist(jsURL, config.BlackDomain) {
					fmt.Printf("[DEBUG] Skipped blacklisted JS: %s\n", jsURL)
					continue
				}

				savedCount++
				// 异步保存，不阻塞主流程
				go func(url string) {
					resp, err := clients.SimpleGet(url, clients.DefaultRestyClient())
					if err != nil {
						return
					}
					err = database.SaveJSResource(database.JSResource{
						TaskID:       taskId,
						Version:      version,
						URL:          url,
						Content:      string(resp.Body()),
						ResponseCode: resp.StatusCode(),
						Size:         len(resp.Body()),
						FetchedAt:    time.Now(),
					})
					if err != nil {
						fmt.Printf("[ERROR] Failed to save JS %s: %v\n", url, err)
					}
				}(jsURL)
			}
			fmt.Printf("[DEBUG] Scheduled %d JS files for saving (out of %d total)\n", savedCount, len(allJS))

			savedAPIRecordCount := 0
			for _, apiRecord := range capturedAPIRecords {
				savedAPIRecordCount++
				go func(record crawl.NetworkRecord) {
					err := database.SaveAPIResource(database.APIResource{
						TaskID:           taskId,
						Version:          version,
						URL:              record.URL,
						Method:           record.Method,
						TraceID:          record.TraceID,
						HasProtocolTrace: record.HasProtocolTrace,
						RequestHeaders:   record.RequestHeaders,
						RequestBody:      record.RequestBody,
						ResponseHeaders:  record.ResponseHeaders,
						ResponseBody:     record.ResponseBody,
						ResponseCode:     record.ResponseCode,
						FetchedAt:        record.FetchedAt,
					})
					if err != nil {
						fmt.Printf("[ERROR] Failed to save API record %s %s: %v\n", record.Method, record.URL, err)
					}
				}(apiRecord)
			}
			fmt.Printf("[DEBUG] Scheduled %d API records for saving\n", savedAPIRecordCount)

			savedProtocolTraceCount := 0
			for _, trace := range protocolTraces {
				savedProtocolTraceCount++
				go func(record crawl.ProtocolTraceRecord) {
					requestSteps := make([]database.ProtocolCryptoStep, 0, len(record.RequestSteps))
					for _, step := range record.RequestSteps {
						requestSteps = append(requestSteps, database.ProtocolCryptoStep{
							Source:        step.Source,
							Algorithm:     step.Algorithm,
							InputPreview:  step.InputPreview,
							OutputPreview: step.OutputPreview,
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
							Stack:         step.Stack,
							CapturedAtMS:  step.CapturedAtMS,
						})
					}

					err := database.SaveProtocolTrace(database.ProtocolTraceRecord{
						TaskID:                 taskId,
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
					})
					if err != nil {
						fmt.Printf("[ERROR] Failed to save protocol trace %s %s: %v\n", record.Method, record.RequestURL, err)
					}
				}(trace)
			}
			fmt.Printf("[DEBUG] Scheduled %d protocol traces for saving\n", savedProtocolTraceCount)
		}

		// 5. 初始化AI检测器（如果启用）
		var aiChecker *crawl.SensitiveInfoChecker
		if config.OpenAI.Enabled && config.OpenAI.APIKey != "" {
			aiChecker = crawl.NewSensitiveInfoChecker(
				config.OpenAI.APIKey,
				config.OpenAI.BaseURL,
				config.OpenAI.Model,
			)
			fmt.Printf("[INFO] AI-assisted sensitive info detection enabled (model: %s)\n", config.OpenAI.Model)
		} else {
			fmt.Printf("[INFO] AI detection disabled, using regex only\n")
		}

		// 6. 从JS中提取资产（使用AI过滤）
		findSomething := crawl.Scan(targetURL, allJS, aiChecker)
		// 转换资产数据
		for _, item := range findSomething.Email {
			result.Assets.Email = append(result.Assets.Email, SensitiveItem{
				Value:  item.Filed,
				Source: item.Source,
			})
		}
		for _, item := range findSomething.IDCard {
			result.Assets.IDCard = append(result.Assets.IDCard, SensitiveItem{
				Value:  item.Filed,
				Source: item.Source,
			})
		}
		for _, item := range findSomething.Phone {
			result.Assets.Phone = append(result.Assets.Phone, SensitiveItem{
				Value:  item.Filed,
				Source: item.Source,
			})
		}
		for _, item := range findSomething.IP_URL {
			result.Assets.IPURL = append(result.Assets.IPURL, SensitiveItem{
				Value:  item.Filed,
				Source: item.Source,
			})
		}
		for _, item := range findSomething.Sensitive {
			result.Assets.Sensitive = append(result.Assets.Sensitive, SensitiveItem{
				Value:  item.Filed,
				Source: item.Source,
			})
		}

		// 7. API路由整合
		var apiRouter []string
		for _, item := range findSomething.APIRoute {
			if strings.Contains(item.Filed, "[") || strings.Contains(item.Filed, "]") {
				continue
			}
			// 删除空行和空白字符
			route := strings.TrimSpace(item.Filed)
			if route != "" {
				apiRouter = append(apiRouter, route)
			}
		}
		for _, route := range classified.Classification.APIRoute {
			// 删除空行和空白字符
			trimmedRoute := strings.TrimSpace(route)
			if trimmedRoute != "" {
				apiRouter = append(apiRouter, trimmedRoute)
			}
		}
		apiRouter = arrayutil.RemoveDuplicates(apiRouter)
		apiRouter = filter.FilterAPIRoutes(apiRouter)

		// 排序：优先处理完整URL的API（以http://或https://开头的排在前面），一般完整的URL都是动态链接获取到的准确度比较高，先访问也防止后续被WAF等设备拦截
		sort.Slice(apiRouter, func(i, j int) bool {
			iIsFullURL := strings.HasPrefix(apiRouter[i], "http://") || strings.HasPrefix(apiRouter[i], "https://")
			jIsFullURL := strings.HasPrefix(apiRouter[j], "http://") || strings.HasPrefix(apiRouter[j], "https://")

			// 如果一个是完整URL，另一个不是，完整URL排在前面
			if iIsFullURL && !jIsFullURL {
				return true
			}
			if !iIsFullURL && jIsFullURL {
				return false
			}
			// 如果都是完整URL或都不是，保持原有顺序（稳定排序）
			return false
		})

		result.Assets.APIRoutes = apiRouter

		// 8. API根路径分析
		apiRoots := filter.APIRoots(apiRouter, 1)
		allApiRoots := classified.Classification.APIRoot
		// 残缺的API路径还需要拼接，但是如果有完整的就跳过
		// e.g. apiRoots: ["/api/v1", "/api/v2"] classified.Classification.APIRoot: ["http://127.0.0.1:8080/api/v1"]
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
				fallbackRoot := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
				fmt.Printf("[INFO] No API root detected, using target root as fallback: %s\n", fallbackRoot)
				allApiRoots = append(allApiRoots, fallbackRoot)
			} else {
				fmt.Printf("[WARN] No API root detected and failed to parse target URL: %s\n", targetURL)
			}
		}

		result.APIRoots = allApiRoots

		currentIPURLAssets := assetValuesFromSensitiveItems(result.Assets.IPURL)
		currentAPIRouterAssets := assetValuesFromStrings(apiRouter, targetURL)
		currentAPIRootAssets := buildAPIRootAssetValues(allApiRoots, apiRouter, targetURL)

		// 收集当前URL的资产数据
		for _, item := range currentIPURLAssets {
			allIPURLAssets = append(allIPURLAssets, item)
		}
		for _, item := range currentAPIRootAssets {
			allAPIRootAssets = append(allAPIRootAssets, item)
			allAPIRoots = append(allAPIRoots, item.Value)
		}
		for _, item := range currentAPIRouterAssets {
			allAPIRouterAssets = append(allAPIRouterAssets, item)
		}

		fmt.Printf("[DEBUG] Collected assets for URL %s: %d IP/URLs, %d API roots, %d API routes\n",
			targetURL, len(result.Assets.IPURL), len(allApiRoots), len(apiRouter))

		// 立即保存当前URL的资产数据到ES（在漏洞检测之前）
		if database.ESClient != nil {
			currentAssetSavedAt := time.Now()
			// 创建当前URL的资产记录
			currentAssetRecord := database.AssetRecord{
				TaskID:    taskId,
				Version:   version,
				Email:     assetValuesFromSensitiveItems(result.Assets.Email),
				IDCard:    assetValuesFromSensitiveItems(result.Assets.IDCard),
				Phone:     assetValuesFromSensitiveItems(result.Assets.Phone),
				IPURL:     currentIPURLAssets,
				APIRoot:   currentAPIRootAssets,
				APIRouter: currentAPIRouterAssets,
				CreatedAt: currentAssetSavedAt,
			}

			if err := database.SaveAsset(currentAssetRecord); err != nil {
				fmt.Printf("[ERROR] Failed to save assets for task %s (URL: %s): %v\n", taskId, targetURL, err)
			} else {
				fmt.Printf("[DEBUG] Saved assets to ES for task %s (URL: %s): %d emails, %d phones, %d idcards, %d IP/URLs, %d API roots, %d API routes\n",
					taskId, targetURL, len(currentAssetRecord.Email), len(currentAssetRecord.Phone), len(currentAssetRecord.IDCard), len(currentAssetRecord.IPURL), len(currentAssetRecord.APIRoot), len(currentAssetRecord.APIRouter))
			}
		}

		// 8. 漏洞检测（API漏洞扫描）
		// 调用 AnalyzeAPI 进行漏洞检测（每个API根路径）
		for _, root := range allApiRoots {
			fmt.Printf("[INFO] Analyzing API root: %s\n", root)
			options := structs.JSFindOptions{
				TaskID:                    taskId, // 传递任务ID，用于保存漏洞结果
				Version:                   version,
				HomeURL:                   targetURL,
				ApiList:                   apiRouter,
				ApiRoot:                   root,
				StaticMethodHints:         staticMethodHints,
				StaticHeaderHints:         staticHeaderHints,
				StaticConstantParams:      staticConstantParamHints,
				StaticRequestPayloadHints: staticRequestPayloadHints,
				SkipVulnScan:              !resolvedVulnDetection.Enabled,
				HighRiskRouter:            config.HighRiskRouter,
				Authentication:            config.Authentication,
				Placeholder:               config.Placeholder,
				LFIConfig:                 resolvedVulnDetection.LFI,
				SSRFConfig:                resolvedVulnDetection.SSRF,
				RedirectConfig:            resolvedVulnDetection.Redirect,
				SQLInjConfig:              resolvedVulnDetection.SQLInjection,
				XSSConfig:                 resolvedVulnDetection.XSS,
				UploadConfig:              resolvedVulnDetection.Upload,
				AIChecker:                 aiChecker, // 传递AI检测器用于文件上传检测
			}

			// 调用漏洞检测（异步执行，不阻塞主流程）
			// 检测结果会直接保存到数据库或打印到日志
			crawl.AnalyzeAPI(options)
		}

		// 生成风险项
		timestamp := time.Now().Format("2006-01-02 15:04:05")

		// 检查是否启用了AI辅助验证
		aiEnabled := aiChecker != nil

		// 生成风险项并保存到ES
		saveAssetAndRisk := func(level, title, riskType string, items []SensitiveItem, isAIVerified bool) {
			for _, item := range items {
				riskID := uuid.New().String()
				risk := RiskItem{
					ID:          riskID,
					Title:       title,
					Level:       level,
					Type:        riskType,
					URL:         item.Source,
					Description: fmt.Sprintf("发现%s: %s", title, item.Value),
					CreatedAt:   timestamp,
				}
				result.Risks = append(result.Risks, risk)

				// 保存到ES（只保存漏洞记录，不保存资产记录）
				if database.ESClient != nil {
					database.SaveVuln(database.VulnRecord{
						TaskID:      taskId,
						Version:     version,
						VulnID:      riskID,
						Title:       title,
						Level:       level,
						Type:        riskType,
						URL:         item.Source,
						Description: risk.Description,
						AIVerified:  isAIVerified, // 只有经过AI验证的才标记为true
						CreatedAt:   now,
					})
				}
			}
		}

		// 身份证 - 低危（不经过AI验证）
		saveAssetAndRisk("low", "身份证号码泄露", "敏感信息泄露", result.Assets.IDCard, false)

		// 手机号 - 低危（不经过AI验证）
		saveAssetAndRisk("low", "手机号码泄露", "敏感信息泄露", result.Assets.Phone, false)

		// 敏感关键词 - 中危（经过AI验证）
		saveAssetAndRisk("medium", "敏感关键词泄露", "敏感信息泄露", result.Assets.Sensitive, aiEnabled)

		// 邮箱 - 信息级别（不经过AI验证）
		saveAssetAndRisk("info", "邮箱信息泄露", "信息泄露", result.Assets.Email, false)

		// 将当前URL的结果添加到总结果中
		allResults = append(allResults, result)
		allTreeData = append(allTreeData, result.TreeData...)

		// 合并资产数据
		allAssets.Email = append(allAssets.Email, result.Assets.Email...)
		allAssets.IDCard = append(allAssets.IDCard, result.Assets.IDCard...)
		allAssets.Phone = append(allAssets.Phone, result.Assets.Phone...)
		allAssets.IPURL = append(allAssets.IPURL, result.Assets.IPURL...)
		allAssets.Sensitive = append(allAssets.Sensitive, result.Assets.Sensitive...)
		allAssets.APIRoutes = append(allAssets.APIRoutes, result.Assets.APIRoutes...)

		// 合并风险数据
		allRisks = append(allRisks, result.Risks...)

		// 合并API根路径
		allAPIRoots = append(allAPIRoots, result.APIRoots...)

		// 更新进度 - 每个URL处理完成后更新
		if taskId != "" {
			progress := int(float64(i+1) / float64(len(urls)) * 100)
			if version > 0 {
				if err := database.UpdateTaskVersionStatus(taskId, version, "running", progress); err != nil {
					fmt.Printf("[ERROR] Failed to update task version progress: %v\n", err)
				}
			}
			task := database.Task{ID: taskId}
			_, err := task.UpdateStatus("running", progress)
			if err != nil {
				fmt.Printf("[ERROR] Failed to update task progress: %v\n", err)
			} else {
				fmt.Printf("[INFO] Updated task %s progress to %d%% (URL %d/%d completed)\n", taskId, progress, i+1, len(urls))
			}
		}
	}

	// 去重处理
	allAssets.Email = arrayutil.RemoveDuplicates(allAssets.Email)
	allAssets.IDCard = arrayutil.RemoveDuplicates(allAssets.IDCard)
	allAssets.Phone = arrayutil.RemoveDuplicates(allAssets.Phone)
	allAssets.IPURL = arrayutil.RemoveDuplicates(allAssets.IPURL)
	allAssets.Sensitive = arrayutil.RemoveDuplicates(allAssets.Sensitive)
	allAssets.APIRoutes = arrayutil.RemoveDuplicates(allAssets.APIRoutes)
	allAPIRoots = arrayutil.RemoveDuplicates(allAPIRoots)

	// 去重收集的资产数据
	allIPURLAssets = database.MergeAssetValues(allIPURLAssets)
	allAPIRootAssets = database.MergeAssetValues(allAPIRootAssets)
	allAPIRouterAssets = database.MergeAssetValues(allAPIRouterAssets)

	// 统一保存所有URL的资产数据到ES
	if database.ESClient != nil {
		unifiedAssetSavedAt := time.Now()
		// 创建统一的资产记录
		assetRecord := database.AssetRecord{
			TaskID:    taskId,
			Version:   version,
			Email:     assetValuesFromSensitiveItems(allAssets.Email),
			IDCard:    assetValuesFromSensitiveItems(allAssets.IDCard),
			Phone:     assetValuesFromSensitiveItems(allAssets.Phone),
			IPURL:     allIPURLAssets,
			APIRoot:   allAPIRootAssets,
			APIRouter: allAPIRouterAssets,
			CreatedAt: unifiedAssetSavedAt,
		}

		if err := database.SaveAsset(assetRecord); err != nil {
			fmt.Printf("[ERROR] Failed to save unified assets for task %s: %v\n", taskId, err)
		} else {
			fmt.Printf("[DEBUG] Saved unified assets to ES for task %s: %d emails, %d phones, %d idcards, %d IP/URLs, %d API roots, %d API routes\n",
				taskId, len(assetRecord.Email), len(assetRecord.Phone), len(assetRecord.IDCard), len(assetRecord.IPURL), len(assetRecord.APIRoot), len(assetRecord.APIRouter))
		}
	}

	// 扫描完成，记录结果统计
	fmt.Printf("[INFO] Scan completed for task %s: %d URLs processed, %d tree nodes, %d risks found\n",
		taskId, len(urls), len(allTreeData), len(allRisks))

	// 清理任务的测试记录，避免内存泄漏
	crawl.ClearTestedURLs(taskId)

	// 更新任务状态为completed
	if taskId != "" {
		// 等待一小段时间，确保所有异步的漏洞保存操作都已完成
		time.Sleep(2 * time.Second)

		if version > 0 {
			if err := database.UpdateTaskVersionStatus(taskId, version, "completed", 100); err != nil {
				fmt.Printf("[WARNING] Failed to update task version status to completed for task %s version %d: %v\n", taskId, version, err)
			}
		}

		if err := database.UpdateTaskHighestRiskLevel(taskId); err != nil {
			fmt.Printf("[WARNING] Failed to update highest risk level for task %s: %v\n", taskId, err)
		}

		task := database.Task{ID: taskId}
		_, err := task.UpdateStatus("completed", 100)
		if err != nil {
			fmt.Printf("[ERROR] Failed to update task status to completed: %v\n", err)
		} else {
			fmt.Printf("[INFO] Updated task %s status to completed\n", taskId)
		}
	}
}

// clearTaskTestedURLs 清理任务的内存去重缓存，允许重新扫描
func clearTaskTestedURLs(c *gin.Context) {
	taskID := c.Param("taskId")
	if taskID == "" {
		c.JSON(400, gin.H{"error": "taskId is required"})
		return
	}

	crawl.ClearTestedURLs(taskID)
	c.JSON(200, gin.H{"message": "已清理任务的内存去重缓存（非历史版本数据），可以重新扫描", "taskId": taskID})
}

// saveTreeToES 递归保存树节点到ES
func saveTreeToES(taskID string, version int, nodes []crawl.ElTreeNode, createdAt time.Time) {
	saveTreeToESWithPath(taskID, version, nodes, "", createdAt)
}

// saveTreeToESWithURL 为特定URL保存网站树
func saveTreeToESWithURL(taskID string, version int, targetURL string, nodes []crawl.ElTreeNode, createdAt time.Time) {
	saveTreeToESWithPathAndURL(taskID, version, targetURL, nodes, "", createdAt)
}

// saveTreeToESWithPathAndURL 递归保存树节点并构建完整URL路径，支持URL标识符
func saveTreeToESWithPathAndURL(taskID string, version int, targetURL string, nodes []crawl.ElTreeNode, parentPath string, createdAt time.Time) {
	for _, node := range nodes {
		// 计算层级
		level := strings.Count(node.ID, "/")

		// 提取父节点ID
		parentID := ""
		if lastSlash := strings.LastIndex(node.ID, "/"); lastSlash > 0 {
			parentID = node.ID[:lastSlash]
		}

		// 构建完整URL路径
		var fullURL string
		if strings.HasPrefix(node.Label, "http://") || strings.HasPrefix(node.Label, "https://") {
			// 如果当前节点本身是完整URL（通常是域名根节点）
			fullURL = node.Label
		} else if parentPath != "" {
			// 拼接父路径和当前label
			fullURL = parentPath + "/" + node.Label
		} else {
			// 没有父路径，使用label
			fullURL = node.Label
		}

		// 创建带URL标识符的节点ID，避免不同URL的节点ID冲突
		urlIdentifier := strings.ReplaceAll(targetURL, "://", "_")
		urlIdentifier = strings.ReplaceAll(urlIdentifier, "/", "_")
		urlIdentifier = strings.ReplaceAll(urlIdentifier, ":", "_")
		uniqueNodeID := urlIdentifier + "_" + node.ID

		treeNode := database.SiteTreeNode{
			TaskID:    taskID,
			Version:   version,
			NodeID:    uniqueNodeID,
			Label:     node.Label,
			ParentID:  parentID,
			URL:       fullURL,
			Level:     level,
			CreatedAt: createdAt,
		}

		// 检查节点是否已存在，避免重复保存
		if !nodeExists(taskID, version, uniqueNodeID) {
			if err := database.SaveSiteTreeNode(treeNode); err != nil {
				fmt.Printf("[ERROR] Failed to save tree node %s: %v\n", uniqueNodeID, err)
			}
		}

		// 递归保存子节点，传递当前完整路径
		if len(node.Children) > 0 {
			saveTreeToESWithPathAndURL(taskID, version, targetURL, node.Children, fullURL, createdAt)
		}
	}
}

// saveTreeToESWithPath 递归保存树节点并构建完整URL路径
func saveTreeToESWithPath(taskID string, version int, nodes []crawl.ElTreeNode, parentPath string, createdAt time.Time) {
	for _, node := range nodes {
		// 计算层级
		level := strings.Count(node.ID, "/")

		// 提取父节点ID
		parentID := ""
		if lastSlash := strings.LastIndex(node.ID, "/"); lastSlash > 0 {
			parentID = node.ID[:lastSlash]
		}

		// 构建完整URL路径
		var fullURL string
		if strings.HasPrefix(node.Label, "http://") || strings.HasPrefix(node.Label, "https://") {
			// 如果当前节点本身是完整URL（通常是域名根节点）
			fullURL = node.Label
		} else if parentPath != "" {
			// 拼接父路径和当前label
			fullURL = parentPath + "/" + node.Label
		} else {
			// 没有父路径，使用label
			fullURL = node.Label
		}

		treeNode := database.SiteTreeNode{
			TaskID:    taskID,
			Version:   version,
			NodeID:    node.ID,
			Label:     node.Label,
			ParentID:  parentID,
			URL:       fullURL,
			Level:     level,
			CreatedAt: createdAt,
		}

		if err := database.SaveSiteTreeNode(treeNode); err != nil {
			fmt.Printf("[ERROR] Failed to save tree node %s: %v\n", node.ID, err)
		}

		// 递归保存子节点，传递当前完整路径
		if len(node.Children) > 0 {
			saveTreeToESWithPath(taskID, version, node.Children, fullURL, createdAt)
		}
	}
}

// nodeExists 检查节点是否已存在
func nodeExists(taskID string, version int, nodeID string) bool {
	if database.ESClient == nil {
		return false
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{"term": map[string]interface{}{"task_id.keyword": taskID}},
					{"term": map[string]interface{}{"version": version}},
					{"term": map[string]interface{}{"node_id.keyword": nodeID}},
				},
			},
		},
		"size": 1,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return false
	}

	res, err := database.ESClient.Search(
		database.ESClient.Search.WithContext(context.Background()),
		database.ESClient.Search.WithIndex(database.IndexSiteTree),
		database.ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return false
	}
	defer res.Body.Close()

	if res.IsError() {
		return false
	}

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return false
	}

	return result.Hits.Total.Value > 0
}

// countTreeNodes 计算树节点数量
func countTreeNodes(nodes []crawl.ElTreeNode) int {
	count := len(nodes)
	for _, node := range nodes {
		if len(node.Children) > 0 {
			count += countTreeNodes(node.Children)
		}
	}
	return count
}

// stopScan 终止扫描
func stopScan(c *gin.Context) {
	var body struct {
		TaskId string `json:"taskId"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	if body.TaskId == "" {
		c.JSON(400, gin.H{"error": "taskId is required"})
		return
	}

	// 清理任务的测试记录
	crawl.ClearTestedURLs(body.TaskId)

	// 更新任务状态为stopped
	task := database.Task{ID: body.TaskId}
	_, err := task.UpdateStatus("stopped", 0)
	if err != nil {
		fmt.Printf("[ERROR] Failed to update task status to stopped: %v\n", err)
		c.JSON(500, gin.H{"error": "failed to update task status"})
		return
	}

	fmt.Printf("[INFO] Task %s scan stopped\n", body.TaskId)
	c.JSON(200, gin.H{"message": "scan stopped successfully", "taskId": body.TaskId})
}

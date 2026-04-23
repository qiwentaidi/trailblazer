package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/scanexec"

	"github.com/gin-gonic/gin"
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

func convertSharedSensitiveItems(items []scanexec.SensitiveItem) []SensitiveItem {
	result := make([]SensitiveItem, 0, len(items))
	for _, item := range items {
		result = append(result, SensitiveItem{
			Value:  item.Value,
			Source: item.Source,
		})
	}
	return result
}

func convertSharedRisks(items []scanexec.RiskItem) []RiskItem {
	result := make([]RiskItem, 0, len(items))
	for _, item := range items {
		result = append(result, RiskItem{
			ID:          item.ID,
			Title:       item.Title,
			Level:       item.Level,
			Type:        item.Type,
			URL:         item.URL,
			Description: item.Description,
			CreatedAt:   item.CreatedAt,
		})
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

		result := ScanResult{
			TaskID: taskId,
			Target: targetURL,
			Assets: AssetInfo{},
			Risks:  []RiskItem{},
		}

		targetScanResult, err := scanexec.RunTarget(targetURL, scanexec.Options{
			TaskID:         taskId,
			Version:        version,
			BlackDomain:    config.BlackDomain,
			HighRiskRouter: config.HighRiskRouter,
			Authentication: config.Authentication,
			Placeholder:    config.Placeholder,
			OpenAI:         config.OpenAI,
			VulnDetection:  resolvedVulnDetection,
			DataStore:      database.GetScanDataStore(),
		})
		if err != nil {
			fmt.Printf("[WARNING] Target %s is not accessible: %v\n", targetURL, err)
			continue
		}

		result.TreeData = targetScanResult.TreeData
		if database.ESClient != nil {
			saveTreeToESWithURL(taskId, version, targetURL, result.TreeData, now)
			fmt.Printf("[DEBUG] Saved %d tree nodes to ES for task %s (URL: %s)\n", countTreeNodes(result.TreeData), taskId, targetURL)
		} else {
			fmt.Printf("[DEBUG] ES client is nil, tree not saved\n")
		}

		if database.ESClient != nil {
			savedCount := 0
			for _, jsResource := range targetScanResult.JSResources {
				if savedCount >= 50 { // 限制最多保存50个JS
					break
				}
				savedCount++
				go func(resource database.JSResource) {
					if err := database.SaveJSResource(resource); err != nil {
						fmt.Printf("[ERROR] Failed to save JS %s: %v\n", resource.URL, err)
					}
				}(jsResource)
			}
			fmt.Printf("[DEBUG] Scheduled %d JS files for saving (out of %d total)\n", savedCount, len(targetScanResult.JSResources))

			savedAPIRecordCount := 0
			for _, apiRecord := range targetScanResult.APIRecords {
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
			for _, trace := range targetScanResult.ProtocolTraces {
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

		result.Assets.Email = convertSharedSensitiveItems(targetScanResult.Assets.Email)
		result.Assets.IDCard = convertSharedSensitiveItems(targetScanResult.Assets.IDCard)
		result.Assets.Phone = convertSharedSensitiveItems(targetScanResult.Assets.Phone)
		result.Assets.IPURL = convertSharedSensitiveItems(targetScanResult.Assets.IPURL)
		result.Assets.Sensitive = convertSharedSensitiveItems(targetScanResult.Assets.Sensitive)
		result.Assets.APIRoutes = targetScanResult.Assets.APIRoutes
		result.APIRoots = targetScanResult.Assets.APIRoots

		currentIPURLAssets := assetValuesFromSensitiveItems(result.Assets.IPURL)
		currentAPIRouterAssets := assetValuesFromStrings(result.Assets.APIRoutes, targetURL)
		currentAPIRootAssets := buildAPIRootAssetValues(result.APIRoots, result.Assets.APIRoutes, targetURL)

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
			targetURL, len(result.Assets.IPURL), len(result.APIRoots), len(result.Assets.APIRoutes))

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

		if database.ESClient != nil {
			for _, vulnRecord := range targetScanResult.Vulnerabilities {
				if err := database.SaveVuln(vulnRecord); err != nil {
					fmt.Printf("[ERROR] Failed to save vulnerability %s %s: %v\n", vulnRecord.Method, vulnRecord.URL, err)
				}
			}
		}

		result.Risks = convertSharedRisks(targetScanResult.Risks)
		for _, risk := range result.Risks {
			if database.ESClient != nil {
				database.SaveVuln(database.VulnRecord{
					TaskID:      taskId,
					Version:     version,
					VulnID:      risk.ID,
					Title:       risk.Title,
					Level:       risk.Level,
					Type:        risk.Type,
					URL:         risk.URL,
					Description: risk.Description,
					AIVerified:  false,
					CreatedAt:   now,
				})
			}
		}

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

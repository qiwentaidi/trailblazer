package web

import (
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func parseTaskVersionQuery(c *gin.Context) (*int, bool) {
	raw := strings.TrimSpace(c.Query("version"))
	if raw == "" {
		return nil, true
	}

	version, err := strconv.Atoi(raw)
	if err != nil || version <= 0 {
		c.JSON(400, gin.H{"error": "invalid version"})
		return nil, false
	}

	return &version, true
}

func versionArgs(version *int) []int {
	if version == nil {
		return nil
	}
	return []int{*version}
}

func parsePositiveIntQuery(c *gin.Context, key string, fallback int) (int, bool) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return fallback, true
	}

	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		c.JSON(400, gin.H{"error": fmt.Sprintf("invalid %s", key)})
		return 0, false
	}

	return value, true
}

type taskVulnResponse struct {
	VulnID             string                       `json:"vuln_id"`
	Title              string                       `json:"title"`
	Level              string                       `json:"level"`
	Status             string                       `json:"status,omitempty"`
	Confidence         string                       `json:"confidence,omitempty"`
	Type               string                       `json:"type"`
	Category           string                       `json:"category,omitempty"`
	Subcategory        string                       `json:"subcategory,omitempty"`
	BusinessObject     string                       `json:"business_object,omitempty"`
	NamingSource       string                       `json:"naming_source,omitempty"`
	URL                string                       `json:"url"`
	Method             string                       `json:"method,omitempty"`
	Request            string                       `json:"request,omitempty"`
	Response           string                       `json:"response,omitempty"`
	ResponsePlaintext  string                       `json:"response_plaintext,omitempty"`
	TraceID            string                       `json:"trace_id,omitempty"`
	HasProtocolTrace   bool                         `json:"has_protocol_trace,omitempty"`
	ResponseCiphertext string                       `json:"response_ciphertext,omitempty"`
	DecryptionStatus   string                       `json:"decryption_status,omitempty"`
	DecryptionDetail   string                       `json:"decryption_detail,omitempty"`
	ResponseLength     int                          `json:"response_length,omitempty"`
	DataExposure       string                       `json:"data_exposure,omitempty"`
	ExposureReason     string                       `json:"exposure_reason,omitempty"`
	StaticContexts     []database.VulnStaticContext `json:"static_contexts,omitempty"`
	CryptoKeyEvidence  *database.CryptoKeyEvidence  `json:"crypto_key_evidence,omitempty"`
	ConfidenceReason   string                       `json:"confidence_reason,omitempty"`
	Description        string                       `json:"description"`
	CreatedAt          time.Time                    `json:"created_at"`
	AIVerified         bool                         `json:"ai_verified,omitempty"`
}

func buildTaskVulnResponses(vulns []database.VulnRecord) []taskVulnResponse {
	result := make([]taskVulnResponse, 0, len(vulns))
	for _, vuln := range vulns {
		result = append(result, taskVulnResponse{
			VulnID:             vuln.VulnID,
			Title:              vuln.Title,
			Level:              vuln.Level,
			Status:             vuln.Status,
			Confidence:         vuln.Confidence,
			Type:               vuln.Type,
			Category:           vuln.Category,
			Subcategory:        vuln.Subcategory,
			BusinessObject:     vuln.BusinessObject,
			NamingSource:       vuln.NamingSource,
			URL:                vuln.URL,
			Method:             normalizeTaskVulnMethod(vuln),
			Request:            vuln.Request,
			Response:           vuln.Response,
			ResponsePlaintext:  vuln.ResponsePlaintext,
			TraceID:            vuln.TraceID,
			HasProtocolTrace:   vuln.HasProtocolTrace,
			ResponseCiphertext: vuln.ResponseCiphertext,
			DecryptionStatus:   vuln.DecryptionStatus,
			DecryptionDetail:   vuln.DecryptionDetail,
			ResponseLength:     vuln.ResponseLength,
			DataExposure:       vuln.DataExposure,
			ExposureReason:     vuln.ExposureReason,
			StaticContexts:     append([]database.VulnStaticContext(nil), vuln.StaticContexts...),
			CryptoKeyEvidence:  vuln.CryptoKeyEvidence,
			ConfidenceReason:   vuln.ConfidenceReason,
			Description:        vuln.Description,
			CreatedAt:          vuln.CreatedAt,
			AIVerified:         vuln.AIVerified,
		})
	}
	return result
}

// backfillUnauthorizedFindingNames upgrades historical generic findings with
// deterministic labels. It deliberately never calls AI while serving a page.
func backfillUnauthorizedFindingNames(vulns []database.VulnRecord) {
	for index := range vulns {
		vuln := &vulns[index]
		if vuln.Type != "未授权访问" || (strings.TrimSpace(vuln.Category) != "" && strings.TrimSpace(vuln.Subcategory) != "" && strings.TrimSpace(vuln.Title) != "") {
			continue
		}
		responsePreview := vuln.ResponsePlaintext
		if strings.TrimSpace(responsePreview) == "" {
			responsePreview = vuln.Response
		}
		name := crawl.ClassifyUnauthorizedFinding(vuln.URL, normalizeTaskVulnMethod(*vuln), responsePreview, vuln.DataExposure)
		vuln.Category = name.Category
		vuln.Subcategory = name.Subcategory
		vuln.BusinessObject = name.BusinessObject
		vuln.NamingSource = name.Source
		if strings.TrimSpace(vuln.Title) == "" || vuln.Title == "未授权访问" {
			vuln.Title = name.Title
		}
		if err := database.SaveVuln(*vuln); err != nil {
			fmt.Printf("[警告] 回填未授权漏洞业务命名失败: %v\n", err)
		}
	}
}

func normalizeTaskVulnMethod(vuln database.VulnRecord) string {
	method := strings.TrimSpace(vuln.Method)
	if method != "" {
		return method
	}
	if strings.TrimSpace(vuln.Type) == "敏感信息泄露" {
		return "GET"
	}
	return ""
}

// getTaskDetail 获取任务详情
func getTaskDetail(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	task, err := database.QueryTaskByID(taskID, versionArgs(version)...)
	if err != nil {
		c.JSON(404, gin.H{"error": "task not found", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": task})
}

// getTaskTree 获取任务的网站树
func getTaskTree(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}
	page, ok := parsePositiveIntQuery(c, "page", 1)
	if !ok {
		return
	}
	pageSize, ok := parsePositiveIntQuery(c, "pageSize", 20)
	if !ok {
		return
	}
	keyword := strings.TrimSpace(c.Query("keyword"))

	if database.DB == nil {
		c.JSON(500, gin.H{"error": "SQLite database not initialized"})
		return
	}

	result, err := database.QuerySiteTreePage(taskID, page, pageSize, keyword, versionArgs(version)...)
	if err != nil {
		// 如果是索引不存在或连接问题，返回空树而不是错误
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{
				"data":           []interface{}{},
				"nodeCount":      0,
				"total":          0,
				"page":           page,
				"pageSize":       pageSize,
				"keyword":        keyword,
				"totalNodeCount": 0,
			})
			return
		}
		c.JSON(500, gin.H{"error": "failed to query tree", "detail": err.Error()})
		return
	}

	// 将扁平的节点列表重建为树形结构
	treeData := rebuildTreeWithURLs(result.Nodes)

	c.JSON(200, gin.H{
		"data":           treeData,
		"nodeCount":      result.TotalNodeCount,
		"total":          result.Total,
		"page":           result.Page,
		"pageSize":       result.PageSize,
		"keyword":        result.Keyword,
		"totalNodeCount": result.TotalNodeCount,
	})
}

// getTaskSiteMap 获取任务的统一站点树，包含网站树节点和接口请求叶子节点
func getTaskSiteMap(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	if database.DB == nil {
		c.JSON(200, gin.H{"data": []TreeNode{}, "nodeCount": 0, "apiCount": 0})
		return
	}

	var nodes []database.SiteTreeNode
	var apiResources []database.APIResource

	siteNodes, siteErr := database.QuerySiteTreeByTaskID(taskID, versionArgs(version)...)
	if siteErr == nil {
		nodes = siteNodes
	} else if !(strings.Contains(siteErr.Error(), "index_not_found_exception") ||
		strings.Contains(siteErr.Error(), "ES client not initialized") ||
		strings.Contains(siteErr.Error(), "connection")) {
		c.JSON(500, gin.H{"error": "failed to query tree", "detail": siteErr.Error()})
		return
	}

	apis, apiErr := database.QueryAPIResourcesByTaskID(taskID, versionArgs(version)...)
	if apiErr == nil {
		apiResources = apis
	} else if !(strings.Contains(apiErr.Error(), "index_not_found_exception") ||
		strings.Contains(apiErr.Error(), "ES client not initialized") ||
		strings.Contains(apiErr.Error(), "connection")) {
		c.JSON(500, gin.H{"error": "failed to query APIs", "detail": apiErr.Error()})
		return
	}

	treeData := rebuildTreeWithURLs(nodes)
	siteMap := mergeSiteTreeWithAPIRecords(treeData, apiResources)

	c.JSON(200, gin.H{
		"data":      siteMap,
		"nodeCount": len(nodes),
		"apiCount":  len(apiResources),
	})
}

// getTaskVulns 获取任务的漏洞列表
func getTaskVulns(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	vulns, err := database.QueryVulnsByTaskID(taskID, versionArgs(version)...)
	if err != nil {
		// 如果是索引不存在或连接问题，返回空列表而不是错误
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{"data": []taskVulnResponse{}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to query vulns", "detail": err.Error()})
		return
	}
	backfillUnauthorizedFindingNames(vulns)

	c.JSON(200, gin.H{"data": buildTaskVulnResponses(vulns)})
}

// getTaskJS 获取任务的JS资源列表
func getTaskJS(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	jsResources, err := database.QueryJSByTaskID(taskID, versionArgs(version)...)
	if err != nil {
		// 如果是索引不存在或连接问题，返回空列表而不是错误
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{"data": []interface{}{}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to query JS", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": jsResources})
}

// getTaskAPIs 获取任务的接口请求/响应记录
func getTaskAPIs(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	apiResources, err := database.QueryAPIResourcesByTaskID(taskID, versionArgs(version)...)
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{"data": []interface{}{}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to query APIs", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": apiResources})
}

// getTaskProtocolTraces 获取任务的协议轨迹
func getTaskProtocolTraces(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	traces, err := database.QueryProtocolTracesByTaskID(taskID, versionArgs(version)...)
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{"data": []interface{}{}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to query protocol traces", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": traces})
}

// getTaskAssets 获取任务的资产信息
func getTaskAssets(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	var taskRecord *database.TaskRecord
	if task, taskErr := database.QueryTaskByID(taskID, versionArgs(version)...); taskErr == nil && task != nil {
		taskRecord = task
	}

	// 从ES查询资产数据
	assets, err := database.QueryAssetsByTaskID(taskID, versionArgs(version)...)
	if err != nil {
		// 如果是索引不存在或连接问题，返回空数据而不是错误
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			// 返回空的资产数据
			result := map[string]interface{}{
				"taskId":        taskID,
				"taskName":      "",
				"email":         []database.AssetValue{},
				"idCard":        []database.AssetValue{},
				"phone":         []database.AssetValue{},
				"ipUrl":         []database.AssetValue{},
				"frontendRoute": []database.AssetValue{},
				"apiRoot":       []database.AssetValue{},
				"apiRouter":     []database.AssetValue{},
				"createdAt":     "",
			}
			c.JSON(200, gin.H{"data": result})
			return
		}
		if strings.Contains(err.Error(), "assets not found") {
			c.JSON(200, gin.H{"data": map[string]interface{}{
				"taskId":        taskID,
				"taskName":      "",
				"email":         []database.AssetValue{},
				"idCard":        []database.AssetValue{},
				"phone":         []database.AssetValue{},
				"ipUrl":         []database.AssetValue{},
				"frontendRoute": []database.AssetValue{},
				"apiRoot":       []database.AssetValue{},
				"apiRouter":     []database.AssetValue{},
				"createdAt":     "",
			}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to query assets", "detail": err.Error()})
		return
	}

	treeNodes, treeErr := database.QuerySiteTreeByTaskID(taskID, versionArgs(version)...)
	if treeErr != nil && !reportCanIgnoreError(treeErr) {
		c.JSON(500, gin.H{"error": "failed to query tree", "detail": treeErr.Error()})
		return
	}
	if reportCanIgnoreError(treeErr) {
		treeNodes = nil
	}

	vulns, vulnErr := database.QueryVulnsByTaskID(taskID, versionArgs(version)...)
	if vulnErr != nil && !reportCanIgnoreError(vulnErr) {
		c.JSON(500, gin.H{"error": "failed to query vulns", "detail": vulnErr.Error()})
		return
	}
	if reportCanIgnoreError(vulnErr) {
		vulns = nil
	}

	assets = buildReportAssetRecord(taskRecord, assets, treeNodes, vulns)

	taskName := ""
	if taskRecord != nil {
		taskName = taskRecord.TaskName
	}

	// 构建响应数据
	result := map[string]interface{}{
		"taskId":        taskID,
		"taskName":      taskName,
		"email":         assets.Email,
		"idCard":        assets.IDCard,
		"phone":         assets.Phone,
		"ipUrl":         assets.IPURL,
		"frontendRoute": assets.FrontendRoute,
		"apiRoot":       assets.APIRoot,
		"apiRouter":     assets.APIRouter,
		"createdAt":     assets.CreatedAt,
	}

	c.JSON(200, gin.H{"data": result})
}

// getJSContent 获取特定JS的内容（已废弃，使用POST方式）
func getJSContent(c *gin.Context) {
	taskID := c.Param("taskId")
	jsURL := c.Param("url")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	// URL需要解码
	decodedURL, err := url.QueryUnescape(jsURL)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid url parameter"})
		return
	}

	jsResource, err := database.QueryJSByURL(taskID, decodedURL, versionArgs(version)...)
	if err != nil {
		c.JSON(404, gin.H{"error": "JS resource not found", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": jsResource})
}

// getJSContentByPost 通过POST方式获取JS内容（避免URL编码问题）
func getJSContentByPost(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	var body struct {
		URL string `json:"url"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	// fmt.Printf("[DEBUG] Querying JS: taskID=%s, url=%s\n", taskID, body.URL)

	jsResource, err := database.QueryJSByURL(taskID, body.URL, versionArgs(version)...)
	if err != nil {
		c.JSON(404, gin.H{"error": "JS resource not found", "detail": err.Error(), "url": body.URL})
		return
	}

	c.JSON(200, gin.H{"data": jsResource})
}

func getTaskVersions(c *gin.Context) {
	taskID := c.Param("taskId")

	versions, err := database.ListTaskVersions(taskID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query task versions", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": versions})
}

// rebuildTreeWithURLs 重建带URL标识符的网站树
func rebuildTreeWithURLs(nodes []database.SiteTreeNode) []TreeNode {
	if len(nodes) == 0 {
		return []TreeNode{}
	}

	nodeMap := make(map[string]*TreeNode, len(nodes))
	childrenMap := make(map[string][]string)
	rootIDs := make([]string, 0)
	rootSeen := make(map[string]struct{})
	childSeen := make(map[string]struct{})

	for i := range nodes {
		node := &nodes[i]
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}

		nodeMap[nodeID] = &TreeNode{
			ID:       nodeID,
			Label:    node.Label,
			URL:      node.URL,
			Children: make([]TreeNode, 0),
		}
	}

	for i := range nodes {
		node := &nodes[i]
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}

		parentID := normalizeSiteTreeParentID(node.NodeID, node.ParentID)
		if parentID == "" || parentID == "0" {
			if _, ok := rootSeen[nodeID]; ok {
				continue
			}
			rootSeen[nodeID] = struct{}{}
			rootIDs = append(rootIDs, nodeID)
			continue
		}

		edgeKey := parentID + "\x00" + nodeID
		if _, ok := childSeen[edgeKey]; ok {
			continue
		}
		childSeen[edgeKey] = struct{}{}
		childrenMap[parentID] = append(childrenMap[parentID], nodeID)
	}

	var buildChildren func(nodeID string) []TreeNode
	buildChildren = func(nodeID string) []TreeNode {
		children := make([]TreeNode, 0, len(childrenMap[nodeID]))
		for _, childID := range childrenMap[nodeID] {
			childNode, ok := nodeMap[childID]
			if !ok {
				continue
			}
			childNode.Children = buildChildren(childID)
			children = append(children, *childNode)
		}
		return children
	}

	result := make([]TreeNode, 0, len(rootIDs))
	for _, rootID := range rootIDs {
		root, ok := nodeMap[rootID]
		if !ok {
			continue
		}
		root.Children = buildChildren(rootID)
		result = append(result, *root)
	}

	return result
}

func normalizeSiteTreeParentID(nodeID, parentID string) string {
	normalizedParentID := strings.TrimSpace(parentID)
	if normalizedParentID == "" || normalizedParentID == "0" {
		return normalizedParentID
	}

	if strings.Contains(normalizedParentID, "_") {
		return normalizedParentID
	}

	urlIdentifier := extractURLIdentifier(strings.TrimSpace(nodeID))
	if urlIdentifier == "" || urlIdentifier == "unknown" {
		return normalizedParentID
	}

	return urlIdentifier + "_" + normalizedParentID
}

// extractURLIdentifier 从NodeID中提取URL标识符
func extractURLIdentifier(nodeID string) string {
	// NodeID格式: urlIdentifier_originalNodeID
	// 例如: http_monitor.zlmlt.com_80__0/0
	// 需要找到最后一个下划线，前面是URL标识符，后面是原始NodeID
	// 但是需要处理连续下划线的情况

	// 找到最后一个下划线
	if idx := strings.LastIndex(nodeID, "_"); idx > 0 {
		remaining := nodeID[idx+1:]
		// 如果剩余部分包含路径分隔符，说明这是原始NodeID
		if strings.Contains(remaining, "/") {
			return nodeID[:idx]
		}
	}

	// 如果没有找到合适的分隔符，尝试其他方法
	// 查找包含路径分隔符的部分
	parts := strings.Split(nodeID, "/")
	if len(parts) > 1 {
		// 找到包含路径分隔符的部分，前面就是URL标识符
		pathPart := parts[0]
		if lastUnderscore := strings.LastIndex(pathPart, "_"); lastUnderscore > 0 {
			return pathPart[:lastUnderscore]
		}
	}

	return "unknown"
}

// rebuildUnifiedTree 重建统一的网站树，合并多个URL的节点
func rebuildUnifiedTree(nodes []database.SiteTreeNode) []TreeNode {
	if len(nodes) == 0 {
		return []TreeNode{}
	}

	nodeMap := make(map[string]*TreeNode)
	var rootIDs []string
	childrenMap := make(map[string][]string)

	// 第一遍：创建所有节点，移除URL标识符前缀
	for i := range nodes {
		node := &nodes[i]
		// 移除URL标识符前缀，恢复原始NodeID
		originalNodeID := strings.TrimPrefix(node.NodeID, extractURLIdentifier(node.NodeID)+"_")

		// 如果节点已存在，合并URL信息
		if existingNode, exists := nodeMap[originalNodeID]; exists {
			// 如果URL不同，合并URL信息
			if existingNode.URL != node.URL && node.URL != "" {
				if existingNode.URL == "" {
					existingNode.URL = node.URL
				} else if !strings.Contains(existingNode.URL, node.URL) {
					existingNode.URL = existingNode.URL + ", " + node.URL
				}
			}
		} else {
			nodeMap[originalNodeID] = &TreeNode{
				ID:       originalNodeID,
				Label:    node.Label,
				URL:      node.URL,
				Children: make([]TreeNode, 0),
			}
		}
	}

	// 第二遍：建立父子关系
	for i := range nodes {
		node := &nodes[i]
		originalNodeID := strings.TrimPrefix(node.NodeID, extractURLIdentifier(node.NodeID)+"_")
		originalParentID := strings.TrimPrefix(node.ParentID, extractURLIdentifier(node.NodeID)+"_")

		if originalParentID == "" || originalParentID == "0" {
			// 根节点
			if !contains(rootIDs, originalNodeID) {
				rootIDs = append(rootIDs, originalNodeID)
			}
		} else {
			// 记录父子关系
			if !contains(childrenMap[originalParentID], originalNodeID) {
				childrenMap[originalParentID] = append(childrenMap[originalParentID], originalNodeID)
			}
		}
	}

	// 递归构建子树
	var buildChildren func(nodeID string) []TreeNode
	buildChildren = func(nodeID string) []TreeNode {
		children := []TreeNode{}
		for _, childID := range childrenMap[nodeID] {
			if childNode, ok := nodeMap[childID]; ok {
				// 递归构建子节点的children
				childNode.Children = buildChildren(childID)
				children = append(children, *childNode)
			}
		}
		return children
	}

	// 构建根节点及其完整子树
	var result []TreeNode
	for _, rootID := range rootIDs {
		if root, ok := nodeMap[rootID]; ok {
			root.Children = buildChildren(rootID)
			result = append(result, *root)
		}
	}

	return result
}

// contains 检查切片中是否包含指定元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// rebuildTreeForURL 为特定URL重建网站树
func rebuildTreeForURL(urlIdentifier string, nodes []database.SiteTreeNode) []TreeNode {
	if len(nodes) == 0 {
		return []TreeNode{}
	}

	nodeMap := make(map[string]*TreeNode)

	// 第一遍：创建所有节点
	for i := range nodes {
		node := &nodes[i]
		// 移除URL标识符前缀，恢复原始NodeID
		originalNodeID := strings.TrimPrefix(node.NodeID, urlIdentifier+"_")
		nodeMap[originalNodeID] = &TreeNode{
			ID:       originalNodeID,
			Label:    node.Label,
			URL:      node.URL,
			Children: make([]TreeNode, 0),
		}
	}

	// 第二遍：建立父子关系
	var rootIDs []string
	childrenMap := make(map[string][]string)

	for i := range nodes {
		node := &nodes[i]
		originalNodeID := strings.TrimPrefix(node.NodeID, urlIdentifier+"_")
		originalParentID := strings.TrimPrefix(node.ParentID, urlIdentifier+"_")

		if originalParentID == "" || originalParentID == "0" {
			// 根节点，避免重复
			if !contains(rootIDs, originalNodeID) {
				rootIDs = append(rootIDs, originalNodeID)
			}
		} else {
			// 记录父子关系，避免重复
			if !contains(childrenMap[originalParentID], originalNodeID) {
				childrenMap[originalParentID] = append(childrenMap[originalParentID], originalNodeID)
			}
		}
	}

	// 递归构建子树
	var buildChildren func(nodeID string) []TreeNode
	buildChildren = func(nodeID string) []TreeNode {
		children := []TreeNode{}
		for _, childID := range childrenMap[nodeID] {
			if childNode, ok := nodeMap[childID]; ok {
				// 递归构建子节点的children
				childNode.Children = buildChildren(childID)
				children = append(children, *childNode)
			}
		}
		return children
	}

	// 构建根节点及其完整子树
	var result []TreeNode
	for _, rootID := range rootIDs {
		if root, ok := nodeMap[rootID]; ok {
			root.Children = buildChildren(rootID)
			result = append(result, *root)
		}
	}

	return result
}

// rebuildTree 重建网站树（保持向后兼容）
func rebuildTree(nodes []database.SiteTreeNode) []TreeNode {
	// fmt.Printf("[DEBUG] rebuildTree called with %d nodes\n", len(nodes))

	if len(nodes) == 0 {
		return []TreeNode{}
	}

	// 打印前3个节点作为样本
	// for i := 0; i < 3 && i < len(nodes); i++ {
	// 	fmt.Printf("[SAMPLE] Node %d: ID=%s, ParentID=%s, Label=%s\n",
	// 		i, nodes[i].NodeID, nodes[i].ParentID, nodes[i].Label)
	// }

	nodeMap := make(map[string]*TreeNode)

	// 第一遍：创建所有节点
	for i := range nodes {
		node := &nodes[i]
		nodeMap[node.NodeID] = &TreeNode{
			ID:       node.NodeID,
			Label:    node.Label,
			URL:      node.URL,
			Children: make([]TreeNode, 0),
		}
		// fmt.Printf("[TRACE] Created node: ID=%s, Label=%s, URL=%s\n", node.NodeID, node.Label, node.URL)
	}

	// 第二遍：建立父子关系
	var rootIDs []string
	childrenMap := make(map[string][]string) // 记录每个节点的子节点ID

	for i := range nodes {
		node := &nodes[i]

		if node.ParentID == "" || node.ParentID == "0" {
			// 根节点
			rootIDs = append(rootIDs, node.NodeID)
			// fmt.Printf("[TRACE] Found root node: ID=%s, Label=%s\n", node.NodeID, node.Label)
		} else {
			// 记录父子关系
			childrenMap[node.ParentID] = append(childrenMap[node.ParentID], node.NodeID)
		}
	}

	// 递归构建子树
	var buildChildren func(nodeID string) []TreeNode
	buildChildren = func(nodeID string) []TreeNode {
		children := []TreeNode{}
		for _, childID := range childrenMap[nodeID] {
			if childNode, ok := nodeMap[childID]; ok {
				// 递归构建子节点的children
				childNode.Children = buildChildren(childID)
				children = append(children, *childNode)
			}
		}
		return children
	}

	fmt.Printf("[调试] 站点树重建完成: %d 个根节点，%d 个总节点\n", len(rootIDs), len(nodes))

	// 构建根节点及其完整子树
	result := make([]TreeNode, 0, len(rootIDs))
	for _, rootID := range rootIDs {
		if root, ok := nodeMap[rootID]; ok {
			root.Children = buildChildren(rootID)
			result = append(result, *root)
		}
	}

	return result
}

func mergeSiteTreeWithAPIRecords(tree []TreeNode, apiResources []database.APIResource) []TreeNode {
	markSiteNodeTypes(tree)

	for index, api := range apiResources {
		if strings.TrimSpace(api.URL) == "" {
			continue
		}

		parsed, err := url.Parse(api.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}

		origin := parsed.Scheme + "://" + parsed.Host
		root := ensureOriginRootNode(&tree, origin)
		current := root

		pathSegments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(pathSegments) == 1 && pathSegments[0] == "" {
			pathSegments = nil
		}

		if len(pathSegments) == 0 {
			current = ensurePathNode(current, "/", origin+"/")
		} else {
			for segmentIndex, segment := range pathSegments {
				partialPath := "/" + strings.Join(pathSegments[:segmentIndex+1], "/")
				current = ensurePathNode(current, segment, origin+partialPath)
			}
		}

		queryLabel := ""
		if parsed.RawQuery != "" {
			queryLabel = "?" + parsed.RawQuery
		}

		label := api.FetchedAt.Format("2006-01-02 15:04:05")
		if label == "" || label == "0001-01-01 00:00:00" {
			label = strings.ToUpper(strings.TrimSpace(api.Method))
			if label == "" {
				label = "API 请求"
			}
		}
		if parsed.RawQuery != "" {
			label = label + " ?" + parsed.RawQuery
		}

		requestNode := TreeNode{
			ID:               fmt.Sprintf("api-request:%d:%s:%s:%s", index, api.Method, api.FetchedAt.Format("20060102150405.000"), api.URL),
			Label:            label,
			URL:              api.URL,
			NodeType:         "api-request",
			Method:           api.Method,
			TraceID:          api.TraceID,
			HasProtocolTrace: api.HasProtocolTrace,
			RequestHeaders:   api.RequestHeaders,
			RequestBody:      api.RequestBody,
			ResponseHeaders:  firstNonEmptyHeaderMap(api.ResponseHeaders, api.Headers),
			ResponseBody:     api.ResponseBody,
			StatusCode:       api.ResponseCode,
			Headers:          firstNonEmptyHeaderMap(api.ResponseHeaders, api.Headers),
			FetchedAt:        api.FetchedAt.Format(time.RFC3339),
			Children:         []TreeNode{},
		}

		if queryLabel != "" {
			if existingNode := findQueryLeafNode(current, queryLabel); existingNode != nil {
				applyRequestNode(existingNode, requestNode)
				continue
			}
		}

		if shouldInlineRequestIntoCurrentNode(parsed, api.RequestBody, current) {
			applyRequestNode(current, requestNode)
			continue
		}

		current.Children = append(current.Children, requestNode)
	}

	return tree
}

func markSiteNodeTypes(nodes []TreeNode) {
	for index := range nodes {
		if nodes[index].NodeType == "" {
			nodes[index].NodeType = "site"
		}
		if len(nodes[index].Children) > 0 {
			markSiteNodeTypes(nodes[index].Children)
		}
	}
}

func ensureOriginRootNode(tree *[]TreeNode, origin string) *TreeNode {
	for index := range *tree {
		node := &(*tree)[index]
		if node.Label == origin || node.URL == origin ||
			comparableOrigin(node.Label) == origin ||
			comparableOrigin(node.URL) == origin {
			return node
		}
	}

	*tree = append(*tree, TreeNode{
		ID:       "origin:" + origin,
		Label:    origin,
		URL:      origin,
		NodeType: "site",
		Children: []TreeNode{},
	})
	return &(*tree)[len(*tree)-1]
}

func ensurePathNode(parent *TreeNode, segment, fullURL string) *TreeNode {
	for index := range parent.Children {
		child := &parent.Children[index]
		if child.Label == segment && normalizeComparableTreeURL(child.URL) == normalizeComparableTreeURL(fullURL) {
			if child.NodeType == "" {
				child.NodeType = "api-path"
			}
			return child
		}
	}

	parent.Children = append(parent.Children, TreeNode{
		ID:       "path:" + fullURL,
		Label:    segment,
		URL:      fullURL,
		NodeType: "api-path",
		Children: []TreeNode{},
	})
	return &parent.Children[len(parent.Children)-1]
}

func findQueryLeafNode(parent *TreeNode, label string) *TreeNode {
	for index := range parent.Children {
		child := &parent.Children[index]
		if child.Label == label && child.NodeType != "api-request" && len(child.Children) == 0 {
			return child
		}
	}
	return nil
}

func firstNonEmptyHeaderMap(candidates ...map[string]string) map[string]string {
	for _, candidate := range candidates {
		if len(candidate) > 0 {
			return candidate
		}
	}
	return nil
}

func shouldInlineRequestIntoCurrentNode(parsed *url.URL, requestBody string, current *TreeNode) bool {
	if parsed == nil || current == nil {
		return false
	}
	if strings.TrimSpace(parsed.RawQuery) != "" {
		return false
	}
	if strings.TrimSpace(requestBody) != "" {
		return false
	}
	return len(current.Children) == 0
}

func applyRequestNode(target *TreeNode, requestNode TreeNode) {
	if target == nil {
		return
	}
	target.ID = requestNode.ID
	target.URL = requestNode.URL
	target.NodeType = requestNode.NodeType
	target.Method = requestNode.Method
	target.TraceID = requestNode.TraceID
	target.HasProtocolTrace = requestNode.HasProtocolTrace
	target.RequestHeaders = requestNode.RequestHeaders
	target.RequestBody = requestNode.RequestBody
	target.ResponseHeaders = requestNode.ResponseHeaders
	target.ResponseBody = requestNode.ResponseBody
	target.StatusCode = requestNode.StatusCode
	target.Headers = requestNode.Headers
	target.FetchedAt = requestNode.FetchedAt
	target.Children = []TreeNode{}
}

func normalizeComparableTreeURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return strings.TrimSpace(raw)
	}
	parsed.Fragment = ""
	return parsed.String()
}

func comparableOrigin(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

// TreeNode 前端树节点结构
type TreeNode struct {
	ID               string            `json:"id"`
	Label            string            `json:"label"`
	URL              string            `json:"url,omitempty"`
	NodeType         string            `json:"nodeType,omitempty"`
	Method           string            `json:"method,omitempty"`
	TraceID          string            `json:"traceId,omitempty"`
	HasProtocolTrace bool              `json:"hasProtocolTrace,omitempty"`
	RequestHeaders   map[string]string `json:"requestHeaders,omitempty"`
	RequestBody      string            `json:"requestBody,omitempty"`
	ResponseHeaders  map[string]string `json:"responseHeaders,omitempty"`
	ResponseBody     string            `json:"responseBody,omitempty"`
	StatusCode       int               `json:"statusCode,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	FetchedAt        string            `json:"fetchedAt,omitempty"`
	Children         []TreeNode        `json:"children,omitempty"`
}

// 从SQLite获取任务列表（支持分页）
func getTasks(c *gin.Context) {
	// 获取查询参数
	page := c.DefaultQuery("page", "1")
	size := c.DefaultQuery("size", "10")
	keyword := strings.TrimSpace(c.Query("keyword"))
	statusFilter := strings.TrimSpace(c.Query("status"))

	// 转换为整数
	pageInt := 1
	sizeInt := 10
	if p, err := strconv.Atoi(page); err == nil && p > 0 {
		pageInt = p
	}
	if s, err := strconv.Atoi(size); err == nil && s > 0 && s <= 100 {
		sizeInt = s
	}

	tasks, err := database.GetTasksByKeyword(keyword)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query local tasks", "detail": err.Error()})
		return
	}

	// 转换为前端格式
	var result []map[string]interface{}
	for _, task := range tasks {
		latestVersion, versionErr := database.GetLatestTaskVersion(task.ID)
		if versionErr != nil {
			c.JSON(500, gin.H{"error": "failed to query task versions", "detail": versionErr.Error()})
			return
		}

		highestRiskLevel := task.HighestRiskLevel
		latestVersionNumber := 0
		latestStatus := ""
		latestProgress := 0
		triggerType := ""
		startedAt := ""
		finishedAt := ""
		versionCount := 0

		versions, versionListErr := database.ListTaskVersions(task.ID)
		if versionListErr != nil {
			c.JSON(500, gin.H{"error": "failed to query task versions", "detail": versionListErr.Error()})
			return
		}
		versionCount = len(versions)

		if latestVersion != nil {
			if strings.TrimSpace(latestVersion.HighestRiskLevel) != "" {
				highestRiskLevel = latestVersion.HighestRiskLevel
			}
			latestVersionNumber = latestVersion.Version
			latestStatus = latestVersion.Status
			latestProgress = latestVersion.Progress
			triggerType = latestVersion.TriggerType
			if !latestVersion.StartedAt.IsZero() {
				startedAt = latestVersion.StartedAt.Format("2006-01-02 15:04:05")
			}
			if !latestVersion.FinishedAt.IsZero() {
				finishedAt = latestVersion.FinishedAt.Format("2006-01-02 15:04:05")
			}
		}

		item := map[string]interface{}{
			"id":               task.ID,
			"name":             task.Name,
			"targets":          task.Targets,
			"status":           task.Status,
			"progress":         task.Progress,
			"highestRiskLevel": highestRiskLevel,
			"createdAt":        task.CreatedAt.Format("2006-01-02 15:04:05"),
			"latestVersion":    latestVersionNumber,
			"latestStatus":     latestStatus,
			"latestProgress":   latestProgress,
			"versionCount":     versionCount,
			"triggerType":      triggerType,
			"startedAt":        startedAt,
			"finishedAt":       finishedAt,
		}

		effectiveStatus := latestStatus
		if effectiveStatus == "" {
			effectiveStatus = task.Status
		}
		if statusFilter != "" && effectiveStatus != statusFilter {
			continue
		}

		result = append(result, item)
	}

	total := len(result)
	offset := (pageInt - 1) * sizeInt
	if offset > total {
		offset = total
	}
	end := offset + sizeInt
	if end > total {
		end = total
	}
	pagedResult := result[offset:end]

	// 计算分页信息
	totalPages := (total + sizeInt - 1) / sizeInt
	if totalPages == 0 {
		totalPages = 1
	}

	c.JSON(200, gin.H{
		"data": pagedResult,
		"pagination": map[string]interface{}{
			"page":       pageInt,
			"size":       sizeInt,
			"total":      total,
			"totalPages": totalPages,
			"hasNext":    pageInt < totalPages,
			"hasPrev":    pageInt > 1,
		},
	})
}

// 保存本地任务
func saveTask(c *gin.Context) {
	var body struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Targets  []string `json:"targets"`
		Status   string   `json:"status"`
		Progress int      `json:"progress"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	task := database.Task{
		ID:       body.ID,
		Name:     body.Name,
		Targets:  body.Targets,
		Status:   body.Status,
		Progress: body.Progress,
	}

	id, err := task.Save()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to save task", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": map[string]interface{}{"id": id}})
}

func updateTask(c *gin.Context) {
	var body struct {
		ID       string   `json:"id"`
		Name     string   `json:"name"`
		Targets  []string `json:"targets"`
		Status   string   `json:"status"`
		Progress int      `json:"progress"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	task := database.Task{
		ID:       body.ID,
		Name:     body.Name,
		Targets:  body.Targets,
		Status:   body.Status,
		Progress: body.Progress,
	}

	id, err := task.Update()
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to update task", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"data": map[string]interface{}{"id": id}})
}

// 删除本地任务及其ES数据
func deleteTask(c *gin.Context) {
	var body struct {
		ID string `json:"id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json"})
		return
	}

	task := database.Task{ID: body.ID}
	// 删除SQLite中的任务
	if err := task.Delete(); err != nil {
		c.JSON(500, gin.H{"error": "failed to delete task", "detail": err.Error()})
		return
	}

	// 删除 SQLite 中的相关扫描数据（使用任务ID）
	if database.DB != nil {
		if err := database.DeleteTaskData(task.ID); err != nil {
			fmt.Printf("[错误] 删除任务 %s 的 SQLite 数据失败: %v\n", task.ID, err)
			c.JSON(500, gin.H{"error": "failed to delete SQLite data", "detail": err.Error()})
			return
		} else {
			fmt.Printf("[信息] 已删除任务 %s 的 SQLite 数据\n", task.ID)
		}
	}

	c.JSON(200, gin.H{"message": "task deleted successfully"})
}

func deleteVuln(c *gin.Context) {
	vulnID := c.Param("vulnId")
	if vulnID == "" {
		c.JSON(400, gin.H{"error": "vuln_id is required"})
		return
	}

	// 删除漏洞记录
	err := database.DeleteVulnByID(vulnID)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to delete vulnerability", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "vulnerability deleted successfully"})
}

func updateVulnStatus(c *gin.Context) {
	vulnID := strings.TrimSpace(c.Param("vulnId"))
	if vulnID == "" {
		c.JSON(400, gin.H{"error": "vuln_id is required"})
		return
	}

	var body struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": "invalid json", "detail": err.Error()})
		return
	}

	status, err := database.NormalizeVulnStatus(body.Status)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid status", "detail": err.Error()})
		return
	}

	if err := database.UpdateVulnStatusByID(vulnID, status); err != nil {
		c.JSON(500, gin.H{"error": "failed to update vulnerability status", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"message": "vulnerability status updated successfully",
		"vuln_id": vulnID,
		"status":  status,
	})
}

func deleteVulnCluster(c *gin.Context) {
	taskID := c.Param("taskId")
	clusterID := strings.TrimSpace(c.Param("clusterId"))
	if taskID == "" || clusterID == "" {
		c.JSON(400, gin.H{"error": "task_id and cluster_id are required"})
		return
	}

	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	vulns, err := database.QueryVulnsByTaskID(taskID, versionArgs(version)...)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to query vulns", "detail": err.Error()})
		return
	}

	vulnIDs := make([]string, 0)
	for _, vuln := range vulns {
		if vuln.DenyTemplateID == clusterID && strings.TrimSpace(vuln.VulnID) != "" {
			vulnIDs = append(vulnIDs, vuln.VulnID)
		}
	}

	if len(vulnIDs) == 0 {
		c.JSON(404, gin.H{"error": "cluster not found"})
		return
	}

	if err := database.DeleteVulnsByIDs(taskID, vulnIDs); err != nil {
		c.JSON(500, gin.H{"error": "failed to delete vulnerability cluster", "detail": err.Error()})
		return
	}

	c.JSON(200, gin.H{
		"message":    "vulnerability cluster deleted successfully",
		"deleted":    len(vulnIDs),
		"cluster_id": clusterID,
		"task_id":    taskID,
		"version":    version,
	})
}

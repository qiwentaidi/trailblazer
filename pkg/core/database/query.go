package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

func resolveQueryVersion(taskID string, versions ...int) (*int, *TaskVersion, error) {
	if len(versions) > 0 {
		version := versions[0]
		if version <= 0 {
			return nil, nil, fmt.Errorf("invalid version: %d", version)
		}
		if DB == nil {
			return &version, nil, nil
		}

		selected, err := GetTaskVersion(taskID, version)
		if err != nil {
			return nil, nil, err
		}
		return &version, selected, nil
	}

	if DB == nil {
		return nil, nil, nil
	}

	latest, err := GetLatestTaskVersion(taskID)
	if err != nil {
		return nil, nil, err
	}
	if latest == nil {
		return nil, nil, nil
	}

	version := latest.Version
	return &version, latest, nil
}

func buildTaskVersionQuery(taskID string, version *int, extraMust ...map[string]interface{}) map[string]interface{} {
	must := []map[string]interface{}{
		{
			"term": map[string]interface{}{
				"task_id.keyword": taskID,
			},
		},
	}

	if versionClause := buildVersionClause(version); versionClause != nil {
		must = append(must, versionClause)
	}
	must = append(must, extraMust...)

	return map[string]interface{}{
		"bool": map[string]interface{}{
			"must": must,
		},
	}
}

func buildVersionClause(version *int) map[string]interface{} {
	if version == nil {
		return nil
	}

	if *version == 1 {
		return map[string]interface{}{
			"bool": map[string]interface{}{
				"should": []map[string]interface{}{
					{
						"term": map[string]interface{}{
							"version": 1,
						},
					},
					{
						"bool": map[string]interface{}{
							"must_not": []map[string]interface{}{
								{
									"exists": map[string]interface{}{
										"field": "version",
									},
								},
							},
						},
					},
				},
				"minimum_should_match": 1,
			},
		}
	}

	return map[string]interface{}{
		"term": map[string]interface{}{
			"version": *version,
		},
	}
}

func applyVersionSummary(task *TaskRecord, version *TaskVersion) {
	if task == nil || version == nil {
		return
	}

	if len(version.TargetsSnapshot) > 0 {
		task.Targets = version.TargetsSnapshot
	}
	if version.Status != "" {
		task.Status = version.Status
	}
	if !version.CreatedAt.IsZero() {
		task.CreatedAt = version.CreatedAt
	}
	if !version.UpdatedAt.IsZero() {
		task.UpdatedAt = version.UpdatedAt
	}
}

// QueryTaskByID 根据任务ID查询任务信息
func QueryTaskByID(taskID string, versions ...int) (*TaskRecord, error) {
	resolvedVersion, versionSummary, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	baseTask, err := GetTaskByID(taskID)
	if err != nil {
		return nil, err
	}
	if baseTask == nil {
		return nil, fmt.Errorf("task not found")
	}

	task := TaskRecord{
		TaskID:    baseTask.ID,
		TaskName:  baseTask.Name,
		Targets:   append([]string(nil), baseTask.Targets...),
		Status:    baseTask.Status,
		CreatedAt: baseTask.CreatedAt,
		UpdatedAt: baseTask.UpdatedAt,
	}
	if resolvedVersion != nil && versionSummary == nil {
		versionSummary, err = GetTaskVersion(taskID, *resolvedVersion)
		if err != nil {
			return nil, err
		}
	}
	applyVersionSummary(&task, versionSummary)
	return &task, nil
}

// QuerySiteTreeByTaskID 查询任务的网站树
func QuerySiteTreeByTaskID(taskID string, versions ...int) ([]SiteTreeNode, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion),
		"size":  10000,
		"sort": []map[string]interface{}{
			{"level": "asc"},
			{"node_id.keyword": "asc"},
		},
	}

	nodes, err := querySiteTree(query)
	fmt.Printf("[调试] QuerySiteTreeByTaskID(%s) 返回 %d 个节点，错误: %v\n", taskID, len(nodes), err)
	return nodes, err
}

type SiteTreePageResult struct {
	Nodes          []SiteTreeNode
	Total          int
	TotalNodeCount int
	Page           int
	PageSize       int
	Keyword        string
}

func QuerySiteTreePage(taskID string, page, pageSize int, keyword string, versions ...int) (*SiteTreePageResult, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	page = normalizePositiveInt(page, 1)
	pageSize = normalizePositiveInt(pageSize, 20)
	keyword = strings.TrimSpace(keyword)

	totalNodeCount, err := countSiteTree(buildTaskVersionQuery(taskID, resolvedVersion))
	if err != nil {
		return nil, err
	}

	if keyword != "" {
		return querySiteTreeSearchPage(taskID, resolvedVersion, page, pageSize, keyword, totalNodeCount)
	}

	return querySiteTreeRootPage(taskID, resolvedVersion, page, pageSize, totalNodeCount)
}

func querySiteTreeRootPage(taskID string, version *int, page, pageSize, totalNodeCount int) (*SiteTreePageResult, error) {
	offset := (page - 1) * pageSize
	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, version, buildRootNodeClause()),
		"from":  offset,
		"size":  pageSize,
		"sort": []map[string]interface{}{
			{"node_id.keyword": "asc"},
		},
	}

	rootNodes, total, err := querySiteTreeWithTotal(query)
	if err != nil {
		return nil, err
	}

	rootIDs := extractSiteTreeNodeIDs(rootNodes)
	nodes, err := querySiteTreeByRootIDs(taskID, version, rootIDs)
	if err != nil {
		return nil, err
	}

	return &SiteTreePageResult{
		Nodes:          nodes,
		Total:          total,
		TotalNodeCount: totalNodeCount,
		Page:           page,
		PageSize:       pageSize,
	}, nil
}

func querySiteTreeSearchPage(taskID string, version *int, page, pageSize int, keyword string, totalNodeCount int) (*SiteTreePageResult, error) {
	searchQuery := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, version, buildSiteTreeKeywordClause(keyword)),
		"size":  2000,
		"sort": []map[string]interface{}{
			{"level": "asc"},
			{"node_id.keyword": "asc"},
		},
	}

	matchedNodes, _, err := querySiteTreeWithTotal(searchQuery)
	if err != nil {
		return nil, err
	}

	if len(matchedNodes) == 0 {
		return &SiteTreePageResult{
			Nodes:          []SiteTreeNode{},
			Total:          0,
			TotalNodeCount: totalNodeCount,
			Page:           page,
			PageSize:       pageSize,
			Keyword:        keyword,
		}, nil
	}

	rootOrder := make([]string, 0)
	rootSeen := make(map[string]struct{})
	relevantIDSet := make(map[string]struct{})
	for _, node := range matchedNodes {
		nodeID := strings.TrimSpace(node.NodeID)
		if nodeID == "" {
			continue
		}
		rootID := rootSiteTreeNodeID(nodeID)
		if rootID == "" {
			continue
		}
		if _, ok := rootSeen[rootID]; !ok {
			rootSeen[rootID] = struct{}{}
			rootOrder = append(rootOrder, rootID)
		}
		for _, ancestorID := range collectAncestorNodeIDs(nodeID) {
			relevantIDSet[ancestorID] = struct{}{}
		}
	}
	sort.Strings(rootOrder)

	total := len(rootOrder)
	start := minInt((page-1)*pageSize, total)
	end := minInt(start+pageSize, total)
	currentRootIDs := rootOrder[start:end]
	currentRootSet := make(map[string]struct{}, len(currentRootIDs))
	for _, rootID := range currentRootIDs {
		currentRootSet[rootID] = struct{}{}
	}

	currentNodeIDs := make([]string, 0, len(relevantIDSet))
	for nodeID := range relevantIDSet {
		if _, ok := currentRootSet[rootSiteTreeNodeID(nodeID)]; ok {
			currentNodeIDs = append(currentNodeIDs, nodeID)
		}
	}
	sort.Strings(currentNodeIDs)

	nodes, err := querySiteTreeByNodeIDs(taskID, version, currentNodeIDs)
	if err != nil {
		return nil, err
	}

	return &SiteTreePageResult{
		Nodes:          nodes,
		Total:          total,
		TotalNodeCount: totalNodeCount,
		Page:           page,
		PageSize:       pageSize,
		Keyword:        keyword,
	}, nil
}

func normalizePositiveInt(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func buildRootNodeClause() map[string]interface{} {
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"should": []map[string]interface{}{
				{
					"term": map[string]interface{}{
						"level": 1,
					},
				},
				{
					"term": map[string]interface{}{
						"parent_id.keyword": "0",
					},
				},
			},
			"minimum_should_match": 1,
		},
	}
}

func buildSiteTreeKeywordClause(keyword string) map[string]interface{} {
	keyword = strings.TrimSpace(keyword)
	return map[string]interface{}{
		"bool": map[string]interface{}{
			"should": []map[string]interface{}{
				{
					"multi_match": map[string]interface{}{
						"query":  keyword,
						"fields": []string{"label", "url", "node_id"},
						"type":   "phrase_prefix",
					},
				},
				{
					"wildcard": map[string]interface{}{
						"node_id.keyword": map[string]interface{}{
							"value":            "*" + keyword + "*",
							"case_insensitive": true,
						},
					},
				},
			},
			"minimum_should_match": 1,
		},
	}
}

func rootSiteTreeNodeID(nodeID string) string {
	normalized := strings.TrimSpace(nodeID)
	if normalized == "" {
		return ""
	}
	if index := strings.Index(normalized, "/"); index >= 0 {
		return normalized[:index]
	}
	return normalized
}

func collectAncestorNodeIDs(nodeID string) []string {
	parts := strings.Split(strings.TrimSpace(nodeID), "/")
	if len(parts) == 0 {
		return nil
	}

	result := make([]string, 0, len(parts))
	current := ""
	for _, part := range parts {
		if strings.TrimSpace(part) == "" {
			continue
		}
		if current == "" {
			current = part
		} else {
			current += "/" + part
		}
		result = append(result, current)
	}
	return result
}

func extractSiteTreeNodeIDs(nodes []SiteTreeNode) []string {
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		if nodeID := strings.TrimSpace(node.NodeID); nodeID != "" {
			result = append(result, nodeID)
		}
	}
	return result
}

func countSiteTree(queryBody map[string]interface{}) (int, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(map[string]interface{}{
		"query": queryBody,
	}); err != nil {
		return 0, err
	}

	res, err := ESClient.Count(
		ESClient.Count.WithContext(context.Background()),
		ESClient.Count.WithIndex(IndexSiteTree),
		ESClient.Count.WithBody(&buf),
	)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return 0, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return 0, err
	}
	return result.Count, nil
}

func querySiteTree(query map[string]interface{}) ([]SiteTreeNode, error) {
	nodes, _, err := querySiteTreeWithTotal(query)
	return nodes, err
}

func querySiteTreeWithTotal(query map[string]interface{}) ([]SiteTreeNode, int, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, 0, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexSiteTree),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, 0, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source SiteTreeNode `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, 0, err
	}

	var nodes []SiteTreeNode
	for _, hit := range result.Hits.Hits {
		nodes = append(nodes, hit.Source)
	}

	return nodes, result.Hits.Total.Value, nil
}

func querySiteTreeByRootIDs(taskID string, version *int, rootIDs []string) ([]SiteTreeNode, error) {
	if len(rootIDs) == 0 {
		return []SiteTreeNode{}, nil
	}

	should := make([]map[string]interface{}, 0, len(rootIDs)*2)
	for _, rootID := range rootIDs {
		normalized := strings.TrimSpace(rootID)
		if normalized == "" {
			continue
		}
		should = append(should,
			map[string]interface{}{
				"term": map[string]interface{}{
					"node_id.keyword": normalized,
				},
			},
			map[string]interface{}{
				"prefix": map[string]interface{}{
					"node_id.keyword": normalized + "/",
				},
			},
		)
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, version, map[string]interface{}{
			"bool": map[string]interface{}{
				"should":               should,
				"minimum_should_match": 1,
			},
		}),
		"size": 10000,
		"sort": []map[string]interface{}{
			{"level": "asc"},
			{"node_id.keyword": "asc"},
		},
	}

	return querySiteTree(query)
}

func querySiteTreeByNodeIDs(taskID string, version *int, nodeIDs []string) ([]SiteTreeNode, error) {
	if len(nodeIDs) == 0 {
		return []SiteTreeNode{}, nil
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, version, map[string]interface{}{
			"terms": map[string]interface{}{
				"node_id.keyword": nodeIDs,
			},
		}),
		"size": len(nodeIDs),
		"sort": []map[string]interface{}{
			{"level": "asc"},
			{"node_id.keyword": "asc"},
		},
	}

	return querySiteTree(query)
}

// QueryVulnsByTaskID 查询任务的漏洞列表
func QueryVulnsByTaskID(taskID string, versions ...int) ([]VulnRecord, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion),
		"size":  10000,
		"sort": []map[string]interface{}{
			{"created_at": "desc"},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexVuln),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source VulnRecord `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var vulns []VulnRecord
	for _, hit := range result.Hits.Hits {
		vulns = append(vulns, hit.Source)
	}

	return dedupeQueriedVulns(vulns), nil
}

func dedupeQueriedVulns(vulns []VulnRecord) []VulnRecord {
	if len(vulns) <= 1 {
		return vulns
	}

	index := make(map[string]int, len(vulns))
	result := make([]VulnRecord, 0, len(vulns))
	for _, vuln := range vulns {
		key := queriedVulnDedupKey(vuln)
		if idx, ok := index[key]; ok {
			result[idx] = choosePreferredQueriedVuln(result[idx], vuln)
			continue
		}
		index[key] = len(result)
		result = append(result, vuln)
	}
	return result
}

func queriedVulnDedupKey(vuln VulnRecord) string {
	responseKey := ""
	if isQueriedUnauthorizedVuln(vuln) {
		responseKey = fmt.Sprintf("|%d|%s", vuln.ResponseLength, vuln.Response)
	}
	parsed, err := url.Parse(strings.TrimSpace(vuln.URL))
	if err == nil && parsed.Host != "" {
		path := parsed.Path
		if isQueriedUnauthorizedVuln(vuln) {
			path = strings.TrimSuffix(path, "/")
		}
		return strings.ToUpper(strings.TrimSpace(vuln.Method)) + "|" +
			strings.ToLower(parsed.Host) + "|" +
			path + "|" +
			strings.TrimSpace(vuln.Type) + responseKey
	}
	urlValue := strings.TrimSpace(vuln.URL)
	if isQueriedUnauthorizedVuln(vuln) {
		urlValue = strings.TrimSuffix(urlValue, "/")
	}
	return strings.ToUpper(strings.TrimSpace(vuln.Method)) + "|" +
		urlValue + "|" +
		strings.TrimSpace(vuln.Type) + responseKey
}

func isQueriedUnauthorizedVuln(vuln VulnRecord) bool {
	return vuln.Type == "未授权访问" || vuln.Title == "未授权访问"
}

func choosePreferredQueriedVuln(current, candidate VulnRecord) VulnRecord {
	currentURL := strings.ToLower(strings.TrimSpace(current.URL))
	candidateURL := strings.ToLower(strings.TrimSpace(candidate.URL))
	if strings.HasPrefix(candidateURL, "https://") && !strings.HasPrefix(currentURL, "https://") {
		return candidate
	}
	if candidate.ResponseLength > current.ResponseLength {
		return candidate
	}
	if len(strings.TrimSpace(candidate.Response)) > len(strings.TrimSpace(current.Response)) {
		return candidate
	}
	if candidate.CreatedAt.After(current.CreatedAt) {
		return candidate
	}
	return current
}

// QueryJSByTaskID 查询任务的JS资源
func QueryJSByTaskID(taskID string, versions ...int) ([]JSResource, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion),
		"size":  100,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexJS),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source JSResource `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var jsResources []JSResource
	for _, hit := range result.Hits.Hits {
		jsResources = append(jsResources, hit.Source)
	}

	return jsResources, nil
}

// QueryAPIResourcesByTaskID 查询任务的接口请求/响应记录
func QueryAPIResourcesByTaskID(taskID string, versions ...int) ([]APIResource, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion),
		"size":  1000,
		"sort": []map[string]interface{}{
			{"fetched_at": map[string]interface{}{"order": "desc", "unmapped_type": "date"}},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexAPI),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source APIResource `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var apiResources []APIResource
	for _, hit := range result.Hits.Hits {
		apiResources = append(apiResources, hit.Source)
	}

	return apiResources, nil
}

// QueryProtocolTracesByTaskID 查询任务的协议轨迹记录
func QueryProtocolTracesByTaskID(taskID string, versions ...int) ([]ProtocolTraceRecord, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion),
		"size":  1000,
		"sort": []map[string]interface{}{
			{"created_at": map[string]interface{}{"order": "desc", "unmapped_type": "date"}},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexProtocol),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source ProtocolTraceRecord `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var traces []ProtocolTraceRecord
	for _, hit := range result.Hits.Hits {
		trace := hit.Source
		trace.NormalizeForView()
		traces = append(traces, trace)
	}

	return traces, nil
}

// QueryProtocolTraceByTaskAndTraceID 查询单条协议轨迹
func QueryProtocolTraceByTaskAndTraceID(taskID, traceID string, versions ...int) (*ProtocolTraceRecord, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion,
			map[string]interface{}{
				"term": map[string]interface{}{
					"trace_id.keyword": traceID,
				},
			},
		),
		"size": 1,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexProtocol),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source ProtocolTraceRecord `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Hits.Hits) == 0 {
		return nil, fmt.Errorf("protocol trace not found")
	}

	trace := result.Hits.Hits[0].Source
	trace.NormalizeForView()
	return &trace, nil
}

// QueryJSByURL 根据URL查询单个JS内容
func QueryJSByURL(taskID, url string, versions ...int) (*JSResource, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion,
			map[string]interface{}{
				"term": map[string]interface{}{
					"url.keyword": url,
				},
			},
		),
		"size": 1,
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexJS),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source JSResource `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Hits.Hits) == 0 {
		return nil, fmt.Errorf("JS resource not found")
	}

	return &result.Hits.Hits[0].Source, nil
}

// QueryAllJS 查询所有JS资源（用于全局搜索）
func QueryAllJS() ([]JSResource, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
		"size": 1000, // 限制返回数量
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexJS),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source JSResource `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var jsResources []JSResource
	for _, hit := range result.Hits.Hits {
		jsResources = append(jsResources, hit.Source)
	}

	return jsResources, nil
}

// QueryJSBatch 分批查询 JS 资源，避免一次性拉取过多 _source 导致 ES 内存压力过大。
func QueryJSBatch(from, size int) ([]JSResource, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}
	if from < 0 {
		from = 0
	}
	if size <= 0 {
		size = 50
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"match_all": map[string]interface{}{},
		},
		"from": from,
		"size": size,
		"_source": map[string]interface{}{
			"includes": []string{"task_id", "url", "content"},
		},
		"sort": []map[string]interface{}{
			{"fetched_at": map[string]interface{}{"order": "desc", "unmapped_type": "date"}},
			{"url.keyword": map[string]interface{}{"order": "asc", "unmapped_type": "keyword"}},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexJS),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source JSResource `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	jsResources := make([]JSResource, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		jsResources = append(jsResources, hit.Source)
	}

	return jsResources, nil
}

// QueryAssetsByTaskID 查询任务的资产信息
func QueryAssetsByTaskID(taskID string, versions ...int) (*AssetRecord, error) {
	if ESClient == nil {
		return nil, fmt.Errorf("ES client not initialized")
	}

	resolvedVersion, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}

	query := map[string]interface{}{
		"query": buildTaskVersionQuery(taskID, resolvedVersion),
		"size":  1000,
		"sort": []map[string]interface{}{
			{"created_at": "desc"},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexAsset),
		ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source AssetRecord `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	if len(result.Hits.Hits) == 0 {
		return nil, fmt.Errorf("assets not found for task %s", taskID)
	}

	merged := &AssetRecord{
		TaskID: taskID,
	}
	if resolvedVersion != nil {
		merged.Version = *resolvedVersion
	}

	for _, hit := range result.Hits.Hits {
		source := hit.Source
		if source.TaskID != "" {
			merged.TaskID = source.TaskID
		}
		if source.Version > 0 {
			merged.Version = source.Version
		}
		if source.CreatedAt.After(merged.CreatedAt) {
			merged.CreatedAt = source.CreatedAt
		}
		merged.Email = MergeAssetValues(merged.Email, source.Email)
		merged.IDCard = MergeAssetValues(merged.IDCard, source.IDCard)
		merged.Phone = MergeAssetValues(merged.Phone, source.Phone)
		merged.IPURL = MergeAssetValues(merged.IPURL, source.IPURL)
		merged.FrontendRoute = MergeAssetValues(merged.FrontendRoute, source.FrontendRoute)
		merged.APIRoot = MergeAssetValues(merged.APIRoot, source.APIRoot)
		merged.APIRouter = MergeAssetValues(merged.APIRouter, source.APIRouter)
	}

	return merged, nil
}

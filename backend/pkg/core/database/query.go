package database

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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
	fmt.Printf("[DEBUG] QuerySiteTreeByTaskID(%s) returned %d nodes, err: %v\n", taskID, len(nodes), err)
	return nodes, err
}

func querySiteTree(query map[string]interface{}) ([]SiteTreeNode, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, err
	}

	res, err := ESClient.Search(
		ESClient.Search.WithContext(context.Background()),
		ESClient.Search.WithIndex(IndexSiteTree),
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
				Source SiteTreeNode `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, err
	}

	var nodes []SiteTreeNode
	for _, hit := range result.Hits.Hits {
		nodes = append(nodes, hit.Source)
	}

	return nodes, nil
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

	return vulns, nil
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
			{"fetched_at": "desc"},
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
			{"created_at": "desc"},
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
		merged.APIRoot = MergeAssetValues(merged.APIRoot, source.APIRoot)
		merged.APIRouter = MergeAssetValues(merged.APIRouter, source.APIRouter)
	}

	return merged, nil
}

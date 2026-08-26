package database

import (
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
		return &version, selected, err
	}
	if DB == nil {
		return nil, nil, nil
	}
	latest, err := GetLatestTaskVersion(taskID)
	if err != nil || latest == nil {
		return nil, latest, err
	}
	return &latest.Version, latest, nil
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

func QueryTaskByID(taskID string, versions ...int) (*TaskRecord, error) {
	resolved, summary, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	base, err := GetTaskByID(taskID)
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, fmt.Errorf("task not found")
	}
	task := &TaskRecord{TaskID: base.ID, TaskName: base.Name, Targets: append([]string(nil), base.Targets...), Status: base.Status, CreatedAt: base.CreatedAt, UpdatedAt: base.UpdatedAt}
	if resolved != nil && summary == nil {
		summary, err = GetTaskVersion(taskID, *resolved)
		if err != nil {
			return nil, err
		}
	}
	applyVersionSummary(task, summary)
	return task, nil
}

func QuerySiteTreeByTaskID(taskID string, versions ...int) ([]SiteTreeNode, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	nodes, err := loadScanDocuments[SiteTreeNode](CollectionSiteTree, taskID, version, "level ASC, identity ASC, id ASC", 10000, 0)
	if nodes == nil {
		nodes = []SiteTreeNode{}
	}
	return nodes, err
}

type SiteTreePageResult struct {
	Nodes                                 []SiteTreeNode
	Total, TotalNodeCount, Page, PageSize int
	Keyword                               string
}

func QuerySiteTreePage(taskID string, page, pageSize int, keyword string, versions ...int) (*SiteTreePageResult, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	page, pageSize, keyword = positive(page, 1), positive(pageSize, 20), strings.TrimSpace(keyword)
	all, err := loadScanDocuments[SiteTreeNode](CollectionSiteTree, taskID, version, "level ASC, identity ASC, id ASC", 10000, 0)
	if err != nil {
		return nil, err
	}
	if keyword == "" {
		return pageRootTree(all, page, pageSize), nil
	}
	return pageSearchTree(all, page, pageSize, keyword), nil
}

func pageRootTree(all []SiteTreeNode, page, pageSize int) *SiteTreePageResult {
	roots := make([]string, 0)
	seen := map[string]bool{}
	for _, node := range all {
		if (node.Level == 1 || node.ParentID == "0") && !seen[node.NodeID] {
			seen[node.NodeID] = true
			roots = append(roots, node.NodeID)
		}
	}
	sort.Strings(roots)
	start := min((page-1)*pageSize, len(roots))
	end := min(start+pageSize, len(roots))
	selected := map[string]bool{}
	for _, root := range roots[start:end] {
		selected[root] = true
	}
	nodes := make([]SiteTreeNode, 0)
	for _, node := range all {
		if selected[rootSiteTreeNodeID(node.NodeID)] {
			nodes = append(nodes, node)
		}
	}
	return &SiteTreePageResult{Nodes: nodes, Total: len(roots), TotalNodeCount: len(all), Page: page, PageSize: pageSize}
}

func pageSearchTree(all []SiteTreeNode, page, pageSize int, keyword string) *SiteTreePageResult {
	needle := strings.ToLower(keyword)
	roots, matchingRoots, relevant := []string{}, map[string]bool{}, map[string]bool{}
	for _, node := range all {
		if !strings.Contains(strings.ToLower(node.Label), needle) && !strings.Contains(strings.ToLower(node.URL), needle) && !strings.Contains(strings.ToLower(node.NodeID), needle) {
			continue
		}
		root := rootSiteTreeNodeID(node.NodeID)
		if !matchingRoots[root] {
			matchingRoots[root] = true
			roots = append(roots, root)
		}
		for _, parent := range collectAncestorNodeIDs(node.NodeID) {
			relevant[parent] = true
		}
	}
	sort.Strings(roots)
	start := min((page-1)*pageSize, len(roots))
	end := min(start+pageSize, len(roots))
	selected := map[string]bool{}
	for _, root := range roots[start:end] {
		selected[root] = true
	}
	nodes := []SiteTreeNode{}
	for _, node := range all {
		if selected[rootSiteTreeNodeID(node.NodeID)] && relevant[node.NodeID] {
			nodes = append(nodes, node)
		}
	}
	return &SiteTreePageResult{Nodes: nodes, Total: len(roots), TotalNodeCount: len(all), Page: page, PageSize: pageSize, Keyword: keyword}
}

func positive(value, fallback int) int {
	if value <= 0 {
		return fallback
	}
	return value
}
func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}
func rootSiteTreeNodeID(nodeID string) string {
	if i := strings.Index(strings.TrimSpace(nodeID), "/"); i >= 0 {
		return nodeID[:i]
	}
	return strings.TrimSpace(nodeID)
}
func collectAncestorNodeIDs(nodeID string) []string {
	parts := strings.Split(strings.TrimSpace(nodeID), "/")
	result := make([]string, 0, len(parts))
	current := ""
	for _, part := range parts {
		if part == "" {
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

func QueryVulnsByTaskID(taskID string, versions ...int) ([]VulnRecord, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	vulns, err := loadScanDocuments[VulnRecord](CollectionVuln, taskID, version, "created_at DESC, id DESC", 10000, 0)
	if err != nil {
		return nil, err
	}
	return dedupeQueriedVulns(vulns), nil
}
func dedupeQueriedVulns(vulns []VulnRecord) []VulnRecord {
	seen := map[string]int{}
	result := make([]VulnRecord, 0, len(vulns))
	for _, vuln := range vulns {
		key := queriedVulnDedupKey(vuln)
		if i, ok := seen[key]; ok {
			result[i] = choosePreferredQueriedVuln(result[i], vuln)
			continue
		}
		seen[key] = len(result)
		result = append(result, vuln)
	}
	return result
}
func queriedVulnDedupKey(v VulnRecord) string {
	response := ""
	if isQueriedUnauthorizedVuln(v) {
		response = fmt.Sprintf("|%d|%s", v.ResponseLength, v.Response)
	}
	parsed, err := url.Parse(strings.TrimSpace(v.URL))
	if err == nil && parsed.Host != "" {
		path := parsed.Path
		if isQueriedUnauthorizedVuln(v) {
			path = strings.TrimSuffix(path, "/")
		}
		return strings.ToUpper(strings.TrimSpace(v.Method)) + "|" + strings.ToLower(parsed.Host) + "|" + path + "|" + strings.TrimSpace(v.Type) + response
	}
	value := strings.TrimSpace(v.URL)
	if isQueriedUnauthorizedVuln(v) {
		value = strings.TrimSuffix(value, "/")
	}
	return strings.ToUpper(strings.TrimSpace(v.Method)) + "|" + value + "|" + strings.TrimSpace(v.Type) + response
}
func isQueriedUnauthorizedVuln(v VulnRecord) bool {
	return v.Type == "未授权访问" || v.Title == "未授权访问"
}
func choosePreferredQueriedVuln(current, candidate VulnRecord) VulnRecord {
	currentURL, candidateURL := strings.ToLower(strings.TrimSpace(current.URL)), strings.ToLower(strings.TrimSpace(candidate.URL))
	if strings.HasPrefix(candidateURL, "https://") && !strings.HasPrefix(currentURL, "https://") {
		return candidate
	}
	if candidate.ResponseLength > current.ResponseLength || len(strings.TrimSpace(candidate.Response)) > len(strings.TrimSpace(current.Response)) || candidate.CreatedAt.After(current.CreatedAt) {
		return candidate
	}
	return current
}

func QueryJSByTaskID(taskID string, versions ...int) ([]JSResource, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	return loadScanDocuments[JSResource](CollectionJS, taskID, version, "fetched_at DESC, id DESC", 100, 0)
}
func QueryAPIResourcesByTaskID(taskID string, versions ...int) ([]APIResource, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	return loadScanDocuments[APIResource](CollectionAPI, taskID, version, "fetched_at DESC, id DESC", 1000, 0)
}
func QueryProtocolTracesByTaskID(taskID string, versions ...int) ([]ProtocolTraceRecord, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	traces, err := loadScanDocuments[ProtocolTraceRecord](CollectionProtocol, taskID, version, "created_at DESC, id DESC", 1000, 0)
	for i := range traces {
		traces[i].NormalizeForView()
	}
	return traces, err
}
func QueryProtocolTraceByTaskAndTraceID(taskID, traceID string, versions ...int) (*ProtocolTraceRecord, error) {
	traces, err := QueryProtocolTracesByTaskID(taskID, versions...)
	if err != nil {
		return nil, err
	}
	for i := range traces {
		if traces[i].TraceID == traceID {
			return &traces[i], nil
		}
	}
	return nil, fmt.Errorf("protocol trace not found")
}
func QueryJSByURL(taskID, resourceURL string, versions ...int) (*JSResource, error) {
	resources, err := QueryJSByTaskID(taskID, versions...)
	if err != nil {
		return nil, err
	}
	for i := range resources {
		if resources[i].URL == resourceURL {
			return &resources[i], nil
		}
	}
	return nil, fmt.Errorf("JS resource not found")
}
func QueryAllJS() ([]JSResource, error) {
	return loadScanDocuments[JSResource](CollectionJS, "", nil, "fetched_at DESC, id DESC", 1000, 0)
}
func QueryJSBatch(from, size int) ([]JSResource, error) {
	if from < 0 {
		from = 0
	}
	if size <= 0 {
		size = 50
	}
	return loadScanDocuments[JSResource](CollectionJS, "", nil, "fetched_at DESC, url ASC, id ASC", size, from)
}
func QueryAssetsByTaskID(taskID string, versions ...int) (*AssetRecord, error) {
	version, _, err := resolveQueryVersion(taskID, versions...)
	if err != nil {
		return nil, err
	}
	assets, err := loadScanDocuments[AssetRecord](CollectionAsset, taskID, version, "created_at DESC, id DESC", 1000, 0)
	if err != nil {
		return nil, err
	}
	if len(assets) == 0 {
		return nil, fmt.Errorf("assets not found for task %s", taskID)
	}
	merged := &AssetRecord{TaskID: taskID}
	if version != nil {
		merged.Version = *version
	}
	for _, source := range assets {
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

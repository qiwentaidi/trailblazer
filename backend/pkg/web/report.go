package web

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
	"trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
)

const (
	reportPageSize        = 10
	reportClusterPageSize = 20
	reportMinClusterSize  = 3
	reportPacketPreview   = 4000
)

type reportAssetRow struct {
	Type      string `json:"type"`
	TypeLabel string `json:"typeLabel"`
	Value     string `json:"value"`
	Source    string `json:"source"`
}

type reportRiskChild struct {
	ID                string `json:"id"`
	Title             string `json:"title"`
	URL               string `json:"url"`
	Method            string `json:"method"`
	Summary           string `json:"summary"`
	Description       string `json:"description"`
	Request           string `json:"request"`
	RequestPreview    string `json:"requestPreview"`
	RequestTruncated  bool   `json:"requestTruncated"`
	Response          string `json:"response"`
	ResponsePreview   string `json:"responsePreview"`
	ResponseTruncated bool   `json:"responseTruncated"`
	CreatedAt         string `json:"createdAt"`
}

type reportRiskItem struct {
	Kind              string            `json:"kind"`
	ID                string            `json:"id"`
	ClusterID         string            `json:"clusterId,omitempty"`
	Label             string            `json:"label,omitempty"`
	KindLabel         string            `json:"kindLabel,omitempty"`
	Title             string            `json:"title,omitempty"`
	Level             string            `json:"level"`
	LevelLabel        string            `json:"levelLabel"`
	Confidence        string            `json:"confidence"`
	ConfidenceLabel   string            `json:"confidenceLabel"`
	Count             int               `json:"count,omitempty"`
	Type              string            `json:"type,omitempty"`
	URL               string            `json:"url,omitempty"`
	Method            string            `json:"method,omitempty"`
	Summary           string            `json:"summary"`
	Description       string            `json:"description,omitempty"`
	Request           string            `json:"request,omitempty"`
	RequestPreview    string            `json:"requestPreview,omitempty"`
	RequestTruncated  bool              `json:"requestTruncated,omitempty"`
	Response          string            `json:"response,omitempty"`
	ResponsePreview   string            `json:"responsePreview,omitempty"`
	ResponseTruncated bool              `json:"responseTruncated,omitempty"`
	CreatedAt         string            `json:"createdAt,omitempty"`
	AIVerified        bool              `json:"aiVerified,omitempty"`
	Items             []reportRiskChild `json:"items,omitempty"`
	PageSize          int               `json:"pageSize,omitempty"`
}

type reportSnapshot struct {
	Meta struct {
		TaskID       string   `json:"taskId"`
		TaskName     string   `json:"taskName"`
		Status       string   `json:"status"`
		Targets      []string `json:"targets"`
		Version      int      `json:"version,omitempty"`
		VersionLabel string   `json:"versionLabel"`
		GeneratedAt  string   `json:"generatedAt"`
	} `json:"meta"`
	Summary struct {
		TotalRisks          int `json:"totalRisks"`
		HighRisks           int `json:"highRisks"`
		MediumRisks         int `json:"mediumRisks"`
		LowRisks            int `json:"lowRisks"`
		InfoRisks           int `json:"infoRisks"`
		ClusteredEntries    int `json:"clusteredEntries"`
		StandaloneEntries   int `json:"standaloneEntries"`
		TotalAssetRows      int `json:"totalAssetRows"`
		EmailAssets         int `json:"emailAssets"`
		PhoneAssets         int `json:"phoneAssets"`
		IDCardAssets        int `json:"idCardAssets"`
		IPURLAssets         int `json:"ipUrlAssets"`
		FrontendRouteAssets int `json:"frontendRouteAssets"`
		APIRootAssets       int `json:"apiRootAssets"`
		APIRouterAssets     int `json:"apiRouterAssets"`
	} `json:"summary"`
	Risks struct {
		PageSize int              `json:"pageSize"`
		Items    []reportRiskItem `json:"items"`
	} `json:"risks"`
	Assets struct {
		PageSize int              `json:"pageSize"`
		Rows     []reportAssetRow `json:"rows"`
	} `json:"assets"`
}

func exportTaskReport(c *gin.Context) {
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

	vulns, err := database.QueryVulnsByTaskID(taskID, versionArgs(version)...)
	if err != nil && !reportCanIgnoreError(err) {
		c.JSON(500, gin.H{"error": "failed to query vulns", "detail": err.Error()})
		return
	}
	treeNodes, err := database.QuerySiteTreeByTaskID(taskID, versionArgs(version)...)
	if err != nil && !reportCanIgnoreError(err) {
		c.JSON(500, gin.H{"error": "failed to query tree", "detail": err.Error()})
		return
	}

	assets, err := database.QueryAssetsByTaskID(taskID, versionArgs(version)...)
	if err != nil && !reportCanIgnoreError(err) {
		c.JSON(500, gin.H{"error": "failed to query assets", "detail": err.Error()})
		return
	}

	mergedAssets := buildReportAssetRecord(task, assets, treeNodes, vulns)
	snapshot := buildReportSnapshot(task, version, vulns, mergedAssets)
	format := strings.TrimSpace(strings.ToLower(c.DefaultQuery("format", "html")))

	filenameVersion := ""
	if version != nil {
		filenameVersion = fmt.Sprintf("_v%d", *version)
	}

	switch format {
	case "json":
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="task_%s%s_risk_asset_report.json"`, taskID, filenameVersion))
		c.JSON(200, snapshot)
	default:
		html, err := buildReportHTML(snapshot)
		if err != nil {
			c.JSON(500, gin.H{"error": "failed to build html report", "detail": err.Error()})
			return
		}
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="task_%s%s_risk_asset_report.html"`, taskID, filenameVersion))
		c.Data(200, "text/html; charset=utf-8", []byte(html))
	}
}

func reportCanIgnoreError(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()
	return strings.Contains(message, "index_not_found_exception") ||
		strings.Contains(message, "ES client not initialized") ||
		strings.Contains(message, "connection") ||
		strings.Contains(message, "not found")
}

func buildReportSnapshot(
	task *database.TaskRecord,
	version *int,
	vulns []database.VulnRecord,
	assets *database.AssetRecord,
) reportSnapshot {
	snapshot := reportSnapshot{}
	snapshot.Meta.TaskID = task.TaskID
	snapshot.Meta.TaskName = task.TaskName
	snapshot.Meta.Status = task.Status
	snapshot.Meta.Targets = append([]string(nil), task.Targets...)
	snapshot.Meta.GeneratedAt = time.Now().Format("2006-01-02 15:04:05")
	if version != nil {
		snapshot.Meta.Version = *version
		snapshot.Meta.VersionLabel = fmt.Sprintf("第 %d 次扫描", *version)
	} else {
		snapshot.Meta.VersionLabel = "最新扫描"
	}

	snapshot.Risks.PageSize = reportPageSize
	snapshot.Risks.Items = buildReportRiskItems(vulns)
	snapshot.Assets.PageSize = reportPageSize
	snapshot.Assets.Rows = buildReportAssetRows(assets)

	snapshot.Summary.TotalRisks = len(vulns)
	snapshot.Summary.TotalAssetRows = len(snapshot.Assets.Rows)
	if assets != nil {
		snapshot.Summary.EmailAssets = len(assets.Email)
		snapshot.Summary.PhoneAssets = len(assets.Phone)
		snapshot.Summary.IDCardAssets = len(assets.IDCard)
		snapshot.Summary.IPURLAssets = len(assets.IPURL)
		snapshot.Summary.FrontendRouteAssets = len(assets.FrontendRoute)
		snapshot.Summary.APIRootAssets = len(assets.APIRoot)
		snapshot.Summary.APIRouterAssets = len(assets.APIRouter)
	}
	for _, vuln := range vulns {
		switch normalizeRiskLevel(vuln.Level) {
		case "high":
			snapshot.Summary.HighRisks++
		case "medium":
			snapshot.Summary.MediumRisks++
		case "low":
			snapshot.Summary.LowRisks++
		default:
			snapshot.Summary.InfoRisks++
		}
	}
	for _, item := range snapshot.Risks.Items {
		if item.Kind == "cluster" {
			snapshot.Summary.ClusteredEntries++
		} else {
			snapshot.Summary.StandaloneEntries++
		}
	}

	return snapshot
}

func buildReportRiskItems(vulns []database.VulnRecord) []reportRiskItem {
	items := make([]reportRiskItem, 0, len(vulns))
	grouped := make(map[string]struct{})

	for _, vuln := range vulns {
		clusterID := strings.TrimSpace(vuln.DenyTemplateID)
		clusterLabel := strings.TrimSpace(vuln.DenyTemplateLabel)
		if clusterID != "" && clusterLabel != "" && vuln.DenyTemplateCount >= reportMinClusterSize {
			if _, exists := grouped[clusterID]; exists {
				continue
			}
			grouped[clusterID] = struct{}{}
			clusterItems := make([]reportRiskChild, 0)
			count := 0
			for _, current := range vulns {
				if current.DenyTemplateID != clusterID {
					continue
				}
				count++
				clusterItems = append(clusterItems, reportRiskChild{
					ID:                current.VulnID,
					Title:             current.Title,
					URL:               current.URL,
					Method:            fallbackString(current.Method, "-"),
					Summary:           buildRiskSummary(current),
					Description:       fallbackString(current.Description, "-"),
					Request:           current.Request,
					RequestPreview:    previewPacket(current.Request),
					RequestTruncated:  isPacketTruncated(current.Request),
					Response:          current.Response,
					ResponsePreview:   previewPacket(current.Response),
					ResponseTruncated: isPacketTruncated(current.Response),
					CreatedAt:         formatTime(current.CreatedAt),
				})
			}
			level := normalizeRiskLevel(vuln.Level)
			confidence := normalizeConfidence(vuln.Confidence)
			items = append(items, reportRiskItem{
				Kind:            "cluster",
				ID:              "cluster-" + clusterID,
				ClusterID:       clusterID,
				Label:           clusterLabel,
				KindLabel:       reportClusterKindLabel(vuln.DenyTemplateKind),
				Level:           level,
				LevelLabel:      reportLevelLabel(level),
				Confidence:      confidence,
				ConfidenceLabel: reportConfidenceLabel(confidence),
				Count:           count,
				Summary:         buildClusterSummary(vuln, count),
				Items:           clusterItems,
				PageSize:        reportClusterPageSize,
			})
			continue
		}

		level := normalizeRiskLevel(vuln.Level)
		confidence := normalizeConfidence(vuln.Confidence)
		items = append(items, reportRiskItem{
			Kind:              "risk",
			ID:                vuln.VulnID,
			Title:             vuln.Title,
			Level:             level,
			LevelLabel:        reportLevelLabel(level),
			Confidence:        confidence,
			ConfidenceLabel:   reportConfidenceLabel(confidence),
			Type:              fallbackString(vuln.Type, "-"),
			URL:               fallbackString(vuln.URL, "-"),
			Method:            fallbackString(vuln.Method, "-"),
			Summary:           buildRiskSummary(vuln),
			Description:       fallbackString(vuln.Description, "-"),
			Request:           vuln.Request,
			RequestPreview:    previewPacket(vuln.Request),
			RequestTruncated:  isPacketTruncated(vuln.Request),
			Response:          vuln.Response,
			ResponsePreview:   previewPacket(vuln.Response),
			ResponseTruncated: isPacketTruncated(vuln.Response),
			CreatedAt:         formatTime(vuln.CreatedAt),
			AIVerified:        vuln.AIVerified,
		})
	}

	return items
}

func buildReportAssetRows(assets *database.AssetRecord) []reportAssetRow {
	if assets == nil {
		return nil
	}

	appendRows := func(rows []reportAssetRow, typeName, label string, items []database.AssetValue) []reportAssetRow {
		for _, item := range items {
			if strings.TrimSpace(item.Value) == "" {
				continue
			}
			rows = append(rows, reportAssetRow{
				Type:      typeName,
				TypeLabel: label,
				Value:     item.Value,
				Source:    strings.Join(item.Source, "\n"),
			})
		}
		return rows
	}

	rows := make([]reportAssetRow, 0)
	rows = appendRows(rows, "email", "邮箱", assets.Email)
	rows = appendRows(rows, "phone", "手机号", assets.Phone)
	rows = appendRows(rows, "idCard", "身份证", assets.IDCard)
	rows = appendRows(rows, "ipUrl", "IP/URL", assets.IPURL)
	rows = appendRows(rows, "frontendRoute", "前端路由", assets.FrontendRoute)
	rows = appendRows(rows, "apiRoot", "API Root", assets.APIRoot)
	rows = appendRows(rows, "apiRouter", "API Router", assets.APIRouter)
	return rows
}

func buildReportAssetRecord(
	task *database.TaskRecord,
	base *database.AssetRecord,
	treeNodes []database.SiteTreeNode,
	vulns []database.VulnRecord,
) *database.AssetRecord {
	result := &database.AssetRecord{}
	if base != nil {
		*result = *base
		result.Email = append([]database.AssetValue(nil), base.Email...)
		result.Phone = append([]database.AssetValue(nil), base.Phone...)
		result.IDCard = append([]database.AssetValue(nil), base.IDCard...)
		result.IPURL = append([]database.AssetValue(nil), base.IPURL...)
		result.FrontendRoute = append([]database.AssetValue(nil), base.FrontendRoute...)
		result.APIRoot = append([]database.AssetValue(nil), base.APIRoot...)
		result.APIRouter = append([]database.AssetValue(nil), base.APIRouter...)
	}
	if result.TaskID == "" && task != nil {
		result.TaskID = task.TaskID
	}

	ipURLSources := make(map[string][]string)
	frontendRouteSources := make(map[string][]string)
	apiRouteSources := make(map[string][]string)
	apiRootSources := make(map[string][]string)

	appendSource := func(target map[string][]string, value string, sources ...string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}

		normalizedSources := make([]string, 0, len(sources))
		for _, source := range sources {
			if normalized := normalizeAssetSourceReference(source); normalized != "" {
				normalizedSources = append(normalizedSources, normalized)
			}
		}

		target[value] = uniqueStrings(append(target[value], normalizedSources...))
	}

	for _, item := range result.IPURL {
		appendSource(ipURLSources, item.Value, item.Source...)
	}
	for _, item := range result.FrontendRoute {
		appendSource(frontendRouteSources, item.Value, item.Source...)
	}
	for _, item := range result.APIRouter {
		appendSource(apiRouteSources, item.Value, item.Source...)
	}
	for _, item := range result.APIRoot {
		appendSource(apiRootSources, item.Value, item.Source...)
	}

	for _, node := range treeNodes {
		normalizedURL := normalizeAbsoluteURL(node.URL)
		if normalizedURL == "" {
			continue
		}
		appendSource(ipURLSources, normalizedURL, normalizedURL)
	}

	for _, vuln := range vulns {
		source := normalizeAssetSourceReference(vuln.URL)
		if source == "" {
			continue
		}
		appendSource(ipURLSources, source, source)
	}

	for value, sources := range ipURLSources {
		apiRoute := normalizeAPIRoute(value)
		if apiRoute == "" {
			continue
		}
		appendSource(apiRouteSources, apiRoute, sources...)
	}

	result.IPURL = sourceMapToAssetValues(ipURLSources)
	result.FrontendRoute = sourceMapToAssetValues(frontendRouteSources)
	result.APIRouter = sourceMapToAssetValues(apiRouteSources)
	result.APIRoot = sourceMapToAssetValues(apiRootSources)
	return result
}

func sourceMapToAssetValues(items map[string][]string) []database.AssetValue {
	values := make([]database.AssetValue, 0, len(items))
	for value, sources := range items {
		values = append(values, database.AssetValue{
			Value:  value,
			Source: uniqueStrings(sources),
		})
	}
	return database.MergeAssetValues(values)
}

func normalizeAbsoluteURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Fragment = ""
	return parsed.String()
}

func normalizeAssetSourceReference(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if strings.HasPrefix(trimmed, "sourceMap/") {
		return trimmed
	}

	return normalizeAbsoluteURL(trimmed)
}

func normalizeAPIRoute(absoluteURL string) string {
	parsed, err := url.Parse(strings.TrimSpace(absoluteURL))
	if err != nil {
		return ""
	}
	path := strings.TrimSpace(parsed.Path)
	if path == "" || path == "/" {
		return ""
	}
	return path
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func normalizeRiskLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

func normalizeConfidence(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high":
		return "high"
	case "low":
		return "low"
	default:
		return "medium"
	}
}

func reportLevelLabel(level string) string {
	switch level {
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "信息"
	}
}

func reportConfidenceLabel(level string) string {
	switch level {
	case "high":
		return "高置信"
	case "low":
		return "低置信"
	default:
		return "中置信"
	}
}

func reportClusterKindLabel(kind string) string {
	if strings.TrimSpace(kind) == "auth_required" {
		return "认证拒绝簇"
	}
	return "拒绝模板簇"
}

func buildRiskSummary(vuln database.VulnRecord) string {
	parts := make([]string, 0, 2)
	if strings.TrimSpace(vuln.ConfidenceReason) != "" {
		parts = append(parts, strings.TrimSpace(vuln.ConfidenceReason))
	} else if strings.TrimSpace(vuln.Description) != "" {
		parts = append(parts, strings.TrimSpace(vuln.Description))
	}
	if vuln.ResponseLength > 0 {
		parts = append(parts, fmt.Sprintf("响应长度: %d", vuln.ResponseLength))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, "；")
}

func buildClusterSummary(vuln database.VulnRecord, count int) string {
	parts := []string{fmt.Sprintf("当前模板命中 %d 个接口，默认折叠展示以降低重复噪音。", count)}
	if strings.TrimSpace(vuln.ConfidenceReason) != "" {
		parts = append(parts, "代表特征: "+strings.TrimSpace(vuln.ConfidenceReason))
	}
	if vuln.ResponseLength > 0 {
		parts = append(parts, fmt.Sprintf("代表响应长度: %d", vuln.ResponseLength))
	}
	return strings.Join(parts, " ")
}

func fallbackString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "-"
	}
	return value.Format("2006-01-02 15:04:05")
}

func previewPacket(value string) string {
	if len(value) <= reportPacketPreview {
		return value
	}
	return value[:reportPacketPreview]
}

func isPacketTruncated(value string) bool {
	return len(value) > reportPacketPreview
}

func buildReportHTML(snapshot reportSnapshot) (string, error) {
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return "", err
	}
	reportJSON := escapeInlineScript(string(payload))

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>%s - 风险资产报告</title>
  <style>
    :root{--bg:#eff4fb;--panel:#fff;--line:#d9e2ee;--text:#16202a;--muted:#617181;--blue:#2563eb;--red:#b91c1c;--orange:#c2410c;--green:#15803d;--soft:#f7f9fc;}
    *{box-sizing:border-box} body{margin:0;font-family:"PingFang SC","Microsoft YaHei",sans-serif;background:linear-gradient(180deg,#f8fbff 0%%,var(--bg) 100%%);color:var(--text)}
    .page{width:min(1200px,calc(100vw - 32px));margin:24px auto 48px}
    .hero,.panel{background:var(--panel);border:1px solid var(--line);border-radius:20px;box-shadow:0 18px 48px rgba(15,23,42,.08)}
    .hero{padding:28px;display:grid;gap:18px}
    .eyebrow{display:inline-flex;align-items:center;gap:8px;background:#dbeafe;color:var(--blue);border-radius:999px;padding:6px 12px;font-size:13px;font-weight:600}
    h1{margin:0;font-size:34px;line-height:1.15}
    .meta,.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
    .targets{display:flex;flex-wrap:wrap;gap:8px}
    .card{background:var(--soft);border:1px solid var(--line);border-radius:16px;padding:14px 16px}
    .label{font-size:13px;color:var(--muted)} .value{margin-top:8px;font-size:16px;font-weight:600;word-break:break-word}
    .section{margin-top:22px}.panel{padding:24px}.section-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}
    .section-title{margin:0;font-size:24px}.section-note{font-size:14px;color:var(--muted)}
    .pagination{display:inline-flex;gap:8px;align-items:center;flex-wrap:wrap}
    .section-tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap;justify-content:flex-end}
    .search-input{min-width:280px;max-width:min(420px,100%%);padding:9px 12px;border:1px solid var(--line);border-radius:10px;background:#fff;color:var(--text);font:inherit}
    .search-input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(37,99,235,.12)}
    .search-meta{font-size:13px;color:var(--muted)}
    button{border:1px solid var(--line);background:#fff;border-radius:10px;padding:8px 12px;cursor:pointer;font:inherit}
    button:disabled{opacity:.45;cursor:not-allowed}
    .risk-list,.asset-list{display:grid;gap:12px}
    .risk-item,.cluster-item{border:1px solid var(--line);border-radius:16px;padding:16px;background:var(--soft)}
    .head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}
    .title{margin:0;font-size:18px}
    .tags{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}
    .tag{display:inline-flex;align-items:center;border-radius:999px;padding:4px 10px;font-size:12px;font-weight:600}
    .level-high{background:var(--red);color:#fff}.level-medium{background:var(--orange);color:#fff}.level-low{background:var(--blue);color:#fff}.level-info{background:#e5e7eb;color:var(--text)}
    .confidence{background:#dcfce7;color:var(--green)} .type{background:#dbeafe;color:#1e3a8a} .ai{background:#ffedd5;color:#9a3412}
    .target-tag{background:#eef2ff;color:#3730a3}
    .kv{display:grid;grid-template-columns:110px 1fr;gap:8px 12px;margin-top:14px;font-size:14px}
    .kv dt{color:var(--muted)} .kv dd{margin:0;word-break:break-word}
    details{margin-top:12px;background:#fff;border:1px dashed #c6d2e1;border-radius:12px;padding:10px 12px}
    summary{cursor:pointer;font-weight:600}
    pre{margin:10px 0 0;padding:14px;background:#0f172a;color:#e2e8f0;border-radius:12px;overflow:auto;white-space:pre-wrap;word-break:break-word;max-height:420px}
    .cluster-items{display:none;gap:10px;margin-top:14px}.cluster-items.open{display:grid}
    .cluster-row{border:1px dashed #c8d6e5;border-radius:12px;padding:12px;background:#fff}
    .cluster-row-title{font-weight:600;margin-bottom:8px;word-break:break-word}
    table{width:100%%;border-collapse:collapse} th,td{border-top:1px solid var(--line);padding:12px 10px;text-align:left;vertical-align:top;word-break:break-word;white-space:pre-wrap} th{background:#f8fafc;color:var(--muted)}
    .empty{padding:24px 0;text-align:center;color:var(--muted)}
    @media print{body{background:#fff}.page{width:100%%;margin:0}.hero,.panel{box-shadow:none;border-radius:0}button{display:none}}
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <div class="eyebrow">Trailblazer 风险资产报告</div>
      <h1>%s</h1>
      <div class="meta">
        <div class="card"><div class="label">任务 ID</div><div class="value">%s</div></div>
        <div class="card"><div class="label">扫描版本</div><div class="value">%s</div></div>
        <div class="card"><div class="label">任务状态</div><div class="value">%s</div></div>
        <div class="card"><div class="label">生成时间</div><div class="value">%s</div></div>
      </div>
      <div class="card">
        <div class="label">目标列表</div>
        <div class="value targets">%s</div>
      </div>
      <div class="summary">
        <div class="card"><div class="label">风险总数</div><div class="value">%d</div></div>
        <div class="card"><div class="label">高危 / 中危 / 低危 / 信息</div><div class="value">%d / %d / %d / %d</div></div>
        <div class="card"><div class="label">聚合簇 / 单条风险</div><div class="value">%d / %d</div></div>
        <div class="card"><div class="label">资产条目数</div><div class="value">%d</div></div>
        <div class="card"><div class="label">邮箱 / 手机 / 身份证</div><div class="value">%d / %d / %d</div></div>
        <div class="card"><div class="label">IP/URL / 前端路由 / API Root / API Router</div><div class="value">%d / %d / %d / %d</div></div>
      </div>
    </section>
    <section class="section"><div class="panel">
      <div class="section-head">
        <div><h2 class="section-title">风险报告</h2><div class="section-note">包含聚合簇、完整请求包和响应包，并提供分页浏览。</div></div>
        <div class="section-tools">
          <input id="risk-search" class="search-input" type="search" placeholder="检索标题、URL、摘要、描述、请求包、响应包" />
          <span id="risk-count" class="search-meta"></span>
          <div class="pagination"><button id="risk-prev">上一页</button><span id="risk-page"></span><button id="risk-next">下一页</button></div>
        </div>
      </div>
      <div id="risk-list" class="risk-list"></div>
    </div></section>
    <section class="section"><div class="panel">
      <div class="section-head">
        <div><h2 class="section-title">资产报告</h2><div class="section-note">保留来源聚合，并提供分页浏览。</div></div>
        <div class="section-tools">
          <input id="asset-search" class="search-input" type="search" placeholder="检索类型、内容、来源" />
          <span id="asset-count" class="search-meta"></span>
          <div class="pagination"><button id="asset-prev">上一页</button><span id="asset-page"></span><button id="asset-next">下一页</button></div>
        </div>
      </div>
      <div id="asset-list" class="asset-list"></div>
    </div></section>
  </div>
  <script>
    const reportData = %s;
    const state = { riskPage: 1, assetPage: 1, riskQuery: '', assetQuery: '', clusterPages: {}, clusterOpen: {} };
    const escapeHtml = (value) => String(value ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    const normalizeSearch = (value) => String(value ?? '').trim().toLowerCase();
    const includesSearch = (term, ...values) => !term || values.some((value) => String(value ?? '').toLowerCase().includes(term));
    const paginate = (items, page, pageSize) => items.slice((page - 1) * pageSize, (page - 1) * pageSize + pageSize);
    const totalPages = (items, pageSize) => Math.max(1, Math.ceil((items?.length || 0) / pageSize));
    const filterRiskItems = (items, query) => {
      const term = normalizeSearch(query);
      if (!term) return items;
      return (items || []).reduce((results, item) => {
        if (item.kind === 'cluster') {
          const clusterMatches = includesSearch(
            term,
            item.label,
            item.kindLabel,
            item.level,
            item.levelLabel,
            item.confidence,
            item.confidenceLabel,
            item.summary,
            item.description,
            item.count
          );
          const matchedChildren = (item.items || []).filter((child) =>
            includesSearch(
              term,
              child.title,
              child.url,
              child.method,
              child.summary,
              child.description,
              child.request,
              child.requestPreview,
              child.response,
              child.responsePreview,
              child.createdAt
            )
          );
          if (clusterMatches || matchedChildren.length) {
            results.push(clusterMatches ? item : { ...item, items: matchedChildren });
          }
          return results;
        }
        if (
          includesSearch(
            term,
            item.title,
            item.url,
            item.method,
            item.summary,
            item.description,
            item.type,
            item.level,
            item.levelLabel,
            item.confidence,
            item.confidenceLabel,
            item.request,
            item.requestPreview,
            item.response,
            item.responsePreview,
            item.createdAt
          )
        ) {
          results.push(item);
        }
        return results;
      }, []);
    };
    const filterAssetRows = (rows, query) => {
      const term = normalizeSearch(query);
      if (!term) return rows || [];
      return (rows || []).filter((row) =>
        includesSearch(term, row.type, row.typeLabel, row.value, row.source)
      );
    };
    const renderPacketBlock = (title, content, truncated, fullContent) => {
      if (!content) return '';
      const note = truncated ? '<div style="margin-top:8px;color:#617181;font-size:12px">内容过长，默认仅展示前 %d 个字符，展开可查看全文。</div>' : '';
      const preview = '<pre>' + escapeHtml(content) + '</pre>';
      if (!truncated || !fullContent) {
        return '<details><summary>' + escapeHtml(title) + '</summary>' + note + preview + '</details>';
      }
      return '<details><summary>' + escapeHtml(title) + '</summary>' + note + preview + '<details style="margin-top:10px"><summary>展开全文</summary><pre>' + escapeHtml(fullContent) + '</pre></details></details>';
    };
    const bindClusterEvents = () => {
      document.querySelectorAll('[data-toggle-cluster]').forEach((element) => {
        element.onclick = () => {
          const id = element.getAttribute('data-toggle-cluster');
          state.clusterOpen[id] = !state.clusterOpen[id];
          if (!state.clusterPages[id]) state.clusterPages[id] = 1;
          renderRiskPage();
        };
      });
      document.querySelectorAll('[data-cluster-prev]').forEach((element) => {
        element.onclick = () => {
          const id = element.getAttribute('data-cluster-prev');
          state.clusterPages[id] = Math.max(1, (state.clusterPages[id] || 1) - 1);
          renderRiskPage();
        };
      });
      document.querySelectorAll('[data-cluster-next]').forEach((element) => {
        element.onclick = () => {
          const id = element.getAttribute('data-cluster-next');
          const cluster = (reportData.risks.items || []).find((item) => item.clusterId === id);
          const max = totalPages(cluster?.items || [], cluster?.pageSize || 20);
          state.clusterPages[id] = Math.min(max, (state.clusterPages[id] || 1) + 1);
          renderRiskPage();
        };
      });
    };
    const renderRiskPage = () => {
      const container = document.getElementById('risk-list');
      const items = filterRiskItems(reportData.risks.items || [], state.riskQuery);
      const pages = totalPages(items, reportData.risks.pageSize || 10);
      state.riskPage = Math.min(Math.max(1, state.riskPage), pages);
      const currentItems = paginate(items, state.riskPage, reportData.risks.pageSize || 10);
      document.getElementById('risk-count').textContent = '检索结果 ' + items.length + ' 条';
      document.getElementById('risk-page').textContent = '第 ' + state.riskPage + ' / ' + pages + ' 页';
      document.getElementById('risk-prev').disabled = state.riskPage <= 1;
      document.getElementById('risk-next').disabled = state.riskPage >= pages;
      if (!currentItems.length) { container.innerHTML = '<div class="empty">' + (state.riskQuery ? '没有匹配的风险结果' : '暂无风险数据') + '</div>'; return; }
      container.innerHTML = currentItems.map((item) => {
        if (item.kind === 'cluster') {
          const currentPage = state.clusterPages[item.clusterId] || 1;
          const pages = totalPages(item.items || [], item.pageSize || 20);
          const pageItems = paginate(item.items || [], currentPage, item.pageSize || 20);
          const open = Boolean(state.clusterOpen[item.clusterId]);
          return '<article class="cluster-item"><div class="head"><div><h3 class="title">' + escapeHtml(item.label) + '</h3><div class="tags"><span class="tag level-' + escapeHtml(item.level) + '">' + escapeHtml(item.levelLabel) + '</span><span class="tag confidence">' + escapeHtml(item.confidenceLabel) + '</span><span class="tag type">' + escapeHtml(item.kindLabel) + '</span><span class="tag type">命中 ' + item.count + ' 个接口</span></div></div><button data-toggle-cluster="' + escapeHtml(item.clusterId) + '">' + (open ? '收起接口' : '展开接口') + '</button></div><dl class="kv"><dt>聚合说明</dt><dd>' + escapeHtml(item.summary) + '</dd></dl><div class="cluster-items ' + (open ? 'open' : '') + '">' + pageItems.map((risk) => '<div class="cluster-row"><div class="cluster-row-title">' + escapeHtml(risk.title) + '</div><div><strong>URL:</strong> ' + escapeHtml(risk.url) + '</div><div><strong>方法:</strong> ' + escapeHtml(risk.method) + '</div><div><strong>摘要:</strong> ' + escapeHtml(risk.summary) + '</div><div><strong>描述:</strong> ' + escapeHtml(risk.description) + '</div><div><strong>发现时间:</strong> ' + escapeHtml(risk.createdAt) + '</div>' + renderPacketBlock('请求包', risk.requestPreview, risk.requestTruncated, risk.request) + renderPacketBlock('响应包', risk.responsePreview, risk.responseTruncated, risk.response) + '</div>').join('') + '<div class="pagination"><button data-cluster-prev="' + escapeHtml(item.clusterId) + '"' + (currentPage <= 1 ? ' disabled' : '') + '>上一页</button><span>第 ' + currentPage + ' / ' + pages + ' 页</span><button data-cluster-next="' + escapeHtml(item.clusterId) + '"' + (currentPage >= pages ? ' disabled' : '') + '>下一页</button></div></div></article>';
        }
        return '<article class="risk-item"><div class="head"><div><h3 class="title">' + escapeHtml(item.title) + '</h3><div class="tags"><span class="tag level-' + escapeHtml(item.level) + '">' + escapeHtml(item.levelLabel) + '</span><span class="tag confidence">' + escapeHtml(item.confidenceLabel) + '</span><span class="tag type">' + escapeHtml(item.type) + '</span>' + (item.aiVerified ? '<span class="tag ai">AI 辅助验证</span>' : '') + '</div></div></div><dl class="kv"><dt>URL</dt><dd>' + escapeHtml(item.url) + '</dd><dt>方法</dt><dd>' + escapeHtml(item.method) + '</dd><dt>摘要</dt><dd>' + escapeHtml(item.summary) + '</dd><dt>描述</dt><dd>' + escapeHtml(item.description) + '</dd><dt>发现时间</dt><dd>' + escapeHtml(item.createdAt) + '</dd></dl>' + renderPacketBlock('请求包', item.requestPreview, item.requestTruncated, item.request) + renderPacketBlock('响应包', item.responsePreview, item.responseTruncated, item.response) + '</article>';
      }).join('');
      bindClusterEvents();
    };
    const renderAssetPage = () => {
      const container = document.getElementById('asset-list');
      const rows = filterAssetRows(reportData.assets.rows || [], state.assetQuery);
      const pages = totalPages(rows, reportData.assets.pageSize || 10);
      state.assetPage = Math.min(Math.max(1, state.assetPage), pages);
      const currentRows = paginate(rows, state.assetPage, reportData.assets.pageSize || 10);
      document.getElementById('asset-count').textContent = '检索结果 ' + rows.length + ' 条';
      document.getElementById('asset-page').textContent = '第 ' + state.assetPage + ' / ' + pages + ' 页';
      document.getElementById('asset-prev').disabled = state.assetPage <= 1;
      document.getElementById('asset-next').disabled = state.assetPage >= pages;
      if (!currentRows.length) { container.innerHTML = '<div class="empty">' + (state.assetQuery ? '没有匹配的资产结果' : '暂无资产数据') + '</div>'; return; }
      container.innerHTML = '<table><thead><tr><th style="width:120px">类型</th><th>内容</th><th style="width:320px">来源</th></tr></thead><tbody>' + currentRows.map((row) => '<tr><td>' + escapeHtml(row.typeLabel) + '</td><td>' + escapeHtml(row.value) + '</td><td>' + escapeHtml(row.source || '-') + '</td></tr>').join('') + '</tbody></table>';
    };
    document.getElementById('risk-prev').onclick = () => { state.riskPage -= 1; renderRiskPage(); };
    document.getElementById('risk-next').onclick = () => { state.riskPage += 1; renderRiskPage(); };
    document.getElementById('asset-prev').onclick = () => { state.assetPage -= 1; renderAssetPage(); };
    document.getElementById('asset-next').onclick = () => { state.assetPage += 1; renderAssetPage(); };
    document.getElementById('risk-search').oninput = (event) => {
      state.riskQuery = event.target.value || '';
      state.riskPage = 1;
      state.clusterPages = {};
      renderRiskPage();
    };
    document.getElementById('asset-search').oninput = (event) => {
      state.assetQuery = event.target.value || '';
      state.assetPage = 1;
      renderAssetPage();
    };
    renderRiskPage(); renderAssetPage();
  </script>
</body>
</html>`,
		escapeStaticHTML(snapshot.Meta.TaskName),
		escapeStaticHTML(snapshot.Meta.TaskName),
		escapeStaticHTML(snapshot.Meta.TaskID),
		escapeStaticHTML(snapshot.Meta.VersionLabel),
		escapeStaticHTML(snapshot.Meta.Status),
		escapeStaticHTML(snapshot.Meta.GeneratedAt),
		renderTargets(snapshot.Meta.Targets),
		snapshot.Summary.TotalRisks,
		snapshot.Summary.HighRisks,
		snapshot.Summary.MediumRisks,
		snapshot.Summary.LowRisks,
		snapshot.Summary.InfoRisks,
		snapshot.Summary.ClusteredEntries,
		snapshot.Summary.StandaloneEntries,
		snapshot.Summary.TotalAssetRows,
		snapshot.Summary.EmailAssets,
		snapshot.Summary.PhoneAssets,
		snapshot.Summary.IDCardAssets,
		snapshot.Summary.IPURLAssets,
		snapshot.Summary.FrontendRouteAssets,
		snapshot.Summary.APIRootAssets,
		snapshot.Summary.APIRouterAssets,
		reportJSON,
		reportPacketPreview,
	), nil
}

func escapeInlineScript(value string) string {
	return strings.NewReplacer("<", "\\u003c", ">", "\\u003e").Replace(value)
}

func escapeStaticHTML(value string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return replacer.Replace(value)
}

func renderTargets(targets []string) string {
	if len(targets) == 0 {
		return `<span class="tag target-tag">-</span>`
	}

	parts := make([]string, 0, len(targets))
	for _, target := range targets {
		parts = append(parts, `<span class="tag target-tag">`+escapeStaticHTML(target)+`</span>`)
	}
	return strings.Join(parts, "")
}

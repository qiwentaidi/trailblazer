package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"
)

type staticProtocolAnalysisDocument struct {
	SchemaVersion int                           `json:"schema_version"`
	TaskID        string                        `json:"task_id"`
	Version       int                           `json:"version"`
	JSCount       int                           `json:"js_count"`
	Profiles      []crawl.StaticProtocolProfile `json:"profiles"`
	APIContexts   []crawl.StaticAPIContext      `json:"api_contexts,omitempty"`
	GeneratedAt   time.Time                     `json:"generated_at"`
}

const staticProtocolAnalysisSchemaVersion = 10

var staticContextMethodPatterns = []struct {
	method string
	regex  *regexp.Regexp
}{
	{method: http.MethodPost, regex: regexp.MustCompile(`(?i)(?:\.|["'\s])post\s*\(`)},
	{method: http.MethodPut, regex: regexp.MustCompile(`(?i)(?:\.|["'\s])put\s*\(`)},
	{method: http.MethodDelete, regex: regexp.MustCompile(`(?i)(?:\.|["'\s])delete\s*\(`)},
	{method: http.MethodPatch, regex: regexp.MustCompile(`(?i)(?:\.|["'\s])patch\s*\(`)},
	{method: http.MethodGet, regex: regexp.MustCompile(`(?i)(?:\.|["'\s])get\s*\(`)},
}

var staticContextParamPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bparams\s*:\s*\{`),
	regexp.MustCompile(`(?i)\bbody\s*:\s*\{`),
	regexp.MustCompile(`(?i)\bdata\s*:\s*\{`),
	regexp.MustCompile(`(?i)\bquery\s*:\s*\{`),
	regexp.MustCompile(`(?i)(?:post|put|patch|delete)\s*\([^)]{0,240},\s*\{`),
	regexp.MustCompile(`(?i)(?:post|put|patch|delete)\s*\([^)]{0,240},\s*[A-Za-z_$][\w$]*`),
	regexp.MustCompile(`(?i)get\s*\([^)]{0,240},\s*\{[^)]{0,240}\bparams\s*:`),
	regexp.MustCompile(`\$\{[^}]+\}`),
}

var staticContextPayloadMarkers = []struct {
	carrier string
	regex   *regexp.Regexp
}{
	{carrier: "params", regex: regexp.MustCompile(`(?i)\bparams\s*:\s*\{`)},
	{carrier: "body", regex: regexp.MustCompile(`(?i)\bbody\s*:\s*\{`)},
	{carrier: "data", regex: regexp.MustCompile(`(?i)\bdata\s*:\s*\{`)},
	{carrier: "query", regex: regexp.MustCompile(`(?i)\bquery\s*:\s*\{`)},
	{carrier: "arg", regex: regexp.MustCompile(`(?i)(?:post|put|patch|delete|get)\s*\([^)]*?,\s*\{`)},
}

var (
	staticProtocolAnalysisGroup singleflight.Group
	analyzeStoredJSProtocols    = crawl.AnalyzeStoredJSProtocols
	queryStoredStaticProtocol   = queryStoredStaticProtocolAnalysis
	saveStoredStaticProtocol    = saveStaticProtocolAnalysis
)

func buildStaticProtocolAnalysisCacheKey(taskID string, version int) string {
	if version <= 0 {
		return taskID + ":latest-pending"
	}
	return fmt.Sprintf("%s:v%d", taskID, version)
}

func resolveStaticProtocolVersion(taskID string, version *int) (int, error) {
	if version != nil {
		return *version, nil
	}

	if database.DB == nil {
		return 0, nil
	}

	latest, err := database.GetLatestTaskVersion(taskID)
	if err != nil {
		return 0, err
	}
	if latest == nil {
		return 0, nil
	}
	return latest.Version, nil
}

func queryStoredStaticProtocolAnalysis(taskID string, version int) (*crawl.StaticProtocolAnalysisResult, bool, error) {
	if database.ESClient == nil {
		return nil, false, fmt.Errorf("ES client not initialized")
	}

	must := []map[string]interface{}{
		{
			"term": map[string]interface{}{
				"task_id.keyword": taskID,
			},
		},
	}
	if version > 0 {
		must = append(must, map[string]interface{}{
			"term": map[string]interface{}{
				"version": version,
			},
		})
	}

	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": must,
			},
		},
		"size": 1,
		"sort": []map[string]interface{}{
			{"generated_at": map[string]interface{}{"order": "desc", "unmapped_type": "date", "missing": "_last"}},
		},
	}

	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(query); err != nil {
		return nil, false, err
	}

	res, err := database.ESClient.Search(
		database.ESClient.Search.WithContext(context.Background()),
		database.ESClient.Search.WithIndex(database.IndexStaticProtocolAnalysis),
		database.ESClient.Search.WithBody(&buf),
	)
	if err != nil {
		return nil, false, err
	}
	defer res.Body.Close()

	if res.IsError() {
		return nil, false, fmt.Errorf("ES error: %s", res.String())
	}

	var result struct {
		Hits struct {
			Hits []struct {
				Source staticProtocolAnalysisDocument `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		return nil, false, err
	}
	if len(result.Hits.Hits) == 0 {
		return nil, false, nil
	}

	doc := result.Hits.Hits[0].Source
	if doc.SchemaVersion < staticProtocolAnalysisSchemaVersion {
		return nil, false, nil
	}
	return &crawl.StaticProtocolAnalysisResult{
		TaskID:      doc.TaskID,
		JSCount:     doc.JSCount,
		Profiles:    doc.Profiles,
		APIContexts: doc.APIContexts,
		GeneratedAt: doc.GeneratedAt,
	}, true, nil
}

func saveStaticProtocolAnalysis(taskID string, version int, result *crawl.StaticProtocolAnalysisResult) error {
	if result == nil {
		return nil
	}
	if database.ESClient == nil {
		return fmt.Errorf("ES client not initialized")
	}

	return database.InsertToES(staticProtocolAnalysisDocument{
		SchemaVersion: staticProtocolAnalysisSchemaVersion,
		TaskID:        taskID,
		Version:       version,
		JSCount:       result.JSCount,
		Profiles:      result.Profiles,
		APIContexts:   result.APIContexts,
		GeneratedAt:   result.GeneratedAt,
	}, database.IndexStaticProtocolAnalysis, false)
}

// getTaskStaticProtocolAnalysis 基于已存 JS 做静态协议分析
func getTaskStaticProtocolAnalysis(c *gin.Context) {
	taskID := c.Param("taskId")
	version, ok := parseTaskVersionQuery(c)
	if !ok {
		return
	}

	resolvedVersion, err := resolveStaticProtocolVersion(taskID, version)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to resolve task version", "detail": err.Error()})
		return
	}

	if cached, hit, err := queryStoredStaticProtocol(taskID, resolvedVersion); err == nil && hit {
		c.JSON(200, gin.H{"data": cached, "cached": true})
		return
	} else if err != nil &&
		!strings.Contains(err.Error(), "index_not_found_exception") &&
		!strings.Contains(err.Error(), "ES client not initialized") &&
		!strings.Contains(err.Error(), "connection") {
		c.JSON(500, gin.H{"error": "failed to query stored static protocol analysis", "detail": err.Error()})
		return
	}

	cacheKey := buildStaticProtocolAnalysisCacheKey(taskID, resolvedVersion)
	computed, err, _ := staticProtocolAnalysisGroup.Do(cacheKey, func() (interface{}, error) {
		if cached, hit, err := queryStoredStaticProtocol(taskID, resolvedVersion); err == nil && hit {
			return cached, nil
		} else if err != nil &&
			!strings.Contains(err.Error(), "index_not_found_exception") &&
			!strings.Contains(err.Error(), "ES client not initialized") &&
			!strings.Contains(err.Error(), "connection") {
			return nil, err
		}

		result, err := analyzeStoredJSProtocols(taskID, versionArgs(version)...)
		if err != nil {
			return nil, err
		}
		enrichStaticProtocolAPIContexts(taskID, resolvedVersion, result)
		if err := saveStoredStaticProtocol(taskID, resolvedVersion, result); err != nil &&
			!strings.Contains(err.Error(), "ES client not initialized") &&
			!strings.Contains(err.Error(), "index_not_found_exception") &&
			!strings.Contains(err.Error(), "connection") {
			return nil, err
		}
		return result, nil
	})
	if err != nil {
		if strings.Contains(err.Error(), "index_not_found_exception") ||
			strings.Contains(err.Error(), "ES client not initialized") ||
			strings.Contains(err.Error(), "connection") {
			c.JSON(200, gin.H{"data": gin.H{
				"task_id":      taskID,
				"js_count":     0,
				"profiles":     []interface{}{},
				"api_contexts": []interface{}{},
				"generated_at": nil,
			}})
			return
		}
		c.JSON(500, gin.H{"error": "failed to analyze stored JS", "detail": err.Error()})
		return
	}

	result, _ := computed.(*crawl.StaticProtocolAnalysisResult)
	c.JSON(200, gin.H{"data": result, "cached": false})
}

func enrichStaticProtocolAPIContexts(taskID string, version int, result *crawl.StaticProtocolAnalysisResult) {
	if result == nil {
		return
	}

	jsResources, err := database.QueryJSByTaskID(taskID, version)
	if err != nil || len(jsResources) == 0 {
		return
	}

	assets, err := database.QueryAssetsByTaskID(taskID, version)
	if err != nil || assets == nil || len(assets.APIRouter) == 0 {
		return
	}

	existing := make([]crawl.StaticAPIContext, 0, len(result.APIContexts)+len(assets.APIRouter))
	existing = append(existing, result.APIContexts...)
	result.APIContexts = mergeStaticAPIContexts(existing, buildStaticAPIContextsFromAssets(assets.APIRouter, jsResources))
}

func buildStaticAPIContextsFromAssets(routes []database.AssetValue, jsResources []database.JSResource) []crawl.StaticAPIContext {
	if len(routes) == 0 || len(jsResources) == 0 {
		return nil
	}

	contexts := make([]crawl.StaticAPIContext, 0, minInt(len(routes), 64))
	seen := make(map[string]struct{})
	for _, route := range routes {
		routeValue := strings.TrimSpace(route.Value)
		needles := buildStaticContextNeedles(routeValue)
		if len(needles) == 0 {
			continue
		}

		for _, resource := range jsResources {
			content := strings.TrimSpace(resource.Content)
			if content == "" {
				continue
			}

			snippet := buildStaticContextSnippet(content, needles)
			if snippet == "" {
				continue
			}

			key := routeValue + "|" + resource.URL + "|" + snippet
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			contexts = append(contexts, crawl.StaticAPIContext{
				URL:        routeValue,
				Method:     inferStaticContextMethod(snippet),
				SourceFile: strings.TrimSpace(resource.URL),
				Snippet:    snippet,
			})
			enrichStaticContextPayload(&contexts[len(contexts)-1])
			if !staticContextRequiresRequestParams(contexts[len(contexts)-1]) {
				contexts = contexts[:len(contexts)-1]
				continue
			}
			if len(contexts) >= 64 {
				return contexts
			}
		}
	}

	return contexts
}

func mergeStaticAPIContexts(base, extra []crawl.StaticAPIContext) []crawl.StaticAPIContext {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}

	merged := make([]crawl.StaticAPIContext, 0, len(base)+len(extra))
	seen := make(map[string]int, len(base)+len(extra))
	appendContext := func(item crawl.StaticAPIContext) {
		item.URL = strings.TrimSpace(item.URL)
		item.Method = normalizeStaticContextMethod(item.Method)
		item.SourceFile = strings.TrimSpace(item.SourceFile)
		item.Snippet = strings.TrimSpace(item.Snippet)
		if item.URL == "" || item.SourceFile == "" || item.Snippet == "" {
			return
		}
		enrichStaticContextPayload(&item)
		if !staticContextRequiresRequestParams(item) {
			return
		}

		key := item.Method + "|" + canonicalizeStaticContextURL(item.URL) + "|" + item.SourceFile + "|" + strings.TrimSpace(item.ParamPreview)
		if index, exists := seen[key]; exists {
			if merged[index].TraceID == "" && item.TraceID != "" {
				merged[index].TraceID = item.TraceID
			}
			if !merged[index].HasProtocolTrace && item.HasProtocolTrace {
				merged[index].HasProtocolTrace = true
			}
			if len(merged[index].RequestHeaders) == 0 && len(item.RequestHeaders) > 0 {
				merged[index].RequestHeaders = item.RequestHeaders
			}
			if merged[index].RequestBody == "" && item.RequestBody != "" {
				merged[index].RequestBody = item.RequestBody
			}
			if merged[index].URL != item.URL {
				merged[index].URL = choosePreferredStaticContextURL(merged[index].URL, item.URL)
			}
			return
		}

		seen[key] = len(merged)
		merged = append(merged, item)
	}

	for _, item := range base {
		appendContext(item)
	}
	for _, item := range extra {
		appendContext(item)
	}

	sort.SliceStable(merged, func(i, j int) bool {
		if merged[i].URL == merged[j].URL {
			if merged[i].Method == merged[j].Method {
				return merged[i].SourceFile < merged[j].SourceFile
			}
			return merged[i].Method < merged[j].Method
		}
		return merged[i].URL < merged[j].URL
	})
	return merged
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

func buildStaticContextSnippet(content string, needles []string) string {
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

func normalizeStaticContextMethod(method string) string {
	normalized := strings.ToUpper(strings.TrimSpace(method))
	if normalized == "" {
		return http.MethodGet
	}
	return normalized
}

func canonicalizeStaticContextURL(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func choosePreferredStaticContextURL(current, candidate string) string {
	current = strings.TrimSpace(current)
	candidate = strings.TrimSpace(candidate)
	if current == "" {
		return candidate
	}
	if candidate == "" {
		return current
	}
	if current == candidate {
		return current
	}
	if strings.EqualFold(current, candidate) {
		if candidate == strings.ToLower(candidate) && current != strings.ToLower(current) {
			return candidate
		}
		return current
	}
	return current
}

func inferStaticContextMethod(snippet string) string {
	normalized := strings.TrimSpace(snippet)
	if normalized == "" {
		return http.MethodGet
	}

	for _, pattern := range staticContextMethodPatterns {
		if pattern.regex.MatchString(normalized) {
			return pattern.method
		}
	}
	return http.MethodGet
}

func enrichStaticContextPayload(item *crawl.StaticAPIContext) {
	if item == nil {
		return
	}

	if strings.TrimSpace(item.RequestBody) != "" {
		item.ParamCarrier = "runtime_body"
		item.ParamPreview = strings.TrimSpace(item.RequestBody)
		if len(item.Params) == 0 {
			item.Params = parseStaticContextParams(item.ParamPreview)
		}
		if item.ParamPreview != "" || len(item.Params) > 0 {
			return
		}
	}

	focused := strings.TrimSpace(focusStaticContextSnippet(item.Snippet, item.URL))
	if focused == "" {
		return
	}

	carrier, payload := extractStaticContextPayload(focused, item.URL)
	if payload == "" {
		return
	}

	item.ParamCarrier = carrier
	item.ParamPreview = payload
	if len(item.Params) == 0 {
		item.Params = parseStaticContextParams(payload)
	}
}

func staticContextRequiresRequestParams(item crawl.StaticAPIContext) bool {
	if strings.TrimSpace(item.RequestBody) != "" {
		return true
	}

	snippet := strings.TrimSpace(focusStaticContextSnippet(item.Snippet, item.URL))
	if snippet == "" {
		return false
	}

	if strings.Contains(snippet, "?") && strings.Contains(snippet, "=") {
		return true
	}

	for _, pattern := range staticContextParamPatterns {
		if pattern.MatchString(snippet) {
			return true
		}
	}

	return false
}

func extractStaticContextPayload(snippet, rawURL string) (string, string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL != "" {
		lowerSnippet := strings.ToLower(snippet)
		lowerURL := strings.ToLower(rawURL)
		if index := strings.Index(lowerSnippet, lowerURL); index >= 0 {
			tailStart := minInt(len(snippet), index+len(rawURL))
			tail := snippet[tailStart:]
			if carrier, payload := extractStaticContextPayloadFromTail(tail); payload != "" {
				return carrier, payload
			}
		}
	}

	for _, marker := range staticContextPayloadMarkers {
		location := marker.regex.FindStringIndex(snippet)
		if len(location) != 2 {
			continue
		}

		start := strings.Index(snippet[location[0]:location[1]], "{")
		if start < 0 {
			continue
		}
		payload := extractBalancedObject(snippet, location[0]+start)
		if payload != "" {
			return marker.carrier, payload
		}
	}

	return "", ""
}

func extractStaticContextPayloadFromTail(tail string) (string, string) {
	tail = strings.TrimSpace(tail)
	if tail == "" {
		return "", ""
	}

	if markerIndex := strings.Index(strings.ToLower(tail), "params:{"); markerIndex >= 0 {
		start := strings.Index(tail[markerIndex:], "{")
		if start >= 0 {
			payload := extractBalancedObject(tail, markerIndex+start)
			if payload != "" {
				return "params", payload
			}
		}
	}

	for _, marker := range []string{"body:{", "data:{", "query:{"} {
		if markerIndex := strings.Index(strings.ToLower(tail), marker); markerIndex >= 0 {
			start := strings.Index(tail[markerIndex:], "{")
			if start >= 0 {
				payload := extractBalancedObject(tail, markerIndex+start)
				if payload != "" {
					return strings.TrimSuffix(marker, ":{"), payload
				}
			}
		}
	}

	if openIndex := strings.Index(tail, "{"); openIndex >= 0 {
		payload := extractBalancedObject(tail, openIndex)
		if payload != "" {
			return "arg", payload
		}
	}

	return "", ""
}

func extractBalancedObject(text string, start int) string {
	if start < 0 || start >= len(text) || text[start] != '{' {
		return ""
	}

	depth := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	escaped := false
	for index := start; index < len(text); index++ {
		ch := text[index]
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' && (inSingle || inDouble || inTemplate) {
			escaped = true
			continue
		}

		switch ch {
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '{':
			if !inSingle && !inDouble && !inTemplate {
				depth++
			}
		case '}':
			if !inSingle && !inDouble && !inTemplate {
				depth--
				if depth == 0 {
					return strings.TrimSpace(text[start : index+1])
				}
			}
		}
	}

	return ""
}

func parseStaticContextParams(payload string) []crawl.StaticAPIContextParam {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return nil
	}

	if strings.HasPrefix(payload, "{") && strings.HasSuffix(payload, "}") {
		payload = strings.TrimSpace(payload[1 : len(payload)-1])
	}
	if payload == "" {
		return nil
	}

	parts := splitStaticContextTopLevel(payload, ',')
	params := make([]crawl.StaticAPIContextParam, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value := splitStaticContextField(part)
		if name == "" {
			continue
		}
		params = append(params, crawl.StaticAPIContextParam{
			Name:  name,
			Value: value,
		})
	}
	return params
}

func splitStaticContextField(part string) (string, string) {
	fieldParts := splitStaticContextTopLevel(part, ':')
	if len(fieldParts) == 0 {
		return "", ""
	}
	if len(fieldParts) == 1 {
		name := normalizeStaticContextFieldName(fieldParts[0])
		return name, ""
	}

	name := normalizeStaticContextFieldName(fieldParts[0])
	if name == "" {
		return "", ""
	}
	value := strings.TrimSpace(strings.Join(fieldParts[1:], ":"))
	return name, value
}

func normalizeStaticContextFieldName(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, `"'`)
	return strings.TrimSpace(raw)
}

func splitStaticContextTopLevel(text string, separator rune) []string {
	result := make([]string, 0, 8)
	start := 0
	braceDepth := 0
	bracketDepth := 0
	parenDepth := 0
	inSingle := false
	inDouble := false
	inTemplate := false
	escaped := false

	for index, char := range text {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' && (inSingle || inDouble || inTemplate) {
			escaped = true
			continue
		}

		switch char {
		case '\'':
			if !inDouble && !inTemplate {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle && !inTemplate {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inTemplate = !inTemplate
			}
		case '{':
			if !inSingle && !inDouble && !inTemplate {
				braceDepth++
			}
		case '}':
			if !inSingle && !inDouble && !inTemplate && braceDepth > 0 {
				braceDepth--
			}
		case '[':
			if !inSingle && !inDouble && !inTemplate {
				bracketDepth++
			}
		case ']':
			if !inSingle && !inDouble && !inTemplate && bracketDepth > 0 {
				bracketDepth--
			}
		case '(':
			if !inSingle && !inDouble && !inTemplate {
				parenDepth++
			}
		case ')':
			if !inSingle && !inDouble && !inTemplate && parenDepth > 0 {
				parenDepth--
			}
		default:
			if char == separator &&
				!inSingle && !inDouble && !inTemplate &&
				braceDepth == 0 && bracketDepth == 0 && parenDepth == 0 {
				result = append(result, text[start:index])
				start = index + 1
			}
		}
	}

	result = append(result, text[start:])
	return result
}

func focusStaticContextSnippet(snippet, rawURL string) string {
	snippet = strings.TrimSpace(snippet)
	rawURL = strings.TrimSpace(rawURL)
	if snippet == "" || rawURL == "" {
		return snippet
	}

	index := strings.Index(strings.ToLower(snippet), strings.ToLower(rawURL))
	if index < 0 {
		return snippet
	}

	start := maxInt(0, index-32)
	searchStart := maxInt(0, index-160)
	lowerSnippet := strings.ToLower(snippet)
	lowerWindow := lowerSnippet[searchStart:index]
	for _, marker := range []string{"get(", "post(", "put(", "patch(", "delete(", "fetch(", "request("} {
		if offset := strings.LastIndex(lowerWindow, marker); offset >= 0 {
			start = searchStart + offset
			break
		}
	}
	if boundary := strings.LastIndexAny(snippet[:index], ";\n"); boundary >= 0 {
		start = maxInt(start, boundary+1)
	}

	end := minInt(len(snippet), index+len(rawURL)+220)
	if suffix := snippet[index+len(rawURL):]; suffix != "" {
		if boundary := strings.Index(suffix, ")"); boundary >= 0 {
			end = minInt(end, index+len(rawURL)+boundary+1)
		}
	}
	if suffix := snippet[index+len(rawURL):]; suffix != "" {
		if boundary := strings.IndexAny(suffix, ";\n"); boundary >= 0 {
			end = minInt(end, index+len(rawURL)+boundary+1)
		}
	}
	return snippet[start:end]
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

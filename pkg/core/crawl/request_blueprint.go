package crawl

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
)

type RequestBlueprintSource struct {
	File    string `json:"file,omitempty"`
	Snippet string `json:"snippet,omitempty"`
}

type RequestBlueprintParam struct {
	Name         string `json:"name"`
	Location     string `json:"location,omitempty"`
	Source       string `json:"source,omitempty"`
	Value        string `json:"value,omitempty"`
	ValueExpr    string `json:"valueExpr,omitempty"`
	Resolved     bool   `json:"resolved"`
	ResolvedFrom string `json:"resolvedFrom,omitempty"`
	Confidence   string `json:"confidence,omitempty"`
}

type RequestBlueprintHeader struct {
	Name    string `json:"name"`
	Value   string `json:"value,omitempty"`
	Source  string `json:"source,omitempty"`
	Dynamic bool   `json:"dynamic,omitempty"`
}

type RequestBlueprintInterceptor struct {
	Client  string   `json:"client,omitempty"`
	Kind    string   `json:"kind"`
	Mutates []string `json:"mutates,omitempty"`
	Snippet string   `json:"snippet,omitempty"`
}

type RequestBlueprint struct {
	ID                    string                        `json:"id"`
	Path                  string                        `json:"path"`
	Method                string                        `json:"method"`
	Client                string                        `json:"client,omitempty"`
	BaseURL               string                        `json:"baseUrl,omitempty"`
	Params                []RequestBlueprintParam       `json:"params,omitempty"`
	Headers               []RequestBlueprintHeader      `json:"headers,omitempty"`
	PayloadCarrier        string                        `json:"payloadCarrier,omitempty"`
	PayloadFormat         string                        `json:"payloadFormat,omitempty"`
	PayloadPreview        string                        `json:"payloadPreview,omitempty"`
	Interceptors          []RequestBlueprintInterceptor `json:"interceptors,omitempty"`
	Context               []string                      `json:"context,omitempty"`
	UnresolvedSymbols     []string                      `json:"unresolvedSymbols,omitempty"`
	Source                RequestBlueprintSource        `json:"source,omitempty"`
	Confidence            string                        `json:"confidence"`
	ConfidenceReason      string                        `json:"confidenceReason,omitempty"`
	ExtractionSource      string                        `json:"extractionSource"`
	CompatibleAPIRequests int                           `json:"compatibleApiRequests,omitempty"`
}

type axiosBlueprintContext struct {
	Name         string
	BaseURL      string
	Headers      []RequestBlueprintHeader
	Interceptors []RequestBlueprintInterceptor
}

type axiosLikeCreateCall struct {
	InstanceName string
	FactoryName  string
	Args         string
	Fields       map[string]string
}

type jsRequestSymbolDefinition struct {
	Name      string
	Kind      string
	Value     string
	ValueExpr string
	Fields    []string
}

type jsRequestSymbolIndex struct {
	content     string
	definitions map[string]jsRequestSymbolDefinition
	callsites   map[string][]callExpression
}

// BuildJSRequestBlueprints extracts request construction blueprints from saved
// JavaScript resources. It is intentionally read-only: callers can compare
// request construction coverage without creating or modifying vulnerability
// findings.
func BuildJSRequestBlueprints(jsResources []database.JSResource) []RequestBlueprint {
	blueprints := make([]RequestBlueprint, 0, len(jsResources)*4)
	resolverContent := buildRequestBlueprintResolverContent(jsResources)
	for _, resource := range jsResources {
		content := strings.TrimSpace(resource.Content)
		if content == "" {
			continue
		}
		if !shouldAnalyzeJSRequestBlueprintContent(resource.URL, content) {
			continue
		}

		axiosContexts := extractAxiosBlueprintContexts(resource.URL, content)
		endpoints := extractHTTPContextEndpointsWithScope(resource.URL, content, resolverContent)
		symbolIndex := buildJSRequestSymbolIndex(buildRequestBlueprintSymbolScope(content, resolverContent), endpoints)
		for _, endpoint := range endpoints {
			blueprint := requestBlueprintFromStaticEndpoint(endpoint, axiosContexts, symbolIndex)
			if strings.TrimSpace(blueprint.Path) == "" || strings.TrimSpace(blueprint.Method) == "" {
				continue
			}
			blueprints = append(blueprints, blueprint)
		}
	}
	return dedupeRequestBlueprints(blueprints)
}

func buildRequestBlueprintSymbolScope(content, resolverContent string) string {
	content = strings.TrimSpace(content)
	resolverContent = strings.TrimSpace(resolverContent)
	if resolverContent == "" || resolverContent == content {
		return content
	}
	if content == "" {
		return resolverContent
	}
	return content + "\n" + resolverContent
}

func buildRequestBlueprintResolverContent(jsResources []database.JSResource) string {
	if len(jsResources) == 0 {
		return ""
	}
	const maxResolverContentBytes = 900 * 1024
	var builder strings.Builder
	for _, resource := range jsResources {
		content := strings.TrimSpace(resource.Content)
		if content == "" {
			continue
		}
		if !shouldIncludeJSRequestResolverContent(resource.URL, content) {
			continue
		}
		if builder.Len()+len(content) > maxResolverContentBytes {
			continue
		}
		if builder.Len() > 0 {
			builder.WriteByte('\n')
		}
		builder.WriteString(content)
	}
	return builder.String()
}

func shouldAnalyzeJSRequestBlueprintContent(resourceURL, content string) bool {
	if !containsJSRequestConstructionMarker(content) {
		return false
	}
	if len(content) <= 700*1024 {
		return true
	}
	if isLikelyLargeSharedJSBundle(resourceURL) {
		return false
	}
	lowerURL := strings.ToLower(strings.TrimSpace(resourceURL))
	if strings.Contains(lowerURL, "vendor") || strings.Contains(lowerURL, "common") {
		return containsBusinessRequestPathMarker(content)
	}
	return true
}

func shouldIncludeJSRequestResolverContent(resourceURL, content string) bool {
	if len(content) <= 700*1024 {
		return containsJSRequestConstructionMarker(content) || strings.Contains(content, ".d(") || containsBusinessRequestPathMarker(content)
	}
	if isLikelyLargeSharedJSBundle(resourceURL) {
		return false
	}
	lowerURL := strings.ToLower(strings.TrimSpace(resourceURL))
	if strings.Contains(lowerURL, "vendor") || strings.Contains(lowerURL, "common") {
		return containsBusinessRequestPathMarker(content)
	}
	return containsBusinessRequestPathMarker(content)
}

func isLikelyLargeSharedJSBundle(resourceURL string) bool {
	name := strings.ToLower(strings.TrimSpace(resourceURL))
	if slash := strings.LastIndex(name, "/"); slash >= 0 {
		name = name[slash+1:]
	}
	return strings.HasPrefix(name, "vendor.") || strings.HasPrefix(name, "common.") ||
		strings.Contains(name, "vendor.") || strings.Contains(name, "common.")
}

func containsJSRequestConstructionMarker(content string) bool {
	for _, marker := range []string{
		"axios", "fetch(", "$.ajax", "jQuery.ajax", "uni.request", "postRequest",
		"Object(", "url:", "url :", "method:", "type:",
		".get(", ".post(", ".put(", ".delete(", ".patch(",
	} {
		if strings.Contains(content, marker) {
			return true
		}
	}
	return false
}

func containsBusinessRequestPathMarker(content string) bool {
	lowerContent := strings.ToLower(content)
	if strings.Contains(lowerContent, "://") && strings.Contains(lowerContent, "/api") {
		return true
	}
	for _, marker := range []string{
		`"/api`, `'/api`, "`/api", `"/admin`, `'/admin`, `"/user`, `'/user`,
		`"/taxi-saas`, `'/taxi-saas`, `"/ccat`, `'/ccat`, `url:`, "url :",
	} {
		if strings.Contains(content, marker) {
			return true
		}
	}
	return false
}

func requestBlueprintFromStaticEndpoint(endpoint StaticProtocolEndpoint, axiosContexts map[string]axiosBlueprintContext, symbols jsRequestSymbolIndex) RequestBlueprint {
	method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
	if method == "" {
		method = "GET"
	}

	blueprint := RequestBlueprint{
		Path:             strings.TrimSpace(endpoint.Path),
		Method:           method,
		Client:           strings.TrimSpace(endpoint.Client),
		Params:           requestBlueprintParams(endpoint.Params, endpoint.RequestPayloadCarrier, endpoint.RequestPayloadFormat, endpoint.Context, symbols),
		PayloadCarrier:   strings.TrimSpace(endpoint.RequestPayloadCarrier),
		PayloadFormat:    strings.TrimSpace(endpoint.RequestPayloadFormat),
		PayloadPreview:   strings.TrimSpace(endpoint.RequestPayloadPreview),
		Context:          append([]string(nil), endpoint.Context...),
		Source:           RequestBlueprintSource{File: strings.TrimSpace(endpoint.SourceFile), Snippet: strings.TrimSpace(endpoint.Snippet)},
		ExtractionSource: "js-static-callgraph",
	}

	if context, ok := matchAxiosBlueprintContext(blueprint.Client, axiosContexts); ok {
		blueprint.BaseURL = context.BaseURL
		blueprint.Headers = mergeRequestBlueprintHeaders(blueprint.Headers, context.Headers)
		blueprint.Interceptors = append(blueprint.Interceptors, context.Interceptors...)
	}
	blueprint.Headers = mergeRequestBlueprintHeaders(blueprint.Headers, requestBlueprintHeadersFromContext(endpoint.Context))
	blueprint = enrichRequestBlueprintFromCallsites(blueprint, symbols)
	blueprint.UnresolvedSymbols = collectRequestBlueprintUnresolvedSymbols(blueprint.Path, blueprint.Params)

	blueprint.Confidence, blueprint.ConfidenceReason = assessRequestBlueprintConfidence(blueprint)
	blueprint.ID = buildRequestBlueprintID(blueprint)
	blueprint.CompatibleAPIRequests = 1
	return blueprint
}

func enrichRequestBlueprintFromCallsites(blueprint RequestBlueprint, symbols jsRequestSymbolIndex) RequestBlueprint {
	functionName := requestBlueprintFunctionNameFromContext(blueprint.Context)
	if functionName == "" || strings.TrimSpace(symbols.content) == "" {
		return blueprint
	}

	dataVariables := requestBlueprintDataVariablesFromContext(blueprint.Context)
	if len(dataVariables) == 0 {
		return blueprint
	}
	functionParams := requestBlueprintFunctionParamsFromContext(blueprint.Context)
	inferred := make([]RequestBlueprintParam, 0, 4)
	for _, dataVariable := range dataVariables {
		if _, ok := functionParams[dataVariable]; !ok {
			continue
		}
		inferred = append(inferred, inferRequestBlueprintParamsFromFunctionCallsites(symbols.content, symbols.callsites[functionName], dataVariable, blueprint.PayloadCarrier, blueprint.PayloadFormat)...)
	}
	if len(inferred) == 0 {
		return blueprint
	}

	blueprint.Params = replaceRequestBlueprintBodyParams(blueprint.Params, inferred)
	if preview := buildRequestBlueprintObjectPreview(inferred); preview != "" {
		blueprint.PayloadPreview = preview
	}
	if strings.TrimSpace(blueprint.PayloadCarrier) == "" {
		blueprint.PayloadCarrier = "body"
	}
	if format := strings.ToLower(strings.TrimSpace(blueprint.PayloadFormat)); format == "" || format == "unknown" {
		blueprint.PayloadFormat = "json"
		for index := range blueprint.Params {
			if blueprint.Params[index].Location == "body" {
				blueprint.Params[index].Location = "json"
			}
		}
	}
	blueprint.Context = appendUniqueStrings(blueprint.Context, "调用点实参: "+functionName+"("+blueprint.PayloadPreview+")")
	return blueprint
}

func requestBlueprintFunctionNameFromContext(context []string) string {
	for _, item := range context {
		item = strings.TrimSpace(item)
		if !strings.HasPrefix(item, "函数:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(item, "函数:"))
		if identifierPattern.MatchString(name) {
			return name
		}
	}
	return ""
}

func requestBlueprintDataVariablesFromContext(context []string) []string {
	result := make([]string, 0, 2)
	for _, item := range context {
		item = strings.TrimSpace(item)
		if !strings.HasPrefix(item, "数据变量:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(item, "数据变量:"))
		if identifierPattern.MatchString(name) {
			result = appendUniqueStrings(result, name)
		}
	}
	return result
}

func inferRequestBlueprintParamsFromFunctionCallsites(content string, matches []callExpression, dataVariable, carrier, format string) []RequestBlueprintParam {
	params := make([]RequestBlueprintParam, 0, len(matches))
	for _, match := range matches {
		if isLikelyFunctionDeclarationCallsite(content, match.Index) {
			continue
		}
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}
		fields := extractTopLevelObjectFields(resolveStaticArgumentExpression(content, args[0]))
		if len(fields) == 0 {
			continue
		}
		for name, expr := range fields {
			if strings.TrimSpace(name) == "" {
				continue
			}
			param := RequestBlueprintParam{
				Name:         name,
				Location:     requestBlueprintParamLocation("body", carrier, format),
				Source:       "callsite-body",
				ValueExpr:    strings.TrimSpace(expr),
				Resolved:     true,
				ResolvedFrom: "callsite-object-field:" + dataVariable,
				Confidence:   "high",
			}
			param = resolveRequestBlueprintParam(param, nil, jsRequestSymbolIndex{content: content, definitions: map[string]jsRequestSymbolDefinition{}})
			params = appendRequestBlueprintParam(params, param)
		}
	}
	sort.SliceStable(params, func(i, j int) bool {
		return params[i].Name < params[j].Name
	})
	return params
}

func isLikelyFunctionDeclarationCallsite(content string, index int) bool {
	start := index - len("function ")
	return start >= 0 && content[start:index] == "function "
}

func replaceRequestBlueprintBodyParams(current, inferred []RequestBlueprintParam) []RequestBlueprintParam {
	result := make([]RequestBlueprintParam, 0, len(current)+len(inferred))
	for _, param := range current {
		switch strings.ToLower(strings.TrimSpace(param.Location)) {
		case "json", "body":
			continue
		default:
			result = appendRequestBlueprintParam(result, param)
		}
	}
	for _, param := range inferred {
		result = appendRequestBlueprintParam(result, param)
	}
	return result
}

func buildRequestBlueprintObjectPreview(params []RequestBlueprintParam) string {
	fields := make([]string, 0, len(params))
	for _, param := range params {
		name := strings.TrimSpace(param.Name)
		if name == "" {
			continue
		}
		expr := strings.TrimSpace(firstNonEmpty(param.ValueExpr, param.Value))
		if expr == "" {
			expr = "undefined"
		}
		fields = append(fields, name+":"+expr)
	}
	sort.Strings(fields)
	if len(fields) == 0 {
		return ""
	}
	return "{" + strings.Join(fields, ",") + "}"
}

func requestBlueprintParams(params []StaticProtocolParam, carrier, format string, context []string, symbols jsRequestSymbolIndex) []RequestBlueprintParam {
	result := make([]RequestBlueprintParam, 0, len(params))
	functionParams := requestBlueprintFunctionParamsFromContext(context)
	for _, param := range params {
		name := strings.TrimSpace(param.Name)
		if name == "" {
			continue
		}
		source := strings.TrimSpace(param.Source)
		blueprintParam := RequestBlueprintParam{
			Name:       name,
			Location:   requestBlueprintParamLocation(source, carrier, format),
			Source:     source,
			Value:      strings.TrimSpace(param.Value),
			ValueExpr:  strings.TrimSpace(param.ValueExpr),
			Resolved:   param.Resolved,
			Confidence: requestBlueprintParamConfidence(source),
		}
		if blueprintParam.ValueExpr == "" && source == "variable" {
			blueprintParam.ValueExpr = name
		}
		blueprintParam = resolveRequestBlueprintParam(blueprintParam, functionParams, symbols)
		result = append(result, blueprintParam)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Location == result[j].Location {
			return result[i].Name < result[j].Name
		}
		return result[i].Location < result[j].Location
	})
	return result
}

func requestBlueprintParamLocation(source, carrier, format string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	carrier = strings.ToLower(strings.TrimSpace(carrier))
	format = strings.ToLower(strings.TrimSpace(format))
	switch {
	case strings.HasPrefix(source, "path"):
		return "path"
	case strings.HasPrefix(source, "query"):
		return "query"
	case carrier == "params" || format == "query":
		return "query"
	case strings.Contains(source, "body"):
		if format == "json" {
			return "json"
		}
		return "body"
	case source == "variable":
		if carrier == "body" || carrier == "data" {
			if format == "json" {
				return "json"
			}
			return "body"
		}
		if carrier == "params" || format == "query" {
			return "query"
		}
		return "unknown"
	default:
		if carrier == "body" || carrier == "data" {
			if format == "json" {
				return "json"
			}
			return "body"
		}
		if carrier == "params" || format == "query" {
			return "query"
		}
		return ""
	}
}

func requestBlueprintParamConfidence(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "variable" || source == "" {
		return "medium"
	}
	return "high"
}

func resolveRequestBlueprintParam(param RequestBlueprintParam, functionParams map[string]struct{}, symbols jsRequestSymbolIndex) RequestBlueprintParam {
	expr := strings.TrimSpace(param.ValueExpr)
	if strings.TrimSpace(param.Value) != "" {
		param.Resolved = true
		if param.ResolvedFrom == "" {
			param.ResolvedFrom = "static-value"
		}
		return param
	}
	if expr == "" {
		if param.Source == "path" || param.Source == "query" {
			param.Resolved = true
			param.ResolvedFrom = "static-" + param.Source
		}
		return param
	}

	if literal := parseStaticStringLikeValue(symbols.content, expr); literal != "" {
		param.Value = literal
		param.Resolved = true
		param.ResolvedFrom = "literal"
		return param
	}
	if strings.HasPrefix(expr, "`") && strings.HasSuffix(expr, "`") {
		param.Value = strings.Trim(expr, "`")
		param.Resolved = true
		param.ResolvedFrom = "literal"
		return param
	}
	switch strings.ToLower(expr) {
	case "true", "false", "null":
		param.Value = expr
		param.Resolved = true
		param.ResolvedFrom = "literal"
		return param
	}
	if json.Valid([]byte(expr)) {
		param.Value = expr
		param.Resolved = true
		param.ResolvedFrom = "literal"
		return param
	}
	if _, err := strconv.ParseFloat(expr, 64); err == nil {
		param.Value = expr
		param.Resolved = true
		param.ResolvedFrom = "literal"
		return param
	}

	if identifierPattern.MatchString(expr) {
		if definition, ok := symbols.definitions[expr]; ok {
			param.Resolved = true
			param.ResolvedFrom = "symbol:" + definition.Kind
			if definition.Value != "" {
				param.Value = definition.Value
			}
			return param
		}
		if _, ok := functionParams[expr]; ok {
			param.Resolved = true
			param.ResolvedFrom = "function-parameter"
			return param
		}
		return param
	}

	for _, identifier := range extractRequestBlueprintIdentifiers(expr) {
		if _, ok := symbols.definitions[identifier]; ok {
			param.Resolved = true
			if param.ResolvedFrom == "" {
				param.ResolvedFrom = "expression-symbol"
			}
			continue
		}
		if _, ok := functionParams[identifier]; ok {
			param.Resolved = true
			if param.ResolvedFrom == "" {
				param.ResolvedFrom = "expression-function-parameter"
			}
		}
	}
	return param
}

func collectRequestBlueprintUnresolvedSymbols(path string, params []RequestBlueprintParam) []string {
	result := make([]string, 0, 4)
	for _, match := range regexp.MustCompile(`\{([^{}]+)\}`).FindAllStringSubmatch(path, -1) {
		if len(match) < 2 {
			continue
		}
		for _, identifier := range extractRequestBlueprintIdentifiers(match[1]) {
			result = appendUniqueStrings(result, identifier)
		}
	}
	for _, param := range params {
		if param.Resolved {
			continue
		}
		for _, identifier := range extractRequestBlueprintIdentifiers(firstNonEmpty(param.ValueExpr, param.Name)) {
			result = appendUniqueStrings(result, identifier)
		}
	}
	sort.Strings(result)
	return result
}

func requestBlueprintFunctionParamsFromContext(context []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, item := range context {
		item = strings.TrimSpace(item)
		for _, prefix := range []string{"函数参数:", "封装形参:"} {
			if !strings.HasPrefix(item, prefix) {
				continue
			}
			raw := strings.TrimSpace(strings.TrimPrefix(item, prefix))
			for _, part := range strings.Split(raw, ",") {
				name := strings.TrimSpace(part)
				if identifierPattern.MatchString(name) {
					result[name] = struct{}{}
				}
			}
		}
	}
	return result
}

func extractRequestBlueprintIdentifiers(expr string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	pattern := regexp.MustCompile(`[A-Za-z_$][\w$]*`)
	matches := pattern.FindAllString(expr, -1)
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		if isRequestBlueprintKeyword(match) {
			continue
		}
		result = appendUniqueStrings(result, match)
	}
	return result
}

func isRequestBlueprintKeyword(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "false", "null", "undefined", "return", "function",
		"json", "stringify", "encodeuricomponent", "object", "array",
		"window", "document", "localstorage", "sessionstorage":
		return true
	default:
		return false
	}
}

func assessRequestBlueprintConfidence(blueprint RequestBlueprint) (string, string) {
	if strings.TrimSpace(blueprint.Path) == "" {
		return "low", "missing request path"
	}
	if strings.TrimSpace(blueprint.Method) == "" {
		return "low", "missing request method"
	}
	if strings.TrimSpace(blueprint.PayloadPreview) != "" || len(blueprint.Params) > 0 || len(blueprint.Headers) > 0 {
		return "high", "method, path, and request shape hints were extracted from JavaScript call context"
	}
	return "medium", "method and path were extracted, but request shape is sparse"
}

func buildRequestBlueprintID(blueprint RequestBlueprint) string {
	hash := sha1.Sum([]byte(strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(blueprint.Method)),
		strings.TrimSpace(blueprint.Path),
		strings.TrimSpace(blueprint.Client),
		strings.TrimSpace(blueprint.Source.File),
		strings.TrimSpace(blueprint.Source.Snippet),
	}, "\x00")))
	return "jrb_" + hex.EncodeToString(hash[:8])
}

func dedupeRequestBlueprints(items []RequestBlueprint) []RequestBlueprint {
	if len(items) <= 1 {
		return items
	}

	index := make(map[string]int, len(items))
	result := make([]RequestBlueprint, 0, len(items))
	for _, item := range items {
		key := strings.Join([]string{
			strings.ToUpper(strings.TrimSpace(item.Method)),
			strings.TrimSpace(item.Path),
			strings.TrimSpace(item.Client),
			strings.TrimSpace(item.Source.File),
			strings.TrimSpace(item.Source.Snippet),
		}, "\x00")
		if existingIndex, ok := index[key]; ok {
			result[existingIndex] = mergeRequestBlueprint(result[existingIndex], item)
			continue
		}
		index[key] = len(result)
		result = append(result, item)
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Source.File == result[j].Source.File {
			if result[i].Path == result[j].Path {
				return result[i].Client < result[j].Client
			}
			return result[i].Path < result[j].Path
		}
		return result[i].Source.File < result[j].Source.File
	})
	return result
}

func mergeRequestBlueprint(base, extra RequestBlueprint) RequestBlueprint {
	base.Headers = mergeRequestBlueprintHeaders(base.Headers, extra.Headers)
	base.Interceptors = mergeRequestBlueprintInterceptors(base.Interceptors, extra.Interceptors)
	for _, param := range extra.Params {
		base.Params = appendRequestBlueprintParam(base.Params, param)
	}
	for _, item := range extra.Context {
		base.Context = appendUniqueStrings(base.Context, item)
	}
	if base.BaseURL == "" {
		base.BaseURL = extra.BaseURL
	}
	if base.PayloadPreview == "" {
		base.PayloadPreview = extra.PayloadPreview
	}
	if base.PayloadCarrier == "" {
		base.PayloadCarrier = extra.PayloadCarrier
	}
	if base.PayloadFormat == "" {
		base.PayloadFormat = extra.PayloadFormat
	}
	base.CompatibleAPIRequests += extra.CompatibleAPIRequests
	base.UnresolvedSymbols = mergeRequestBlueprintUnresolvedSymbols(base.UnresolvedSymbols, extra.UnresolvedSymbols)
	base.Confidence, base.ConfidenceReason = assessRequestBlueprintConfidence(base)
	base.ID = buildRequestBlueprintID(base)
	return base
}

func mergeRequestBlueprintUnresolvedSymbols(base, extra []string) []string {
	result := append([]string(nil), base...)
	for _, item := range extra {
		result = appendUniqueStrings(result, item)
	}
	sort.Strings(result)
	return result
}

func appendRequestBlueprintParam(params []RequestBlueprintParam, param RequestBlueprintParam) []RequestBlueprintParam {
	name := strings.TrimSpace(param.Name)
	if name == "" {
		return params
	}
	location := strings.TrimSpace(param.Location)
	for index := range params {
		if params[index].Name == name && params[index].Location == location {
			if params[index].Source == "" {
				params[index].Source = param.Source
			}
			if params[index].Value == "" {
				params[index].Value = param.Value
			}
			if params[index].ValueExpr == "" {
				params[index].ValueExpr = param.ValueExpr
			}
			params[index].Resolved = params[index].Resolved || param.Resolved
			if params[index].ResolvedFrom == "" {
				params[index].ResolvedFrom = param.ResolvedFrom
			}
			if params[index].Confidence == "" {
				params[index].Confidence = param.Confidence
			}
			return params
		}
	}
	return append(params, param)
}

func buildJSRequestSymbolIndex(content string, endpoints []StaticProtocolEndpoint) jsRequestSymbolIndex {
	index := jsRequestSymbolIndex{
		content:     content,
		definitions: make(map[string]jsRequestSymbolDefinition),
		callsites:   make(map[string][]callExpression),
	}
	for _, name := range collectRequestBlueprintSymbolCandidates(endpoints) {
		expr, ok := findJSAssignmentExpression(content, name)
		if !ok {
			continue
		}
		definition := jsRequestSymbolDefinition{
			Name:      name,
			Kind:      "variable",
			ValueExpr: strings.TrimSpace(expr),
		}
		if literal := parseStaticStringLikeValue(content, definition.ValueExpr); literal != "" {
			definition.Kind = "constant"
			definition.Value = literal
		}
		if fields := extractTopLevelObjectFields(resolveStaticArgumentExpression(content, definition.ValueExpr)); len(fields) > 0 {
			definition.Kind = "object"
			definition.Fields = make([]string, 0, len(fields))
			for field := range fields {
				definition.Fields = append(definition.Fields, field)
			}
			sort.Strings(definition.Fields)
		}
		index.definitions[name] = definition
	}
	for _, name := range collectRequestBlueprintCallsiteFunctionCandidates(endpoints) {
		index.callsites[name] = findCallExpressions(content, name)
	}
	return index
}

func collectRequestBlueprintCallsiteFunctionCandidates(endpoints []StaticProtocolEndpoint) []string {
	result := make([]string, 0, 16)
	for _, endpoint := range endpoints {
		if len(requestBlueprintDataVariablesFromContext(endpoint.Context)) == 0 {
			continue
		}
		name := requestBlueprintFunctionNameFromContext(endpoint.Context)
		if len(name) < 3 || !identifierPattern.MatchString(name) || isCompilerGeneratedRequestWrapperName(name) {
			continue
		}
		result = appendUniqueStrings(result, name)
	}
	sort.Strings(result)
	return result
}

func isCompilerGeneratedRequestWrapperName(name string) bool {
	name = strings.TrimSpace(name)
	if strings.HasPrefix(name, "_") {
		return true
	}
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "callee") || strings.HasPrefix(lower, "generator")
}

func collectRequestBlueprintSymbolCandidates(endpoints []StaticProtocolEndpoint) []string {
	result := make([]string, 0, 16)
	for _, endpoint := range endpoints {
		for _, param := range endpoint.Params {
			expr := strings.TrimSpace(firstNonEmpty(param.ValueExpr, param.Name))
			if len(expr) >= 3 && identifierPattern.MatchString(expr) {
				result = appendUniqueStrings(result, expr)
			}
		}
	}
	sort.Strings(result)
	return result
}

func findJSAssignmentExpression(content, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if !identifierPattern.MatchString(name) {
		return "", false
	}
	pattern := regexp.MustCompile(`(?:^|[^A-Za-z0-9_$\.])` + regexp.QuoteMeta(name) + `\s*=`)
	matches := pattern.FindAllStringIndex(content, -1)
	for _, match := range matches {
		eqIndex := strings.LastIndex(content[match[0]:match[1]], "=")
		if eqIndex < 0 {
			continue
		}
		start := match[0] + eqIndex + 1
		expr, ok := readJSAssignmentExpression(content, start, 1000)
		if ok {
			return expr, true
		}
	}
	return "", false
}

func readJSAssignmentExpression(content string, start, maxLen int) (string, bool) {
	quote := byte(0)
	escaped := false
	parenDepth := 0
	braceDepth := 0
	bracketDepth := 0
	endLimit := start + maxLen
	if endLimit > len(content) {
		endLimit = len(content)
	}
	for index := start; index < endLimit; index++ {
		ch := content[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == quote {
				quote = 0
			}
			continue
		}
		switch ch {
		case '"', '\'', '`':
			quote = ch
		case '(':
			parenDepth++
		case ')':
			if parenDepth > 0 {
				parenDepth--
			}
		case '{':
			braceDepth++
		case '}':
			if braceDepth > 0 {
				braceDepth--
			}
		case '[':
			bracketDepth++
		case ']':
			if bracketDepth > 0 {
				bracketDepth--
			}
		case ',', ';', '\n':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 {
				expr := strings.TrimSpace(content[start:index])
				return expr, expr != ""
			}
		}
	}
	expr := strings.TrimSpace(content[start:endLimit])
	return expr, expr != ""
}

func extractAxiosBlueprintContexts(fileURL, content string) map[string]axiosBlueprintContext {
	contexts := make(map[string]axiosBlueprintContext)
	for _, instance := range extractAxiosCreateBlueprintContexts(content) {
		contexts[instance.Name] = instance
	}
	for name, context := range contexts {
		context.Interceptors = extractAxiosRequestInterceptors(name, content)
		context.Headers = mergeRequestBlueprintHeaders(context.Headers, headersFromInterceptors(context.Interceptors))
		contexts[name] = context
	}
	for name, context := range contexts {
		for index := range context.Interceptors {
			if strings.TrimSpace(context.Interceptors[index].Snippet) == "" {
				continue
			}
			context.Interceptors[index].Snippet = normalizeSnippet(context.Interceptors[index].Snippet)
		}
		contexts[name] = context
	}
	_ = fileURL
	return contexts
}

func extractAxiosCreateBlueprintContexts(content string) []axiosBlueprintContext {
	createCalls := findAxiosLikeCreateCalls(content)
	result := make([]axiosBlueprintContext, 0, len(createCalls))
	for _, call := range createCalls {
		fields := call.Fields
		context := axiosBlueprintContext{Name: call.InstanceName}
		if baseURL := parseStaticStringLikeValue(content, fields["baseURL"]); baseURL != "" {
			context.BaseURL = baseURL
		}
		context.Headers = requestBlueprintHeadersFromObject(content, fields["headers"], "axios.create", false)
		result = append(result, context)
	}
	return result
}

func findAxiosLikeCreateCalls(content string) []axiosLikeCreateCall {
	pattern := regexp.MustCompile(`(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\.\s*create\s*\(`)
	matches := pattern.FindAllStringSubmatchIndex(content, -1)
	result := make([]axiosLikeCreateCall, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}
		instanceName := strings.TrimSpace(content[match[2]:match[3]])
		factoryName := normalizeJSMemberExpression(content[match[4]:match[5]])
		openIndex := match[1] - 1
		if openIndex < 0 || openIndex >= len(content) || content[openIndex] != '(' {
			continue
		}
		args, _, ok := extractBalancedJS(content, openIndex, '(', ')')
		if !ok {
			continue
		}
		fields := extractTopLevelObjectFields(strings.TrimSpace(args))
		if !isLikelyAxiosLikeCreate(instanceName, fields, content) {
			continue
		}
		key := instanceName + "\x00" + strconv.Itoa(openIndex)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, axiosLikeCreateCall{
			InstanceName: instanceName,
			FactoryName:  factoryName,
			Args:         strings.TrimSpace(args),
			Fields:       fields,
		})
	}
	return result
}

func isLikelyAxiosLikeCreate(instanceName string, fields map[string]string, content string) bool {
	if isLikelyAxiosCreateConfig(fields) {
		return true
	}
	return hasAxiosLikeInstanceUsage(instanceName, content)
}

func isLikelyAxiosCreateConfig(fields map[string]string) bool {
	if len(fields) == 0 {
		return false
	}
	for _, field := range []string{
		"baseURL", "baseUrl", "timeout", "headers", "withCredentials",
		"responseType", "validateStatus", "paramsSerializer",
		"transformRequest", "transformResponse",
	} {
		if _, ok := fields[field]; ok {
			return true
		}
	}
	return false
}

func hasAxiosLikeInstanceUsage(instanceName, content string) bool {
	instanceName = strings.TrimSpace(instanceName)
	if instanceName == "" {
		return false
	}
	if strings.Contains(content, instanceName+".interceptors.request.use") ||
		strings.Contains(content, instanceName+".interceptors.response.use") {
		return true
	}
	for _, method := range []string{"get", "post", "put", "delete", "patch", "request"} {
		if strings.Contains(content, instanceName+"."+method+"(") {
			return true
		}
	}
	return false
}

func normalizeJSMemberExpression(value string) string {
	return strings.ReplaceAll(strings.TrimSpace(value), " ", "")
}

func matchAxiosBlueprintContext(client string, contexts map[string]axiosBlueprintContext) (axiosBlueprintContext, bool) {
	client = strings.TrimSpace(client)
	for name, context := range contexts {
		if strings.Contains(client, "axios-instance:"+name+".") ||
			strings.HasPrefix(client, name+".") ||
			strings.Contains(client, "wrapper:"+name) {
			return context, true
		}
	}
	return axiosBlueprintContext{}, false
}

func extractAxiosRequestInterceptors(instanceName, content string) []RequestBlueprintInterceptor {
	callee := instanceName + ".interceptors.request.use"
	matches := findCallExpressions(content, callee)
	result := make([]RequestBlueprintInterceptor, 0, len(matches))
	for _, match := range matches {
		mutates := extractInterceptorMutations(match.Args)
		result = append(result, RequestBlueprintInterceptor{
			Client:  instanceName,
			Kind:    "request",
			Mutates: mutates,
			Snippet: normalizeSnippet(match.CallText),
		})
	}
	return result
}

func extractInterceptorMutations(args string) []string {
	mutations := make([]string, 0, 4)
	headerAssignPattern := regexp.MustCompile(`\b[A-Za-z_$][\w$]*\s*\.\s*headers\s*(?:\[\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]\s*\]|\.\s*([A-Za-z_$][\w$]*))\s*=`)
	for _, match := range headerAssignPattern.FindAllStringSubmatch(args, -1) {
		name := strings.TrimSpace(firstNonEmpty(match[1], match[2]))
		if name != "" {
			mutations = appendUniqueStrings(mutations, "headers."+name)
		}
	}
	for _, field := range []string{"baseURL", "url", "params", "data"} {
		pattern := regexp.MustCompile(`(?:config|cfg|request)\s*\.\s*` + regexp.QuoteMeta(field) + `\s*=`)
		if pattern.MatchString(args) {
			mutations = appendUniqueStrings(mutations, field)
		}
	}
	return mutations
}

func headersFromInterceptors(interceptors []RequestBlueprintInterceptor) []RequestBlueprintHeader {
	headers := make([]RequestBlueprintHeader, 0, 4)
	for _, interceptor := range interceptors {
		for _, mutation := range interceptor.Mutates {
			if !strings.HasPrefix(mutation, "headers.") {
				continue
			}
			name := strings.TrimSpace(strings.TrimPrefix(mutation, "headers."))
			headers = mergeRequestBlueprintHeaders(headers, []RequestBlueprintHeader{{
				Name:    name,
				Source:  "request-interceptor",
				Dynamic: true,
			}})
		}
	}
	return headers
}

func requestBlueprintHeadersFromContext(context []string) []RequestBlueprintHeader {
	headers := make([]RequestBlueprintHeader, 0, 4)
	for _, item := range context {
		item = strings.TrimSpace(item)
		if strings.HasPrefix(item, "请求头动态: ") {
			raw := strings.TrimSpace(strings.TrimPrefix(item, "请求头动态: "))
			key, source, _ := strings.Cut(raw, "<-")
			headers = mergeRequestBlueprintHeaders(headers, []RequestBlueprintHeader{{
				Name:    strings.TrimSpace(key),
				Source:  firstNonEmpty(strings.TrimSpace(source), "static-context"),
				Dynamic: true,
			}})
			continue
		}
		if !strings.HasPrefix(item, "请求头常量: ") {
			continue
		}
		raw := strings.TrimSpace(strings.TrimPrefix(item, "请求头常量: "))
		key, value, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		headers = mergeRequestBlueprintHeaders(headers, []RequestBlueprintHeader{{
			Name:   strings.TrimSpace(key),
			Value:  strings.TrimSpace(value),
			Source: "static-context",
		}})
	}
	return headers
}

func requestBlueprintHeadersFromObject(content, raw, source string, dynamic bool) []RequestBlueprintHeader {
	fields := extractTopLevelObjectFields(resolveStaticArgumentExpression(content, raw))
	if len(fields) == 0 {
		return nil
	}
	headers := make([]RequestBlueprintHeader, 0, len(fields))
	for key, value := range fields {
		key = strings.Trim(key, `"'`)
		if strings.TrimSpace(key) == "" {
			continue
		}
		literal := parseStaticStringLikeValue(content, value)
		headers = mergeRequestBlueprintHeaders(headers, []RequestBlueprintHeader{{
			Name:    strings.TrimSpace(key),
			Value:   literal,
			Source:  source,
			Dynamic: dynamic || literal == "",
		}})
	}
	return headers
}

func mergeRequestBlueprintHeaders(base, extra []RequestBlueprintHeader) []RequestBlueprintHeader {
	result := append([]RequestBlueprintHeader(nil), base...)
	for _, header := range extra {
		name := strings.TrimSpace(header.Name)
		if name == "" {
			continue
		}
		found := false
		for index := range result {
			if strings.EqualFold(result[index].Name, name) {
				if result[index].Value == "" {
					result[index].Value = header.Value
				}
				if result[index].Source == "" {
					result[index].Source = header.Source
				}
				result[index].Dynamic = result[index].Dynamic || header.Dynamic
				found = true
				break
			}
		}
		if !found {
			result = append(result, header)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})
	return result
}

func mergeRequestBlueprintInterceptors(base, extra []RequestBlueprintInterceptor) []RequestBlueprintInterceptor {
	result := append([]RequestBlueprintInterceptor(nil), base...)
	for _, interceptor := range extra {
		key := strings.Join([]string{interceptor.Client, interceptor.Kind, interceptor.Snippet}, "\x00")
		exists := false
		for _, current := range result {
			if strings.Join([]string{current.Client, current.Kind, current.Snippet}, "\x00") == key {
				exists = true
				break
			}
		}
		if !exists {
			result = append(result, interceptor)
		}
	}
	return result
}

func parseStaticStringLikeValue(content, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if resolved := strings.TrimSpace(resolveStaticArgumentExpression(content, raw)); resolved != "" && resolved != raw {
		raw = resolved
	}
	if literal := parseStringLiteral(raw); literal != "" {
		return literal
	}
	if json.Valid([]byte(raw)) {
		var value string
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			return value
		}
	}
	if parsed, err := url.Parse(raw); err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return raw
	}
	return ""
}

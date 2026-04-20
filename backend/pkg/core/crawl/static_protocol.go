package crawl

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/structs"
)

type StaticProtocolEvidence struct {
	Label   string `json:"label"`
	FileURL string `json:"file_url"`
	Snippet string `json:"snippet"`
}

type StaticProtocolParam struct {
	Name   string `json:"name"`
	Source string `json:"source,omitempty"`
}

type StaticProtocolEndpoint struct {
	Path                   string                        `json:"path"`
	Method                 string                        `json:"method"`
	Client                 string                        `json:"client,omitempty"`
	Params                 []StaticProtocolParam         `json:"params,omitempty"`
	RequestPayloadCarrier  string                        `json:"request_payload_carrier,omitempty"`
	RequestPayloadFormat   string                        `json:"request_payload_format,omitempty"`
	RequestPayloadPreview  string                        `json:"request_payload_preview,omitempty"`
	Context                []string                      `json:"context,omitempty"`
	SourceFile             string                        `json:"source_file"`
	Snippet                string                        `json:"snippet"`
	TraceID                string                        `json:"trace_id,omitempty"`
	PageURL                string                        `json:"page_url,omitempty"`
	RequestURL             string                        `json:"request_url,omitempty"`
	RequestBeforeTransform string                        `json:"request_before_transform,omitempty"`
	FinalRequestBody       string                        `json:"final_request_body,omitempty"`
	RequestSteps           []database.ProtocolCryptoStep `json:"request_steps,omitempty"`
	ResponseSteps          []database.ProtocolCryptoStep `json:"response_steps,omitempty"`
	SessionMaterials       map[string]string             `json:"session_materials,omitempty"`
	Algorithms             []string                      `json:"algorithms,omitempty"`
}

type StaticProtocolProfile struct {
	ID                    string                   `json:"id"`
	Name                  string                   `json:"name"`
	RequestWrapper        string                   `json:"request_wrapper,omitempty"`
	APIBaseURLs           []string                 `json:"api_base_urls,omitempty"`
	MatchedFiles          []string                 `json:"matched_files,omitempty"`
	EncryptionEnabled     bool                     `json:"encryption_enabled"`
	RequestCipher         string                   `json:"request_cipher,omitempty"`
	ResponseCipher        string                   `json:"response_cipher,omitempty"`
	KeyExchange           string                   `json:"key_exchange,omitempty"`
	KeyTransportPublicKey string                   `json:"key_transport_public_key,omitempty"`
	SignatureAlgorithm    string                   `json:"signature_algorithm,omitempty"`
	RequestKeyDerivation  string                   `json:"request_key_derivation,omitempty"`
	SignatureFormula      string                   `json:"signature_formula,omitempty"`
	HeaderFields          map[string]string        `json:"header_fields,omitempty"`
	ControlFields         []string                 `json:"control_fields,omitempty"`
	RequestPipeline       []string                 `json:"request_pipeline,omitempty"`
	ResponsePipeline      []string                 `json:"response_pipeline,omitempty"`
	PrimaryEndpoint       *StaticProtocolEndpoint  `json:"primary_endpoint,omitempty"`
	Endpoints             []StaticProtocolEndpoint `json:"endpoints,omitempty"`
	Evidence              []StaticProtocolEvidence `json:"evidence,omitempty"`
}

type StaticProtocolAnalysisResult struct {
	TaskID      string                  `json:"task_id"`
	JSCount     int                     `json:"js_count"`
	GeneratedAt time.Time               `json:"generated_at"`
	Profiles    []StaticProtocolProfile `json:"profiles"`
}

var (
	apiBasePattern        = regexp.MustCompile(`api\s*:\s*"([^"]+/api)"`)
	postRequestPattern    = regexp.MustCompile(`postRequest\("([^"]+)"`)
	publicKeyPattern      = regexp.MustCompile(`6zzbinypyphq":\(0,d\.st\)\(b,atob\("([^"]+)"\)\)`)
	stringLiteralPattern  = regexp.MustCompile(`^['"` + "`" + `]([^'"` + "`" + `]+)['"` + "`" + `]$`)
	concatPathPattern     = regexp.MustCompile(`\.concat\((?:[^()]|"(?:\\.|[^"])*"|'(?:\\.|[^'])*'|` + "`" + `(?:\\.|[^` + "`" + `])*` + "`" + `)*?["'` + "`" + `](/[^"'` + "`" + `]+)["'` + "`" + `]\s*\)`)
	identifierPattern     = regexp.MustCompile(`^[A-Za-z_$][\w$]*$`)
	configLikeCallPattern = regexp.MustCompile(`(^|[^A-Za-z0-9_$\.])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(\s*\{`)
)

func AnalyzeStoredJSProtocols(taskID string, versions ...int) (*StaticProtocolAnalysisResult, error) {
	jsResources, err := database.QueryJSByTaskID(taskID, versions...)
	if err != nil {
		return nil, err
	}

	apiResources, err := database.QueryAPIResourcesByTaskID(taskID, versions...)
	if err != nil {
		if !strings.Contains(err.Error(), "index_not_found_exception") &&
			!strings.Contains(err.Error(), "ES client not initialized") &&
			!strings.Contains(err.Error(), "connection") {
			return nil, err
		}
		apiResources = nil
	}

	traces, err := database.QueryProtocolTracesByTaskID(taskID, versions...)
	if err != nil {
		if !strings.Contains(err.Error(), "index_not_found_exception") &&
			!strings.Contains(err.Error(), "ES client not initialized") &&
			!strings.Contains(err.Error(), "connection") {
			return nil, err
		}
		traces = nil
	}

	sort.Slice(jsResources, func(i, j int) bool {
		return jsResources[i].Size > jsResources[j].Size
	})

	result := &StaticProtocolAnalysisResult{
		TaskID:      taskID,
		JSCount:     len(jsResources),
		GeneratedAt: time.Now(),
		Profiles:    []StaticProtocolProfile{},
	}

	if len(jsResources) == 0 {
		return result, nil
	}

	apiBaseSet := map[string]struct{}{}
	fileSet := map[string]struct{}{}
	endpointSet := map[string]struct{}{}
	endpoints := make([]StaticProtocolEndpoint, 0, 24)
	evidence := make([]StaticProtocolEvidence, 0, 8)

	foundWrapper := false
	foundRequestSM4 := false
	foundResponseSM4 := false
	foundHeaderTransport := false
	foundMD5Signature := false
	publicKey := ""
	contextEndpoints := make([]StaticProtocolEndpoint, 0, 64)
	contextEndpointSet := make(map[string]int)
	contextFileSet := map[string]struct{}{}
	contextEvidence := make([]StaticProtocolEvidence, 0, 8)

	for _, js := range jsResources {
		content := js.Content

		for _, match := range apiBasePattern.FindAllStringSubmatch(content, -1) {
			if len(match) > 1 {
				apiBaseSet[match[1]] = struct{}{}
			}
		}

		if strings.Contains(content, `e.postRequest=u`) &&
			strings.Contains(content, `uni.request({url:o.API+"/"+e,data:i,method:n,header:B})`) {
			foundWrapper = true
			fileSet[js.URL] = struct{}{}
			appendEvidence(&evidence, "请求封装", js.URL, content, `uni.request({url:o.API+"/"+e,data:i,method:n,header:B})`)
		}

		if strings.Contains(content, `o.NETWORK_ENCRYPTION&&(i=(0,d.se)(JSON.stringify(i),atob(atob(y))))`) {
			foundRequestSM4 = true
			fileSet[js.URL] = struct{}{}
			appendEvidence(&evidence, "请求体加密", js.URL, content, `o.NETWORK_ENCRYPTION&&(i=(0,d.se)(JSON.stringify(i),atob(atob(y))))`)
		}

		if strings.Contains(content, `200===e.statusCode?o.NETWORK_ENCRYPTION&&(e.data=(0,d.sd)(e.data,atob(atob(y))))`) {
			foundResponseSM4 = true
			fileSet[js.URL] = struct{}{}
			appendEvidence(&evidence, "响应体解密", js.URL, content, `200===e.statusCode?o.NETWORK_ENCRYPTION&&(e.data=(0,d.sd)(e.data,atob(atob(y))))`)
		}

		if strings.Contains(content, `v=(0,p.default)((0,p.default)(k+i)+x)`) {
			foundMD5Signature = true
			fileSet[js.URL] = struct{}{}
			appendEvidence(&evidence, "签名公式", js.URL, content, `v=(0,p.default)((0,p.default)(k+i)+x)`)
		}

		if strings.Contains(content, `gv59JPPEesNW:x`) &&
			strings.Contains(content, `KQN29pKXsTKN:k`) &&
			strings.Contains(content, `BpzHepzRVcJy:v`) &&
			strings.Contains(content, `6zzbinypyphq`) {
			foundHeaderTransport = true
			fileSet[js.URL] = struct{}{}
			appendEvidence(&evidence, "关键请求头", js.URL, content, `"x-access-token":f,"channel-code":m,gv59JPPEesNW:x,KQN29pKXsTKN:k,BpzHepzRVcJy:v,"6zzbinypyphq":(0,d.st)(b,atob("`)
		}

		if publicKey == "" {
			if match := publicKeyPattern.FindStringSubmatch(content); len(match) > 1 {
				publicKey = decodeBase64(match[1])
			}
		}

		for _, match := range postRequestPattern.FindAllStringSubmatch(content, -1) {
			if len(match) < 2 {
				continue
			}
			path := strings.TrimSpace(match[1])
			if path == "" {
				continue
			}
			if _, exists := endpointSet[path]; exists {
				continue
			}
			endpointSet[path] = struct{}{}
			endpoints = append(endpoints, StaticProtocolEndpoint{
				Path:       path,
				Method:     "POST",
				Client:     "postRequest",
				SourceFile: js.URL,
				Snippet:    extractSnippet(content, `postRequest("`+path+`"`, 220),
			})
		}

		extracted := extractHTTPContextEndpoints(js.URL, content)
		if len(extracted) > 0 {
			contextFileSet[js.URL] = struct{}{}
			if len(contextEvidence) < 8 {
				contextEvidence = append(contextEvidence, StaticProtocolEvidence{
					Label:   "请求上下文",
					FileURL: js.URL,
					Snippet: extracted[0].Snippet,
				})
			}
		}
		for _, endpoint := range extracted {
			fingerprint := strings.Join([]string{
				strings.ToUpper(endpoint.Method),
				endpoint.Path,
				endpoint.SourceFile,
			}, "\x00")
			if existingIndex, exists := contextEndpointSet[fingerprint]; exists {
				contextEndpoints[existingIndex] = mergeStaticEndpoints(contextEndpoints[existingIndex], endpoint)
				continue
			}
			contextEndpointSet[fingerprint] = len(contextEndpoints)
			contextEndpoints = append(contextEndpoints, endpoint)
		}
	}

	observedEndpoints := extractObservedAPIResourceEndpoints(apiResources, sortedKeys(apiBaseSet))
	if len(observedEndpoints) > 0 {
		contextEndpoints = mergeStaticEndpointCollections(contextEndpoints, observedEndpoints)
	}

	sort.Slice(contextEndpoints, func(i, j int) bool {
		if contextEndpoints[i].Path == contextEndpoints[j].Path {
			return contextEndpoints[i].Method < contextEndpoints[j].Method
		}
		return contextEndpoints[i].Path < contextEndpoints[j].Path
	})

	if len(contextEndpoints) > 0 {
		genericProfile := StaticProtocolProfile{
			ID:                "request-context-analysis",
			Name:              "请求上下文分析",
			RequestWrapper:    "axios / fetch / $.ajax / uni.request / postRequest",
			MatchedFiles:      sortedKeys(contextFileSet),
			EncryptionEnabled: false,
			RequestPipeline: []string{
				"识别常见 HTTP 客户端调用",
				"提取请求方法、URL 与客户端类型",
				"分析 query/body/params/path 中的参数候选",
				"补充函数参数、变量来源等上下文提示",
			},
			Endpoints: trimStaticEndpoints(contextEndpoints, 60),
			Evidence:  contextEvidence,
		}
		result.Profiles = append(result.Profiles, genericProfile)
	}

	if !(foundWrapper || foundRequestSM4 || foundResponseSM4 || foundHeaderTransport) {
		return result, nil
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Path < endpoints[j].Path
	})
	if len(endpoints) > 20 {
		endpoints = endpoints[:20]
	}

	traceEndpoints := extractTraceMatchedEndpoints(traces, sortedKeys(apiBaseSet))

	mergedEndpoints := mergeStaticEndpointCollections(mergeStaticEndpointCollections(endpoints, contextEndpoints), traceEndpoints)
	profile := StaticProtocolProfile{
		ID:                    "sm4-sm2-md5-envelope",
		Name:                  "SM4/SM2/MD5 网络封装",
		RequestWrapper:        "postRequest",
		APIBaseURLs:           sortedKeys(apiBaseSet),
		MatchedFiles:          sortedKeys(fileSet),
		EncryptionEnabled:     true,
		RequestCipher:         "SM4(hex output)",
		ResponseCipher:        "SM4(hex input -> utf8/json)",
		KeyExchange:           "SM2 公钥加密传递会话密钥",
		KeyTransportPublicKey: publicKey,
		RequestKeyDerivation:  "b = rn(16) -> sth(b) -> 作为 SM4 key；请求体为 se(JSON.stringify(body), sth(b))",
		SignatureFormula:      "md5(md5(timestamp + ciphertext) + nonce)",
		HeaderFields: map[string]string{
			"x-access-token": "登录态 token",
			"channel-code":   "渠道号",
			"gv59JPPEesNW":   "8 位随机 nonce",
			"KQN29pKXsTKN":   "13 位毫秒时间戳",
			"BpzHepzRVcJy":   "MD5 签名",
			"6zzbinypyphq":   "SM2 加密后的会话密钥材料",
		},
		ControlFields: []string{
			"needPrevent",
			"loading",
			"showErrorToast",
			"showErrorPage",
		},
		RequestPipeline: []string{
			"删除控制字段",
			"JSON.stringify(body)",
			"生成 16 位数字随机串 b",
			"sth(b) 生成十六进制 SM4 key",
			"SM4 加密得到十六进制请求体",
			"生成 nonce / timestamp / md5 签名",
			"SM2 加密会话密钥材料写入请求头",
		},
		ResponsePipeline: []string{
			"读取相同会话 key",
			"SM4 解密十六进制响应体",
			"utf8 -> JSON.parse",
		},
		PrimaryEndpoint: selectPrimaryTraceEndpoint(mergedEndpoints),
		Endpoints:       mergedEndpoints,
		Evidence:        evidence,
	}
	if foundMD5Signature {
		profile.SignatureAlgorithm = "MD5"
	}

	result.Profiles = append(result.Profiles, profile)
	return result, nil
}

func BuildStaticConstantParamHints(jsResources []database.JSResource) map[string]url.Values {
	bundle := BuildStaticEndpointHintBundle(jsResources)
	return bundle.ConstantParams
}

type StaticEndpointHintBundle struct {
	Methods        map[string]string
	ConstantParams map[string]url.Values
	Headers        map[string]map[string]string
	RequestPayload map[string]structs.StaticRequestPayloadHint
}

func BuildStaticEndpointHintBundle(jsResources []database.JSResource) StaticEndpointHintBundle {
	bundle := StaticEndpointHintBundle{}
	if len(jsResources) == 0 {
		return bundle
	}

	constantHints := make(map[string]url.Values)
	methodHints := make(map[string]string)
	headerHints := make(map[string]map[string]string)
	payloadHints := make(map[string]structs.StaticRequestPayloadHint)
	appendMethodHints := func(path, method string) {
		method = strings.ToUpper(strings.TrimSpace(method))
		path = strings.TrimSpace(path)
		if path == "" || (method != http.MethodGet && method != http.MethodPost) {
			return
		}

		current := strings.ToUpper(strings.TrimSpace(methodHints[path]))
		if current == "" || (current == http.MethodGet && method == http.MethodPost) {
			methodHints[path] = method
		}
	}
	appendConstantHints := func(method, path string, params url.Values) {
		method = strings.ToUpper(strings.TrimSpace(method))
		path = strings.TrimSpace(path)
		if method == "" || path == "" || len(params) == 0 {
			return
		}

		key := method + "\x00" + path
		if _, exists := constantHints[key]; !exists {
			constantHints[key] = url.Values{}
		}
		for paramName, values := range params {
			if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
				continue
			}
			if _, exists := constantHints[key][paramName]; exists {
				continue
			}
			constantHints[key][paramName] = []string{values[0]}
		}
	}

	for _, js := range jsResources {
		endpoints := extractHTTPContextEndpoints(js.URL, js.Content)
		for _, endpoint := range endpoints {
			method := strings.ToUpper(strings.TrimSpace(endpoint.Method))
			path := strings.TrimSpace(endpoint.Path)
			if method == "" || path == "" {
				continue
			}

			appendMethodHints(path, method)
			key := method + "\x00" + path
			constantParams := extractStaticConstantParamsFromContext(endpoint.Context)
			appendConstantHints(method, path, constantParams)

			headers := extractStaticHeadersFromContext(endpoint.Context)
			if len(headers) > 0 {
				if _, exists := headerHints[key]; !exists {
					headerHints[key] = make(map[string]string)
				}
				for headerName, headerValue := range headers {
					if strings.TrimSpace(headerName) == "" || strings.TrimSpace(headerValue) == "" {
						continue
					}
					if _, exists := headerHints[key][headerName]; exists {
						continue
					}
					headerHints[key][headerName] = headerValue
				}
			}

			hint := structs.StaticRequestPayloadHint{
				Carrier: strings.TrimSpace(endpoint.RequestPayloadCarrier),
				Format:  strings.TrimSpace(endpoint.RequestPayloadFormat),
				Preview: strings.TrimSpace(endpoint.RequestPayloadPreview),
			}
			if hint.Carrier != "" || hint.Format != "" || hint.Preview != "" {
				if current, exists := payloadHints[key]; exists {
					payloadHints[key] = mergeStaticRequestPayloadHint(current, hint)
				} else {
					payloadHints[key] = hint
				}
			}

		}
	}

	if len(constantHints) > 0 {
		bundle.ConstantParams = constantHints
	}
	if len(methodHints) > 0 {
		bundle.Methods = methodHints
	}
	if len(headerHints) > 0 {
		bundle.Headers = headerHints
	}
	if len(payloadHints) > 0 {
		bundle.RequestPayload = payloadHints
	}
	return bundle
}

func BuildStaticHeaderHints(jsResources []database.JSResource) map[string]map[string]string {
	bundle := BuildStaticEndpointHintBundle(jsResources)
	return bundle.Headers
}

func BuildStaticRequestPayloadHints(jsResources []database.JSResource) map[string]structs.StaticRequestPayloadHint {
	bundle := BuildStaticEndpointHintBundle(jsResources)
	return bundle.RequestPayload
}

func extractBoundRootsFromEndpoint(content string, endpoint StaticProtocolEndpoint) []string {
	roots := make([]string, 0, 2)
	for _, root := range extractBoundRootsFromSnippet(content, endpoint.Snippet, endpoint.Path) {
		roots = appendUniqueStrings(roots, root)
	}
	for _, root := range extractBoundRootsFromRequestURL(endpoint.RequestURL, endpoint.Path) {
		roots = appendUniqueStrings(roots, root)
	}
	return roots
}

func extractBoundRootsFromSnippet(content, snippet, endpointPath string) []string {
	snippet = strings.TrimSpace(snippet)
	endpointPath = strings.TrimSpace(endpointPath)
	if snippet == "" || endpointPath == "" {
		return nil
	}

	roots := make([]string, 0, 3)
	if match := regexp.MustCompile(`\.concat\((.+)\)`).FindStringSubmatch(snippet); len(match) >= 2 {
		args := splitTopLevelCSV(match[1])
		if len(args) >= 2 {
			for _, arg := range args[:len(args)-1] {
				for _, root := range resolveStaticRootExpression(content, strings.TrimSpace(arg)) {
					roots = appendUniqueStrings(roots, root)
				}
			}
		}
	}

	if fields := extractTopLevelObjectFields(snippet); len(fields) > 0 {
		for _, root := range extractStaticRootsFromURLExpression(content, fields["url"], endpointPath) {
			roots = appendUniqueStrings(roots, root)
		}
	}

	if match := regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(`).FindStringSubmatch(snippet); len(match) >= 2 {
		for _, root := range resolveStaticClientBaseRoots(content, strings.TrimSpace(match[1])) {
			roots = appendUniqueStrings(roots, root)
		}
	}

	return roots
}

func extractStaticRootsFromURLExpression(content, expr, endpointPath string) []string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	values := resolveStaticStringExpression(content, expr, 0)
	if len(values) == 0 {
		return nil
	}

	roots := make([]string, 0, len(values))
	normalizedEndpointPath := normalizeStaticRouteHintPath(endpointPath)
	for _, value := range values {
		normalizedValue := strings.TrimSpace(value)
		if normalizedValue == "" {
			continue
		}
		if normalizedEndpointPath != "" && strings.HasSuffix(normalizedValue, normalizedEndpointPath) {
			trimmed := strings.TrimSuffix(normalizedValue, normalizedEndpointPath)
			if normalized := normalizeStaticBoundRoot(trimmed); normalized != "" {
				roots = appendUniqueStrings(roots, normalized)
			}
			continue
		}
		if normalized := normalizeStaticBoundRoot(normalizedValue); normalized != "" {
			roots = appendUniqueStrings(roots, normalized)
		}
	}
	return roots
}

func extractBoundRootsFromRequestURL(rawURL, endpointPath string) []string {
	rawURL = strings.TrimSpace(rawURL)
	endpointPath = strings.TrimSpace(endpointPath)
	if rawURL == "" || endpointPath == "" {
		return nil
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}

	requestPath := strings.TrimSpace(parsed.Path)
	if requestPath == "" {
		return nil
	}

	normalizedEndpointPath := normalizeStaticRouteHintPath(endpointPath)
	normalizedRequestPath := normalizeStaticRouteHintPath(requestPath)
	if normalizedEndpointPath == "" || normalizedRequestPath == "" {
		return nil
	}

	if normalizedRequestPath == normalizedEndpointPath {
		return []string{parsed.Scheme + "://" + parsed.Host}
	}
	if !strings.HasSuffix(normalizedRequestPath, normalizedEndpointPath) {
		return nil
	}

	rootPath := strings.TrimSuffix(normalizedRequestPath, normalizedEndpointPath)
	rootPath = normalizeStaticBoundRoot(rootPath)
	rootURL := parsed.Scheme + "://" + parsed.Host
	if rootPath == "" || rootPath == "/" {
		return []string{rootURL}
	}
	return []string{strings.TrimRight(rootURL, "/") + rootPath}
}

func resolveStaticRootExpression(content, expr string) []string {
	values := resolveStaticStringExpression(content, expr, 0)
	roots := make([]string, 0, len(values))
	for _, value := range values {
		if normalized := normalizeStaticBoundRoot(value); normalized != "" {
			roots = appendUniqueStrings(roots, normalized)
		}
	}
	return roots
}

func resolveStaticIdentifierRoots(content, identifier string) []string {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:var|let|const)\s+` + regexp.QuoteMeta(identifier) + `\s*=\s*([^;\n]+)`),
		regexp.MustCompile(`(?:^|[,{]\s*)` + regexp.QuoteMeta(identifier) + `\s*:\s*([^,}\n]+)`),
		regexp.MustCompile(regexp.QuoteMeta(identifier) + `\s*=\s*([^;\n]+)`),
	}

	roots := make([]string, 0, 2)
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			for _, resolved := range resolveStaticRootExpression(content, match[1]) {
				roots = appendUniqueStrings(roots, resolved)
			}
		}
	}
	return roots
}

func resolveStaticClientBaseRoots(content, clientName string) []string {
	clientName = strings.TrimSpace(clientName)
	if clientName == "" {
		return nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:var|let|const)\s+` + regexp.QuoteMeta(clientName) + `\s*=\s*[A-Za-z_$][\w$]*\s*\.\s*create\(\s*\{[^{}]*baseURL\s*:\s*([^,}\n]+)`),
		regexp.MustCompile(regexp.QuoteMeta(clientName) + `\s*\.\s*defaults\s*\.\s*baseURL\s*=\s*([^;\n]+)`),
	}

	roots := make([]string, 0, 2)
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			for _, resolved := range resolveStaticRootExpression(content, match[1]) {
				roots = appendUniqueStrings(roots, resolved)
			}
		}
	}
	return roots
}

func normalizeStaticRouteHintPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}

	if parsed, err := url.Parse(path); err == nil && parsed != nil && parsed.Path != "" {
		path = parsed.Path
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + strings.TrimLeft(path, "/")
	}
	return strings.TrimRight(path, "/")
}

func normalizeStaticBoundRoot(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}

	if parsed, err := url.Parse(root); err == nil && parsed != nil && parsed.Scheme != "" && parsed.Host != "" {
		normalizedPath := normalizeStaticBoundRootPath(parsed.Path)
		if normalizedPath == "" {
			return parsed.Scheme + "://" + parsed.Host
		}
		return parsed.Scheme + "://" + parsed.Host + normalizedPath
	}

	root = normalizeStaticBoundRootPath(root)
	if root == "" {
		return "/"
	}
	return root
}

func normalizeStaticBoundRootPath(root string) string {
	root = strings.TrimSpace(root)
	if root == "" {
		return ""
	}
	if !strings.HasPrefix(root, "/") {
		root = "/" + strings.TrimLeft(root, "/")
	}
	for strings.Contains(root, "//") {
		root = strings.ReplaceAll(root, "//", "/")
	}
	root = strings.TrimRight(root, "/")
	return root
}

func mergeStaticRouteRoots(base, extra []string) []string {
	merged := append([]string{}, base...)
	for _, item := range extra {
		if normalized := normalizeStaticBoundRoot(item); normalized != "" {
			merged = appendUniqueStrings(merged, normalized)
		}
	}
	return merged
}

func mergeStaticRequestPayloadHint(base, extra structs.StaticRequestPayloadHint) structs.StaticRequestPayloadHint {
	if scoreStaticRequestPayloadHint(extra) > scoreStaticRequestPayloadHint(base) {
		base = extra
	}
	if base.Carrier == "" {
		base.Carrier = extra.Carrier
	}
	if base.Format == "" {
		base.Format = extra.Format
	}
	if base.Preview == "" {
		base.Preview = extra.Preview
	}
	return base
}

func scoreStaticRequestPayloadHint(hint structs.StaticRequestPayloadHint) int {
	score := 0
	switch hint.Format {
	case "json":
		score += 6
	case "query":
		score += 5
	case "form-data":
		score += 4
	case "unknown":
		score += 2
	}
	switch hint.Carrier {
	case "body", "data":
		score += 3
	case "params":
		score += 2
	}
	if hint.Preview != "" {
		score++
	}
	return score
}

func extractStaticConstantParamsFromContext(context []string) url.Values {
	params := make(url.Values)
	for _, item := range context {
		normalized := strings.TrimSpace(item)
		if !strings.HasPrefix(normalized, "参数常量: ") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(normalized, "参数常量: "))
		parts := strings.SplitN(payload, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" || value == "" {
			continue
		}
		if _, exists := params[key]; exists {
			continue
		}
		params.Set(key, value)
	}
	return params
}

func selectPrimaryTraceEndpoint(endpoints []StaticProtocolEndpoint) *StaticProtocolEndpoint {
	bestIndex := -1
	bestScore := -1

	for index, endpoint := range endpoints {
		if strings.TrimSpace(endpoint.TraceID) == "" {
			continue
		}

		score := 0
		if strings.TrimSpace(endpoint.RequestBeforeTransform) != "" {
			score += 4
		}
		if strings.TrimSpace(endpoint.FinalRequestBody) != "" {
			score += 4
		}
		if strings.TrimSpace(endpoint.SessionMaterials["latest_response_ciphertext"]) != "" {
			score += 4
		}
		if strings.TrimSpace(endpoint.SessionMaterials["latest_response_plaintext"]) != "" {
			score += 4
		}
		score += len(endpoint.RequestSteps) * 2
		score += len(endpoint.ResponseSteps) * 2

		if score > bestScore {
			bestScore = score
			bestIndex = index
		}
	}

	if bestIndex < 0 {
		return nil
	}

	selected := endpoints[bestIndex]
	return &selected
}

func extractTraceMatchedEndpoints(traces []database.ProtocolTraceRecord, apiBases []string) []StaticProtocolEndpoint {
	if len(traces) == 0 {
		return nil
	}

	baseURLs := make([]*url.URL, 0, len(apiBases))
	for _, raw := range apiBases {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		baseURLs = append(baseURLs, parsed)
	}

	result := make([]StaticProtocolEndpoint, 0, len(traces))
	seen := make(map[string]struct{}, len(traces))
	for _, trace := range traces {
		requestURL := strings.TrimSpace(trace.RequestURL)
		if requestURL == "" {
			continue
		}

		parsedRequest, err := url.Parse(requestURL)
		if err != nil || parsedRequest == nil || parsedRequest.Scheme == "" || parsedRequest.Host == "" {
			continue
		}

		path := traceMatchedEndpointPath(parsedRequest, baseURLs)
		if path == "" {
			continue
		}

		method := normalizeProtocolMethod(trace.Method)
		if method == "" {
			method = "GET"
		}
		key := method + "\x00" + path
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		result = append(result, StaticProtocolEndpoint{
			Path:                   path,
			Method:                 method,
			Client:                 "protocol-trace",
			RequestPayloadCarrier:  inferObservedPayloadCarrier(method, parsedRequest, strings.TrimSpace(trace.FinalRequestBody)),
			RequestPayloadFormat:   inferObservedPayloadFormat(parsedRequest, strings.TrimSpace(trace.FinalRequestBody), trace.RequestHeaders),
			Context:                []string{"轨迹 ID: " + strings.TrimSpace(trace.TraceID)},
			SourceFile:             "protocol-trace",
			Snippet:                requestURL,
			TraceID:                strings.TrimSpace(trace.TraceID),
			PageURL:                strings.TrimSpace(trace.PageURL),
			RequestURL:             requestURL,
			RequestBeforeTransform: strings.TrimSpace(trace.RequestBeforeTransform),
			FinalRequestBody:       strings.TrimSpace(trace.FinalRequestBody),
			RequestSteps:           trace.RequestSteps,
			ResponseSteps:          trace.ResponseSteps,
			SessionMaterials:       trace.SessionMaterials,
			Algorithms:             trace.Algorithms,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Path == result[j].Path {
			return result[i].Method < result[j].Method
		}
		return result[i].Path < result[j].Path
	})
	return result
}

func extractObservedAPIResourceEndpoints(apiResources []database.APIResource, apiBases []string) []StaticProtocolEndpoint {
	if len(apiResources) == 0 {
		return nil
	}

	baseURLs := make([]*url.URL, 0, len(apiBases))
	for _, raw := range apiBases {
		parsed, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || parsed == nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		baseURLs = append(baseURLs, parsed)
	}

	result := make([]StaticProtocolEndpoint, 0, len(apiResources))
	seen := make(map[string]struct{}, len(apiResources))
	for _, resource := range apiResources {
		rawURL := strings.TrimSpace(resource.URL)
		if rawURL == "" {
			continue
		}

		parsedRequest, err := url.Parse(rawURL)
		if err != nil || parsedRequest == nil || parsedRequest.Scheme == "" || parsedRequest.Host == "" {
			continue
		}

		path := traceMatchedEndpointPath(parsedRequest, baseURLs)
		if path == "" {
			path = strings.TrimSpace(parsedRequest.Path)
			if path == "" {
				path = "/"
			}
		}

		method := normalizeProtocolMethod(resource.Method)
		if method == "" {
			method = "GET"
		}

		key := method + "\x00" + path
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		requestBody := strings.TrimSpace(resource.RequestBody)
		result = append(result, StaticProtocolEndpoint{
			Path:                  path,
			Method:                method,
			Client:                "api-resource",
			RequestPayloadCarrier: inferObservedPayloadCarrier(method, parsedRequest, requestBody),
			RequestPayloadFormat:  inferObservedPayloadFormat(parsedRequest, requestBody, resource.RequestHeaders),
			Context:               []string{"请求记录观测"},
			SourceFile:            "api-resource",
			Snippet:               rawURL,
			RequestURL:            rawURL,
			FinalRequestBody:      requestBody,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Path == result[j].Path {
			return result[i].Method < result[j].Method
		}
		return result[i].Path < result[j].Path
	})

	return result
}

func inferObservedPayloadCarrier(method string, parsedRequest *url.URL, requestBody string) string {
	if parsedRequest == nil {
		return ""
	}
	method = normalizeProtocolMethod(method)
	requestBody = strings.TrimSpace(requestBody)
	if method == "GET" && parsedRequest.RawQuery != "" {
		return "params"
	}
	if requestBody != "" {
		return "body"
	}
	if parsedRequest.RawQuery != "" {
		return "params"
	}
	if method == "GET" {
		return "params"
	}
	return ""
}

func inferObservedPayloadFormat(parsedRequest *url.URL, requestBody string, headers map[string]string) string {
	requestBody = strings.TrimSpace(requestBody)
	contentType := strings.ToLower(strings.TrimSpace(headerValueIgnoreCase(headers, "Content-Type")))
	if requestBody != "" {
		switch {
		case json.Valid([]byte(requestBody)):
			return "json"
		case strings.Contains(contentType, "application/json"):
			return "json"
		case strings.Contains(contentType, "application/x-www-form-urlencoded"):
			return "query"
		case strings.Contains(contentType, "multipart/form-data"):
			return "form-data"
		default:
			return "unknown"
		}
	}
	if parsedRequest != nil && parsedRequest.RawQuery != "" {
		return "query"
	}
	return ""
}

func headerValueIgnoreCase(headers map[string]string, key string) string {
	for existingKey, value := range headers {
		if strings.EqualFold(strings.TrimSpace(existingKey), key) {
			return value
		}
	}
	return ""
}

func traceMatchedEndpointPath(requestURL *url.URL, apiBases []*url.URL) string {
	requestPath := strings.TrimSpace(requestURL.Path)
	if requestPath == "" {
		requestPath = "/"
	}

	for _, base := range apiBases {
		if !strings.EqualFold(base.Scheme, requestURL.Scheme) || !strings.EqualFold(base.Host, requestURL.Host) {
			continue
		}
		basePath := strings.TrimRight(strings.TrimSpace(base.Path), "/")
		if basePath == "" {
			basePath = "/"
		}

		switch {
		case requestPath == basePath:
			if requestURL.RawQuery != "" {
				return "/?" + requestURL.RawQuery
			}
			return "/"
		case strings.HasPrefix(requestPath, basePath+"/"):
			suffix := requestPath[len(basePath):]
			if suffix == "" {
				suffix = "/"
			}
			if requestURL.RawQuery != "" {
				return suffix + "?" + requestURL.RawQuery
			}
			return suffix
		}
	}

	return ""
}

func appendEvidence(target *[]StaticProtocolEvidence, label, fileURL, content, needle string) {
	if len(*target) >= 8 {
		return
	}
	snippet := extractSnippet(content, needle, 280)
	if snippet == "" {
		return
	}
	*target = append(*target, StaticProtocolEvidence{
		Label:   label,
		FileURL: fileURL,
		Snippet: snippet,
	})
}

func extractSnippet(content, needle string, radius int) string {
	idx := strings.Index(content, needle)
	if idx < 0 {
		return ""
	}
	start := idx - radius/2
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + radius/2
	if end > len(content) {
		end = len(content)
	}
	snippet := content[start:end]
	return strings.Join(strings.Fields(snippet), " ")
}

func sortedKeys(set map[string]struct{}) []string {
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)
	return items
}

func decodeBase64(value string) string {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return ""
	}
	return string(decoded)
}

func extractHTTPContextEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	var endpoints []StaticProtocolEndpoint

	endpoints = append(endpoints, extractCallStyleEndpoints(fileURL, content, "axios.get", "axios.get", "GET")...)
	endpoints = append(endpoints, extractCallStyleEndpoints(fileURL, content, "axios.post", "axios.post", "POST")...)
	endpoints = append(endpoints, extractCallStyleEndpoints(fileURL, content, "axios.put", "axios.put", "PUT")...)
	endpoints = append(endpoints, extractCallStyleEndpoints(fileURL, content, "axios.delete", "axios.delete", "DELETE")...)
	endpoints = append(endpoints, extractCallStyleEndpoints(fileURL, content, "axios.patch", "axios.patch", "PATCH")...)
	endpoints = append(endpoints, extractAxiosConfigEndpoints(fileURL, content)...)
	endpoints = append(endpoints, extractAxiosInstanceEndpoints(fileURL, content)...)
	endpoints = append(endpoints, extractFetchEndpoints(fileURL, content)...)
	endpoints = append(endpoints, extractObjectRequestEndpoints(fileURL, content, "$.ajax", "$.ajax")...)
	endpoints = append(endpoints, extractObjectRequestEndpoints(fileURL, content, "jQuery.ajax", "jQuery.ajax")...)
	endpoints = append(endpoints, extractObjectRequestEndpoints(fileURL, content, "uni.request", "uni.request")...)
	endpoints = append(endpoints, extractNamedWrapperContextEndpoints(fileURL, content)...)
	endpoints = append(endpoints, extractObjectRequestEndpoints(fileURL, content, "rn", "rn")...)
	endpoints = append(endpoints, extractPostRequestContextEndpoints(fileURL, content)...)
	endpoints = append(endpoints, extractConfigLikeCallEndpoints(fileURL, content)...)

	return endpoints
}

func extractAxiosInstanceEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	instanceNames := findAxiosInstanceNames(content)
	if len(instanceNames) == 0 {
		return nil
	}

	results := make([]StaticProtocolEndpoint, 0, len(instanceNames)*5)
	methods := []struct {
		name   string
		method string
	}{
		{name: "get", method: "GET"},
		{name: "post", method: "POST"},
		{name: "put", method: "PUT"},
		{name: "delete", method: "DELETE"},
		{name: "patch", method: "PATCH"},
	}
	for _, instanceName := range instanceNames {
		for _, item := range methods {
			client := "axios-instance:" + instanceName + "." + item.name
			results = append(results, extractCallStyleEndpoints(fileURL, content, instanceName+"."+item.name, client, item.method)...)
		}
	}
	return results
}

func findAxiosInstanceNames(content string) []string {
	pattern := regexp.MustCompile(`(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*[A-Za-z_$][\w$]*\s*\.\s*create\(\s*\{`)
	matches := pattern.FindAllStringSubmatch(content, -1)
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		names = appendUniqueStrings(names, strings.TrimSpace(match[1]))
	}
	return names
}

func extractCallStyleEndpoints(fileURL, content, callee, client, defaultMethod string) []StaticProtocolEndpoint {
	matches := findCallExpressions(content, callee)
	results := make([]StaticProtocolEndpoint, 0, len(matches))
	for _, match := range matches {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}
		path := parseRequestPath(args[0])
		if path == "" {
			continue
		}
		params := collectPathAndQueryParams(path)
		context := extractNearbyFunctionContext(content, match.Index)
		payloadCarrier := ""
		payloadFormat := ""
		payloadPreview := ""
		if len(args) > 1 {
			secondArg := strings.TrimSpace(args[1])
			resolvedSecondArg := resolveStaticArgumentExpression(content, secondArg)
			if defaultMethod == "GET" || defaultMethod == "DELETE" {
				params = mergeStaticParams(params, collectParamsFromConfigArg(resolvedSecondArg))
				payloadCarrier, payloadFormat, payloadPreview = detectGETCallPayloadMetadata(resolvedSecondArg)
				context = appendStaticHeaderContext(context, resolvedSecondArg, content)
			} else {
				params = mergeStaticParams(params, collectParamsFromBodyArg(resolvedSecondArg))
				payloadCarrier, payloadFormat, payloadPreview = detectPayloadMetadata("body", resolvedSecondArg)
				if len(args) > 2 {
					resolvedThirdArg := resolveStaticArgumentExpression(content, args[2])
					params = mergeStaticParams(params, collectParamsFromConfigArg(resolvedThirdArg))
					context = appendStaticHeaderContext(context, resolvedThirdArg, content)
				}
			}
			if identifierPattern.MatchString(secondArg) {
				context = appendUniqueStrings(context, "数据变量: "+secondArg)
			}
		}
		results = append(results, StaticProtocolEndpoint{
			Path:                  path,
			Method:                defaultMethod,
			Client:                client,
			Params:                params,
			RequestPayloadCarrier: payloadCarrier,
			RequestPayloadFormat:  payloadFormat,
			RequestPayloadPreview: payloadPreview,
			Context:               context,
			SourceFile:            fileURL,
			Snippet:               normalizeSnippet(match.CallText),
		})
	}
	return results
}

func extractAxiosConfigEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	matches := findCallExpressions(content, "axios")
	results := make([]StaticProtocolEndpoint, 0, len(matches))
	for _, match := range matches {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}
		config := extractResolvedTopLevelObjectFields(content, args[0])
		if len(config) == 0 {
			continue
		}
		path := parseRequestPath(config["url"])
		if path == "" {
			continue
		}
		method := strings.ToUpper(parseStringLiteral(config["method"]))
		if method == "" {
			method = "GET"
		}
		params := collectPathAndQueryParams(path)
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["data"])))
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["body"])))
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["params"])))
		config = resolveStaticConfigFields(content, config)
		payloadCarrier, payloadFormat, payloadPreview := detectPayloadMetadataFromConfig(config)
		context := extractNearbyFunctionContext(content, match.Index)
		context = appendStaticHeaderContext(context, args[0], content)
		for _, field := range []string{"data", "params", "body"} {
			value := strings.TrimSpace(config[field])
			if identifierPattern.MatchString(value) {
				context = appendUniqueStrings(context, "数据变量: "+value)
			}
		}
		results = append(results, StaticProtocolEndpoint{
			Path:                  path,
			Method:                method,
			Client:                "axios(config)",
			Params:                params,
			RequestPayloadCarrier: payloadCarrier,
			RequestPayloadFormat:  payloadFormat,
			RequestPayloadPreview: payloadPreview,
			Context:               context,
			SourceFile:            fileURL,
			Snippet:               normalizeSnippet(match.CallText),
		})
	}
	return results
}

func extractFetchEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	matches := findCallExpressions(content, "fetch")
	results := make([]StaticProtocolEndpoint, 0, len(matches))
	for _, match := range matches {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}
		path := parseRequestPath(args[0])
		if path == "" {
			continue
		}
		method := "GET"
		params := collectPathAndQueryParams(path)
		context := extractNearbyFunctionContext(content, match.Index)
		payloadCarrier := ""
		payloadFormat := ""
		payloadPreview := ""
		if len(args) > 1 {
			config := extractResolvedTopLevelObjectFields(content, args[1])
			if value := strings.ToUpper(parseStringLiteral(config["method"])); value != "" {
				method = value
			}
			params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["body"])))
			params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["params"])))
			config = resolveStaticConfigFields(content, config)
			payloadCarrier, payloadFormat, payloadPreview = detectPayloadMetadataFromConfig(config)
			context = appendStaticHeaderContext(context, args[1], content)
			if identifierPattern.MatchString(strings.TrimSpace(config["body"])) {
				context = appendUniqueStrings(context, "数据变量: "+strings.TrimSpace(config["body"]))
			}
		}
		results = append(results, StaticProtocolEndpoint{
			Path:                  path,
			Method:                method,
			Client:                "fetch",
			Params:                params,
			RequestPayloadCarrier: payloadCarrier,
			RequestPayloadFormat:  payloadFormat,
			RequestPayloadPreview: payloadPreview,
			Context:               context,
			SourceFile:            fileURL,
			Snippet:               normalizeSnippet(match.CallText),
		})
	}
	return results
}

func extractObjectRequestEndpoints(fileURL, content, callee, client string) []StaticProtocolEndpoint {
	matches := findCallExpressions(content, callee)
	results := make([]StaticProtocolEndpoint, 0, len(matches))
	for _, match := range matches {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}
		config := extractResolvedTopLevelObjectFields(content, args[0])
		if len(config) == 0 {
			continue
		}
		path := parseRequestPath(config["url"])
		if path == "" {
			continue
		}
		method := strings.ToUpper(parseStringLiteral(config["method"]))
		if method == "" {
			method = strings.ToUpper(parseStringLiteral(config["type"]))
		}
		if method == "" {
			method = "GET"
		}
		params := collectPathAndQueryParams(path)
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["data"])))
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["body"])))
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["params"])))
		config = resolveStaticConfigFields(content, config)
		payloadCarrier, payloadFormat, payloadPreview := detectPayloadMetadataFromConfig(config)
		context := extractNearbyFunctionContext(content, match.Index)
		context = appendStaticHeaderContext(context, args[0], content)
		for _, field := range []string{"data", "params", "body"} {
			value := strings.TrimSpace(config[field])
			if identifierPattern.MatchString(value) {
				context = appendUniqueStrings(context, "数据变量: "+value)
			}
		}
		results = append(results, StaticProtocolEndpoint{
			Path:                  path,
			Method:                method,
			Client:                client,
			Params:                params,
			RequestPayloadCarrier: payloadCarrier,
			RequestPayloadFormat:  payloadFormat,
			RequestPayloadPreview: payloadPreview,
			Context:               context,
			SourceFile:            fileURL,
			Snippet:               normalizeSnippet(match.CallText),
		})
	}
	return results
}

func extractPostRequestContextEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	matches := findCallExpressions(content, "postRequest")
	results := make([]StaticProtocolEndpoint, 0, len(matches))
	for _, match := range matches {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}
		path := parseRequestPath(args[0])
		if path == "" {
			continue
		}
		params := collectPathAndQueryParams(path)
		context := extractNearbyFunctionContext(content, match.Index)
		payloadCarrier := ""
		payloadFormat := ""
		payloadPreview := ""
		if len(args) > 1 {
			resolvedSecondArg := resolveStaticArgumentExpression(content, args[1])
			params = mergeStaticParams(params, collectParamsFromBodyArg(resolvedSecondArg))
			payloadCarrier, payloadFormat, payloadPreview = detectPayloadMetadata("body", resolvedSecondArg)
			if identifierPattern.MatchString(strings.TrimSpace(args[1])) {
				context = appendUniqueStrings(context, "数据变量: "+strings.TrimSpace(args[1]))
			}
		}
		results = append(results, StaticProtocolEndpoint{
			Path:                  path,
			Method:                "POST",
			Client:                "postRequest",
			Params:                params,
			RequestPayloadCarrier: payloadCarrier,
			RequestPayloadFormat:  payloadFormat,
			RequestPayloadPreview: payloadPreview,
			Context:               context,
			SourceFile:            fileURL,
			Snippet:               normalizeSnippet(match.CallText),
		})
	}
	return results
}

func extractConfigLikeCallEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	matches := findConfigLikeCallExpressions(content)
	results := make([]StaticProtocolEndpoint, 0, len(matches))
	for _, match := range matches {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}

		config := extractResolvedTopLevelObjectFields(content, args[0])
		if len(config) == 0 || !isLikelyRequestConfigObject(config) {
			continue
		}

		path := parseRequestPath(config["url"])
		if path == "" {
			continue
		}

		method := strings.ToUpper(parseStringLiteral(config["method"]))
		if method == "" {
			method = strings.ToUpper(parseStringLiteral(config["type"]))
		}
		if method == "" {
			method = "GET"
		}

		params := collectPathAndQueryParams(path)
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["data"])))
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["body"])))
		params = mergeStaticParams(params, collectParamsFromBodyArg(resolveStaticArgumentExpression(content, config["params"])))

		config = resolveStaticConfigFields(content, config)
		payloadCarrier, payloadFormat, payloadPreview := detectPayloadMetadataFromConfig(config)
		context := extractNearbyFunctionContext(content, match.Index)
		context = appendStaticHeaderContext(context, args[0], content)
		for _, field := range []string{"data", "params", "body"} {
			value := strings.TrimSpace(config[field])
			if identifierPattern.MatchString(value) {
				context = appendUniqueStrings(context, "数据变量: "+value)
			}
		}

		results = append(results, StaticProtocolEndpoint{
			Path:                  path,
			Method:                method,
			Client:                "wrapper-config:" + match.Callee,
			Params:                params,
			RequestPayloadCarrier: payloadCarrier,
			RequestPayloadFormat:  payloadFormat,
			RequestPayloadPreview: payloadPreview,
			Context:               context,
			SourceFile:            fileURL,
			Snippet:               normalizeSnippet(match.CallText),
		})
	}
	return results
}

type namedWrapperDefinition struct {
	Name   string
	Params []string
	Body   string
}

func extractNamedWrapperContextEndpoints(fileURL, content string) []StaticProtocolEndpoint {
	wrappers := findNamedWrapperDefinitions(content)
	if len(wrappers) == 0 {
		return nil
	}

	results := make([]StaticProtocolEndpoint, 0, len(wrappers)*2)
	for _, wrapper := range wrappers {
		innerEndpoints := extractObjectRequestEndpoints(fileURL, wrapper.Body, "rn", "rn")
		if len(innerEndpoints) == 0 {
			continue
		}

		invocationMappings := buildWrapperInvocationMappings(content, wrapper.Name, wrapper.Params)
		for _, endpoint := range innerEndpoints {
			endpoint.Client = "wrapper:" + wrapper.Name + " -> " + endpoint.Client
			endpoint.Context = appendUniqueStrings(endpoint.Context, "封装函数: "+wrapper.Name)
			if len(wrapper.Params) > 0 {
				endpoint.Context = appendUniqueStrings(endpoint.Context, "封装形参: "+strings.Join(wrapper.Params, ", "))
			}

			requestConfigArg := findRequestConfigArgFromSnippet(endpoint.Snippet)
			if requestConfigArg != "" {
				endpoint.Context = appendWrapperParamContext(
					endpoint.Context,
					wrapper.Params,
					collectRequestParamBindings(requestConfigArg),
					invocationMappings,
				)
			}
			results = append(results, endpoint)
		}
	}

	return results
}

func findNamedWrapperDefinitions(content string) []namedWrapperDefinition {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`Iv\([^,]+,\s*["']([A-Za-z_$][\w$]*)["']\s*,\s*\(function\s*\(([^)]{0,240})\)\s*\{`),
		regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*[:=]\s*function\s*\(([^)]{0,240})\)\s*\{`),
	}

	definitions := make([]namedWrapperDefinition, 0, 8)
	seen := make(map[string]struct{})
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatchIndex(content, -1)
		for _, match := range matches {
			if len(match) < 6 {
				continue
			}
			name := strings.TrimSpace(content[match[2]:match[3]])
			if name == "" {
				continue
			}

			openBraceIndex := match[1] - 1
			body, _, ok := extractBalancedJS(content, openBraceIndex, '{', '}')
			if !ok || !strings.Contains(body, "rn(") {
				continue
			}

			key := name + "\x00" + strings.TrimSpace(content[match[4]:match[5]])
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}

			definitions = append(definitions, namedWrapperDefinition{
				Name:   name,
				Params: normalizeFunctionParams(content[match[4]:match[5]]),
				Body:   body,
			})
		}
	}

	return definitions
}

func findRequestConfigArgFromSnippet(snippet string) string {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return ""
	}
	openIndex := strings.Index(snippet, "(")
	if openIndex < 0 {
		return ""
	}
	args, _, ok := extractBalancedJS(snippet, openIndex, '(', ')')
	if !ok {
		return ""
	}
	parts := splitTopLevelCSV(args)
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func collectRequestParamBindings(configArg string) map[string]string {
	config := extractTopLevelObjectFields(configArg)
	if len(config) == 0 {
		return nil
	}

	bindings := make(map[string]string)
	for _, field := range []string{"params", "data", "body"} {
		fields := extractTopLevelObjectFields(config[field])
		for key, value := range fields {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			bindings[key] = value
		}
	}
	return bindings
}

func resolveStaticArgumentExpression(content, raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if fields := extractTopLevelObjectFields(trimmed); len(fields) > 0 {
		return trimmed
	}

	if strings.HasPrefix(trimmed, "JSON.stringify(") {
		if inner, _, ok := extractBalancedJS(trimmed, len("JSON.stringify"), '(', ')'); ok {
			if resolved := resolveStaticArgumentExpression(content, inner); resolved != "" {
				return resolved
			}
		}
	}

	if !identifierPattern.MatchString(trimmed) {
		return trimmed
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:var|let|const)\s+` + regexp.QuoteMeta(trimmed) + `\s*=\s*`),
		regexp.MustCompile(`(?:^|[;\n])\s*` + regexp.QuoteMeta(trimmed) + `\s*=\s*`),
	}

	for _, pattern := range patterns {
		indexes := pattern.FindAllStringIndex(content, -1)
		for idx := len(indexes) - 1; idx >= 0; idx-- {
			assignEnd := indexes[idx][1]
			for assignEnd < len(content) && (content[assignEnd] == ' ' || content[assignEnd] == '\n' || content[assignEnd] == '\r' || content[assignEnd] == '\t') {
				assignEnd++
			}
			if assignEnd >= len(content) || content[assignEnd] != '{' {
				continue
			}
			_, endIndex, ok := extractBalancedJS(content, assignEnd, '{', '}')
			if !ok {
				continue
			}
			return content[assignEnd : endIndex+1]
		}
	}

	return trimmed
}

func extractResolvedTopLevelObjectFields(content, raw string) map[string]string {
	return extractTopLevelObjectFields(resolveStaticArgumentExpression(content, raw))
}

func resolveStaticConfigFields(content string, fields map[string]string) map[string]string {
	if len(fields) == 0 {
		return fields
	}

	resolved := make(map[string]string, len(fields))
	for key, value := range fields {
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "params", "data", "body", "headers":
			resolved[key] = resolveStaticArgumentExpression(content, value)
		default:
			resolved[key] = value
		}
	}
	return resolved
}

func hasTransportPayloadFields(fields map[string]string) bool {
	for _, key := range []string{"params", "data", "body"} {
		if strings.TrimSpace(fields[key]) != "" {
			return true
		}
	}
	return false
}

func isLikelyRequestConfigObject(fields map[string]string) bool {
	for _, key := range []string{"method", "url", "headers", "baseurl", "timeout", "responsetype", "withcredentials"} {
		for field := range fields {
			if strings.EqualFold(strings.TrimSpace(field), key) {
				return true
			}
		}
	}
	return hasTransportPayloadFields(fields)
}

func detectGETCallPayloadMetadata(raw string) (string, string, string) {
	fields := extractTopLevelObjectFields(raw)
	if len(fields) == 0 {
		return detectPayloadMetadata("config", raw)
	}
	if isLikelyRequestConfigObject(fields) {
		return detectPayloadMetadata("config", raw)
	}
	return detectPayloadMetadata("body", raw)
}

func buildWrapperInvocationMappings(content, wrapperName string, wrapperParams []string) map[string][]string {
	if wrapperName == "" || len(wrapperParams) == 0 {
		return nil
	}

	results := make(map[string][]string)
	for _, match := range findCallExpressions(content, wrapperName) {
		args := splitTopLevelCSV(match.Args)
		if len(args) == 0 {
			continue
		}

		for index, paramName := range wrapperParams {
			if index >= len(args) {
				break
			}
			arg := strings.TrimSpace(args[index])
			if arg == "" {
				continue
			}
			results[paramName] = appendUniqueStrings(results[paramName], arg)
			results[paramName] = appendUniqueStrings(results[paramName], "调用: "+normalizeSnippet(match.CallText))
		}
	}

	return results
}

func appendWrapperParamContext(
	base []string,
	wrapperParams []string,
	bindings map[string]string,
	invocationMappings map[string][]string,
) []string {
	if len(bindings) == 0 {
		return base
	}

	paramIndex := make(map[string]int, len(wrapperParams))
	for index, paramName := range wrapperParams {
		paramIndex[paramName] = index
	}

	keys := make([]string, 0, len(bindings))
	for key := range bindings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := strings.TrimSpace(bindings[key])
		if value == "" {
			continue
		}

		if literal := parseStringLiteral(value); literal != "" {
			base = appendUniqueStrings(base, "参数常量: "+key+" = "+literal)
			continue
		}

		if _, exists := paramIndex[value]; exists {
			base = appendUniqueStrings(base, "参数映射: "+key+" <- "+value)
			for _, sample := range invocationMappings[value] {
				if strings.HasPrefix(sample, "调用: ") {
					base = appendUniqueStrings(base, "调用样例: "+strings.TrimPrefix(sample, "调用: "))
					continue
				}
				base = appendUniqueStrings(base, "实参样例: "+key+" <- "+sample)
			}
			continue
		}

		base = appendUniqueStrings(base, "参数表达式: "+key+" <- "+value)
	}

	return base
}

func appendStaticHeaderContext(base []string, configArg, content string) []string {
	config := extractTopLevelObjectFields(configArg)
	if len(config) == 0 {
		return base
	}

	headers := extractTopLevelObjectFields(config["headers"])
	if len(headers) == 0 {
		return base
	}

	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		rawValue := strings.TrimSpace(headers[key])
		if rawValue == "" {
			continue
		}

		if literal := parseStringLiteral(rawValue); literal != "" {
			if isReusableStaticHeader(key, literal) {
				base = appendUniqueStrings(base, "请求头常量: "+key+" = "+literal)
			}
			continue
		}

		base = appendSourceContextHints(base, key, rawValue, content)
	}

	return base
}

func appendSourceContextHints(base []string, key, rawValue, content string) []string {
	value := strings.TrimSpace(rawValue)
	if value == "" {
		return base
	}

	if strings.Contains(value, "process.env.") {
		base = appendUniqueStrings(base, "来源线索: header "+key+" <- process.env")
	}
	if strings.Contains(value, "window.__") {
		base = appendUniqueStrings(base, "来源线索: header "+key+" <- window config")
	}
	if strings.Contains(value, "localStorage.") || strings.Contains(value, "localStorage.getItem(") {
		base = appendUniqueStrings(base, "来源线索: header "+key+" <- localStorage")
	}
	if strings.Contains(value, "sessionStorage.") || strings.Contains(value, "sessionStorage.getItem(") {
		base = appendUniqueStrings(base, "来源线索: header "+key+" <- sessionStorage")
	}
	if strings.Contains(value, "document.cookie") {
		base = appendUniqueStrings(base, "来源线索: header "+key+" <- cookie")
	}

	for _, resolved := range resolveStaticStringExpression(content, value, 0) {
		if isReusableStaticHeader(key, resolved) {
			base = appendUniqueStrings(base, "请求头常量: "+key+" = "+resolved)
		}
	}
	return base
}

func detectPayloadMetadataFromConfig(config map[string]string) (string, string, string) {
	for _, carrier := range []string{"body", "data", "params"} {
		if value := strings.TrimSpace(config[carrier]); value != "" {
			return detectPayloadMetadata(carrier, value)
		}
	}
	return "", "", ""
}

func extractStaticHeadersFromContext(context []string) map[string]string {
	headers := make(map[string]string)
	for _, item := range context {
		normalized := strings.TrimSpace(item)
		if !strings.HasPrefix(normalized, "请求头常量: ") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(normalized, "请求头常量: "))
		parts := strings.SplitN(payload, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if !isReusableStaticHeader(key, value) {
			continue
		}
		if _, exists := headers[key]; exists {
			continue
		}
		headers[key] = value
	}
	return headers
}

func isReusableStaticHeader(key, value string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.TrimSpace(value)
	if key == "" || value == "" {
		return false
	}

	switch key {
	case "authorization", "cookie", "x-access-token", "proxy-authorization":
		return false
	}
	return true
}

func detectPayloadMetadata(carrier, raw string) (string, string, string) {
	carrier = strings.TrimSpace(carrier)
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", ""
	}

	if carrier == "config" {
		if configFields := extractTopLevelObjectFields(raw); len(configFields) > 0 {
			if nestedCarrier, nestedFormat, nestedPreview := detectPayloadMetadataFromConfig(configFields); nestedCarrier != "" || nestedFormat != "" || nestedPreview != "" {
				return nestedCarrier, nestedFormat, nestedPreview
			}
		}
	}

	format := "unknown"
	switch {
	case carrier == "params":
		format = "query"
	case strings.HasPrefix(raw, "JSON.stringify("):
		format = "json"
	case strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}"):
		format = "json"
	case strings.Contains(raw, "FormData("):
		format = "form-data"
	case strings.Contains(raw, "URLSearchParams("):
		format = "query"
	}

	return carrier, format, normalizeSnippet(raw)
}

type callExpression struct {
	Index    int
	Args     string
	CallText string
	Callee   string
}

func findCallExpressions(content, callee string) []callExpression {
	pattern := callee + "("
	results := make([]callExpression, 0, 8)
	searchFrom := 0
	for {
		idx := strings.Index(content[searchFrom:], pattern)
		if idx < 0 {
			break
		}
		callStart := searchFrom + idx
		openIndex := callStart + len(callee)
		args, endIndex, ok := extractBalancedJS(content, openIndex, '(', ')')
		if ok {
			results = append(results, callExpression{
				Index:    callStart,
				Args:     args,
				CallText: content[callStart : endIndex+1],
				Callee:   callee,
			})
			searchFrom = endIndex + 1
			continue
		}
		searchFrom = callStart + len(pattern)
	}
	return results
}

func findConfigLikeCallExpressions(content string) []callExpression {
	matches := configLikeCallPattern.FindAllStringSubmatchIndex(content, -1)
	results := make([]callExpression, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 6 {
			continue
		}

		callee := strings.TrimSpace(content[match[4]:match[5]])
		if callee == "" {
			continue
		}

		callStart := match[4]
		openIndex := strings.Index(content[callStart:], "(")
		if openIndex < 0 {
			continue
		}
		openIndex += callStart

		args, endIndex, ok := extractBalancedJS(content, openIndex, '(', ')')
		if !ok {
			continue
		}

		key := callee + "\x00" + strconv.Itoa(callStart)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		results = append(results, callExpression{
			Index:    callStart,
			Args:     args,
			CallText: content[callStart : endIndex+1],
			Callee:   callee,
		})
	}
	return results
}

func extractBalancedJS(content string, openIndex int, openChar, closeChar byte) (string, int, bool) {
	if openIndex < 0 || openIndex >= len(content) || content[openIndex] != openChar {
		return "", 0, false
	}
	depth := 0
	quote := byte(0)
	escaped := false
	for index := openIndex; index < len(content); index++ {
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
		if ch == '"' || ch == '\'' || ch == '`' {
			quote = ch
			continue
		}
		if ch == openChar {
			depth++
			continue
		}
		if ch == closeChar {
			depth--
			if depth == 0 {
				return content[openIndex+1 : index], index, true
			}
		}
	}
	return "", 0, false
}

func splitTopLevelCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	var parts []string
	start := 0
	parenDepth := 0
	braceDepth := 0
	bracketDepth := 0
	quote := byte(0)
	escaped := false

	for index := 0; index < len(value); index++ {
		ch := value[index]
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
			parenDepth--
		case '{':
			braceDepth++
		case '}':
			braceDepth--
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case ',':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 {
				part := strings.TrimSpace(value[start:index])
				if part != "" {
					parts = append(parts, part)
				}
				start = index + 1
			}
		}
	}

	if tail := strings.TrimSpace(value[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func parseStringLiteral(value string) string {
	trimmed := strings.TrimSpace(value)
	match := stringLiteralPattern.FindStringSubmatch(trimmed)
	if len(match) > 1 {
		if strings.HasPrefix(trimmed, "`") && strings.Contains(match[1], "${") {
			return ""
		}
		return match[1]
	}
	if strings.HasPrefix(trimmed, "`") && strings.HasSuffix(trimmed, "`") && !strings.Contains(trimmed, "${") {
		return strings.Trim(trimmed, "`")
	}
	return ""
}

func parseRequestPath(value string) string {
	if literal := parseStringLiteral(value); literal != "" {
		if isLikelyStaticRequestPath(literal) {
			return literal
		}
		return ""
	}

	trimmed := strings.TrimSpace(value)
	if template := resolveStaticTemplateLiteral("", trimmed, 0); template != "" {
		if isLikelyStaticRequestPath(template) {
			return template
		}
		return ""
	}
	match := concatPathPattern.FindStringSubmatch(trimmed)
	if len(match) > 1 {
		resolved := strings.TrimSpace(match[1])
		if isLikelyStaticRequestPath(resolved) {
			return resolved
		}
	}

	return ""
}

func isLikelyStaticRequestPath(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") || strings.HasPrefix(trimmed, "//") {
		return true
	}

	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") {
		return true
	}

	if strings.Contains(trimmed, "/") {
		return true
	}

	if strings.HasPrefix(trimmed, "?") && strings.Contains(trimmed, "=") {
		return true
	}

	return false
}

func resolveStaticStringExpression(content interface{}, expr string, depth int) []string {
	if depth > 6 {
		return nil
	}
	source, _ := content.(string)
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	if literal := parseStringLiteral(expr); literal != "" {
		return []string{literal}
	}

	if resolved := resolveStaticTemplateLiteral(source, expr, depth); resolved != "" {
		return []string{resolved}
	}

	if inner, _, ok := extractBalancedJS(expr, len("String("), '(', ')'); ok && strings.HasPrefix(expr, "String(") {
		return resolveStaticStringExpression(source, inner, depth+1)
	}

	if parts := splitStaticConcatenation(expr); len(parts) > 1 {
		acc := []string{""}
		for _, part := range parts {
			resolved := resolveStaticStringExpression(source, part, depth+1)
			if len(resolved) == 0 {
				return nil
			}
			next := make([]string, 0, len(acc)*len(resolved))
			for _, prefix := range acc {
				for _, item := range resolved {
					next = appendUniqueStrings(next, prefix+item)
				}
			}
			acc = next
		}
		return acc
	}

	if memberValues := resolveStaticMemberExpression(source, expr, depth+1); len(memberValues) > 0 {
		return memberValues
	}

	if strings.HasSuffix(expr, ".baseURL") {
		return resolveStaticClientBaseRoots(source, strings.TrimSuffix(expr, ".baseURL"))
	}
	if identifierPattern.MatchString(expr) {
		return resolveStaticIdentifierRoots(source, expr)
	}
	if strings.Contains(expr, ".") {
		memberParts := strings.Split(expr, ".")
		if len(memberParts) >= 2 {
			member := memberParts[len(memberParts)-1]
			if roots := resolveStaticIdentifierRoots(source, expr); len(roots) > 0 {
				return roots
			}
			return resolveStaticIdentifierRoots(source, member)
		}
	}

	return nil
}

func resolveStaticMemberExpression(content, expr string, depth int) []string {
	expr = strings.TrimSpace(expr)
	if !strings.Contains(expr, ".") {
		return nil
	}

	parts := strings.Split(expr, ".")
	if len(parts) != 2 {
		return nil
	}
	objectName := strings.TrimSpace(parts[0])
	fieldName := strings.TrimSpace(parts[1])
	if objectName == "" || fieldName == "" {
		return nil
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:var|let|const)\s+` + regexp.QuoteMeta(objectName) + `\s*=\s*(\{[^;]+\})`),
		regexp.MustCompile(regexp.QuoteMeta(objectName) + `\s*=\s*(\{[^;]+\})`),
	}

	values := make([]string, 0, 2)
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			fields := extractTopLevelObjectFields(strings.TrimSpace(match[1]))
			fieldValue, ok := fields[fieldName]
			if !ok {
				continue
			}
			for _, resolved := range resolveStaticStringExpression(content, fieldValue, depth+1) {
				values = appendUniqueStrings(values, resolved)
			}
		}
	}
	return values
}

func resolveStaticTemplateLiteral(content, expr string, depth int) string {
	expr = strings.TrimSpace(expr)
	if !strings.HasPrefix(expr, "`") || !strings.HasSuffix(expr, "`") {
		return ""
	}
	body := expr[1 : len(expr)-1]
	if !strings.Contains(body, "${") {
		return body
	}

	var builder strings.Builder
	for len(body) > 0 {
		index := strings.Index(body, "${")
		if index < 0 {
			builder.WriteString(body)
			break
		}
		builder.WriteString(body[:index])
		inner, endIndex, ok := extractBalancedJS(body[index:], 1, '{', '}')
		if !ok {
			return ""
		}
		values := resolveStaticStringExpression(content, inner, depth+1)
		if len(values) != 1 {
			return ""
		}
		builder.WriteString(values[0])
		body = body[index+endIndex+1:]
	}
	return builder.String()
}

func splitStaticConcatenation(value string) []string {
	parts := make([]string, 0, 3)
	quote := byte(0)
	escaped := false
	parenDepth := 0
	braceDepth := 0
	bracketDepth := 0
	start := 0
	for index := 0; index < len(value); index++ {
		ch := value[index]
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
			parenDepth--
		case '{':
			braceDepth++
		case '}':
			braceDepth--
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case '+':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 {
				part := strings.TrimSpace(value[start:index])
				if part != "" {
					parts = append(parts, part)
				}
				start = index + 1
			}
		}
	}
	if tail := strings.TrimSpace(value[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func extractTopLevelObjectFields(value string) map[string]string {
	trimmed := strings.TrimSpace(value)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return nil
	}
	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	fields := make(map[string]string)
	for _, part := range splitTopLevelCSV(inner) {
		key, fieldValue, ok := splitTopLevelKeyValue(part)
		if !ok {
			continue
		}
		fields[key] = fieldValue
	}
	return fields
}

func splitTopLevelKeyValue(value string) (string, string, bool) {
	quote := byte(0)
	escaped := false
	parenDepth := 0
	braceDepth := 0
	bracketDepth := 0
	for index := 0; index < len(value); index++ {
		ch := value[index]
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
			parenDepth--
		case '{':
			braceDepth++
		case '}':
			braceDepth--
		case '[':
			bracketDepth++
		case ']':
			bracketDepth--
		case ':':
			if parenDepth == 0 && braceDepth == 0 && bracketDepth == 0 {
				key := strings.TrimSpace(value[:index])
				key = strings.Trim(key, `"'`+"`")
				return key, strings.TrimSpace(value[index+1:]), key != ""
			}
		}
	}
	return "", "", false
}

func collectPathAndQueryParams(path string) []StaticProtocolParam {
	params := make([]StaticProtocolParam, 0, 6)
	if strings.TrimSpace(path) == "" {
		return params
	}
	for _, segment := range strings.Split(path, "/") {
		if strings.HasPrefix(segment, ":") && len(segment) > 1 {
			params = appendStaticParam(params, segment[1:], "path")
		}
	}
	if queryIndex := strings.Index(path, "?"); queryIndex >= 0 && queryIndex < len(path)-1 {
		for _, pair := range strings.Split(path[queryIndex+1:], "&") {
			key := strings.TrimSpace(strings.SplitN(pair, "=", 2)[0])
			if key != "" {
				params = appendStaticParam(params, key, "query")
			}
		}
	}
	return params
}

func collectParamsFromConfigArg(value string) []StaticProtocolParam {
	fields := extractTopLevelObjectFields(value)
	if len(fields) == 0 {
		return nil
	}

	if !hasTransportPayloadFields(fields) && !isLikelyRequestConfigObject(fields) {
		return collectParamsFromBodyArg(value)
	}

	params := make([]StaticProtocolParam, 0, 6)
	for _, field := range []string{"params", "data", "body"} {
		params = mergeStaticParams(params, collectParamsFromBodyArg(fields[field]))
	}
	return params
}

func collectParamsFromBodyArg(value string) []StaticProtocolParam {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}

	if strings.HasPrefix(trimmed, "JSON.stringify(") {
		if inner, _, ok := extractBalancedJS(trimmed, len("JSON.stringify"), '(', ')'); ok {
			trimmed = strings.TrimSpace(inner)
		}
	}

	if fields := extractTopLevelObjectFields(trimmed); len(fields) > 0 {
		params := make([]StaticProtocolParam, 0, len(fields))
		for key, nestedValue := range fields {
			params = appendStaticParam(params, key, "body")
			if nestedFields := extractTopLevelObjectFields(nestedValue); len(nestedFields) > 0 {
				for nestedKey := range nestedFields {
					params = appendStaticParam(params, nestedKey, "body.nested")
				}
			}
		}
		return params
	}

	if identifierPattern.MatchString(trimmed) {
		return []StaticProtocolParam{{Name: trimmed, Source: "variable"}}
	}

	return nil
}

func extractNearbyFunctionContext(content string, callIndex int) []string {
	start := callIndex - 320
	if start < 0 {
		start = 0
	}
	window := content[start:callIndex]
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`function\s+([A-Za-z_$][\w$]*)?\s*\(([^)]{0,160})\)\s*\{?$`),
		regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*[:=]\s*function\s*\(([^)]{0,160})\)\s*\{?$`),
		regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*[:=]\s*\(([^)]{0,160})\)\s*=>\s*\{?$`),
	}
	context := make([]string, 0, 2)
	for _, pattern := range patterns {
		matches := pattern.FindAllStringSubmatch(window, -1)
		if len(matches) == 0 {
			continue
		}
		last := matches[len(matches)-1]
		if len(last) < 3 {
			continue
		}
		name := strings.TrimSpace(last[1])
		params := normalizeFunctionParams(last[2])
		if name != "" {
			context = appendUniqueStrings(context, "函数: "+name)
		}
		if len(params) > 0 {
			context = appendUniqueStrings(context, "函数参数: "+strings.Join(params, ", "))
		}
	}
	return context
}

func normalizeFunctionParams(value string) []string {
	rawParts := splitTopLevelCSV(value)
	params := make([]string, 0, len(rawParts))
	for _, part := range rawParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		part = strings.Split(part, "=")[0]
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "{}[]")
		if part != "" {
			params = append(params, part)
		}
	}
	return params
}

func mergeStaticParams(base, extra []StaticProtocolParam) []StaticProtocolParam {
	merged := append([]StaticProtocolParam{}, base...)
	for _, param := range extra {
		merged = appendStaticParam(merged, param.Name, param.Source)
	}
	return merged
}

func appendStaticParam(params []StaticProtocolParam, name, source string) []StaticProtocolParam {
	name = strings.TrimSpace(name)
	if name == "" {
		return params
	}
	for index := range params {
		if params[index].Name == name {
			if params[index].Source == "" && source != "" {
				params[index].Source = source
			}
			return params
		}
	}
	return append(params, StaticProtocolParam{Name: name, Source: source})
}

func appendUniqueStrings(items []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func normalizeSnippet(value string) string {
	return strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
}

func mergeStaticEndpoints(base, extra StaticProtocolEndpoint) StaticProtocolEndpoint {
	base.Client = mergeStaticClientLabels(base.Client, extra.Client)
	if base.TraceID == "" {
		base.TraceID = extra.TraceID
	}
	if base.PageURL == "" {
		base.PageURL = extra.PageURL
	}
	if base.RequestURL == "" {
		base.RequestURL = extra.RequestURL
	}
	if base.RequestBeforeTransform == "" {
		base.RequestBeforeTransform = extra.RequestBeforeTransform
	}
	if base.FinalRequestBody == "" {
		base.FinalRequestBody = extra.FinalRequestBody
	}
	if len(base.RequestSteps) == 0 {
		base.RequestSteps = extra.RequestSteps
	}
	if len(base.ResponseSteps) == 0 {
		base.ResponseSteps = extra.ResponseSteps
	}
	if len(base.SessionMaterials) == 0 {
		base.SessionMaterials = extra.SessionMaterials
	}
	if len(base.Algorithms) == 0 {
		base.Algorithms = extra.Algorithms
	}
	if shouldPreferObservedPayloadMetadata(base, extra) {
		base.RequestPayloadCarrier = extra.RequestPayloadCarrier
		base.RequestPayloadFormat = extra.RequestPayloadFormat
		if extra.FinalRequestBody != "" {
			base.FinalRequestBody = extra.FinalRequestBody
		}
	} else if base.RequestPayloadCarrier == "" {
		base.RequestPayloadCarrier = extra.RequestPayloadCarrier
	}
	if base.RequestPayloadFormat == "" {
		base.RequestPayloadFormat = extra.RequestPayloadFormat
	}
	if base.RequestPayloadPreview == "" {
		base.RequestPayloadPreview = extra.RequestPayloadPreview
	}
	base.Params = mergeStaticParams(base.Params, extra.Params)
	base.Context = appendUniqueStrings(base.Context, strings.Join(extra.Context, " | "))
	if base.Snippet == "" {
		base.Snippet = extra.Snippet
	}
	return normalizeStaticEndpoint(base)
}

func shouldPreferObservedPayloadMetadata(base, extra StaticProtocolEndpoint) bool {
	if strings.TrimSpace(extra.RequestPayloadCarrier) == "" {
		return false
	}
	if extra.SourceFile != "protocol-trace" && extra.SourceFile != "api-resource" {
		return false
	}
	if strings.TrimSpace(base.RequestPayloadCarrier) == "" {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(base.Method), "GET") &&
		(strings.EqualFold(base.RequestPayloadCarrier, "body") || strings.EqualFold(base.RequestPayloadCarrier, "data")) &&
		strings.EqualFold(extra.RequestPayloadCarrier, "params") {
		return true
	}
	return false
}

func mergeStaticEndpointCollections(base, extra []StaticProtocolEndpoint) []StaticProtocolEndpoint {
	merged := make([]StaticProtocolEndpoint, 0, len(base)+len(extra))
	indexMap := make(map[string]int)
	routeIndexMap := make(map[string]int)

	appendEndpoint := func(endpoint StaticProtocolEndpoint) {
		routeKey := strings.Join([]string{strings.ToUpper(endpoint.Method), endpoint.Path}, "\x00")
		keyParts := []string{strings.ToUpper(endpoint.Method), endpoint.Path}
		if endpoint.SourceFile != "protocol-trace" && endpoint.SourceFile != "api-resource" {
			keyParts = append(keyParts, endpoint.SourceFile)
		}
		key := strings.Join(keyParts, "\x00")
		if existingIndex, exists := routeIndexMap[routeKey]; exists {
			merged[existingIndex] = mergeStaticEndpoints(merged[existingIndex], endpoint)
			indexMap[key] = existingIndex
			return
		}
		if existingIndex, exists := indexMap[key]; exists {
			merged[existingIndex] = mergeStaticEndpoints(merged[existingIndex], endpoint)
			routeIndexMap[routeKey] = existingIndex
			return
		}
		indexMap[key] = len(merged)
		routeIndexMap[routeKey] = len(merged)
		merged = append(merged, normalizeStaticEndpoint(endpoint))
	}

	for _, endpoint := range base {
		appendEndpoint(endpoint)
	}
	for _, endpoint := range extra {
		appendEndpoint(endpoint)
	}

	sort.Slice(merged, func(i, j int) bool {
		if merged[i].Path == merged[j].Path {
			return merged[i].Method < merged[j].Method
		}
		return merged[i].Path < merged[j].Path
	})

	return trimStaticEndpoints(merged, 40)
}

func trimStaticEndpoints(endpoints []StaticProtocolEndpoint, limit int) []StaticProtocolEndpoint {
	if len(endpoints) <= limit {
		result := make([]StaticProtocolEndpoint, 0, len(endpoints))
		for _, endpoint := range endpoints {
			result = append(result, normalizeStaticEndpoint(endpoint))
		}
		return result
	}
	result := make([]StaticProtocolEndpoint, 0, limit)
	for _, endpoint := range endpoints[:limit] {
		result = append(result, normalizeStaticEndpoint(endpoint))
	}
	return result
}

func normalizeStaticEndpoint(endpoint StaticProtocolEndpoint) StaticProtocolEndpoint {
	if endpoint.Method == "" {
		endpoint.Method = "GET"
	}
	endpoint.Client = mergeStaticClientLabels(endpoint.Client)
	if len(endpoint.Context) > 1 {
		flattened := make([]string, 0, len(endpoint.Context))
		for _, item := range endpoint.Context {
			if strings.Contains(item, " | ") {
				for _, splitItem := range strings.Split(item, " | ") {
					flattened = appendUniqueStrings(flattened, splitItem)
				}
				continue
			}
			flattened = appendUniqueStrings(flattened, item)
		}
		endpoint.Context = flattened
	}
	return endpoint
}

func mergeStaticClientLabels(items ...string) string {
	merged := make([]string, 0, len(items))
	for _, item := range items {
		for _, part := range strings.Split(item, " | ") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			merged = appendUniqueStrings(merged, part)
		}
	}
	return strings.Join(merged, " | ")
}

package lib

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	tbdb "github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/scanexec"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/logger"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/qiwentaidi/katana/pkg/apiaudit"
	"github.com/qiwentaidi/katana/pkg/apicontext"
	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
	"gopkg.in/yaml.v3"
)

var sdkIgnoredProtocolAlgorithms = map[string]struct{}{
	"json.stringify":            {},
	"json.parse":                {},
	"json.parse(inferred)":      {},
	"json.stringify(inferred)":  {},
	"json.parse()":              {},
	"json.stringify()":          {},
	"base64-encoded-payload":    {},
	"hex-encoded-payload":       {},
	"encrypted-field(inferred)": {},
	"se":                        {},
	"sd":                        {},
	"module.se":                 {},
	"module.sd":                 {},
}

// VulnRecord 漏洞记录（SDK独立定义，避免ES依赖）
type VulnRecord struct {
	TaskID             string                       `json:"task_id"`
	VulnID             string                       `json:"vuln_id"`
	Title              string                       `json:"title"`
	Level              string                       `json:"level"` // high, medium, low, info
	Type               string                       `json:"type"`
	URL                string                       `json:"url"`
	Method             string                       `json:"method,omitempty"`
	Request            string                       `json:"request,omitempty"`
	Response           string                       `json:"response,omitempty"`
	ResponseType       string                       `json:"response_type,omitempty"`
	TraceID            string                       `json:"trace_id,omitempty"`
	HasProtocolTrace   bool                         `json:"has_protocol_trace,omitempty"`
	ResponsePlaintext  string                       `json:"response_plaintext,omitempty"`
	ResponseCiphertext string                       `json:"response_ciphertext,omitempty"`
	DecryptionStatus   string                       `json:"decryption_status,omitempty"`
	DecryptionDetail   string                       `json:"decryption_detail,omitempty"`
	ResponseLength     int                          `json:"response_length,omitempty"` // 原始响应长度（字节）
	Confidence         string                       `json:"confidence,omitempty"`
	ConfidenceReason   string                       `json:"confidence_reason,omitempty"`
	DataExposure       string                       `json:"data_exposure,omitempty"`
	ExposureReason     string                       `json:"exposure_reason,omitempty"`
	StaticContexts     []database.VulnStaticContext `json:"static_contexts,omitempty"`
	Description        string                       `json:"description"`
	AIVerified         bool                         `json:"ai_verified"` // AI辅助验证标记
	CreatedAt          time.Time                    `json:"created_at"`
}

// ScanEventType 扫描事件类型
type ScanEventType string

const (
	EventTypeVulnerability ScanEventType = "vulnerability" // 漏洞发现
	EventTypeAsset         ScanEventType = "asset"         // 资产发现
	EventTypeAPIRecord     ScanEventType = "api_record"    // 接口请求/响应记录
	EventTypeProtocolTrace ScanEventType = "protocol_trace"
	EventTypeProgress      ScanEventType = "progress" // 进度更新
	EventTypeError         ScanEventType = "error"    // 错误
)

// ScanEvent 扫描事件（用于回调）
type ScanEvent struct {
	Type      ScanEventType `json:"type"`             // 事件类型
	Target    string        `json:"target,omitempty"` // 目标URL
	Timestamp time.Time     `json:"timestamp"`        // 时间戳
	Data      interface{}   `json:"data"`             // 事件数据（根据类型不同而不同）
}

// ScanCallback 扫描结果回调函数类型
// event: 扫描事件，包含类型和数据
// 返回false表示停止扫描，返回true表示继续扫描
type ScanCallback func(event ScanEvent) bool

// ScanOptions SDK扫描选项配置
type ScanOptions struct {
	// TaskID 扫描任务标识。嵌入业务系统时可传入业务侧任务 ID；为空时使用 cli-mode。
	TaskID string `json:"taskId,omitempty"`

	// Version 扫描任务版本。与 TaskID 一起用于 DataStore 查询和结果关联；小于等于 0 表示不限定版本。
	Version int `json:"version,omitempty"`

	// OpenAI配置
	OpenAI OpenAIOptions `json:"openai"`

	// 黑名单域名列表
	BlackDomain []string `json:"blackDomain"`

	// 高风险路由关键词列表
	HighRiskRouter []string `json:"highRiskRouter"`

	// 认证失败关键词列表
	Authentication []string `json:"authentication"`

	// 占位符映射（用于参数替换）
	Placeholder map[string]string `json:"placeholder"`

	// 弱口令字典
	WeakCreds []string `json:"weakCreds"`

	// 漏洞检测配置
	VulnDetection VulnDetectionOptions `json:"vulnDetection"`

	// 输出路径（可选，为空则输出到标准输出）
	OutputPath string `json:"outputPath,omitempty"`

	// LogOutput 允许宿主系统接管扫描日志输出。
	LogOutput io.Writer `json:"-"`

	// LogOutputPath 指定扫描日志文件路径。设置后，扫描期间的 fmt/log/stderr 输出会写入该文件。
	LogOutputPath string `json:"logOutputPath,omitempty"`

	// 结果回调函数（可选，用于实时获取扫描结果，类似nuclei）
	// 当发现漏洞、资产、风险时会调用此回调
	// 返回false表示停止扫描，返回true表示继续扫描
	OnResult ScanCallback `json:"-"`

	Proxy string `json:"proxy,omitempty"` // 代理设置（可选）

	DataStore database.ScanDataStore `json:"-"`
}

// OpenAIOptions OpenAI配置选项
type OpenAIOptions struct {
	APIKey  string `json:"apiKey"`
	BaseURL string `json:"baseURL"`
	Model   string `json:"model"`
	Enabled bool   `json:"enabled"`
}

// VulnDetectionOptions 漏洞检测配置选项
type VulnDetectionOptions struct {
	Enabled       bool                       `json:"enabled"`
	Authorization config.AuthorizationConfig `json:"authorization"`
	SQLInjection  config.SQLInjectionConfig  `json:"sqlInjection"`
	LFI           config.LFIConfig           `json:"lfi"`
	SSRF          config.SSRFConfig          `json:"ssrf"`
	Redirect      config.RedirectConfig      `json:"redirect"`
	XSS           config.XSSConfig           `json:"xss"`
	Upload        config.UploadConfig        `json:"upload"`
}

// NewScanOptions 创建默认的扫描选项
func NewScanOptions() *ScanOptions {
	return &ScanOptions{
		OpenAI: OpenAIOptions{
			Enabled: false,
		},
		BlackDomain:    []string{},
		HighRiskRouter: []string{},
		Authentication: []string{},
		Placeholder:    make(map[string]string),
		WeakCreds:      []string{},
		VulnDetection: VulnDetectionOptions{
			Enabled:       true,
			Authorization: config.AuthorizationConfig{Enabled: true},
			SQLInjection:  config.SQLInjectionConfig{Enabled: true},
			LFI:           config.LFIConfig{Enabled: true},
			SSRF:          config.SSRFConfig{Enabled: true},
			Redirect:      config.RedirectConfig{Enabled: true},
			XSS:           config.XSSConfig{Enabled: true},
			Upload:        config.UploadConfig{Enabled: true},
		},
	}
}

// LoadScanOptionsFromFile 从配置文件加载扫描选项（向后兼容）
func LoadScanOptionsFromFile(configPath string) (*ScanOptions, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %v", err)
	}

	var cfg config.ConfigYAML
	if err := yaml.Unmarshal(configData, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	var raw struct {
		VulnDetection struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"vuln-detection"`
	}
	if err := yaml.Unmarshal(configData, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse vuln-detection config: %v", err)
	}

	vulnDetectionEnabled := true
	if raw.VulnDetection.Enabled != nil {
		vulnDetectionEnabled = *raw.VulnDetection.Enabled
	}
	return &ScanOptions{
		OpenAI: OpenAIOptions{
			APIKey:  cfg.OpenAI.APIKey,
			BaseURL: cfg.OpenAI.BaseURL,
			Model:   cfg.OpenAI.Model,
			Enabled: cfg.OpenAI.Enabled,
		},
		BlackDomain:    cfg.BlackDomain,
		HighRiskRouter: cfg.HighRiskRouter,
		Authentication: cfg.Authentication,
		Placeholder:    cfg.Placeholder,
		WeakCreds:      cfg.WeakCreds,
		LogOutputPath:  cfg.Log.OutputPath,
		VulnDetection: VulnDetectionOptions{
			Enabled:       vulnDetectionEnabled,
			Authorization: cfg.VulnDetection.Authorization,
			SQLInjection:  cfg.VulnDetection.SQLInjection,
			LFI:           cfg.VulnDetection.LFI,
			SSRF:          cfg.VulnDetection.SSRF,
			Redirect:      cfg.VulnDetection.Redirect,
			XSS:           cfg.VulnDetection.XSS,
			Upload:        cfg.VulnDetection.Upload,
		},
	}, nil
}

func resolveSDKVulnDetectionOptions(options VulnDetectionOptions) VulnDetectionOptions {
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

func buildSDKJSFindOptions(
	taskID string,
	targetURL string,
	apiRouter []string,
	root string,
	hintBundle crawl.StaticEndpointHintBundle,
	options *ScanOptions,
	aiChecker *crawl.SensitiveInfoChecker,
) structs.JSFindOptions {
	vulnDetection := resolveSDKVulnDetectionOptions(options.VulnDetection)

	return structs.JSFindOptions{
		TaskID:                    taskID,
		HomeURL:                   targetURL,
		ApiList:                   apiRouter,
		ApiRoot:                   root,
		StaticMethodHints:         hintBundle.Methods,
		StaticHeaderHints:         hintBundle.Headers,
		StaticConstantParams:      hintBundle.ConstantParams,
		StaticRequestPayloadHints: hintBundle.RequestPayload,
		SkipVulnScan:              !vulnDetection.Enabled,
		// Authorization findings are generated from captured authenticated
		// baselines after the scan; never fall back to the old anonymous-only
		// heuristic here.
		SkipUnauthorizedScan: true,
		HighRiskRouter:       options.HighRiskRouter,
		Authentication:       options.Authentication,
		Placeholder:          options.Placeholder,
		LFIConfig:            vulnDetection.LFI,
		SSRFConfig:           vulnDetection.SSRF,
		RedirectConfig:       vulnDetection.Redirect,
		SQLInjConfig:         vulnDetection.SQLInjection,
		XSSConfig:            vulnDetection.XSS,
		UploadConfig:         vulnDetection.Upload,
		AIChecker:            aiChecker,
		DataStore:            options.DataStore,
	}
}

type sdkJSFetcher func(string) ([]byte, error)

func defaultSDKJSFetcher(jsURL string) ([]byte, error) {
	resp, err := clients.SimpleGet(jsURL, clients.NewRestyClient(nil, true))
	if err != nil {
		return nil, err
	}
	body := resp.Body()
	copied := make([]byte, len(body))
	copy(copied, body)
	return copied, nil
}

func buildSDKStaticHintBundle(homeURL string, jsLinks []string) crawl.StaticEndpointHintBundle {
	return buildSDKStaticHintBundleWithFetcherAndTempDir(homeURL, jsLinks, defaultSDKJSFetcher, "")
}

func buildSDKStaticHintBundleWithFetcherAndTempDir(
	homeURL string,
	jsLinks []string,
	fetcher sdkJSFetcher,
	tempParentDir string,
) crawl.StaticEndpointHintBundle {
	if len(jsLinks) == 0 || fetcher == nil {
		return crawl.StaticEndpointHintBundle{}
	}

	tempDir, err := os.MkdirTemp(tempParentDir, "trailblazer-sdk-js-*")
	if err != nil {
		fmt.Printf("[警告] 无法创建SDK JS临时目录: %v\n", err)
		return crawl.StaticEndpointHintBundle{}
	}
	defer os.RemoveAll(tempDir)

	merged := crawl.StaticEndpointHintBundle{}
	for _, jsLink := range jsLinks {
		resolvedURL := normalizeSDKJSURL(homeURL, jsLink)
		if strings.TrimSpace(resolvedURL) == "" {
			continue
		}

		content, err := fetcher(resolvedURL)
		if err != nil {
			fmt.Printf("[警告] SDK下载JS失败 %s: %v\n", resolvedURL, err)
			continue
		}

		filePath := filepath.Join(tempDir, buildSDKTempJSFileName(resolvedURL))
		if err := os.WriteFile(filePath, content, 0o600); err != nil {
			fmt.Printf("[警告] SDK写入JS临时文件失败 %s: %v\n", resolvedURL, err)
			continue
		}

		fileContent, err := os.ReadFile(filePath)
		_ = os.Remove(filePath)
		if err != nil {
			fmt.Printf("[警告] SDK读取JS临时文件失败 %s: %v\n", resolvedURL, err)
			continue
		}

		singleBundle := crawl.BuildStaticEndpointHintBundle([]database.JSResource{
			{
				TaskID:    "cli-mode",
				URL:       resolvedURL,
				Content:   string(fileContent),
				Size:      len(fileContent),
				FetchedAt: time.Now(),
			},
		})
		merged = mergeSDKStaticHintBundles(merged, singleBundle)
	}

	return merged
}

func normalizeSDKJSURL(homeURL, jsLink string) string {
	jsLink = strings.TrimSpace(jsLink)
	if jsLink == "" {
		return ""
	}
	if strings.HasPrefix(jsLink, "http://") || strings.HasPrefix(jsLink, "https://") {
		return jsLink
	}

	baseURL := strings.TrimSpace(homeURL)
	if parsed, err := url.Parse(baseURL); err == nil && parsed != nil && parsed.Scheme != "" && parsed.Host != "" {
		return parsed.Scheme + "://" + parsed.Host + "/" + strings.TrimLeft(jsLink, "/")
	}
	return jsLink
}

func buildSDKTempJSFileName(jsURL string) string {
	sum := sha1.Sum([]byte(jsURL))
	extension := filepath.Ext(strings.TrimSpace(jsURL))
	if extension == "" || len(extension) > 10 {
		extension = ".js"
	}
	return hex.EncodeToString(sum[:]) + extension
}

func mergeSDKStaticHintBundles(base, extra crawl.StaticEndpointHintBundle) crawl.StaticEndpointHintBundle {
	if len(extra.Methods) > 0 {
		if base.Methods == nil {
			base.Methods = make(map[string]string, len(extra.Methods))
		}
		for path, method := range extra.Methods {
			method = strings.ToUpper(strings.TrimSpace(method))
			if strings.TrimSpace(path) == "" || method == "" {
				continue
			}
			current := strings.ToUpper(strings.TrimSpace(base.Methods[path]))
			if current == "" || (current == "GET" && method == "POST") {
				base.Methods[path] = method
			}
		}
	}

	if len(extra.ConstantParams) > 0 {
		if base.ConstantParams == nil {
			base.ConstantParams = make(map[string]url.Values, len(extra.ConstantParams))
		}
		for key, values := range extra.ConstantParams {
			if strings.TrimSpace(key) == "" || len(values) == 0 {
				continue
			}
			if _, exists := base.ConstantParams[key]; !exists {
				base.ConstantParams[key] = url.Values{}
			}
			for paramName, paramValues := range values {
				if len(paramValues) == 0 || strings.TrimSpace(paramValues[0]) == "" {
					continue
				}
				if _, exists := base.ConstantParams[key][paramName]; exists {
					continue
				}
				base.ConstantParams[key][paramName] = []string{paramValues[0]}
			}
		}
	}

	if len(extra.Headers) > 0 {
		if base.Headers == nil {
			base.Headers = make(map[string]map[string]string, len(extra.Headers))
		}
		for key, headers := range extra.Headers {
			if strings.TrimSpace(key) == "" || len(headers) == 0 {
				continue
			}
			if _, exists := base.Headers[key]; !exists {
				base.Headers[key] = make(map[string]string, len(headers))
			}
			for headerName, headerValue := range headers {
				if strings.TrimSpace(headerName) == "" || strings.TrimSpace(headerValue) == "" {
					continue
				}
				if _, exists := base.Headers[key][headerName]; exists {
					continue
				}
				base.Headers[key][headerName] = headerValue
			}
		}
	}

	if len(extra.RequestPayload) > 0 {
		if base.RequestPayload == nil {
			base.RequestPayload = make(map[string]structs.StaticRequestPayloadHint, len(extra.RequestPayload))
		}
		for key, hint := range extra.RequestPayload {
			if strings.TrimSpace(key) == "" {
				continue
			}
			if current, exists := base.RequestPayload[key]; exists {
				if strings.TrimSpace(current.Carrier) == "" {
					current.Carrier = hint.Carrier
				}
				if strings.TrimSpace(current.Format) == "" {
					current.Format = hint.Format
				}
				if strings.TrimSpace(current.Preview) == "" {
					current.Preview = hint.Preview
				}
				base.RequestPayload[key] = current
				continue
			}
			base.RequestPayload[key] = hint
		}
	}

	return base
}

// ScanResult CLI扫描结果
type ScanResult struct {
	TaskID   string         `json:"taskId,omitempty"`
	Version  int            `json:"version,omitempty"`
	Targets  []TargetResult `json:"targets"`
	ScanTime string         `json:"scanTime"`
	Summary  Summary        `json:"summary"`
}

type SeverityCount struct {
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

type AuxiliaryCount struct {
	APIRecords     int `json:"apiRecords"`
	ProtocolTraces int `json:"protocolTraces"`
	APIRoutes      int `json:"apiRoutes"`
	APIRoots       int `json:"apiRoots"`
}

type FindingDigest struct {
	Title            string `json:"title"`
	Level            string `json:"level"`
	Type             string `json:"type"`
	URL              string `json:"url"`
	Method           string `json:"method,omitempty"`
	Confidence       string `json:"confidence,omitempty"`
	DataExposure     string `json:"dataExposure,omitempty"`
	HasProtocolTrace bool   `json:"hasProtocolTrace,omitempty"`
}

type VulnerabilityOverview struct {
	VulnerabilityCount  int             `json:"vulnerabilityCount"`
	VulnerableEndpoints int             `json:"vulnerableEndpoints"`
	Severity            SeverityCount   `json:"severity"`
	VulnerabilityTypes  map[string]int  `json:"vulnerabilityTypes"`
	KeyFindings         []FindingDigest `json:"keyFindings,omitempty"`
	Auxiliary           AuxiliaryCount  `json:"auxiliary"`
}

// TargetResult 单个目标的扫描结果
type TargetResult struct {
	Target                string                   `json:"target"`
	Overview              VulnerabilityOverview    `json:"overview"`
	SiteTree              []crawl.ElTreeNode       `json:"siteTree"`
	JSResources           []tbdb.JSResource        `json:"jsResources,omitempty"`
	RequestBlueprintCount int                      `json:"requestBlueprintCount"`
	RequestBlueprints     []crawl.RequestBlueprint `json:"requestBlueprints,omitempty"`
	// AnchorCandidates preserves request-like anchors that fell outside the
	// static analysis budget so coverage loss is visible instead of silent.
	AnchorCandidates []crawl.RequestAnchorCandidate `json:"anchorCandidates,omitempty"`
	// OperationSpecs are persistable interface templates (no credential
	// values); dynamic parameters must be completed from runtime traffic.
	OperationSpecs []crawl.OperationSpec `json:"operationSpecs,omitempty"`
	APIRecords     []APIRecord           `json:"apiRecords,omitempty"`
	// APIContexts is the deduplicated interface asset set built
	// from the same runtime capture used by parameter inference. It is safe to
	// export as OpenAPI and never contains credential values.
	APIContexts         []*apicontext.Context `json:"apiContexts,omitempty"`
	AuthorizationChecks []AuthorizationCheck  `json:"authorizationChecks,omitempty"`
	ProtocolTraces      []ProtocolTrace       `json:"protocolTraces,omitempty"`
	Assets              AssetInfo             `json:"assets"`
	Fingerprints        []FingerprintItem     `json:"fingerprints,omitempty"`
	SecurityLeads       []SecurityLead        `json:"securityLeads,omitempty"`
	Vulnerabilities     []VulnerabilityItem   `json:"vulnerabilities"`
}

// AuthorizationCheck binds a comparative authorization verdict to the
// observed operation. It is emitted even when no vulnerability is found so
// callers can audit coverage and inconclusive cases.
type AuthorizationCheck struct {
	OperationID string                `json:"operationId"`
	URL         string                `json:"url"`
	Method      string                `json:"method"`
	Verdict     apiaudit.AuthzVerdict `json:"verdict"`
}

// SecurityLead is a non-vulnerability review artifact. It preserves high-risk
// or state-changing API clues that should not be fuzzed automatically, while
// carrying enough static request context for manual or AI follow-up analysis.
type SecurityLead struct {
	ID                string                       `json:"id"`
	Route             string                       `json:"route"`
	URL               string                       `json:"url,omitempty"`
	Method            string                       `json:"method,omitempty"`
	Category          string                       `json:"category"`
	Decision          string                       `json:"decision"`
	Reason            string                       `json:"reason"`
	MatchedKeyword    string                       `json:"matchedKeyword,omitempty"`
	RiskHypotheses    []string                     `json:"riskHypotheses,omitempty"`
	SuggestedNextStep string                       `json:"suggestedNextStep,omitempty"`
	Request           SecurityLeadRequest          `json:"request,omitempty"`
	Source            crawl.RequestBlueprintSource `json:"source,omitempty"`
	EvidenceSnippets  []string                     `json:"evidenceSnippets,omitempty"`
}

type SecurityLeadRequest struct {
	PayloadCarrier    string                              `json:"payloadCarrier,omitempty"`
	PayloadFormat     string                              `json:"payloadFormat,omitempty"`
	PayloadPreview    string                              `json:"payloadPreview,omitempty"`
	RequestBody       string                              `json:"requestBody,omitempty"`
	Params            []crawl.RequestBlueprintParam       `json:"params,omitempty"`
	Headers           []crawl.RequestBlueprintHeader      `json:"headers,omitempty"`
	Interceptors      []crawl.RequestBlueprintInterceptor `json:"interceptors,omitempty"`
	UnresolvedSymbols []string                            `json:"unresolvedSymbols,omitempty"`
}

func sdkVulnerabilityDedupKey(vuln VulnRecord) string {
	responseKey := ""
	if isSDKUnauthorizedVulnerability(vuln) {
		// Preserve findings with different responses even if their URLs differ
		// only by a trailing slash.
		responseKey = "|" + strconv.Itoa(vuln.ResponseLength) + "|" + vuln.Response
	}
	parsed, err := url.Parse(strings.TrimSpace(vuln.URL))
	if err == nil && parsed.Host != "" {
		path := parsed.Path
		if isSDKUnauthorizedVulnerability(vuln) {
			path = strings.TrimSuffix(path, "/")
		}
		return strings.ToUpper(strings.TrimSpace(vuln.Method)) + "|" + strings.ToLower(parsed.Host) + "|" + path + "|" + strings.TrimSpace(vuln.Type) + responseKey
	}
	urlValue := strings.TrimSpace(vuln.URL)
	if isSDKUnauthorizedVulnerability(vuln) {
		urlValue = strings.TrimSuffix(urlValue, "/")
	}
	return strings.ToUpper(strings.TrimSpace(vuln.Method)) + "|" + urlValue + "|" + strings.TrimSpace(vuln.Type) + responseKey
}

func isSDKUnauthorizedVulnerability(vuln VulnRecord) bool {
	return vuln.Type == "未授权访问" || vuln.Title == "未授权访问"
}

func choosePreferredSDKVulnerability(current, candidate VulnRecord) VulnRecord {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(candidate.URL)), "https://") &&
		!strings.HasPrefix(strings.ToLower(strings.TrimSpace(current.URL)), "https://") {
		return candidate
	}
	if candidate.ResponseLength > current.ResponseLength {
		return candidate
	}
	if len(strings.TrimSpace(candidate.Response)) > len(strings.TrimSpace(current.Response)) {
		return candidate
	}
	return current
}

func dedupeSDKVulnerabilities(vulns []VulnRecord) []VulnRecord {
	if len(vulns) <= 1 {
		return vulns
	}

	index := make(map[string]int, len(vulns))
	result := make([]VulnRecord, 0, len(vulns))
	for _, vuln := range vulns {
		key := sdkVulnerabilityDedupKey(vuln)
		if idx, ok := index[key]; ok {
			result[idx] = choosePreferredSDKVulnerability(result[idx], vuln)
			continue
		}
		index[key] = len(result)
		result = append(result, vuln)
	}
	return result
}

// APIRecord 浏览器运行时捕获到的接口请求/响应记录
type APIRecord struct {
	URL              string            `json:"url"`
	Method           string            `json:"method"`
	ResourceType     string            `json:"resourceType,omitempty"`
	TraceID          string            `json:"traceId,omitempty"`
	HasProtocolTrace bool              `json:"hasProtocolTrace,omitempty"`
	RequestHeaders   map[string]string `json:"requestHeaders,omitempty"`
	RequestBody      string            `json:"requestBody,omitempty"`
	ResponseHeaders  map[string]string `json:"responseHeaders,omitempty"`
	ResponseBody     string            `json:"responseBody,omitempty"`
	ResponseCode     int               `json:"responseCode"`
	MIMEType         string            `json:"mimeType,omitempty"`
	FetchedAt        time.Time         `json:"fetchedAt"`
}

// ProtocolCryptoStep 单个加密/签名步骤
type ProtocolCryptoStep struct {
	Source        string `json:"source"`
	Algorithm     string `json:"algorithm,omitempty"`
	InputPreview  string `json:"inputPreview,omitempty"`
	OutputPreview string `json:"outputPreview,omitempty"`
	CallID        string `json:"callId,omitempty"`
	ParentCallID  string `json:"parentCallId,omitempty"`
	FunctionPath  string `json:"functionPath,omitempty"`
	ModuleID      string `json:"moduleId,omitempty"`
	Stack         string `json:"stack,omitempty"`
	CapturedAtMS  int64  `json:"capturedAtMs,omitempty"`
}

// ProtocolTrace 协议轨迹记录
type ProtocolTrace struct {
	TaskID                 string               `json:"taskId,omitempty"`
	Version                int                  `json:"version,omitempty"`
	TargetURL              string               `json:"targetUrl,omitempty"`
	TraceID                string               `json:"traceId"`
	Transport              string               `json:"transport,omitempty"`
	PageURL                string               `json:"pageUrl,omitempty"`
	RequestURL             string               `json:"requestUrl"`
	Method                 string               `json:"method"`
	RequestHeaders         map[string]string    `json:"requestHeaders,omitempty"`
	RequestBeforeTransform string               `json:"requestBeforeTransform,omitempty"`
	FinalRequestBody       string               `json:"finalRequestBody,omitempty"`
	RequestSteps           []ProtocolCryptoStep `json:"requestSteps,omitempty"`
	ResponseSteps          []ProtocolCryptoStep `json:"responseSteps,omitempty"`
	SignatureFields        []string             `json:"signatureFields,omitempty"`
	DynamicParams          map[string]string    `json:"dynamicParams,omitempty"`
	SessionMaterials       map[string]string    `json:"sessionMaterials,omitempty"`
	Algorithms             []string             `json:"algorithms,omitempty"`
	Stack                  string               `json:"stack,omitempty"`
	CreatedAt              time.Time            `json:"createdAt"`
}

// AssetInfo 资产信息
type AssetInfo struct {
	Email          []SensitiveItem `json:"email"`
	IDCard         []SensitiveItem `json:"idCard"`
	Phone          []SensitiveItem `json:"phone"`
	IPURL          []SensitiveItem `json:"ipUrl"`
	Sensitive      []SensitiveItem `json:"sensitive"`
	FrontendRoutes []string        `json:"frontendRoutes"`
	APIRoutes      []string        `json:"apiRoutes"`
	APIRoots       []string        `json:"apiRoots"`
}

type SensitiveItem struct {
	Value      string   `json:"value"`
	Source     string   `json:"source"`
	Sources    []string `json:"sources,omitempty"`
	AIVerified bool     `json:"aiVerified,omitempty"`
}

// FingerprintItem identifies a technology or request characteristic; it is
// deliberately separate from vulnerabilities.
type FingerprintItem struct {
	URL          string                 `json:"url"`
	StatusCode   int                    `json:"statusCode,omitempty"`
	Length       int                    `json:"length,omitempty"`
	Title        string                 `json:"title,omitempty"`
	Fingerprints []FingerprintMatchItem `json:"fingerprints"`
	Detect       string                 `json:"detect,omitempty"`
}

type FingerprintMatchItem struct {
	Name string `json:"name"`
}

// VulnerabilityItem 漏洞信息（来自AnalyzeAPI检测）
type VulnerabilityItem struct {
	ID                 string                       `json:"id"`
	Title              string                       `json:"title"`
	Level              string                       `json:"level"`
	Type               string                       `json:"type"`
	URL                string                       `json:"url"`
	Method             string                       `json:"method,omitempty"`
	Request            string                       `json:"request,omitempty"`
	Response           string                       `json:"response,omitempty"`
	ResponseType       string                       `json:"responseType,omitempty"`
	TraceID            string                       `json:"traceId,omitempty"`
	HasProtocolTrace   bool                         `json:"hasProtocolTrace,omitempty"`
	ResponsePlaintext  string                       `json:"responsePlaintext,omitempty"`
	ResponseCiphertext string                       `json:"responseCiphertext,omitempty"`
	DecryptionStatus   string                       `json:"decryptionStatus,omitempty"`
	DecryptionDetail   string                       `json:"decryptionDetail,omitempty"`
	ResponseLength     int                          `json:"responseLength,omitempty"`
	Confidence         string                       `json:"confidence,omitempty"`
	ConfidenceReason   string                       `json:"confidenceReason,omitempty"`
	DataExposure       string                       `json:"dataExposure,omitempty"`
	ExposureReason     string                       `json:"exposureReason,omitempty"`
	AIReviewVerdict    string                       `json:"aiReviewVerdict,omitempty"`
	AIReviewType       string                       `json:"aiReviewType,omitempty"`
	AIReviewConfidence int                          `json:"aiReviewConfidence,omitempty"`
	AIReviewReason     string                       `json:"aiReviewReason,omitempty"`
	StaticContexts     []database.VulnStaticContext `json:"staticContexts,omitempty"`
	Description        string                       `json:"description"`
	AIVerified         bool                         `json:"aiVerified"`
	CreatedAt          string                       `json:"createdAt"`
}

// Summary 扫描摘要
type Summary struct {
	Focus                string          `json:"focus"`
	TotalTargets         int             `json:"totalTargets"`
	VulnerableTargets    int             `json:"vulnerableTargets"`
	TotalTreeNodes       int             `json:"totalTreeNodes"`
	TotalVulnerabilities int             `json:"totalVulnerabilities"`
	VulnerableEndpoints  int             `json:"vulnerableEndpoints"`
	Severity             SeverityCount   `json:"severity"`
	VulnerabilityTypes   map[string]int  `json:"vulnerabilityTypes"`
	KeyFindings          []FindingDigest `json:"keyFindings,omitempty"`
	Auxiliary            AuxiliaryCount  `json:"auxiliary"`
	TotalAssets          AssetCount      `json:"totalAssets"`
}

type AssetCount struct {
	Email          int `json:"email"`
	IDCard         int `json:"idCard"`
	Phone          int `json:"phone"`
	IPURL          int `json:"ipUrl"`
	Sensitive      int `json:"sensitive"`
	FrontendRoutes int `json:"frontendRoutes"`
	APIRoutes      int `json:"apiRoutes"`
	APIRoots       int `json:"apiRoots"`
}

func incrementSDKSeverityCount(counter *SeverityCount, level string) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high":
		counter.High++
	case "medium":
		counter.Medium++
	case "low":
		counter.Low++
	default:
		counter.Info++
	}
}

func sdkDigestFromVulnerability(item VulnerabilityItem) FindingDigest {
	return FindingDigest{
		Title:            item.Title,
		Level:            item.Level,
		Type:             item.Type,
		URL:              item.URL,
		Method:           item.Method,
		Confidence:       item.Confidence,
		DataExposure:     item.DataExposure,
		HasProtocolTrace: item.HasProtocolTrace,
	}
}

func sdkVulnerabilityEndpointKey(item VulnerabilityItem) string {
	parsed, err := url.Parse(strings.TrimSpace(item.URL))
	if err == nil && parsed.Host != "" {
		return strings.ToUpper(strings.TrimSpace(item.Method)) + "|" + strings.ToLower(parsed.Host) + "|" + parsed.Path
	}
	return strings.ToUpper(strings.TrimSpace(item.Method)) + "|" + strings.TrimSpace(item.URL)
}

func buildSDKTargetOverview(target TargetResult) VulnerabilityOverview {
	overview := VulnerabilityOverview{
		VulnerabilityCount: len(target.Vulnerabilities),
		VulnerabilityTypes: make(map[string]int),
		KeyFindings:        make([]FindingDigest, 0, min(len(target.Vulnerabilities), 8)),
		Auxiliary: AuxiliaryCount{
			APIRecords:     len(target.APIRecords),
			ProtocolTraces: len(target.ProtocolTraces),
			APIRoutes:      len(target.Assets.APIRoutes),
			APIRoots:       len(target.Assets.APIRoots),
		},
	}

	endpointSet := make(map[string]struct{}, len(target.Vulnerabilities))
	for i, item := range target.Vulnerabilities {
		incrementSDKSeverityCount(&overview.Severity, item.Level)
		typeKey := strings.TrimSpace(item.Type)
		if typeKey == "" {
			typeKey = "unknown"
		}
		overview.VulnerabilityTypes[typeKey]++

		endpointKey := sdkVulnerabilityEndpointKey(item)
		if _, exists := endpointSet[endpointKey]; !exists {
			endpointSet[endpointKey] = struct{}{}
		}

		if i < 8 {
			overview.KeyFindings = append(overview.KeyFindings, sdkDigestFromVulnerability(item))
		}
	}
	overview.VulnerableEndpoints = len(endpointSet)

	return overview
}

func mergeSDKOverviewIntoSummary(summary *Summary, overview VulnerabilityOverview) {
	if overview.VulnerabilityCount > 0 {
		summary.VulnerableTargets++
	}
	summary.VulnerableEndpoints += overview.VulnerableEndpoints
	summary.Severity.High += overview.Severity.High
	summary.Severity.Medium += overview.Severity.Medium
	summary.Severity.Low += overview.Severity.Low
	summary.Severity.Info += overview.Severity.Info
	summary.Auxiliary.APIRecords += overview.Auxiliary.APIRecords
	summary.Auxiliary.ProtocolTraces += overview.Auxiliary.ProtocolTraces
	summary.Auxiliary.APIRoutes += overview.Auxiliary.APIRoutes
	summary.Auxiliary.APIRoots += overview.Auxiliary.APIRoots

	if summary.VulnerabilityTypes == nil {
		summary.VulnerabilityTypes = make(map[string]int)
	}
	for vulnType, count := range overview.VulnerabilityTypes {
		summary.VulnerabilityTypes[vulnType] += count
	}

	for _, digest := range overview.KeyFindings {
		if len(summary.KeyFindings) >= 12 {
			break
		}
		summary.KeyFindings = append(summary.KeyFindings, digest)
	}
}

// VulnCollector 漏洞收集器接口（SDK版本，避免ES依赖）
type VulnCollector interface {
	Collect(vuln VulnRecord)
	GetVulns() []VulnRecord
	Clear()
}

// CLIVulnCollector CLI模式的漏洞收集器
type CLIVulnCollector struct {
	vulns []VulnRecord
	mu    sync.Mutex
}

func NewCLIVulnCollector() *CLIVulnCollector {
	return &CLIVulnCollector{
		vulns: make([]VulnRecord, 0),
	}
}

// Collect 收集漏洞
func (vc *CLIVulnCollector) Collect(vuln VulnRecord) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.vulns = append(vc.vulns, vuln)
}

// GetVulns 获取收集到的漏洞
func (vc *CLIVulnCollector) GetVulns() []VulnRecord {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	// 返回副本
	result := make([]VulnRecord, len(vc.vulns))
	copy(result, vc.vulns)
	return result
}

// Clear 清空收集的漏洞
func (vc *CLIVulnCollector) Clear() {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	vc.vulns = make([]VulnRecord, 0)
}

// SDKVulnCollectorAdapter 适配器，实现crawl.VulnCollector接口
// 注意：这个适配器需要导入database包来满足接口要求，但SDK本身不直接使用ES功能
// 如果要在其他项目中使用SDK，需要导入database包（用于类型定义），但不需要初始化ES客户端
type SDKVulnCollectorAdapter struct {
	collector *CLIVulnCollector
}

// NewSDKVulnCollectorAdapter 创建适配器
func NewSDKVulnCollectorAdapter(collector *CLIVulnCollector) crawl.VulnCollector {
	return &SDKVulnCollectorAdapter{collector: collector}
}

// Collect 实现crawl.VulnCollector接口
// 将database.VulnRecord转换为SDK的VulnRecord
func (a *SDKVulnCollectorAdapter) Collect(vuln database.VulnRecord) {
	// 使用JSON序列化/反序列化来转换，因为两个结构体字段相同
	jsonData, err := json.Marshal(vuln)
	if err != nil {
		fmt.Printf("[警告] 无法序列化漏洞记录: %v\n", err)
		return
	}

	var sdkVuln VulnRecord
	if err := json.Unmarshal(jsonData, &sdkVuln); err != nil {
		fmt.Printf("[警告] 无法反序列化漏洞记录: %v\n", err)
		return
	}

	a.collector.Collect(sdkVuln)
}

func convertNetworkRecord(record crawl.NetworkRecord) APIRecord {
	return APIRecord{
		URL:              record.URL,
		Method:           record.Method,
		ResourceType:     record.ResourceType,
		TraceID:          record.TraceID,
		HasProtocolTrace: record.HasProtocolTrace,
		RequestHeaders:   record.RequestHeaders,
		RequestBody:      record.RequestBody,
		ResponseHeaders:  record.ResponseHeaders,
		ResponseBody:     record.ResponseBody,
		ResponseCode:     record.ResponseCode,
		MIMEType:         record.MIMEType,
		FetchedAt:        record.FetchedAt,
	}
}

func convertProtocolTrace(record crawl.ProtocolTraceRecord) ProtocolTrace {
	requestSteps := make([]ProtocolCryptoStep, 0, len(record.RequestSteps))
	for _, step := range record.RequestSteps {
		requestSteps = append(requestSteps, ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}
	responseSteps := make([]ProtocolCryptoStep, 0, len(record.ResponseSteps))
	for _, step := range record.ResponseSteps {
		responseSteps = append(responseSteps, ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}

	return ProtocolTrace{
		TaskID:                 record.TaskID,
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
	}
}

func convertDatabaseProtocolTrace(record database.ProtocolTraceRecord) ProtocolTrace {
	requestSteps := make([]ProtocolCryptoStep, 0, len(record.RequestSteps))
	for _, step := range record.RequestSteps {
		requestSteps = append(requestSteps, ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}
	responseSteps := make([]ProtocolCryptoStep, 0, len(record.ResponseSteps))
	for _, step := range record.ResponseSteps {
		responseSteps = append(responseSteps, ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}

	return ProtocolTrace{
		TaskID:                 record.TaskID,
		Version:                record.Version,
		TargetURL:              record.TargetURL,
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
	}
}

func normalizeSDKProtocolTraceForView(trace ProtocolTrace) ProtocolTrace {
	dbTrace := toDatabaseProtocolTrace(trace)
	dbTrace.NormalizeForView()
	normalized := convertDatabaseProtocolTrace(*dbTrace)
	normalized.RequestSteps = filterSDKProtocolSteps(normalized.RequestSteps)
	normalized.ResponseSteps = filterSDKProtocolSteps(normalized.ResponseSteps)
	normalized.Algorithms = filterSDKProtocolAlgorithms(normalized.Algorithms)
	return normalized
}

func filterSDKProtocolSteps(steps []ProtocolCryptoStep) []ProtocolCryptoStep {
	if len(steps) == 0 {
		return steps
	}

	filtered := make([]ProtocolCryptoStep, 0, len(steps))
	for _, step := range steps {
		if !isMeaningfulSDKProtocolStep(step) {
			continue
		}
		filtered = append(filtered, step)
	}
	return filtered
}

func filterSDKProtocolAlgorithms(algorithms []string) []string {
	if len(algorithms) == 0 {
		return algorithms
	}

	filtered := make([]string, 0, len(algorithms))
	seen := make(map[string]struct{}, len(algorithms))
	for _, algorithm := range algorithms {
		if !isMeaningfulSDKProtocolAlgorithm(algorithm) {
			continue
		}
		if _, ok := seen[algorithm]; ok {
			continue
		}
		seen[algorithm] = struct{}{}
		filtered = append(filtered, algorithm)
	}
	return filtered
}

func shouldIgnoreSDKProtocolAlgorithm(algorithm string) bool {
	_, ignored := sdkIgnoredProtocolAlgorithms[strings.ToLower(strings.TrimSpace(algorithm))]
	return ignored
}

func isMeaningfulSDKProtocolAlgorithm(algorithm string) bool {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	if shouldIgnoreSDKProtocolAlgorithm(algorithm) {
		return false
	}
	if strings.Contains(algorithm, "encrypt") || strings.Contains(algorithm, "decrypt") || strings.Contains(algorithm, "sign") {
		return true
	}
	for _, token := range []string{"rsa", "sm2", "sm3", "sm4", "aes", "des", "tripledes", "rc4", "rabbit", "hmac", "sha", "md5"} {
		if strings.Contains(algorithm, token) {
			return true
		}
	}
	return false
}

func isMeaningfulSDKProtocolStep(step ProtocolCryptoStep) bool {
	if isMeaningfulSDKProtocolAlgorithm(step.Source) || isMeaningfulSDKProtocolAlgorithm(step.Algorithm) {
		return true
	}
	source := strings.ToLower(strings.TrimSpace(firstNonEmptySDKProtocolString(step.Source, step.FunctionPath)))
	input := strings.TrimSpace(step.InputPreview)
	output := strings.TrimSpace(step.OutputPreview)
	if input == "" || output == "" || input == output {
		return false
	}
	switch {
	case source == "se" || strings.HasSuffix(source, ".se"):
		return isLikelySDKCiphertext(output)
	case source == "sd" || strings.HasSuffix(source, ".sd"):
		return isLikelySDKCiphertext(input) && !isLikelySDKCiphertext(output)
	default:
		return false
	}
}

func isLikelySDKCiphertext(text string) bool {
	text = strings.TrimSpace(text)
	if len(text) >= 2 && strings.HasPrefix(text, `"`) && strings.HasSuffix(text, `"`) {
		text = strings.TrimSpace(text[1 : len(text)-1])
	}
	if len(text) < 24 || strings.ContainsAny(text, "{[") {
		return false
	}
	if len(text) >= 32 && len(text)%2 == 0 && isSDKHexString(text) {
		return true
	}
	return isSDKBase64Like(text)
}

func isSDKHexString(text string) bool {
	if text == "" {
		return false
	}
	for _, ch := range text {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

func isSDKBase64Like(text string) bool {
	if len(text) < 24 || len(text)%4 != 0 {
		return false
	}
	for _, ch := range text {
		switch {
		case ch >= 'A' && ch <= 'Z':
		case ch >= 'a' && ch <= 'z':
		case ch >= '0' && ch <= '9':
		case ch == '+' || ch == '/' || ch == '=':
		default:
			return false
		}
	}
	return true
}

func firstNonEmptySDKProtocolString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func toDatabaseProtocolTrace(trace ProtocolTrace) *database.ProtocolTraceRecord {
	requestSteps := make([]database.ProtocolCryptoStep, 0, len(trace.RequestSteps))
	for _, step := range trace.RequestSteps {
		requestSteps = append(requestSteps, database.ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}
	responseSteps := make([]database.ProtocolCryptoStep, 0, len(trace.ResponseSteps))
	for _, step := range trace.ResponseSteps {
		responseSteps = append(responseSteps, database.ProtocolCryptoStep{
			Source:        step.Source,
			Algorithm:     step.Algorithm,
			InputPreview:  step.InputPreview,
			OutputPreview: step.OutputPreview,
			CallID:        step.CallID,
			ParentCallID:  step.ParentCallID,
			FunctionPath:  step.FunctionPath,
			ModuleID:      step.ModuleID,
			Stack:         step.Stack,
			CapturedAtMS:  step.CapturedAtMS,
		})
	}

	return &database.ProtocolTraceRecord{
		TaskID:                 trace.TaskID,
		Version:                trace.Version,
		TargetURL:              trace.TargetURL,
		TraceID:                trace.TraceID,
		Transport:              trace.Transport,
		PageURL:                trace.PageURL,
		RequestURL:             trace.RequestURL,
		Method:                 trace.Method,
		RequestHeaders:         trace.RequestHeaders,
		RequestBeforeTransform: trace.RequestBeforeTransform,
		FinalRequestBody:       trace.FinalRequestBody,
		RequestSteps:           requestSteps,
		ResponseSteps:          responseSteps,
		SignatureFields:        trace.SignatureFields,
		DynamicParams:          trace.DynamicParams,
		SessionMaterials:       trace.SessionMaterials,
		Algorithms:             trace.Algorithms,
		Stack:                  trace.Stack,
		CreatedAt:              trace.CreatedAt,
	}
}

func newTargetResultFromCapturedActivity(targetURL string, allNetworkURLs []string, apiRecords []crawl.NetworkRecord, protocolTraces []crawl.ProtocolTraceRecord, frontendRoutes []crawl.FrontendRouteRecord) TargetResult {
	result := TargetResult{
		Target:          targetURL,
		SiteTree:        crawl.BuildElTree(allNetworkURLs),
		APIRecords:      make([]APIRecord, 0, len(apiRecords)),
		ProtocolTraces:  make([]ProtocolTrace, 0, len(protocolTraces)),
		Assets:          AssetInfo{},
		Vulnerabilities: []VulnerabilityItem{},
	}

	for _, record := range apiRecords {
		result.APIRecords = append(result.APIRecords, convertNetworkRecord(record))
	}
	for _, trace := range protocolTraces {
		result.ProtocolTraces = append(
			result.ProtocolTraces,
			normalizeSDKProtocolTraceForView(convertProtocolTrace(trace)),
		)
	}
	for _, route := range frontendRoutes {
		if path := strings.TrimSpace(route.Path); path != "" {
			result.Assets.FrontendRoutes = append(result.Assets.FrontendRoutes, path)
		}
	}

	return result
}

func convertNetworkRecordToDatabaseAPIResource(taskID string, version int, record crawl.NetworkRecord) database.APIResource {
	return database.APIResource{
		TaskID:           taskID,
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
		Headers:          record.ResponseHeaders,
		FetchedAt:        record.FetchedAt,
	}
}

func preferTraceResponseBody(trace crawl.ProtocolTraceRecord) string {
	if body := strings.TrimSpace(trace.SessionMaterials["latest_response_plaintext"]); body != "" {
		return body
	}
	if body := strings.TrimSpace(trace.SessionMaterials["latest_response_ciphertext"]); body != "" {
		return body
	}
	return ""
}

func mergeCapturedAPIRecordsWithProtocolTraces(apiRecords []crawl.NetworkRecord, protocolTraces []crawl.ProtocolTraceRecord) []crawl.NetworkRecord {
	merged := make([]crawl.NetworkRecord, 0, len(apiRecords)+len(protocolTraces))
	recordIndex := make(map[string]int, len(apiRecords)+len(protocolTraces))
	traceIndex := make(map[string]int, len(apiRecords)+len(protocolTraces))
	urlMethodIndex := make(map[string]int, len(apiRecords)+len(protocolTraces))

	putRecord := func(record crawl.NetworkRecord) {
		key := strings.TrimSpace(record.Method) + "|" + strings.TrimSpace(record.URL) + "|" + strings.TrimSpace(record.RequestBody)
		urlMethodKey := strings.TrimSpace(record.Method) + "|" + strings.TrimSpace(record.URL)

		idx := -1
		if traceID := strings.TrimSpace(record.TraceID); traceID != "" {
			if existingIdx, ok := traceIndex[traceID]; ok {
				idx = existingIdx
			}
		}
		if idx == -1 {
			if existingIdx, ok := recordIndex[key]; ok {
				idx = existingIdx
			}
		}
		if idx == -1 {
			if existingIdx, ok := urlMethodIndex[urlMethodKey]; ok {
				existing := merged[existingIdx]
				if strings.TrimSpace(existing.RequestBody) == "" || strings.TrimSpace(record.RequestBody) == "" {
					idx = existingIdx
				}
			}
		}

		if idx >= 0 {
			existing := &merged[idx]
			if existing.TraceID == "" {
				existing.TraceID = record.TraceID
			}
			existing.HasProtocolTrace = existing.HasProtocolTrace || record.HasProtocolTrace
			if existing.ResourceType == "" {
				existing.ResourceType = record.ResourceType
			}
			if len(existing.RequestHeaders) == 0 {
				existing.RequestHeaders = record.RequestHeaders
			}
			if existing.RequestBody == "" {
				existing.RequestBody = record.RequestBody
			}
			if len(existing.ResponseHeaders) == 0 {
				existing.ResponseHeaders = record.ResponseHeaders
			}
			if existing.ResponseBody == "" {
				existing.ResponseBody = record.ResponseBody
			}
			if existing.ResponseCode == 0 {
				existing.ResponseCode = record.ResponseCode
			}
			if existing.MIMEType == "" {
				existing.MIMEType = record.MIMEType
			}
			if existing.FetchedAt.IsZero() {
				existing.FetchedAt = record.FetchedAt
			}
			recordIndex[key] = idx
			urlMethodIndex[urlMethodKey] = idx
			if traceID := strings.TrimSpace(existing.TraceID); traceID != "" {
				traceIndex[traceID] = idx
			}
			return
		}

		nextIdx := len(merged)
		recordIndex[key] = nextIdx
		urlMethodIndex[urlMethodKey] = nextIdx
		if traceID := strings.TrimSpace(record.TraceID); traceID != "" {
			traceIndex[traceID] = nextIdx
		}
		merged = append(merged, record)
	}

	for _, record := range apiRecords {
		putRecord(record)
	}

	for _, trace := range protocolTraces {
		requestURL := strings.TrimSpace(trace.RequestURL)
		if requestURL == "" {
			continue
		}

		record := crawl.NetworkRecord{
			URL:              requestURL,
			Method:           trace.Method,
			ResourceType:     trace.Transport,
			TraceID:          trace.TraceID,
			HasProtocolTrace: strings.TrimSpace(trace.TraceID) != "",
			RequestHeaders:   trace.RequestHeaders,
			RequestBody:      trace.FinalRequestBody,
			ResponseBody:     preferTraceResponseBody(trace),
			FetchedAt:        trace.CreatedAt,
		}

		if strings.HasPrefix(strings.TrimSpace(record.ResponseBody), "{") || strings.HasPrefix(strings.TrimSpace(record.ResponseBody), "[") {
			record.MIMEType = "application/json"
		}

		putRecord(record)
	}

	return merged
}

func mergeRuntimeAPIRoutes(routes []string, apiRecords []crawl.NetworkRecord, protocolTraces []crawl.ProtocolTraceRecord) []string {
	merged := append([]string{}, routes...)
	for _, record := range apiRecords {
		if url := strings.TrimSpace(record.URL); url != "" {
			merged = append(merged, url)
		}
	}
	for _, trace := range protocolTraces {
		if url := strings.TrimSpace(trace.RequestURL); url != "" {
			merged = append(merged, url)
		}
	}
	return arrayutil.RemoveDuplicates(merged)
}

func preferAbsoluteRuntimeRoutes(routes []string, runtimeRouteGroups ...[]string) []string {
	runtimeAbsoluteByPath := make(map[string]bool)
	for _, group := range runtimeRouteGroups {
		for _, route := range group {
			pathKey, isAbsolute := sdkAPIRoutePathKey(route)
			if pathKey != "" && isAbsolute {
				runtimeAbsoluteByPath[pathKey] = true
			}
		}
	}

	relativeByPath := make(map[string]bool)
	for _, route := range routes {
		pathKey, isAbsolute := sdkAPIRoutePathKey(route)
		if pathKey == "" || isAbsolute {
			continue
		}
		relativeByPath[pathKey] = true
	}

	result := make([]string, 0, len(routes))
	for _, route := range routes {
		trimmed := strings.TrimSpace(route)
		if trimmed == "" {
			continue
		}

		pathKey, isAbsolute := sdkAPIRoutePathKey(trimmed)
		if pathKey != "" {
			if !isAbsolute && runtimeAbsoluteByPath[pathKey] {
				continue
			}
			if isAbsolute && !runtimeAbsoluteByPath[pathKey] && relativeByPath[pathKey] {
				continue
			}
		}
		result = append(result, trimmed)
	}
	return crawl.DeduplicateSimilarAPIRoutes(arrayutil.RemoveDuplicates(result))
}

func sdkAPIRoutePathKey(route string) (string, bool) {
	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return "", false
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", false
	}

	pathValue := strings.TrimSpace(parsed.Path)
	if pathValue == "" {
		return "", parsed.Scheme != "" && parsed.Host != ""
	}
	if !strings.HasPrefix(pathValue, "/") {
		pathValue = "/" + pathValue
	}
	return pathValue, parsed.Scheme != "" && parsed.Host != ""
}

func buildSDKSecurityLeads(targetURL string, routes []string, blueprints []crawl.RequestBlueprint, apiRecords []APIRecord, highRiskKeywords []string) []SecurityLead {
	keywords := sdkSecurityLeadKeywords(highRiskKeywords)
	blueprintIndex := indexSDKRequestBlueprints(blueprints)
	recordIndex := indexSDKAPIRecords(apiRecords)
	seen := make(map[string]struct{}, len(routes))
	leads := make([]SecurityLead, 0)

	for _, route := range routes {
		normalizedRoute := strings.TrimSpace(route)
		if normalizedRoute == "" {
			continue
		}
		keyword, category, hypotheses, nextStep, ok := classifySDKSecurityLead(normalizedRoute, keywords)
		if !ok {
			continue
		}
		pathKey, _ := sdkAPIRoutePathKey(normalizedRoute)
		if pathKey == "" {
			pathKey = normalizedRoute
		}
		if _, exists := seen[pathKey]; exists {
			continue
		}
		seen[pathKey] = struct{}{}

		blueprint := findSDKSecurityLeadBlueprint(pathKey, blueprintIndex)
		record := recordIndex[pathKey]
		method := firstNonEmptyString(blueprint.Method, record.Method, inferSDKSecurityLeadMethod(category))
		fullURL := normalizedRoute
		if parsed, err := url.Parse(normalizedRoute); err != nil || parsed.Scheme == "" || parsed.Host == "" {
			fullURL = resolveSDKSecurityLeadURL(targetURL, normalizedRoute)
		}
		lead := SecurityLead{
			ID:                buildSDKSecurityLeadID(method, pathKey, keyword),
			Route:             normalizedRoute,
			URL:               fullURL,
			Method:            method,
			Category:          category,
			Decision:          "needs_review",
			Reason:            "matched high-risk/business-action keyword: " + keyword,
			MatchedKeyword:    keyword,
			RiskHypotheses:    hypotheses,
			SuggestedNextStep: nextStep,
			Request:           buildSDKSecurityLeadRequest(blueprint, record),
			Source:            blueprint.Source,
			EvidenceSnippets:  buildSDKSecurityLeadEvidence(blueprint),
		}
		leads = append(leads, lead)
	}

	return leads
}

func sdkSecurityLeadKeywords(extra []string) []string {
	defaults := []string{
		"sms", "sendsms", "send_sms", "sendcode", "send_code",
		"/save", "submit", "apply", "getapplyid",
		"upload", "delete", "remove", "update", "modify",
		"pay", "order", "login", "logout", "token",
	}
	seen := make(map[string]struct{}, len(defaults)+len(extra))
	result := make([]string, 0, len(defaults)+len(extra))
	for _, keyword := range append(defaults, extra...) {
		keyword = strings.ToLower(strings.TrimSpace(keyword))
		if keyword == "" {
			continue
		}
		if _, exists := seen[keyword]; exists {
			continue
		}
		seen[keyword] = struct{}{}
		result = append(result, keyword)
	}
	return result
}

func classifySDKSecurityLead(route string, keywords []string) (string, string, []string, string, bool) {
	lower := strings.ToLower(strings.TrimSpace(route))
	for _, keyword := range keywords {
		if keyword == "" || !strings.Contains(lower, keyword) {
			continue
		}
		category := "business-action"
		hypotheses := []string{"state-changing endpoint", "requires authorized test data before active probing"}
		nextStep := "manual-review-or-authorized-replay"
		switch {
		case strings.Contains(keyword, "sms") || strings.Contains(keyword, "sendcode") || strings.Contains(lower, "sms"):
			category = "sms-action"
			hypotheses = []string{"arbitrary recipient SMS trigger", "SMS rate-limit bypass", "verification-code workflow abuse"}
			nextStep = "review with test phone number and strict rate limit before replay"
		case strings.Contains(keyword, "save") || strings.Contains(keyword, "submit") || strings.Contains(keyword, "apply") || strings.Contains(lower, "/save"):
			category = "state-changing-submit"
			hypotheses = []string{"unauthorized submission", "parameter tampering", "duplicate submission or business-data pollution"}
			nextStep = "dry-run request construction first; replay only in authorized test environment"
		case strings.Contains(keyword, "upload"):
			category = "file-upload-action"
			hypotheses = []string{"unsafe file upload", "storage path exposure", "content-type validation bypass"}
			nextStep = "manual upload test with benign fixture in authorized environment"
		case strings.Contains(keyword, "delete") || strings.Contains(keyword, "remove") || strings.Contains(keyword, "update") || strings.Contains(keyword, "modify"):
			category = "mutation-action"
			hypotheses = []string{"unauthorized mutation", "IDOR on mutable object", "missing CSRF or replay protection"}
			nextStep = "manual review with disposable test object"
		case strings.Contains(keyword, "token") || strings.Contains(keyword, "login") || strings.Contains(keyword, "logout"):
			category = "auth-session-action"
			hypotheses = []string{"session workflow weakness", "token leakage or replay", "authentication state confusion"}
			nextStep = "review authentication flow and replay only with test account"
		}
		return keyword, category, hypotheses, nextStep, true
	}
	return "", "", nil, "", false
}

func indexSDKRequestBlueprints(blueprints []crawl.RequestBlueprint) map[string]crawl.RequestBlueprint {
	index := make(map[string]crawl.RequestBlueprint, len(blueprints))
	for _, blueprint := range blueprints {
		key, _ := sdkAPIRoutePathKey(blueprint.Path)
		if key == "" {
			key = strings.TrimSpace(blueprint.Path)
		}
		if key == "" {
			continue
		}
		current, exists := index[key]
		if !exists || shouldPreferSDKSecurityLeadBlueprint(current, blueprint) {
			index[key] = blueprint
		}
	}
	return index
}

func shouldPreferSDKSecurityLeadBlueprint(current, candidate crawl.RequestBlueprint) bool {
	currentScore := len(current.Params) + len(current.Headers) + len(current.Interceptors)
	candidateScore := len(candidate.Params) + len(candidate.Headers) + len(candidate.Interceptors)
	if strings.TrimSpace(current.PayloadPreview) != "" {
		currentScore += 2
	}
	if strings.TrimSpace(candidate.PayloadPreview) != "" {
		candidateScore += 2
	}
	if strings.TrimSpace(current.Source.Snippet) != "" {
		currentScore++
	}
	if strings.TrimSpace(candidate.Source.Snippet) != "" {
		candidateScore++
	}
	return candidateScore > currentScore
}

func indexSDKAPIRecords(records []APIRecord) map[string]APIRecord {
	index := make(map[string]APIRecord, len(records))
	for _, record := range records {
		key, _ := sdkAPIRoutePathKey(record.URL)
		if key == "" {
			continue
		}
		index[key] = record
	}
	return index
}

func findSDKSecurityLeadBlueprint(pathKey string, index map[string]crawl.RequestBlueprint) crawl.RequestBlueprint {
	if blueprint, ok := index[pathKey]; ok {
		return blueprint
	}
	for key, blueprint := range index {
		if strings.HasSuffix(pathKey, key) || strings.HasSuffix(key, pathKey) {
			return blueprint
		}
	}
	return crawl.RequestBlueprint{}
}

func buildSDKSecurityLeadRequest(blueprint crawl.RequestBlueprint, record APIRecord) SecurityLeadRequest {
	return SecurityLeadRequest{
		PayloadCarrier:    blueprint.PayloadCarrier,
		PayloadFormat:     blueprint.PayloadFormat,
		PayloadPreview:    limitSDKLeadText(blueprint.PayloadPreview, 2000),
		RequestBody:       limitSDKLeadText(record.RequestBody, 2000),
		Params:            append([]crawl.RequestBlueprintParam(nil), blueprint.Params...),
		Headers:           append([]crawl.RequestBlueprintHeader(nil), blueprint.Headers...),
		Interceptors:      append([]crawl.RequestBlueprintInterceptor(nil), blueprint.Interceptors...),
		UnresolvedSymbols: append([]string(nil), blueprint.UnresolvedSymbols...),
	}
}

func buildSDKSecurityLeadEvidence(blueprint crawl.RequestBlueprint) []string {
	evidence := make([]string, 0, 1+len(blueprint.Context))
	if snippet := limitSDKLeadText(blueprint.Source.Snippet, 1200); snippet != "" {
		evidence = append(evidence, snippet)
	}
	for _, context := range blueprint.Context {
		if trimmed := limitSDKLeadText(context, 1200); trimmed != "" {
			evidence = append(evidence, trimmed)
		}
	}
	if len(evidence) > 4 {
		return evidence[:4]
	}
	return evidence
}

func buildSDKSecurityLeadID(method, pathKey, keyword string) string {
	hash := sha1.Sum([]byte(strings.ToUpper(strings.TrimSpace(method)) + "|" + strings.TrimSpace(pathKey) + "|" + strings.TrimSpace(keyword)))
	return "lead-" + hex.EncodeToString(hash[:])[:12]
}

func inferSDKSecurityLeadMethod(category string) string {
	switch category {
	case "sms-action", "state-changing-submit", "file-upload-action", "mutation-action", "auth-session-action":
		return "POST"
	default:
		return "GET"
	}
}

func resolveSDKSecurityLeadURL(targetURL, route string) string {
	base, err := url.Parse(strings.TrimSpace(targetURL))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return strings.TrimSpace(route)
	}
	trimmedRoute := strings.TrimSpace(route)
	if strings.HasPrefix(trimmedRoute, "/m/") {
		basePath := base.EscapedPath()
		if idx := strings.Index(basePath, "/m/"); idx >= 0 {
			return base.Scheme + "://" + base.Host + basePath[:idx] + trimmedRoute
		}
		if strings.HasSuffix(basePath, "/m") {
			return base.Scheme + "://" + base.Host + strings.TrimSuffix(basePath, "/m") + trimmedRoute
		}
	}
	parsed, err := url.Parse(trimmedRoute)
	if err != nil {
		return trimmedRoute
	}
	return base.ResolveReference(parsed).String()
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func limitSDKLeadText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return value[:limit] + "...[truncated]"
}

func sdkEnsureTrailingSlash(value string) string {
	if strings.HasSuffix(value, "/") {
		return value
	}
	return value + "/"
}

func preferAbsoluteAPIRoots(roots []string) []string {
	absoluteByPath := make(map[string]bool)
	for _, root := range roots {
		parsed, err := url.Parse(strings.TrimSpace(root))
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		absoluteByPath[sdkEnsureTrailingSlash(parsed.Path)] = true
	}

	result := make([]string, 0, len(roots))
	for _, root := range roots {
		trimmed := strings.TrimSpace(root)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "/") && absoluteByPath[sdkEnsureTrailingSlash(trimmed)] {
			continue
		}
		result = append(result, trimmed)
	}
	return arrayutil.RemoveDuplicates(result)
}

func normalizeProtocolTraceRecordsForStore(records []crawl.ProtocolTraceRecord) []database.ProtocolTraceRecord {
	result := make([]database.ProtocolTraceRecord, 0, len(records))
	for _, record := range records {
		trace := normalizeSDKProtocolTraceForView(convertProtocolTrace(record))
		result = append(result, *toDatabaseProtocolTrace(trace))
	}
	return result
}

func resolveSDKScanIdentity(options *ScanOptions) (string, int) {
	const defaultTaskID = "cli-mode"

	taskID := strings.TrimSpace(options.TaskID)
	if taskID == "" {
		taskID = defaultTaskID
	}
	version := options.Version
	if version < 0 {
		version = 0
	}
	return taskID, version
}

func prepareSDKLogCapture(options *ScanOptions) (func() error, error) {
	if options == nil || (options.LogOutput == nil && strings.TrimSpace(options.LogOutputPath) == "") {
		return func() error { return nil }, nil
	}

	restoreOutput, err := logger.ConfigureOutput(options.LogOutput, options.LogOutputPath)
	if err != nil {
		return nil, err
	}

	capture, err := logger.InstallStandardCapture()
	if err != nil {
		_ = restoreOutput()
		return nil, err
	}

	return func() error {
		return errors.Join(capture.Restore(), restoreOutput())
	}, nil
}

// PerformScan 执行CLI扫描（无数据库操作）- SDK版本，使用ScanOptions
func PerformScan(urls []string, options *ScanOptions) (*ScanResult, error) {
	if options == nil {
		return nil, fmt.Errorf("scan options cannot be nil")
	}
	restoreLogs, err := prepareSDKLogCapture(options)
	if err != nil {
		return nil, fmt.Errorf("configure log output: %w", err)
	}
	defer func() {
		_ = restoreLogs()
	}()

	if options.DataStore == nil {
		options.DataStore = database.NewMemoryScanDataStore()
	}

	startTime := time.Now()
	scanTaskID, scanVersion := resolveSDKScanIdentity(options)

	var allTargetResults []TargetResult
	var totalTreeNodes int
	var totalVulnerabilities int
	var totalAssets AssetCount
	shouldContinue := true

	for i, targetURL := range urls {
		if !shouldContinue {
			break
		}

		fmt.Printf("[信息] 处理 URL %d/%d: %s\n", i+1, len(urls), targetURL)
		if options.OnResult != nil {
			event := ScanEvent{
				Type:      EventTypeProgress,
				Target:    targetURL,
				Timestamp: time.Now(),
				Data: map[string]interface{}{
					"current": i + 1,
					"total":   len(urls),
					"url":     targetURL,
					"status":  "started",
				},
			}
			if !options.OnResult(event) {
				fmt.Printf("[信息] 扫描已通过回调函数停止\n")
				shouldContinue = false
				break
			}
		}

		targetScanResult, err := scanexec.RunTarget(targetURL, scanexec.Options{
			TaskID:         scanTaskID,
			Version:        scanVersion,
			BlackDomain:    options.BlackDomain,
			HighRiskRouter: options.HighRiskRouter,
			Authentication: options.Authentication,
			Placeholder:    options.Placeholder,
			WeakCreds:      options.WeakCreds,
			OpenAI: config.OpenAI{
				APIKey:  options.OpenAI.APIKey,
				BaseURL: options.OpenAI.BaseURL,
				Model:   options.OpenAI.Model,
				Enabled: options.OpenAI.Enabled,
			},
			VulnDetection: config.VulnDetection{
				Enabled:       options.VulnDetection.Enabled,
				Authorization: options.VulnDetection.Authorization,
				SQLInjection:  options.VulnDetection.SQLInjection,
				LFI:           options.VulnDetection.LFI,
				SSRF:          options.VulnDetection.SSRF,
				Redirect:      options.VulnDetection.Redirect,
				XSS:           options.VulnDetection.XSS,
				Upload:        options.VulnDetection.Upload,
			},
			DataStore: options.DataStore,
		})
		if err != nil {
			fmt.Printf("[警告] 目标 %s 无法访问: %v\n", targetURL, err)
			if options.OnResult != nil {
				options.OnResult(ScanEvent{
					Type:      EventTypeError,
					Target:    targetURL,
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"error": err.Error(),
						"url":   targetURL,
					},
				})
			}
			continue
		}

		if memoryStore, ok := options.DataStore.(*database.MemoryScanDataStore); ok {
			apiResources := make([]database.APIResource, 0, len(targetScanResult.APIRecords))
			for _, record := range targetScanResult.APIRecords {
				apiResources = append(apiResources, convertNetworkRecordToDatabaseAPIResource(scanTaskID, scanVersion, record))
			}
			memoryStore.AddJSResources(scanTaskID, targetScanResult.JSResources)
			memoryStore.AddAPIResources(scanTaskID, apiResources)
			memoryStore.AddProtocolTraces(scanTaskID, normalizeProtocolTraceRecordsForStore(targetScanResult.ProtocolTraces))
		}

		targetResult := TargetResult{
			Target:                targetURL,
			SiteTree:              targetScanResult.TreeData,
			JSResources:           make([]tbdb.JSResource, 0, len(targetScanResult.JSResources)),
			RequestBlueprintCount: len(targetScanResult.RequestBlueprints),
			RequestBlueprints:     append([]crawl.RequestBlueprint(nil), targetScanResult.RequestBlueprints...),
			AnchorCandidates:      append([]crawl.RequestAnchorCandidate(nil), targetScanResult.RequestAnchorCandidates...),
			OperationSpecs:        append([]crawl.OperationSpec(nil), targetScanResult.OperationSpecs...),
			APIRecords:            make([]APIRecord, 0, len(targetScanResult.APIRecords)),
			APIContexts:           append([]*apicontext.Context(nil), targetScanResult.APIContexts...),
			ProtocolTraces:        make([]ProtocolTrace, 0, len(targetScanResult.ProtocolTraces)),
			Assets:                convertSharedAssets(targetScanResult.Assets),
			Fingerprints:          convertSharedFingerprints(targetScanResult.Fingerprints),
			Vulnerabilities:       convertSharedVulnerabilities(targetScanResult.Vulnerabilities),
		}
		for _, check := range targetScanResult.AuthorizationChecks {
			targetResult.AuthorizationChecks = append(targetResult.AuthorizationChecks, AuthorizationCheck{
				OperationID: check.OperationID,
				URL:         check.URL,
				Method:      check.Method,
				Verdict:     check.Verdict,
			})
		}
		for _, resource := range targetScanResult.JSResources {
			targetResult.JSResources = append(targetResult.JSResources, resource)
		}
		for _, record := range targetScanResult.APIRecords {
			targetResult.APIRecords = append(targetResult.APIRecords, convertNetworkRecord(record))
		}
		for _, trace := range targetScanResult.ProtocolTraces {
			targetResult.ProtocolTraces = append(targetResult.ProtocolTraces, normalizeSDKProtocolTraceForView(convertProtocolTrace(trace)))
		}
		targetResult.SecurityLeads = buildSDKSecurityLeads(targetURL, targetResult.Assets.APIRoutes, targetResult.RequestBlueprints, targetResult.APIRecords, options.HighRiskRouter)
		targetResult.Overview = buildSDKTargetOverview(targetResult)

		totalTreeNodes += countTreeNodes(targetResult.SiteTree)
		if options.OnResult != nil {
			for _, record := range targetResult.APIRecords {
				if !options.OnResult(ScanEvent{
					Type:      EventTypeAPIRecord,
					Target:    targetURL,
					Timestamp: record.FetchedAt,
					Data:      record,
				}) {
					fmt.Printf("[信息] 扫描已通过回调函数停止\n")
					shouldContinue = false
					break
				}
			}
			if shouldContinue {
				for _, trace := range targetResult.ProtocolTraces {
					if !options.OnResult(ScanEvent{
						Type:      EventTypeProtocolTrace,
						Target:    targetURL,
						Timestamp: trace.CreatedAt,
						Data:      trace,
					}) {
						fmt.Printf("[信息] 扫描已通过回调函数停止\n")
						shouldContinue = false
						break
					}
				}
			}
			if !shouldContinue {
				break
			}
		}

		for _, assetGroup := range []struct {
			assetType string
			items     []SensitiveItem
		}{
			{assetType: "email", items: targetResult.Assets.Email},
			{assetType: "idCard", items: targetResult.Assets.IDCard},
			{assetType: "phone", items: targetResult.Assets.Phone},
			{assetType: "ipUrl", items: targetResult.Assets.IPURL},
			{assetType: "sensitive", items: targetResult.Assets.Sensitive},
		} {
			for _, assetItem := range assetGroup.items {
				if options.OnResult == nil {
					continue
				}
				if !options.OnResult(ScanEvent{
					Type:      EventTypeAsset,
					Target:    targetURL,
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"type":    assetGroup.assetType,
						"value":   assetItem.Value,
						"source":  assetItem.Source,
						"sources": assetItem.Sources,
					},
				}) {
					fmt.Printf("[信息] 扫描已通过回调函数停止\n")
					shouldContinue = false
					break
				}
			}
			if !shouldContinue {
				break
			}
		}
		if !shouldContinue {
			break
		}

		for _, vulnItem := range targetResult.Vulnerabilities {
			if options.OnResult == nil {
				continue
			}
			if !options.OnResult(ScanEvent{
				Type:      EventTypeVulnerability,
				Target:    targetURL,
				Timestamp: parseSDKTimestamp(vulnItem.CreatedAt),
				Data:      vulnItem,
			}) {
				fmt.Printf("[信息] 扫描已通过回调函数停止\n")
				shouldContinue = false
				break
			}
		}
		totalVulnerabilities += len(targetResult.Vulnerabilities)
		if !shouldContinue {
			break
		}

		allTargetResults = append(allTargetResults, targetResult)
		totalAssets.Email += len(targetResult.Assets.Email)
		totalAssets.IDCard += len(targetResult.Assets.IDCard)
		totalAssets.Phone += len(targetResult.Assets.Phone)
		totalAssets.IPURL += len(targetResult.Assets.IPURL)
		totalAssets.Sensitive += len(targetResult.Assets.Sensitive)
		totalAssets.FrontendRoutes += len(targetResult.Assets.FrontendRoutes)
		totalAssets.APIRoutes += len(targetResult.Assets.APIRoutes)
		totalAssets.APIRoots += len(targetResult.Assets.APIRoots)
	}

	crawl.ClearTestedURLs(scanTaskID)

	result := &ScanResult{
		TaskID:   scanTaskID,
		Version:  scanVersion,
		Targets:  allTargetResults,
		ScanTime: time.Now().Format("2006-01-02 15:04:05"),
		Summary: Summary{
			Focus:                "api_vulnerability_discovery",
			TotalTargets:         len(allTargetResults),
			TotalTreeNodes:       totalTreeNodes,
			TotalVulnerabilities: totalVulnerabilities,
			VulnerabilityTypes:   make(map[string]int),
			TotalAssets:          totalAssets,
		},
	}

	for _, targetResult := range allTargetResults {
		mergeSDKOverviewIntoSummary(&result.Summary, targetResult.Overview)
	}

	if options.OnResult != nil {
		options.OnResult(ScanEvent{
			Type:      EventTypeProgress,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"status":  "completed",
				"summary": result.Summary,
			},
		})
	}

	if options.OutputPath != "" {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON: %v", err)
		}
		if err := os.WriteFile(options.OutputPath, jsonData, 0644); err != nil {
			return nil, fmt.Errorf("failed to write output file: %v", err)
		}
		fmt.Printf("[信息] 扫描结果已保存到: %s\n", options.OutputPath)
	}

	fmt.Printf("[信息] 扫描完成，耗时: %v\n", time.Since(startTime))
	return result, nil
}

func convertSharedAssets(assets scanexec.AssetInfo) AssetInfo {
	return AssetInfo{
		Email:          convertSharedSensitiveItemsToSDK(assets.Email),
		IDCard:         convertSharedSensitiveItemsToSDK(assets.IDCard),
		Phone:          convertSharedSensitiveItemsToSDK(assets.Phone),
		IPURL:          convertSharedSensitiveItemsToSDK(assets.IPURL),
		Sensitive:      convertSharedSensitiveItemsToSDK(assets.Sensitive),
		FrontendRoutes: append([]string{}, assets.FrontendRoutes...),
		APIRoutes:      append([]string{}, assets.APIRoutes...),
		APIRoots:       append([]string{}, assets.APIRoots...),
	}
}

func convertSharedSensitiveItemsToSDK(items []scanexec.SensitiveItem) []SensitiveItem {
	result := make([]SensitiveItem, 0, len(items))
	for _, item := range items {
		result = append(result, SensitiveItem{
			Value:      item.Value,
			Source:     item.Source,
			Sources:    append([]string(nil), item.Sources...),
			AIVerified: item.AIVerified,
		})
	}
	return result
}

func convertSharedFingerprints(items []structs.FingerprintResult) []FingerprintItem {
	result := make([]FingerprintItem, 0, len(items))
	for _, item := range items {
		matches := make([]FingerprintMatchItem, 0, len(item.Fingerprints))
		for _, match := range item.Fingerprints {
			matches = append(matches, FingerprintMatchItem{Name: match.Name})
		}
		result = append(result, FingerprintItem{
			URL:          item.URL,
			StatusCode:   item.StatusCode,
			Length:       item.Length,
			Title:        item.Title,
			Fingerprints: matches,
			Detect:       item.Detect,
		})
	}
	return result
}

func convertSharedVulnerabilities(items []database.VulnRecord) []VulnerabilityItem {
	result := make([]VulnerabilityItem, 0, len(items))
	for _, vuln := range items {
		result = append(result, VulnerabilityItem{
			ID:                 vuln.VulnID,
			Title:              vuln.Title,
			Level:              vuln.Level,
			Type:               vuln.Type,
			URL:                vuln.URL,
			Method:             normalizeSDKVulnerabilityMethod(vuln),
			Request:            vuln.Request,
			Response:           vuln.Response,
			ResponseType:       vuln.ResponseType,
			TraceID:            vuln.TraceID,
			HasProtocolTrace:   vuln.HasProtocolTrace,
			ResponsePlaintext:  vuln.ResponsePlaintext,
			ResponseCiphertext: vuln.ResponseCiphertext,
			DecryptionStatus:   vuln.DecryptionStatus,
			DecryptionDetail:   vuln.DecryptionDetail,
			ResponseLength:     vuln.ResponseLength,
			Confidence:         vuln.Confidence,
			ConfidenceReason:   vuln.ConfidenceReason,
			DataExposure:       vuln.DataExposure,
			ExposureReason:     vuln.ExposureReason,
			AIReviewVerdict:    vuln.AIReviewVerdict,
			AIReviewType:       vuln.AIReviewType,
			AIReviewConfidence: vuln.AIReviewConfidence,
			AIReviewReason:     vuln.AIReviewReason,
			StaticContexts:     append([]database.VulnStaticContext(nil), vuln.StaticContexts...),
			Description:        vuln.Description,
			AIVerified:         vuln.AIVerified,
			CreatedAt:          vuln.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return result
}

func normalizeSDKVulnerabilityMethod(vuln database.VulnRecord) string {
	method := strings.TrimSpace(vuln.Method)
	if method != "" {
		return method
	}
	if strings.TrimSpace(vuln.Type) == "敏感信息泄露" {
		return "GET"
	}
	return ""
}

func parseSDKTimestamp(value string) time.Time {
	timestamp, err := time.ParseInLocation("2006-01-02 15:04:05", strings.TrimSpace(value), time.Local)
	if err != nil {
		return time.Now()
	}
	return timestamp
}

// PerformScanWithConfigFile 执行CLI扫描（使用配置文件，向后兼容）
func PerformScanWithConfigFile(urls []string, configPath string, outputPath string) error {
	options, err := LoadScanOptionsFromFile(configPath)
	if err != nil {
		return err
	}

	options.OutputPath = outputPath
	_, err = PerformScan(urls, options)
	return err
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

// removeDuplicateSensitiveItems 去重敏感信息项
func removeDuplicateSensitiveItems(items []SensitiveItem) []SensitiveItem {
	seen := make(map[string]int, len(items))
	result := make([]SensitiveItem, 0)
	for _, item := range items {
		key := strings.TrimSpace(item.Value)
		if key == "" {
			continue
		}
		item.Sources = mergeSDKSensitiveSources(nil, append([]string{item.Source}, item.Sources...)...)
		if strings.TrimSpace(item.Source) == "" && len(item.Sources) > 0 {
			item.Source = item.Sources[0]
		}
		if index, ok := seen[key]; ok {
			result[index].Sources = mergeSDKSensitiveSources(result[index].Sources, append([]string{item.Source}, item.Sources...)...)
			if strings.TrimSpace(result[index].Source) == "" && len(result[index].Sources) > 0 {
				result[index].Source = result[index].Sources[0]
			}
			result[index].AIVerified = result[index].AIVerified || item.AIVerified
			continue
		}
		seen[key] = len(result)
		result = append(result, item)
	}
	return result
}

func mergeSDKSensitiveSources(base []string, sources ...string) []string {
	result := make([]string, 0, len(base)+len(sources))
	seen := make(map[string]struct{}, len(base)+len(sources))
	for _, source := range append(base, sources...) {
		trimmed := strings.TrimSpace(source)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

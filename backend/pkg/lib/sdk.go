package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/crawl"
	"trailblazer/pkg/core/database"
	"trailblazer/pkg/core/protocoltool"
	"trailblazer/pkg/core/structs"

	"github.com/google/uuid"
	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"
	"gopkg.in/yaml.v3"
)

// VulnRecord 漏洞记录（SDK独立定义，避免ES依赖）
type VulnRecord struct {
	TaskID             string    `json:"task_id"`
	VulnID             string    `json:"vuln_id"`
	Title              string    `json:"title"`
	Level              string    `json:"level"` // high, medium, low, info
	Type               string    `json:"type"`
	URL                string    `json:"url"`
	Method             string    `json:"method,omitempty"`
	Request            string    `json:"request,omitempty"`
	Response           string    `json:"response,omitempty"`
	TraceID            string    `json:"trace_id,omitempty"`
	HasProtocolTrace   bool      `json:"has_protocol_trace,omitempty"`
	ResponseCiphertext string    `json:"response_ciphertext,omitempty"`
	DecryptionStatus   string    `json:"decryption_status,omitempty"`
	DecryptionDetail   string    `json:"decryption_detail,omitempty"`
	ResponseLength     int       `json:"response_length,omitempty"` // 原始响应长度（字节）
	Confidence         string    `json:"confidence,omitempty"`
	ConfidenceReason   string    `json:"confidence_reason,omitempty"`
	DenyTemplateID     string    `json:"deny_template_id,omitempty"`
	DenyTemplateKind   string    `json:"deny_template_kind,omitempty"`
	DenyTemplateLabel  string    `json:"deny_template_label,omitempty"`
	DenyTemplateCount  int       `json:"deny_template_count,omitempty"`
	Description        string    `json:"description"`
	AIVerified         bool      `json:"ai_verified"` // AI辅助验证标记
	CreatedAt          time.Time `json:"created_at"`
}

// ScanEventType 扫描事件类型
type ScanEventType string

const (
	EventTypeVulnerability ScanEventType = "vulnerability" // 漏洞发现
	EventTypeAsset         ScanEventType = "asset"         // 资产发现
	EventTypeRisk          ScanEventType = "risk"          // 风险发现
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

	// 漏洞检测配置
	VulnDetection VulnDetectionOptions `json:"vulnDetection"`

	// 输出路径（可选，为空则输出到标准输出）
	OutputPath string `json:"outputPath,omitempty"`

	// 结果回调函数（可选，用于实时获取扫描结果，类似nuclei）
	// 当发现漏洞、资产、风险时会调用此回调
	// 返回false表示停止扫描，返回true表示继续扫描
	OnResult ScanCallback `json:"-"`

	Proxy string `json:"proxy,omitempty"` // 代理设置（可选）
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
	Enabled      bool                      `json:"enabled"`
	SQLInjection config.SQLInjectionConfig `json:"sqlInjection"`
	LFI          config.LFIConfig          `json:"lfi"`
	SSRF         config.SSRFConfig         `json:"ssrf"`
	Redirect     config.RedirectConfig     `json:"redirect"`
	XSS          config.XSSConfig          `json:"xss"`
	Upload       config.UploadConfig       `json:"upload"`
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
		VulnDetection: VulnDetectionOptions{
			Enabled:      true,
			SQLInjection: config.SQLInjectionConfig{Enabled: true},
			LFI:          config.LFIConfig{Enabled: true},
			SSRF:         config.SSRFConfig{Enabled: true},
			Redirect:     config.RedirectConfig{Enabled: true},
			XSS:          config.XSSConfig{Enabled: true},
			Upload:       config.UploadConfig{Enabled: true},
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
		VulnDetection: VulnDetectionOptions{
			Enabled:      vulnDetectionEnabled,
			SQLInjection: cfg.VulnDetection.SQLInjection,
			LFI:          cfg.VulnDetection.LFI,
			SSRF:         cfg.VulnDetection.SSRF,
			Redirect:     cfg.VulnDetection.Redirect,
			XSS:          cfg.VulnDetection.XSS,
			Upload:       cfg.VulnDetection.Upload,
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
	options *ScanOptions,
	aiChecker *crawl.SensitiveInfoChecker,
) structs.JSFindOptions {
	vulnDetection := resolveSDKVulnDetectionOptions(options.VulnDetection)

	return structs.JSFindOptions{
		TaskID:         taskID,
		HomeURL:        targetURL,
		ApiList:        apiRouter,
		ApiRoot:        root,
		SkipVulnScan:   !vulnDetection.Enabled,
		HighRiskRouter: options.HighRiskRouter,
		Authentication: options.Authentication,
		Placeholder:    options.Placeholder,
		LFIConfig:      vulnDetection.LFI,
		SSRFConfig:     vulnDetection.SSRF,
		RedirectConfig: vulnDetection.Redirect,
		SQLInjConfig:   vulnDetection.SQLInjection,
		XSSConfig:      vulnDetection.XSS,
		UploadConfig:   vulnDetection.Upload,
		AIChecker:      aiChecker,
	}
}

// ScanResult CLI扫描结果
type ScanResult struct {
	Targets  []TargetResult `json:"targets"`
	ScanTime string         `json:"scanTime"`
	Summary  Summary        `json:"summary"`
}

// TargetResult 单个目标的扫描结果
type TargetResult struct {
	Target          string              `json:"target"`
	SiteTree        []crawl.ElTreeNode  `json:"siteTree"`
	APIRecords      []APIRecord         `json:"apiRecords,omitempty"`
	ProtocolTraces  []ProtocolTrace     `json:"protocolTraces,omitempty"`
	Assets          AssetInfo           `json:"assets"`
	Risks           []RiskItem          `json:"risks"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
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

// DecryptResult 解密结果
type DecryptResult = protocoltool.DecryptResult

// AssetInfo 资产信息
type AssetInfo struct {
	Email     []SensitiveItem `json:"email"`
	IDCard    []SensitiveItem `json:"idCard"`
	Phone     []SensitiveItem `json:"phone"`
	IPURL     []SensitiveItem `json:"ipUrl"`
	Sensitive []SensitiveItem `json:"sensitive"`
	APIRoutes []string        `json:"apiRoutes"`
	APIRoots  []string        `json:"apiRoots"`
}

type SensitiveItem struct {
	Value  string `json:"value"`
	Source string `json:"source"`
}

type RiskItem struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Level       string `json:"level"`
	Type        string `json:"type"`
	URL         string `json:"url"`
	Description string `json:"description"`
	CreatedAt   string `json:"createdAt"`
}

// VulnerabilityItem 漏洞信息（来自AnalyzeAPI检测）
type VulnerabilityItem struct {
	ID                 string `json:"id"`
	Title              string `json:"title"`
	Level              string `json:"level"`
	Type               string `json:"type"`
	URL                string `json:"url"`
	Method             string `json:"method,omitempty"`
	Request            string `json:"request,omitempty"`
	Response           string `json:"response,omitempty"`
	TraceID            string `json:"traceId,omitempty"`
	HasProtocolTrace   bool   `json:"hasProtocolTrace,omitempty"`
	ResponseCiphertext string `json:"responseCiphertext,omitempty"`
	DecryptionStatus   string `json:"decryptionStatus,omitempty"`
	DecryptionDetail   string `json:"decryptionDetail,omitempty"`
	ResponseLength     int    `json:"responseLength,omitempty"`
	Description        string `json:"description"`
	AIVerified         bool   `json:"aiVerified"`
	CreatedAt          string `json:"createdAt"`
}

// Summary 扫描摘要
type Summary struct {
	TotalTargets         int        `json:"totalTargets"`
	TotalTreeNodes       int        `json:"totalTreeNodes"`
	TotalRisks           int        `json:"totalRisks"`
	TotalVulnerabilities int        `json:"totalVulnerabilities"`
	TotalAssets          AssetCount `json:"totalAssets"`
}

type AssetCount struct {
	Email     int `json:"email"`
	IDCard    int `json:"idCard"`
	Phone     int `json:"phone"`
	IPURL     int `json:"ipUrl"`
	Sensitive int `json:"sensitive"`
	APIRoutes int `json:"apiRoutes"`
	APIRoots  int `json:"apiRoots"`
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
		fmt.Printf("[WARNING] 无法序列化漏洞记录: %v\n", err)
		return
	}

	var sdkVuln VulnRecord
	if err := json.Unmarshal(jsonData, &sdkVuln); err != nil {
		fmt.Printf("[WARNING] 无法反序列化漏洞记录: %v\n", err)
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

func newTargetResultFromCapturedActivity(targetURL string, allNetworkURLs []string, apiRecords []crawl.NetworkRecord, protocolTraces []crawl.ProtocolTraceRecord) TargetResult {
	result := TargetResult{
		Target:          targetURL,
		SiteTree:        crawl.BuildElTree(allNetworkURLs),
		APIRecords:      make([]APIRecord, 0, len(apiRecords)),
		ProtocolTraces:  make([]ProtocolTrace, 0, len(protocolTraces)),
		Assets:          AssetInfo{},
		Risks:           []RiskItem{},
		Vulnerabilities: []VulnerabilityItem{},
	}

	for _, record := range apiRecords {
		result.APIRecords = append(result.APIRecords, convertNetworkRecord(record))
	}
	for _, trace := range protocolTraces {
		result.ProtocolTraces = append(result.ProtocolTraces, convertProtocolTrace(trace))
	}

	return result
}

// DecryptProtocolTrace 使用 SDK 暴露的协议轨迹材料解密密文
func DecryptProtocolTrace(trace ProtocolTrace, keyHex, ciphertext string) (*DecryptResult, error) {
	return protocoltool.DecryptWithTrace(toDatabaseProtocolTrace(trace), keyHex, ciphertext)
}

// PerformScan 执行CLI扫描（无数据库操作）- SDK版本，使用ScanOptions
func PerformScan(urls []string, options *ScanOptions) (*ScanResult, error) {
	if options == nil {
		return nil, fmt.Errorf("scan options cannot be nil")
	}

	startTime := time.Now()
	const cliTaskID = "cli-mode"

	// 存储所有URL的扫描结果
	var allTargetResults []TargetResult
	var totalTreeNodes int
	var totalRisks int
	var totalVulnerabilities int
	var totalAssets AssetCount

	// 创建漏洞收集器
	vulnCollector := NewCLIVulnCollector()

	// 标志变量，用于控制是否继续扫描
	shouldContinue := true

	// 循环处理每个URL
	for i, targetURL := range urls {
		if !shouldContinue {
			break
		}

		fmt.Printf("[INFO] 处理 URL %d/%d: %s\n", i+1, len(urls), targetURL)

		// 发送进度事件
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
				fmt.Printf("[INFO] 扫描已通过回调函数停止\n")
				shouldContinue = false
				break
			}
		}

		// 存活验证
		_, err := clients.SimpleGet(targetURL, clients.DefaultRestyClient())
		if err != nil {
			fmt.Printf("[WARNING] 目标 %s 无法访问: %v\n", targetURL, err)
			// 发送错误事件
			if options.OnResult != nil {
				event := ScanEvent{
					Type:      EventTypeError,
					Target:    targetURL,
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"error": err.Error(),
						"url":   targetURL,
					},
				}
				options.OnResult(event)
			}
			continue
		}

		e := crawl.Extract{}
		filter := crawl.Filter{}

		// 1. 捕获网络链接、接口请求/响应和协议轨迹
		allNetworkURLs, capturedAPIRecords, capturedProtocolTraces := crawl.CaptureNetworkActivity(targetURL)
		for i := range capturedProtocolTraces {
			if strings.TrimSpace(capturedProtocolTraces[i].TaskID) == "" {
				capturedProtocolTraces[i].TaskID = cliTaskID
			}
		}

		targetResult := newTargetResultFromCapturedActivity(targetURL, allNetworkURLs, capturedAPIRecords, capturedProtocolTraces)

		// 2. 生成网站树（不保存到ES）
		totalTreeNodes += countTreeNodes(targetResult.SiteTree)

		if options.OnResult != nil {
			for _, record := range targetResult.APIRecords {
				event := ScanEvent{
					Type:      EventTypeAPIRecord,
					Target:    targetURL,
					Timestamp: record.FetchedAt,
					Data:      record,
				}
				if !options.OnResult(event) {
					fmt.Printf("[INFO] 扫描已通过回调函数停止\n")
					shouldContinue = false
					break
				}
			}
			if shouldContinue {
				for _, trace := range targetResult.ProtocolTraces {
					event := ScanEvent{
						Type:      EventTypeProtocolTrace,
						Target:    targetURL,
						Timestamp: trace.CreatedAt,
						Data:      trace,
					}
					if !options.OnResult(event) {
						fmt.Printf("[INFO] 扫描已通过回调函数停止\n")
						shouldContinue = false
						break
					}
				}
			}
			if !shouldContinue {
				break
			}
		}

		// 3. 分类链接
		classified := e.ClassifyLinks(allNetworkURLs, options.BlackDomain)

		// 4. 静态JS提取 + 合并去重
		var allJS []string
		staticJsLinks := filter.Blacklist(e.StaticJSLink(targetURL), options.BlackDomain)
		classified.Classification.JS = filter.Blacklist(classified.Classification.JS, options.BlackDomain)

		allJS = classified.Classification.JS
		if len(classified.Classification.JS) > 0 {
			for _, static := range staticJsLinks {
				present := false
				for _, dynamic := range classified.Classification.JS {
					if strings.Contains(dynamic, static) || strings.Contains(static, dynamic) {
						present = true
						break
					}
				}
				if !present {
					allJS = append(allJS, static)
				}
			}
		} else {
			allJS = append(allJS, staticJsLinks...)
		}
		allJS = arrayutil.RemoveDuplicates(allJS)

		// CLI模式不保存JS资源

		// 5. 初始化AI检测器（如果启用）
		var aiChecker *crawl.SensitiveInfoChecker
		if options.OpenAI.Enabled && options.OpenAI.APIKey != "" {
			aiChecker = crawl.NewSensitiveInfoChecker(
				options.OpenAI.APIKey,
				options.OpenAI.BaseURL,
				options.OpenAI.Model,
			)
			fmt.Printf("[INFO] AI辅助敏感信息检测已启用 (模型: %s)\n", options.OpenAI.Model)
		}

		// 6. 从JS中提取资产
		findSomething := crawl.Scan(targetURL, allJS, aiChecker)

		// 转换资产数据并发送回调
		processAsset := func(items []structs.InfoSource, assetType string, target *[]SensitiveItem) {
			for _, item := range items {
				if !shouldContinue {
					return
				}

				assetItem := SensitiveItem{
					Value:  item.Filed,
					Source: item.Source,
				}
				*target = append(*target, assetItem)

				// 调用回调函数（如果设置了）
				if options.OnResult != nil {
					event := ScanEvent{
						Type:      EventTypeAsset,
						Target:    targetURL,
						Timestamp: time.Now(),
						Data: map[string]interface{}{
							"type":   assetType,
							"value":  item.Filed,
							"source": item.Source,
						},
					}
					if !options.OnResult(event) {
						// 回调返回false，停止扫描
						fmt.Printf("[INFO] 扫描已通过回调函数停止\n")
						shouldContinue = false
						return
					}
				}
			}
		}

		processAsset(findSomething.Email, "email", &targetResult.Assets.Email)
		processAsset(findSomething.IDCard, "idCard", &targetResult.Assets.IDCard)
		processAsset(findSomething.Phone, "phone", &targetResult.Assets.Phone)
		processAsset(findSomething.IP_URL, "ipUrl", &targetResult.Assets.IPURL)
		processAsset(findSomething.Sensitive, "sensitive", &targetResult.Assets.Sensitive)

		// 7. API路由整合
		var apiRouter []string
		for _, item := range findSomething.APIRoute {
			route := strings.TrimSpace(item.Filed)
			if route != "" {
				apiRouter = append(apiRouter, route)
			}
		}
		for _, route := range classified.Classification.APIRoute {
			trimmedRoute := strings.TrimSpace(route)
			if trimmedRoute != "" {
				apiRouter = append(apiRouter, trimmedRoute)
			}
		}
		apiRouter = arrayutil.RemoveDuplicates(apiRouter)
		apiRouter = filter.FilterAPIRoutes(apiRouter)
		targetResult.Assets.APIRoutes = apiRouter

		// 8. API根路径分析
		apiRoots := filter.APIRoots(apiRouter, 1)
		allApiRoots := classified.Classification.APIRoot
		for _, item := range classified.Classification.APIRoot {
			for _, v := range apiRoots {
				if !strings.Contains(item, v) {
					allApiRoots = append(allApiRoots, v)
				}
			}
		}
		allApiRoots = append(allApiRoots, apiRoots...)
		allApiRoots = arrayutil.RemoveDuplicates(allApiRoots)
		targetResult.Assets.APIRoots = allApiRoots

		// 9. 漏洞检测（使用收集器模式）
		vulnCollector.Clear()

		// 创建适配器，将SDK的收集器适配为crawl.VulnCollector接口
		adapter := NewSDKVulnCollectorAdapter(vulnCollector)

		for _, root := range allApiRoots {
			fmt.Printf("[INFO] 分析 API 根路径: %s\n", root)
			jsFindOptions := buildSDKJSFindOptions(cliTaskID, targetURL, apiRouter, root, options, aiChecker)

			// 调用漏洞检测，使用适配器收集结果
			crawl.AnalyzeAPIWithCollector(jsFindOptions, adapter)
		}

		// 将收集到的漏洞转换为VulnerabilityItem格式
		for _, vuln := range vulnCollector.GetVulns() {
			if !shouldContinue {
				break
			}

			vulnItem := VulnerabilityItem{
				ID:                 vuln.VulnID,
				Title:              vuln.Title,
				Level:              vuln.Level,
				Type:               vuln.Type,
				URL:                vuln.URL,
				Method:             vuln.Method,
				Request:            vuln.Request,
				Response:           vuln.Response,
				TraceID:            vuln.TraceID,
				HasProtocolTrace:   vuln.HasProtocolTrace,
				ResponseCiphertext: vuln.ResponseCiphertext,
				DecryptionStatus:   vuln.DecryptionStatus,
				DecryptionDetail:   vuln.DecryptionDetail,
				ResponseLength:     vuln.ResponseLength,
				Description:        vuln.Description,
				AIVerified:         vuln.AIVerified,
				CreatedAt:          vuln.CreatedAt.Format("2006-01-02 15:04:05"),
			}
			targetResult.Vulnerabilities = append(targetResult.Vulnerabilities, vulnItem)

			// 调用回调函数（如果设置了）
			if options.OnResult != nil {
				event := ScanEvent{
					Type:      EventTypeVulnerability,
					Target:    targetURL,
					Timestamp: vuln.CreatedAt,
					Data:      vulnItem,
				}
				if !options.OnResult(event) {
					// 回调返回false，停止扫描
					fmt.Printf("[INFO] 扫描已通过回调函数停止\n")
					shouldContinue = false
					break
				}
			}
		}
		totalVulnerabilities += len(targetResult.Vulnerabilities)

		// 生成风险项（基于敏感信息）
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		aiEnabled := aiChecker != nil

		// 生成风险项
		saveAssetAndRisk := func(level, title, riskType string, items []SensitiveItem, isAIVerified bool) {
			for _, item := range items {
				if !shouldContinue {
					return
				}

				riskID := uuid.New().String()
				risk := RiskItem{
					ID:          riskID,
					Title:       title,
					Level:       level,
					Type:        riskType,
					URL:         item.Source,
					Description: fmt.Sprintf("发现%s: %s", title, item.Value),
					CreatedAt:   timestamp,
				}
				targetResult.Risks = append(targetResult.Risks, risk)

				// 调用回调函数（如果设置了）
				if options.OnResult != nil {
					event := ScanEvent{
						Type:      EventTypeRisk,
						Target:    targetURL,
						Timestamp: time.Now(),
						Data:      risk,
					}
					if !options.OnResult(event) {
						// 回调返回false，停止扫描
						fmt.Printf("[INFO] 扫描已通过回调函数停止\n")
						shouldContinue = false
						return
					}
				}
			}
		}

		// 身份证 - 低危
		saveAssetAndRisk("low", "身份证号码泄露", "敏感信息泄露", targetResult.Assets.IDCard, false)
		// 手机号 - 低危
		saveAssetAndRisk("low", "手机号码泄露", "敏感信息泄露", targetResult.Assets.Phone, false)
		// 敏感关键词 - 中危
		saveAssetAndRisk("medium", "敏感关键词泄露", "敏感信息泄露", targetResult.Assets.Sensitive, aiEnabled)
		// 邮箱 - 信息级别
		saveAssetAndRisk("info", "邮箱信息泄露", "信息泄露", targetResult.Assets.Email, false)

		// 去重处理
		targetResult.Assets.Email = removeDuplicateSensitiveItems(targetResult.Assets.Email)
		targetResult.Assets.IDCard = removeDuplicateSensitiveItems(targetResult.Assets.IDCard)
		targetResult.Assets.Phone = removeDuplicateSensitiveItems(targetResult.Assets.Phone)
		targetResult.Assets.IPURL = removeDuplicateSensitiveItems(targetResult.Assets.IPURL)
		targetResult.Assets.Sensitive = removeDuplicateSensitiveItems(targetResult.Assets.Sensitive)
		targetResult.Assets.APIRoutes = arrayutil.RemoveDuplicates(targetResult.Assets.APIRoutes)
		targetResult.Assets.APIRoots = arrayutil.RemoveDuplicates(targetResult.Assets.APIRoots)

		// 添加到总结果
		allTargetResults = append(allTargetResults, targetResult)
		totalRisks += len(targetResult.Risks)
		totalAssets.Email += len(targetResult.Assets.Email)
		totalAssets.IDCard += len(targetResult.Assets.IDCard)
		totalAssets.Phone += len(targetResult.Assets.Phone)
		totalAssets.IPURL += len(targetResult.Assets.IPURL)
		totalAssets.Sensitive += len(targetResult.Assets.Sensitive)
		totalAssets.APIRoutes += len(targetResult.Assets.APIRoutes)
		totalAssets.APIRoots += len(targetResult.Assets.APIRoots)
	}

	// 清理任务的测试记录
	crawl.ClearTestedURLs("cli-mode")

	// 构建最终结果
	result := &ScanResult{
		Targets:  allTargetResults,
		ScanTime: time.Now().Format("2006-01-02 15:04:05"),
		Summary: Summary{
			TotalTargets:         len(allTargetResults),
			TotalTreeNodes:       totalTreeNodes,
			TotalRisks:           totalRisks,
			TotalVulnerabilities: totalVulnerabilities,
			TotalAssets:          totalAssets,
		},
	}

	// 发送扫描完成事件
	if options.OnResult != nil {
		event := ScanEvent{
			Type:      EventTypeProgress,
			Timestamp: time.Now(),
			Data: map[string]interface{}{
				"status":  "completed",
				"summary": result.Summary,
			},
		}
		options.OnResult(event)
	}

	// 如果指定了输出路径，则保存到文件
	if options.OutputPath != "" {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON: %v", err)
		}

		err = os.WriteFile(options.OutputPath, jsonData, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write output file: %v", err)
		}
		fmt.Printf("[INFO] 扫描结果已保存到: %s\n", options.OutputPath)
	}

	duration := time.Since(startTime)
	fmt.Printf("[INFO] 扫描完成，耗时: %v\n", duration)

	return result, nil
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
	seen := make(map[string]bool)
	result := make([]SensitiveItem, 0)
	for _, item := range items {
		key := item.Value + "|" + item.Source
		if !seen[key] {
			seen[key] = true
			result = append(result, item)
		}
	}
	return result
}

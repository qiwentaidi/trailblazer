package config

import (
	"fmt"
)

type Options struct{}

// ConfigYAML represents the structure of config.yaml
type ConfigYAML struct {
	Elasticsearch  Elasticsearch     `yaml:"elasticsearch"`
	OpenAI         OpenAI            `yaml:"openai"`
	Web            WebConfig         `yaml:"web"`
	BlackDomain    []string          `yaml:"black-domain"`
	HighRiskRouter []string          `yaml:"high-risk-router"`
	Authentication []string          `yaml:"authentication"`
	Placeholder    map[string]string `yaml:"placeholder"`
	WeakCreds      []string          `yaml:"weakCreds"`
	VulnDetection  VulnDetection     `yaml:"vuln-detection"`
	Collaborative  CollaborativeTest `yaml:"collaborative-testing"`
	Log            LogConfig         `yaml:"log" json:"log"`
}

// CollaborativeTest controls the explicit boundary for business-action replay.
// An empty allowlist means that approval records may be created, but no replay
// executor can dispatch a request.
type CollaborativeTest struct {
	AllowedReplayHosts []string `yaml:"allowed-replay-hosts" json:"allowedReplayHosts"`
}

type WebConfig struct {
	Port  int    `yaml:"port" json:"port"`
	Host  string `yaml:"host" json:"host"`
	Debug bool   `yaml:"debug" json:"debug"`
}

type LogConfig struct {
	OutputPath string `yaml:"output-path" json:"outputPath"`
}

type VulnDetection struct {
	Enabled       bool                `yaml:"enabled" json:"enabled"`
	Authorization AuthorizationConfig `yaml:"authorization" json:"authorization"`
	SQLInjection  SQLInjectionConfig  `yaml:"sql-injection" json:"sqlInjection"`
	LFI           LFIConfig           `yaml:"lfi" json:"lfi"`
	SSRF          SSRFConfig          `yaml:"ssrf" json:"ssrf"`
	Redirect      RedirectConfig      `yaml:"redirect" json:"redirect"`
	XSS           XSSConfig           `yaml:"xss" json:"xss"`
	Upload        UploadConfig        `yaml:"upload" json:"upload"`
}

// AuthorizationConfig controls the authenticated-baseline versus anonymous
// request experiment. It intentionally has no low-privilege/IDOR mode: that
// requires additional accounts and must be modelled explicitly by callers.
type AuthorizationConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
}

func (v *VulnDetection) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type rawVulnDetection VulnDetection
	aux := rawVulnDetection{
		Enabled:       true,
		Authorization: AuthorizationConfig{Enabled: true},
	}
	if err := unmarshal(&aux); err != nil {
		return err
	}
	*v = VulnDetection(aux)
	return nil
}

type SQLInjectionConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Deprecated: payload 已内置（boolean/time-based 探测对 + error-based
	// 特征库），该字段仅作为追加项保留，后续版本将移除。
	Payloads []string `yaml:"payloads" json:"payloads"`
	// Deprecated: 同上，匹配关键词已内置。
	MatchKeywords []string `yaml:"match-keywords" json:"matchKeywords"`
	// Rules: 可选。支持为每个特定 payload 配置期望行为（响应体包含等）
	// Deprecated: 高级自定义入口，常规使用无需配置。
	Rules []SQLiPayloadRule `yaml:"rules" json:"rules"`
}

// SQLiPayloadRule 描述针对特定 payload 的期望条件
type SQLiPayloadRule struct {
	// Payloads 要注入的载荷数组
	Payloads []string `yaml:"payloads" json:"payloads"`
	// Type 注入类型：error-based, boolean-based
	Type string `yaml:"type" json:"type"`
	// BodyContains 响应体需包含的任意关键词（为空表示不校验）
	BodyContains []string `yaml:"body-contains" json:"bodyContains"`
}

type LFIConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ParamKeywords []string `yaml:"param-keywords" json:"paramKeywords"`
	// Deprecated: payload 已内置，该字段仅作为追加项保留。
	Payloads []string `yaml:"payloads" json:"payloads"` // 兼容旧配置
	// Deprecated: 匹配关键词已内置。
	MatchKeywords []string         `yaml:"match-keywords" json:"matchKeywords"` // 兼容旧配置
	Rules         []LFIPayloadRule `yaml:"rules" json:"rules"`                  // 规则配置（优先使用）
}

// LFIPayloadRule LFI payload 规则配置
type LFIPayloadRule struct {
	// Payloads 要注入的文件路径 payload 数组
	Payloads []string `yaml:"payloads" json:"payloads"`
	// MatchType 匹配类型：regex（正则表达式）或 word（关键词）
	MatchType string `yaml:"match-type" json:"matchType"`
	// Regex 当 MatchType 为 "regex" 时，提供正则表达式列表（任意一个匹配即成功）
	Regex []string `yaml:"regex,omitempty" json:"regex,omitempty"`
	// Words 当 MatchType 为 "word" 时，提供关键词列表
	Words []string `yaml:"words,omitempty" json:"words,omitempty"`
	// Condition 当 MatchType 为 "word" 时的匹配条件：and（所有关键词都需要匹配）或 or（任意一个匹配即可）
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"` // "and" 或 "or"，默认为 "or"
}

type SSRFConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ParamKeywords []string `yaml:"param-keywords" json:"paramKeywords"`
	// CallbackURL 可选的回连地址（如自建 OOB 服务或 interactsh 域名）。
	// 设置后会额外派发带外探测，命中需在回连服务端确认。
	CallbackURL string `yaml:"callback-url" json:"callbackUrl"`
}

type RedirectConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ParamKeywords []string `yaml:"param-keywords" json:"paramKeywords"`
}

type XSSConfig struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	// Deprecated: payload 已内置，该字段仅作为追加项保留。
	Payloads []string `yaml:"payloads" json:"payloads"` // 兼容旧配置
	// Deprecated: 匹配关键词已内置。
	MatchKeywords []string         `yaml:"match-keywords" json:"matchKeywords"` // 兼容旧配置
	Rules         []XSSPayloadRule `yaml:"rules" json:"rules"`                  // 规则配置（优先使用）
}

// XSSPayloadRule XSS payload 规则配置
type XSSPayloadRule struct {
	// Payloads 要注入的XSS payload 数组
	Payloads []string `yaml:"payloads" json:"payloads"`
	// Payload (deprecated) 兼容旧配置
	Payload string `yaml:"payload,omitempty" json:"payload,omitempty"`
	// Type 漏洞类型：reflected, dom-based
	// 注意：stored（存储型）无法通过参数注入方式检测，已移除该选项
	Type string `yaml:"type" json:"type"`
	// StatusEquals 期望的 HTTP 状态码（0 表示不校验）
	StatusEquals int `yaml:"status-equals" json:"statusEquals"`
	// Words 关键词列表（用于匹配验证）
	Words []string `yaml:"words,omitempty" json:"words,omitempty"`
	// Condition 匹配条件：and（所有关键词都需要匹配）或 or（任意一个匹配即可）
	Condition string `yaml:"condition,omitempty" json:"condition,omitempty"` // "and" 或 "or"，默认为 "or"
	// HeaderContains 响应头需包含的键值片段（为空表示不校验）
	HeaderContains map[string]string `yaml:"header-contains" json:"headerContains"`
	// BodyContains (deprecated) 兼容旧配置
	BodyContains []string `yaml:"body-contains" json:"bodyContains"`
}

type UploadConfig struct {
	Enabled       bool     `yaml:"enabled" json:"enabled"`
	ParamKeywords []string `yaml:"param-keywords" json:"paramKeywords"` // URL或参数关键词，用于识别上传接口
	// Deprecated: 测试文件内容将下沉为内置测试文件矩阵（类型/大小/双后缀）。
	TestContent string `yaml:"test-content" json:"testContent"` // 测试文件内容
	// Deprecated: 同上，文件名将内置。
	TestFileName string `yaml:"test-file-name" json:"testFileName"` // 测试文件名
}

type Elasticsearch struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type OpenAI struct {
	APIKey  string `yaml:"api_key" json:"api_key"`
	BaseURL string `yaml:"base_url" json:"base_url"`
	Model   string `yaml:"model" json:"model"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

const version = "1.0.1"

func Banner() {
	fmt.Println(`
  __                .__.__ ___.   .__                              
_/  |_____________  |__|  |\_ |__ |  | _____  ________ ___________ 
\   __\_  __ \__  \ |  |  | | __ \|  | \__  \ \___   // __ \_  __ \
 |  |  |  | \// __ \|  |  |_| \_\ \  |__/ __ \_/    /\  ___/|  | \/
 |__|  |__|  (____  /__|____/___  /____(____  /_____ \\___  >__|   
                  \/            \/          \/      \/    \/       v` + version + `
	`)
}

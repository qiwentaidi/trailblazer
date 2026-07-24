package structs

import (
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"net/url"
)

type InfoSource struct {
	Filed      string
	Source     string
	AIVerified bool
}

type FindSomething struct {
	JS        []InfoSource
	APIRoute  []InfoSource
	IP_URL    []InfoSource
	IDCard    []InfoSource
	Phone     []InfoSource
	Email     []InfoSource
	Sensitive []InfoSource
}

type JSFindResult struct {
	Target   string
	VulType  string
	Severity string
	Source   string
	Method   string
	Request  string
	Response string
	Length   int
	Filed    string
}

type StaticRequestPayloadHint struct {
	Carrier string
	Format  string
	Preview string
}

type JSFindOptions struct {
	TaskID                    string // 任务ID，用于关联检测结果
	Version                   int    // 任务版本，用于关联当前扫描执行
	HomeURL                   string
	ApiRoot                   string
	ApiList                   []string
	StaticMethodHints         map[string]string
	StaticHeaderHints         map[string]map[string]string
	StaticConstantParams      map[string]url.Values
	StaticRequestPayloadHints map[string]StaticRequestPayloadHint
	SkipVulnScan              bool
	Authentication            []string
	HighRiskRouter            []string
	Placeholder               map[string]string
	Headers                   map[string]string
	LFIConfig                 interface{} // LFI检测配置
	SSRFConfig                interface{} // SSRF检测配置
	RedirectConfig            interface{} // 重定向检测配置
	SQLInjConfig              interface{} // SQL注入检测配置
	XSSConfig                 interface{} // XSS检测配置
	UploadConfig              interface{} // 文件上传检测配置
	AIChecker                 interface{} // AI检测器（用于文件上传等漏洞检测），类型为 *crawl.SensitiveInfoChecker
	DataStore                 database.ScanDataStore
}

// APIRequest 结构体表示 API 请求信息
type APIRequest struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers"`
	Params         url.Values        `json:"params"`
	Body           string            `json:"body"`
	PayloadCarrier string            `json:"payloadCarrier,omitempty"`
	PayloadFormat  string            `json:"payloadFormat,omitempty"`
}

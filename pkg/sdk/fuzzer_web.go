// fuzzer_web.go 把 LFI / SSRF / XSS 检测器适配为 OperationFuzzer。
// 参数构造与凭证剔除规则复用 fuzzer_sqli.go 的 apiRequestFromOperationSpec；
// 漏洞记录字段与 PerformScan 旧管线（jsfind.go）保持一致。
package sdk

import (
	"fmt"
	"strings"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/lfi"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/ssrf"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/xss"
)

// lfiFuzzer 任意文件读取检测器。
type lfiFuzzer struct{ cfg LFIConfig }

// NewLFIFuzzer 创建 LFI OperationFuzzer。参数关键词为空时使用内置
// file/path/filepath 词表，payload 与匹配指纹均为内置。
func NewLFIFuzzer(cfg LFIConfig) OperationFuzzer { return lfiFuzzer{cfg: cfg} }

func (f lfiFuzzer) Name() string { return "lfi" }

func (f lfiFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if fuzzTargets == 0 || apiReq.URL == "" {
		return nil
	}
	result, err := lfi.TestLocalFileInclusion(apiReq, f.cfg)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return []database.VulnRecord{{
		VulnID:         "lfi-" + spec.ID,
		Title:          "任意文件读取(LFI)",
		Level:          "high",
		Type:           "LFI",
		URL:            apiReq.URL,
		Method:         strings.ToUpper(strings.TrimSpace(spec.Method)),
		Request:        vuln.BuildRawRequest(apiReq),
		Response:       result.Response,
		ResponseLength: len(result.Response),
		Description:    fmt.Sprintf("发现任意文件读取漏洞，Payload: %s，原因: %s", result.Payload, result.Reason),
		CreatedAt:      time.Now(),
	}}
}

// ssrfFuzzer 服务端请求伪造检测器。
type ssrfFuzzer struct{ cfg SSRFConfig }

// NewSSRFFuzzer 创建 SSRF OperationFuzzer。判定只认"服务端实际取回目标
// 内容"的带内指纹；配置 CallbackURL 时会额外派发带外探测，命中需在回连
// 服务端确认（带外命中不在本函数内判定）。
func NewSSRFFuzzer(cfg SSRFConfig) OperationFuzzer { return ssrfFuzzer{cfg: cfg} }

func (f ssrfFuzzer) Name() string { return "ssrf" }

func (f ssrfFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if fuzzTargets == 0 || apiReq.URL == "" {
		return nil
	}
	result, err := ssrf.TestServerSideRequestForgery(apiReq, f.cfg)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return []database.VulnRecord{{
		VulnID:         "ssrf-" + spec.ID,
		Title:          "服务端请求伪造(SSRF)",
		Level:          "high",
		Type:           "SSRF",
		URL:            apiReq.URL,
		Method:         strings.ToUpper(strings.TrimSpace(spec.Method)),
		Request:        vuln.BuildRawRequest(apiReq),
		Response:       result.Response,
		ResponseLength: len(result.Response),
		Description:    fmt.Sprintf("发现服务端请求伪造漏洞，Payload: %s，原因: %s", result.Payload, result.Reason),
		CreatedAt:      time.Now(),
	}}
}

// xssFuzzer 反射型 XSS 检测器。
type xssFuzzer struct{ cfg XSSConfig }

// NewXSSFuzzer 创建 XSS OperationFuzzer。检测器内置浏览器执行验证，
// 仅在 payload 被真实执行时才产出漏洞，因此该 fuzzer 运行成本高于其他
// 检测器；API 场景（JSON 响应为主）通常不会有命中。
func NewXSSFuzzer(cfg XSSConfig) OperationFuzzer { return xssFuzzer{cfg: cfg} }

func (f xssFuzzer) Name() string { return "xss" }

func (f xssFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if fuzzTargets == 0 || apiReq.URL == "" {
		return nil
	}
	result, err := xss.TestXSS(apiReq, f.cfg)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return []database.VulnRecord{{
		VulnID:           "xss-" + spec.ID,
		Title:            fmt.Sprintf("跨站脚本攻击漏洞 (%s)", result.Type),
		Level:            "high",
		Type:             "XSS",
		URL:              apiReq.URL,
		Method:           strings.ToUpper(strings.TrimSpace(spec.Method)),
		Request:          vuln.BuildRawRequest(apiReq),
		Response:         result.Response,
		ResponseLength:   len(result.Response),
		Confidence:       result.Confidence,
		ConfidenceReason: result.ConfidenceReason,
		Description:      fmt.Sprintf("发现跨站脚本攻击漏洞，类型: %s，Payload: %s，原因: %s", result.Type, result.Payload, result.Reason),
		CreatedAt:        time.Now(),
	}}
}

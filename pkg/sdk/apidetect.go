// apidetect.go 实现采集/检测分离架构下的独立漏洞检测入口。
//
// CrawlAPIAssets 只读地产出接口资产（运行时上下文、JS 蓝图、OperationSpec
// 模板与锚点证据），本文件在其之上提供检测层：
//   - 授权对照：对已观测接口批量执行 RunAuthorizationCheck（匿名变体复放）
//   - 参数 fuzz：OperationFuzzer 扩展点（占位），面向 OperationSpec 模板
//
// 漏洞事件沿用与 PerformScan 一致的 ScanEvent / ScanCallback 模型，
// Data 载荷为 database.VulnRecord，现有接收/存储代码可直接复用。
//
// 安全约束：静态 OperationSpec 只是模板，requiresRuntime 标记的动态值
// （token、签名、nonce、时间戳等）必须由运行时流量补全后才允许发出请求；
// 检测器永远不应该把模板原文直接打到目标上。
package sdk

import (
	"crypto/sha1"
	"fmt"
	"strings"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/unauth"
)

// OperationFuzzer 是参数级检测器的扩展点（占位接口）。
// 实现方针对单个 OperationSpec 模板做参数 fuzz（SQLi/LFI/SSRF/XSS/Upload
// 等），返回漏洞记录；无发现返回 nil。实现方必须先用运行时流量补全
// spec.RequiresRuntime 中的动态值，再构造真实请求。
type OperationFuzzer interface {
	Name() string
	Fuzz(spec crawl.OperationSpec) []database.VulnRecord
}

// DetectOptions 独立漏洞检测的配置。
type DetectOptions struct {
	// TaskID / Version 与扫描任务关联，写入漏洞记录；TaskID 为空时用 sdk-detect。
	TaskID  string
	Version int
	// Target 事件归属的目标 URL，仅用于事件路由展示。
	Target string
	// OnFinding 每发现一条漏洞回调一次 ScanEvent{Type: EventTypeVulnerability,
	// Data: database.VulnRecord}；返回 false 停止检测。与 PerformScan 的
	// OnResult 语义一致。
	OnFinding ScanCallback
	// DisableAuthorization 关闭授权对照实验（默认开启）。
	DisableAuthorization bool
	// Sender 覆盖授权实验的 HTTP 发送器（可注入代理/Cookie 池/限速）；
	// 为空时使用默认 10s 超时客户端。
	Sender AuthzSender
	// Fuzzers 参数级检测器扩展点；nil 表示不执行参数 fuzz。
	Fuzzers []OperationFuzzer
}

// DetectResult 汇总一次独立检测的全部产出。
type DetectResult struct {
	Checks          []AuthorizationCheck  `json:"checks,omitempty"`
	Vulnerabilities []database.VulnRecord `json:"vulnerabilities,omitempty"`
}

// DetectOperationVulns 对已采集的接口资产执行独立漏洞检测。
// 授权检测分为两类：带认证上下文走认证对照；运行时实际捕获的匿名请求
// 走旧判定器的匿名业务响应检测。参数 fuzz 针对静态 OperationSpec 模板。
// 所有发现都通过 OnFinding 实时推送并汇总返回。
func DetectOperationVulns(assets *APIAssetResult, opts *DetectOptions) (*DetectResult, error) {
	if assets == nil {
		return nil, fmt.Errorf("apidetect: assets cannot be nil")
	}
	if opts == nil {
		opts = &DetectOptions{}
	}
	taskID := strings.TrimSpace(opts.TaskID)
	if taskID == "" {
		taskID = "sdk-detect"
	}

	result := &DetectResult{}
	emit := func(record database.VulnRecord) bool {
		result.Vulnerabilities = append(result.Vulnerabilities, record)
		if opts.OnFinding == nil {
			return true
		}
		return opts.OnFinding(ScanEvent{
			Type:      EventTypeVulnerability,
			Target:    opts.Target,
			Timestamp: time.Now(),
			Data:      record,
		})
	}

	if !opts.DisableAuthorization && assets.Store != nil {
		sender := opts.Sender
		if sender == nil {
			sender = defaultAuthzSender()
		}
		for _, ctx := range assets.Store.List() {
			if ctx == nil || !ctx.Auth.Present {
				continue
			}
			verdict := RunAuthorizationCheck(ctx, sender)
			result.Checks = append(result.Checks, AuthorizationCheck{
				OperationID: ctx.OperationID,
				URL:         ctx.ObservedURL,
				Method:      ctx.Method,
				Verdict:     verdict,
			})
			if !verdict.Vulnerable {
				continue
			}
			if !emit(authorizationVulnRecord(taskID, opts.Version, ctx.OperationID, ctx.ObservedURL, ctx.Method, verdict)) {
				return result, nil
			}
		}
	}
	if !opts.DisableAuthorization {
		for _, record := range anonymousUnauthorizedFindings(assets.RuntimeRecords, taskID, opts.Version) {
			if !emit(record) {
				return result, nil
			}
		}
	}

	for _, fuzzer := range opts.Fuzzers {
		if fuzzer == nil {
			continue
		}
		for _, spec := range assets.OperationSpecs {
			for _, record := range fuzzer.Fuzz(spec) {
				if record.TaskID == "" {
					record.TaskID = taskID
				}
				if record.Version == 0 {
					record.Version = opts.Version
				}
				if !emit(record) {
					return result, nil
				}
			}
		}
	}
	return result, nil
}

// anonymousUnauthorizedFindings covers APIs which are already invoked by the
// application without credentials. Unlike the comparative path, these have no
// authenticated baseline to remove. We assess its captured response with the
// established unauth detector, which rejects login pages, error responses and
// non-business data without replaying potentially state-changing requests.
// Static templates are deliberately excluded: their dynamic values cannot be
// safely reconstructed into a request.
func anonymousUnauthorizedFindings(records []crawl.NetworkRecord, taskID string, version int) []database.VulnRecord {
	findings := make([]database.VulnRecord, 0)
	for _, record := range records {
		if strings.TrimSpace(record.URL) == "" || strings.TrimSpace(record.Method) == "" || recordHasAuthentication(record.RequestHeaders) {
			continue
		}
		request := structs.APIRequest{
			URL:     record.URL,
			Method:  record.Method,
			Headers: anonymousRequestHeaders(record.RequestHeaders),
			Body:    record.RequestBody,
		}
		vulnerable, assessment, err := unauth.AssessUnauthorizedResponse("", request.URL, record.ResponseCode, responseContentType(record), record.ResponseBody, nil)
		if err != nil || !vulnerable {
			continue
		}
		name := crawl.ClassifyUnauthorizedFinding(request.URL, request.Method, record.ResponseBody, assessment.DataExposure)
		findings = append(findings, database.VulnRecord{
			TaskID:           taskID,
			Version:          version,
			VulnID:           "unauth-" + runtimeOperationID(record),
			Title:            name.Title,
			Level:            assessment.RiskLevel,
			Type:             "未授权访问",
			Category:         name.Category,
			Subcategory:      name.Subcategory,
			BusinessObject:   name.BusinessObject,
			NamingSource:     name.Source,
			URL:              request.URL,
			Method:           request.Method,
			Request:          vuln.BuildRawRequest(request),
			Response:         record.ResponseBody,
			ResponseType:     assessment.ResponseType,
			ResponseLength:   len(record.ResponseBody),
			Confidence:       assessment.Confidence,
			ConfidenceReason: assessment.ConfidenceReason,
			DataExposure:     assessment.DataExposure,
			ExposureReason:   assessment.ExposureReason,
			Description:      anonymousUnauthorizedDescription(assessment, len(record.ResponseBody)),
			CreatedAt:        time.Now(),
		})
	}
	return findings
}

func recordHasAuthentication(headers map[string]string) bool {
	for name := range headers {
		if isAuthenticationHeader(name) {
			return true
		}
	}
	return false
}

func anonymousRequestHeaders(headers map[string]string) map[string]string {
	clean := make(map[string]string, len(headers))
	for name, value := range headers {
		if !isAuthenticationHeader(name) {
			clean[name] = value
		}
	}
	return clean
}

func isAuthenticationHeader(name string) bool {
	if crawl.IsSensitiveHeaderName(name) {
		return true
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	return strings.Contains(lower, "auth") || strings.Contains(lower, "token") || strings.Contains(lower, "cookie") || strings.Contains(lower, "session") || strings.Contains(lower, "api-key") || strings.Contains(lower, "secret")
}

func responseContentType(record crawl.NetworkRecord) string {
	for name, value := range record.ResponseHeaders {
		if strings.EqualFold(strings.TrimSpace(name), "Content-Type") {
			return value
		}
	}
	return record.MIMEType
}

func runtimeOperationID(record crawl.NetworkRecord) string {
	hash := sha1.Sum([]byte(strings.ToUpper(strings.TrimSpace(record.Method)) + "\x00" + strings.TrimSpace(record.URL)))
	return fmt.Sprintf("%x", hash[:8])
}

func anonymousUnauthorizedDescription(assessment unauth.UnauthorizedAssessment, responseLength int) string {
	return fmt.Sprintf("发现匿名可访问的业务接口，风险等级: %s，置信度: %s，数据暴露评级: %s，响应长度: %d；置信度说明: %s；暴露评级说明: %s",
		assessment.RiskLevel, assessment.Confidence, assessment.DataExposure, responseLength, assessment.ConfidenceReason, assessment.ExposureReason)
}

// authorizationVulnRecord 把授权对照结论转换为漏洞记录，与 scanexec
// 管线内 PerformScan 路径产出的记录结构保持一致。
func authorizationVulnRecord(taskID string, version int, operationID, url, method string, verdict AuthzVerdict) database.VulnRecord {
	return database.NewAuthorizationVulnRecord(taskID, version, operationID, url, method, verdict)
}

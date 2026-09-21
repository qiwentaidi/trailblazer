// fuzzer_sqli.go 把现有 SQL 注入检测器（pkg/core/vuln/sqli）适配为
// OperationFuzzer，使其可以直接消费静态分析产出的 OperationSpec 模板。
//
// 参数构造原则（与目标 6 的安全约束一致）：
//   - 静态值参数：携带真实静态值，且作为正常 fuzz 目标；
//   - 未解析符号参数（如 json:content 来源未知）：以占位值携带，可被注入
//     payload —— 这正是 fuzz 的意义；
//   - 凭证命名参数（token/sign/nonce/timestamp/cookie 等，DynamicReason 为
//     dynamic-name）：不构造、不伪造，整条请求中直接剔除；需要这些参数才能
//     通过的接口必须在运行时流量补全后再检测（后续由 ReplayFixture 路径支持）。
package sdk

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/crawl"
	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln/sqli"
)

// sqlInjectionFuzzer 面向 OperationSpec 的 SQL 注入检测器。
type sqlInjectionFuzzer struct {
	cfg SQLInjectionConfig
}

// NewSQLInjectionFuzzer 创建 SQL 注入 OperationFuzzer。传入空的
// SQLInjectionConfig 时使用内置探测对（布尔/时间盲注 + error-based 特征库）。
func NewSQLInjectionFuzzer(cfg SQLInjectionConfig) OperationFuzzer {
	return sqlInjectionFuzzer{cfg: cfg}
}

func (f sqlInjectionFuzzer) Name() string { return "sqli" }

func (f sqlInjectionFuzzer) Fuzz(spec crawl.OperationSpec) []database.VulnRecord {
	apiReq, fuzzTargets := apiRequestFromOperationSpec(spec)
	if fuzzTargets == 0 || apiReq.URL == "" {
		return nil
	}
	result, err := sqli.TestSQLInjection(apiReq, f.cfg)
	if err != nil || result == nil || !result.Vulnerable {
		return nil
	}
	return []database.VulnRecord{{
		VulnID:         "sqli-" + spec.ID,
		Title:          fmt.Sprintf("SQL注入漏洞 (%s)", result.Type),
		Level:          "high",
		Type:           "SQL_INJECTION",
		URL:            apiReq.URL,
		Method:         strings.ToUpper(strings.TrimSpace(spec.Method)),
		Request:        vuln.BuildRawRequest(apiReq),
		Response:       result.Response,
		ResponseLength: result.ResponseLength,
		Description:    fmt.Sprintf("发现SQL注入漏洞，类型: %s，Payload: %s，原因: %s", result.Type, result.Payload, result.Reason),
		CreatedAt:      time.Now(),
	}}
}

var specPathParamPattern = regexp.MustCompile(`\{([^{}]+)\}`)

// apiRequestFromOperationSpec 把接口模板转换为可发送的探测请求。返回请求与
// 可 fuzz 参数数量；凭证命名参数会被剔除，无 URL 或无参数时返回空请求。
func apiRequestFromOperationSpec(spec crawl.OperationSpec) (structs.APIRequest, int) {
	origin := strings.TrimRight(strings.TrimSpace(spec.Origin), "/")
	path := strings.TrimSpace(spec.PathTemplate)
	if origin == "" || path == "" {
		return structs.APIRequest{}, 0
	}

	params := url.Values{}
	fuzzTargets := 0
	bodyFields := map[string]string{}

	for _, param := range spec.Params {
		name := strings.TrimSpace(param.Name)
		if name == "" {
			continue
		}
		// 凭证命名参数不构造、不伪造。
		if param.Dynamic && param.DynamicReason == "dynamic-name" {
			continue
		}
		value := strings.TrimSpace(param.Value)
		if value == "" {
			value = "1"
		}
		location := strings.ToLower(strings.TrimSpace(param.Location))
		switch location {
		case "path":
			// 路径参数在下方模板替换时处理。
			continue
		case "json", "body", "form":
			bodyFields[name] = value
		default: // query 及未标注位置的参数按 query 处理
			params.Set(name, value)
		}
		fuzzTargets++
	}

	// 路径模板参数替换：静态值优先，否则占位 1；凭证命名的路径参数同样剔除
	// 会导致 URL 不完整，此类接口跳过（返回零值）。
	skip := false
	path = specPathParamPattern.ReplaceAllStringFunc(path, func(token string) string {
		name := token[1 : len(token)-1]
		for _, param := range spec.Params {
			if strings.TrimSpace(param.Name) != name {
				continue
			}
			if param.Dynamic && param.DynamicReason == "dynamic-name" {
				skip = true
				return token
			}
			if value := strings.TrimSpace(param.Value); value != "" {
				return url.PathEscape(value)
			}
			return "1"
		}
		return "1"
	})
	if skip {
		return structs.APIRequest{}, 0
	}

	apiReq := structs.APIRequest{
		URL:            origin + path,
		Method:         strings.ToUpper(strings.TrimSpace(spec.Method)),
		Headers:        map[string]string{},
		Params:         params,
		PayloadCarrier: strings.TrimSpace(spec.PayloadCarrier),
		PayloadFormat:  strings.TrimSpace(spec.PayloadFormat),
	}
	// 只携带静态头；动态头（Authorization/Cookie 等）不伪造。
	for _, header := range spec.Headers {
		if header.Dynamic {
			continue
		}
		name := strings.TrimSpace(header.Name)
		if name == "" {
			continue
		}
		apiReq.Headers[name] = strings.TrimSpace(header.Value)
	}

	if len(bodyFields) > 0 {
		format := strings.ToLower(apiReq.PayloadFormat)
		if format == "" {
			format = "json"
		}
		switch format {
		case "form", "formdata", "multipart", "urlencoded", "urlsearchparams":
			form := url.Values{}
			for name, value := range bodyFields {
				form.Set(name, value)
			}
			apiReq.Body = form.Encode()
			apiReq.PayloadFormat = "form"
			if apiReq.Headers["Content-Type"] == "" {
				apiReq.Headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
		default:
			payload := make(map[string]string, len(bodyFields))
			for name, value := range bodyFields {
				payload[name] = value
			}
			if raw, err := json.Marshal(payload); err == nil {
				apiReq.Body = string(raw)
			}
			apiReq.PayloadFormat = "json"
			if apiReq.Headers["Content-Type"] == "" {
				apiReq.Headers["Content-Type"] = "application/json"
			}
		}
		// body 参数名并入 Params 供检测器迭代注入；transport 层在 Body 非空时
		// 优先使用 Body，不会把这些参数重复放进 query string。
		for name, value := range bodyFields {
			params.Set(name, value)
		}
	}
	return apiReq, fuzzTargets
}

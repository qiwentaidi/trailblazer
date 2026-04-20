package ssrf

import (
	"net/http"
	"strings"

	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
	"trailblazer/pkg/core/vuln"

	httputil "github.com/qiwentaidi/utils/http"
)

// SSRFResult 表示 SSRF 测试结果
type SSRFResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
}

// TestServerSideRequestForgery 测试服务端请求伪造漏洞
// apiReq: 原始 API 请求
// cfg: SSRF配置（包含payloads、参数关键词、匹配关键词）
// returns: SSRFResult 测试结果
func TestServerSideRequestForgery(apiReq structs.APIRequest, cfg config.SSRFConfig) (*SSRFResult, error) {
	payloads := []string{
		"http://example.com",
	}

	// 尝试每个载荷
	for _, payload := range payloads {
		modifiedReq := injectSSRFPayload(apiReq, payload, cfg.ParamKeywords)
		resp, err := vuln.SendAPIRequest(modifiedReq, false)
		if err != nil {
			continue // 跳过失败的请求
		}

		if resp.StatusCode() == 302 {
			rawHeaders := httputil.DumpResponseHeadersOnly(resp.RawResponse)
			rawHeadersStr := string(rawHeaders)
			if strings.Contains(rawHeadersStr, "Location: "+payload) {
				continue
			}
		}

		body := string(resp.Body())
		// 仅在成功获取外部资源时判断为SSRF
		if resp.StatusCode() == http.StatusOK && isSSRFVulnerable(body) {
			return &SSRFResult{
				Vulnerable: true,
				Payload:    payload,
				Response:   vuln.TruncateResponse(body),
				Reason:     "检测到SSRF漏洞",
			}, nil
		}
	}

	return &SSRFResult{
		Vulnerable: false,
		Reason:     "未检测到SSRF漏洞",
	}, nil
}

// 只探测出网的SSRF
func isSSRFVulnerable(response string) bool {
	matchKeywords := []string{
		"<title>Example Domain</title>",
	}
	for _, keyword := range matchKeywords {
		if strings.Contains(response, keyword) {
			return true
		}
	}

	return false
}

// injectPayload 将载荷注入到API请求中
func injectSSRFPayload(apiReq structs.APIRequest, payload string, paramKeywords []string) structs.APIRequest {
	modifiedReq := apiReq

	// 如果参数关键词为空，使用默认关键词
	if len(paramKeywords) == 0 {
		paramKeywords = []string{
			"url", "uri", "link", "href", "src", "path", "file", "page", "redirect", "forward",
			"target", "dest", "destination", "next", "continue", "return", "callback", "callback_url",
			"callbackUrl", "return_url", "returnUrl", "redirect_url", "redirectUrl", "forward_url",
			"forwardUrl", "next_url", "nextUrl", "continue_url", "continueUrl", "target_url",
			"targetUrl", "dest_url", "destUrl", "destination_url", "destinationUrl", "page_url",
			"pageUrl", "file_url", "fileUrl", "path_url", "pathUrl", "link_url", "linkUrl",
			"href_url", "hrefUrl", "src_url", "srcUrl", "uri_url", "uriUrl", "url_url", "urlUrl",
		}
	}

	// 尝试在URL参数中注入
	if modifiedReq.Params != nil {
		for key := range modifiedReq.Params {
			for _, keyword := range paramKeywords {
				if strings.Contains(strings.ToLower(key), strings.ToLower(keyword)) {
					modifiedReq.Params[key] = []string{payload}
					break
				}
			}
		}
	}

	// 尝试在请求体中注入
	if modifiedReq.Body != "" {
		// 简单的JSON注入
		if strings.Contains(modifiedReq.Body, "{") && strings.Contains(modifiedReq.Body, "}") {
			for _, keyword := range paramKeywords {
				if strings.Contains(strings.ToLower(modifiedReq.Body), strings.ToLower(keyword)) {
					// 这里可以实现更复杂的JSON注入逻辑
					modifiedReq.Body = strings.Replace(modifiedReq.Body, `"`+keyword+`"`, `"`+payload+`"`, 1)
					break
				}
			}
		}
	}

	return modifiedReq
}

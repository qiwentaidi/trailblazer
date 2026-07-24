package vuln

import (
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/qiwentaidi/clients"
)

func SendAPIRequest(apiReq structs.APIRequest, redirect bool) (*resty.Response, error) {
	finalURL, resolvedBody := resolveAPIRequestTransport(apiReq)
	requestBody := strings.NewReader(resolvedBody)

	resp, err := clients.DoRequest(
		apiReq.Method,
		finalURL,
		apiReq.Headers,
		requestBody,
		10,
		clients.NewRestyClient(nil, redirect),
	)
	return resp, err
}

func ResolveAPIRequestTransport(apiReq structs.APIRequest) (string, string) {
	return resolveAPIRequestTransport(apiReq)
}

func resolveAPIRequestTransport(apiReq structs.APIRequest) (string, string) {
	finalURL := apiReq.URL
	method := strings.ToUpper(strings.TrimSpace(apiReq.Method))
	payloadCarrier := strings.ToLower(strings.TrimSpace(apiReq.PayloadCarrier))
	payloadFormat := strings.ToLower(strings.TrimSpace(apiReq.PayloadFormat))
	contentType := strings.ToLower(headerValue(apiReq.Headers, "Content-Type"))

	if method == http.MethodGet {
		if payloadCarrier == "params" || payloadFormat == "query" {
			return appendQueryParams(finalURL, apiReq.Params), strings.TrimSpace(apiReq.Body)
		}
		if strings.TrimSpace(apiReq.Body) != "" {
			return finalURL, apiReq.Body
		}
		if payloadCarrier == "body" || payloadCarrier == "data" || payloadFormat == "json" || strings.Contains(contentType, "application/json") {
			if body := marshalParamsAsJSON(apiReq.Params); body != "" {
				return finalURL, body
			}
			if payloadFormat == "json" || strings.Contains(contentType, "application/json") {
				return finalURL, "{}"
			}
		}
		return appendQueryParams(finalURL, apiReq.Params), ""
	}

	if payloadCarrier == "params" || payloadFormat == "query" {
		return appendQueryParams(finalURL, apiReq.Params), strings.TrimSpace(apiReq.Body)
	}

	if strings.TrimSpace(apiReq.Body) != "" {
		return finalURL, apiReq.Body
	}

	if payloadFormat == "json" || strings.Contains(contentType, "application/json") {
		if body := marshalParamsAsJSON(apiReq.Params); body != "" {
			return finalURL, body
		}
		return finalURL, "{}"
	}

	if len(apiReq.Params) > 0 {
		return finalURL, apiReq.Params.Encode()
	}
	return finalURL, ""
}

func appendQueryParams(rawURL string, params url.Values) string {
	if len(params) == 0 {
		return rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	query := parsedURL.Query()
	for key, values := range params {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String()
}

func marshalParamsAsJSON(params url.Values) string {
	if len(params) == 0 {
		return ""
	}

	payload := make(map[string]any, len(params))
	for key, values := range params {
		switch len(values) {
		case 0:
			payload[key] = ""
		case 1:
			payload[key] = values[0]
		default:
			payload[key] = values
		}
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func headerValue(headers map[string]string, key string) string {
	for existingKey, value := range headers {
		if strings.EqualFold(existingKey, key) {
			return value
		}
	}
	return ""
}

// TruncateResponse 截断响应内容用于日志显示
func TruncateResponse(response string) string {
	if len(response) <= 10000 {
		return response
	}
	return response[:10000] + "..."
}

// 构建RawRequest
func BuildRawRequest(req structs.APIRequest) string {
	var sb strings.Builder

	parsedURL, err := url.Parse(req.URL)
	if err != nil {
		return "" // URL解析失败直接返回空
	}
	finalURL, resolvedBody := resolveAPIRequestTransport(req)
	parsedURL, err = url.Parse(finalURL)
	if err != nil {
		return ""
	}

	// 写入请求行，只保留Path+Query，不要域名
	pathWithQuery := parsedURL.Path
	if parsedURL.RawQuery != "" {
		pathWithQuery += "?" + parsedURL.RawQuery
	}
	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", req.Method, pathWithQuery))

	// Host 头
	sb.WriteString(fmt.Sprintf("Host: %s\n", parsedURL.Host))

	// 其他 Headers
	for k, v := range req.Headers {
		// 避免重复写 Host
		if strings.ToLower(k) == "host" {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}

	sb.WriteString("\n") // 头结束空一行

	// 写入请求体
	if strings.TrimSpace(resolvedBody) != "" {
		sb.WriteString(resolvedBody)
	}
	return sb.String()
}

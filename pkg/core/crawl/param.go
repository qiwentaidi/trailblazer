package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/qiwentaidi/clients"
)

type Parameter struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

const (
	maxParameterProbeAttempts = 3
	parameterProbeTimeout     = 5 * time.Second
)

var parameterProbeFunc = doParameterProbe

// 支持多种错误信息格式的正则表达式
var extractMissingRegexes = []*regexp.Regexp{
	// 原始格式: required string 'paramName'
	regexp.MustCompile(`(?i)required (string|int|long|double|boolean|date|arraylist).*?'([^']+)'`),
	// Spring Boot格式: Required request parameter 'paramName' for method parameter type String is not present
	regexp.MustCompile(`(?i)required request parameter '([^']+)' for method parameter type (string|int|long|double|boolean|date|arraylist)`),
	// 简单格式: missing parameter 'paramName'
	regexp.MustCompile(`(?i)missing parameter '([^']+)'`),
	// 简单格式: parameter 'paramName' is required
	regexp.MustCompile(`(?i)parameter '([^']+)' is required`),
	// 简单格式: 'paramName' is required
	regexp.MustCompile(`(?i)'([^']+)' is required`),
}

// 从错误信息中提取缺失参数的名称
func extractMissingParams(message string) *Parameter {
	// 尝试所有正则表达式
	for i, regex := range extractMissingRegexes {
		matches := regex.FindStringSubmatch(message)
		if len(matches) > 1 {
			var paramName, paramType string

			switch i {
			case 0: // 原始格式: required string 'paramName'
				if len(matches) > 2 {
					paramType = matches[1]
					paramName = matches[2]
				}
			case 1: // Spring Boot格式: Required request parameter 'paramName' for method parameter type String
				if len(matches) > 2 {
					paramName = matches[1]
					paramType = matches[2]
				}
			case 2, 3, 4: // 简单格式，默认为string类型
				paramName = matches[1]
				paramType = "string"
			}

			if paramName != "" {
				return &Parameter{
					Name: paramName,
					Type: paramType,
				}
			}
		}
	}
	return nil
}

// 根据参数类型生成默认值
func generateDefaultValue(paramType string) interface{} {
	switch strings.ToLower(paramType) {
	case "string":
		return "test"
	case "int":
		return 0
	case "long":
		return int64(0)
	case "double":
		return 0.0
	case "boolean":
		return false
	case "date":
		return "1970-01-01"
	case "arraylist":
		return []string{"1"}
	default:
		return "defaultValue"
	}
}

func buildParameterProbeURL(apiURL string, params url.Values) string {
	encoded := params.Encode()
	if encoded == "" {
		return apiURL
	}
	return fmt.Sprintf("%s?%s", apiURL, encoded)
}

func newParameterProbeClient() *resty.Client {
	client := clients.NewRestyClient(nil, true)
	client.SetTimeout(parameterProbeTimeout)

	if transport, ok := client.GetClient().Transport.(*http.Transport); ok {
		cloned := transport.Clone()
		cloned.ResponseHeaderTimeout = parameterProbeTimeout
		cloned.DisableKeepAlives = true
		cloned.ForceAttemptHTTP2 = false
		cloned.MaxIdleConns = 0
		cloned.MaxConnsPerHost = 2
		client.SetTransport(cloned)
	}

	return client
}

func doParameterProbe(
	ctx context.Context,
	method, fullURL string,
) (string, error) {
	client := newParameterProbeClient()
	req := client.R().SetContext(ctx)

	var (
		resp *resty.Response
		err  error
	)

	switch method {
	case http.MethodGet:
		resp, err = req.Get(fullURL)
	case http.MethodPost:
		resp, err = req.Post(fullURL)
	case http.MethodPut:
		resp, err = req.Put(fullURL)
	case http.MethodDelete:
		resp, err = req.Delete(fullURL)
	case http.MethodPatch:
		resp, err = req.Patch(fullURL)
	case http.MethodOptions:
		resp, err = req.Options(fullURL)
	default:
		return "", fmt.Errorf("unsupported method: %s", method)
	}

	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}

	return string(resp.Body()), nil
}

// 参数补全
func completeParameters(method, apiURL string, params url.Values) url.Values {
	if params == nil {
		params = url.Values{}
	}

	for attempt := 0; attempt < maxParameterProbeAttempts; attempt++ {
		fullURL := buildParameterProbeURL(apiURL, params)
		ctx, cancel := context.WithTimeout(context.Background(), parameterProbeTimeout)
		content, err := parameterProbeFunc(ctx, method, fullURL)
		cancel()
		if err != nil {
			fmt.Printf("[警告] %s 参数探测请求失败: %v\n", fullURL, err)
			return params
		}

		missingParam := extractMissingParams(content)
		if missingParam == nil {
			return params
		}

		if _, exists := params[missingParam.Name]; exists {
			fmt.Printf("[警告] %s 缺失参数 %s 已存在，跳过重复补全\n", fullURL, missingParam.Name)
			return params
		}

		defaultValue := generateDefaultValue(missingParam.Type)
		params.Set(missingParam.Name, fmt.Sprint(defaultValue))
		fmt.Printf(
			"[INFO] %s 识别到缺失参数 %s，使用默认值补全（第 %d/%d 次探测）\n",
			apiURL,
			missingParam.Name,
			attempt+1,
			maxParameterProbeAttempts,
		)
	}

	fmt.Printf(
		"[WARN] %s 参数补全已达到最大探测次数 %d，停止继续探测\n",
		apiURL,
		maxParameterProbeAttempts,
	)
	return params
}

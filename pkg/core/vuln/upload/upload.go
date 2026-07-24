package upload

import (
	"bytes"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"maps"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/qiwentaidi/clients"
)

// UploadResult 表示文件上传漏洞测试结果
type UploadResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
	UploadURL  string `json:"uploadUrl"` // 上传后的文件访问URL
	RawRequest string `json:"rawRequest"`
}

// FileUploadAIChecker 定义AI检测器接口（避免循环导入）
type FileUploadAIChecker interface {
	CheckFileUpload(responseBody, testFileName, testContent string) (bool, string, error)
}

// TestFileUpload 测试文件上传漏洞
// apiReq: 原始 API 请求
// cfg: 文件上传配置
// aiChecker: AI检测器（可选，如果提供则使用AI分析响应）
// returns: UploadResult 测试结果
func TestFileUpload(apiReq structs.APIRequest, cfg config.UploadConfig, aiChecker FileUploadAIChecker) (*UploadResult, error) {
	// 如果未启用，直接返回
	if !cfg.Enabled {
		return &UploadResult{
			Vulnerable: false,
			Reason:     "文件上传检测未启用",
		}, nil
	}

	// 检查接口名称（URL路径）是否包含"upload"字段
	urlLower := strings.ToLower(apiReq.URL)
	if !strings.Contains(urlLower, "upload") {
		return &UploadResult{
			Vulnerable: false,
			Reason:     "接口名称未包含upload字段，跳过检测",
		}, nil
	}

	// 只检测POST请求
	if apiReq.Method != http.MethodPost {
		return &UploadResult{
			Vulnerable: false,
			Reason:     "仅检测POST请求",
		}, nil
	}

	fmt.Printf("[调试] 开始文件上传检测: %s\n", apiReq.URL)

	// 使用配置的测试内容
	testContent := cfg.TestContent
	if testContent == "" {
		testContent = "<h1>uploadtest</h1>"
	}

	// 使用配置的文件名
	testFileName := cfg.TestFileName
	if testFileName == "" {
		testFileName = "test.html"
	}

	// 构造multipart/form-data请求
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 使用默认的文件字段名
	fieldName := "file"

	// 创建文件字段
	part, err := writer.CreateFormFile(fieldName, testFileName)
	if err != nil {
		return &UploadResult{
			Vulnerable: false,
			Reason:     fmt.Sprintf("创建文件字段失败: %v", err),
		}, nil
	}
	_, err = part.Write([]byte(testContent))
	if err != nil {
		return &UploadResult{
			Vulnerable: false,
			Reason:     fmt.Sprintf("写入文件内容失败: %v", err),
		}, nil
	}

	// 添加其他参数（如果有）
	if apiReq.Params != nil {
		for key, values := range apiReq.Params {
			// 跳过文件字段
			if strings.EqualFold(key, fieldName) {
				continue
			}
			for _, value := range values {
				writer.WriteField(key, value)
			}
		}
	}

	writer.Close()

	// 创建修改后的请求头
	headers := make(map[string]string)
	maps.Copy(headers, apiReq.Headers)

	headers["Content-Type"] = writer.FormDataContentType()
	headers["Content-Length"] = strconv.Itoa(body.Len())

	rawRequest := buildRawHTTPRequest(apiReq.Method, apiReq.URL, headers, body.Bytes())

	// 直接使用clients.DoRequest发送multipart请求
	resp, err := clients.DoRequest(
		apiReq.Method,
		apiReq.URL,
		headers,
		body,
		10,
		clients.NewRestyClient(nil, false),
	)
	if err != nil {
		return &UploadResult{
			Vulnerable: false,
			Reason:     fmt.Sprintf("发送请求失败: %v", err),
			RawRequest: rawRequest,
		}, nil
	}

	bodyStr := string(resp.Body())

	// 如果提供了AI检测器，使用AI分析响应
	if aiChecker != nil {
		success, uploadURL, err := aiChecker.CheckFileUpload(bodyStr, testFileName, testContent)
		if err != nil {
			// AI检测失败，返回未检测到（避免误报）
			return &UploadResult{
				Vulnerable: false,
				Payload:    "",
				Response:   "",
				Reason:     fmt.Sprintf("AI分析失败: %v", err),
				UploadURL:  "",
				RawRequest: rawRequest,
			}, nil
		}

		if success {
			return &UploadResult{
				Vulnerable: true,
				Payload:    testFileName,
				Response:   vuln.TruncateResponse(bodyStr),
				Reason:     "AI检测到文件上传漏洞",
				UploadURL:  uploadURL,
				RawRequest: rawRequest,
			}, nil
		}

		return &UploadResult{
			Vulnerable: false,
			Payload:    "",
			Response:   "",
			Reason:     "AI分析未检测到文件上传漏洞",
			UploadURL:  "",
			RawRequest: rawRequest,
		}, nil
	}

	// 如果没有AI检测器，返回未检测到（因为不再使用程序自己分析）
	return &UploadResult{
		Vulnerable: false,
		Payload:    "",
		Response:   "",
		Reason:     "未启用AI检测，跳过文件上传检测",
		UploadURL:  "",
		RawRequest: rawRequest,
	}, nil
}

func buildRawHTTPRequest(method, rawURL string, headers map[string]string, body []byte) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	var sb strings.Builder

	pathWithQuery := parsedURL.RequestURI()
	if pathWithQuery == "" {
		pathWithQuery = "/"
	}

	sb.WriteString(fmt.Sprintf("%s %s HTTP/1.1\n", method, pathWithQuery))

	host := parsedURL.Host
	if host == "" {
		host = parsedURL.Hostname()
	}
	if host != "" {
		sb.WriteString(fmt.Sprintf("Host: %s\n", host))
	}

	for k, v := range headers {
		if strings.EqualFold(k, "host") {
			continue
		}
		sb.WriteString(fmt.Sprintf("%s: %s\n", k, v))
	}

	sb.WriteString("\n")
	if len(body) > 0 {
		sb.Write(body)
	}

	return sb.String()
}

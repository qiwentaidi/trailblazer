package lfi

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
)

// LFIResult 表示 LFI 测试结果
type LFIResult struct {
	Vulnerable bool   `json:"vulnerable"`
	Payload    string `json:"payload"`
	Response   string `json:"response"`
	Reason     string `json:"reason"`
}

// TestLocalFileInclusion 测试任意文件读取漏洞
// apiReq: 原始 API 请求
// cfg: LFI配置（包含payloads、参数关键词、匹配关键词）
// returns: LFIResult 测试结果
func TestLocalFileInclusion(apiReq structs.APIRequest, cfg config.LFIConfig) (*LFIResult, error) {
	// 如果未启用，直接返回
	if !cfg.Enabled {
		return &LFIResult{
			Vulnerable: false,
			Reason:     "LFI检测未启用",
		}, nil
	}

	// 检查是否有相关参数，如果没有则跳过测试
	hasRelevantParam := false
	paramKeywords := cfg.ParamKeywords
	if len(paramKeywords) == 0 {
		paramKeywords = []string{"file", "path", "filepath"}
	}

	if apiReq.Params != nil {
		for paramName := range apiReq.Params {
			paramNameLower := strings.ToLower(paramName)
			for _, kw := range paramKeywords {
				if strings.Contains(paramNameLower, strings.ToLower(kw)) {
					hasRelevantParam = true
					break
				}
			}
			if hasRelevantParam {
				break
			}
		}
	}

	// 如果没有相关参数，直接返回不进行测试
	if !hasRelevantParam {
		return &LFIResult{
			Vulnerable: false,
			Payload:    "",
			Response:   "",
			Reason:     "接口无相关参数，跳过LFI检测",
		}, nil
	}

	// 优先使用规则配置
	if len(cfg.Rules) > 0 {
		for _, rule := range cfg.Rules {
			for _, payload := range rule.Payloads {
				modifiedReq := injectLFIPayload(apiReq, payload, paramKeywords)
				resp, err := vuln.SendAPIRequest(modifiedReq, true)
				if err != nil {
					continue
				}

				body := string(resp.Body())

				// 根据规则类型进行匹配
				matched := false
				switch rule.MatchType {
				case "regex":
					matched = isLFIMatchedByRegex(body, rule.Regex)
				case "word":
					matched = isLFIMatchedByWords(body, rule.Words, rule.Condition)
				}

				if matched {
					return &LFIResult{
						Vulnerable: true,
						Payload:    payload,
						Response:   body,
						Reason:     "检测到任意文件读取漏洞",
					}, nil
				}
			}
		}
	} else {
		// 兼容旧配置：使用 payloads 和 matchKeywords
		payloads := cfg.Payloads
		if len(payloads) == 0 {
			payloads = []string{
				"../../../etc/passwd",
				"..\\..\\..\\windows\\win.ini",
				"/etc/passwd",
			}
		}

		for _, payload := range payloads {
			modifiedReq := injectLFIPayload(apiReq, payload, paramKeywords)
			resp, err := vuln.SendAPIRequest(modifiedReq, true)
			if err != nil {
				continue
			}

			body := string(resp.Body())

			if isLFIResponse(body, cfg.MatchKeywords) {
				return &LFIResult{
					Vulnerable: true,
					Payload:    payload,
					Response:   body,
					Reason:     "检测到任意文件读取漏洞",
				}, nil
			}

			if containsFileSystemError(body) {
				return &LFIResult{
					Vulnerable: true,
					Payload:    payload,
					Response:   body,
					Reason:     "检测到文件系统访问错误，可能存在路径遍历",
				}, nil
			}
		}
	}

	return &LFIResult{
		Vulnerable: false,
		Payload:    "",
		Response:   "",
		Reason:     "未检测到任意文件读取漏洞",
	}, nil
}

// injectLFIPayload 将载荷注入到 API 请求中（使用配置的参数关键词）
func injectLFIPayload(apiReq structs.APIRequest, payload string, paramKeywords []string) structs.APIRequest {
	modifiedReq := apiReq
	u, _ := url.Parse(modifiedReq.URL)
	if u.RawQuery != "" {
		param, _ := url.ParseQuery(u.RawQuery)
		modifiedReq.Params = param
		u.RawQuery = ""
		modifiedReq.URL = u.String()
	}

	// 使用配置的参数关键词，如果为空则使用默认值
	if len(paramKeywords) == 0 {
		paramKeywords = []string{"file", "path", "filepath"}
	}

	// 检查是否有包含关键词的参数
	hasRelevantParam := false
	for paramName := range modifiedReq.Params {
		paramNameLower := strings.ToLower(paramName)
		for _, kw := range paramKeywords {
			if strings.Contains(paramNameLower, strings.ToLower(kw)) {
				hasRelevantParam = true
				break
			}
		}
		if hasRelevantParam {
			break
		}
	}

	// 如果没有相关参数，返回原始请求（不进行测试）
	if !hasRelevantParam {
		return modifiedReq
	}

	// 只在包含关键词的参数中注入载荷
	for paramName := range modifiedReq.Params {
		paramNameLower := strings.ToLower(paramName)
		for _, kw := range paramKeywords {
			if strings.Contains(paramNameLower, strings.ToLower(kw)) {
				modifiedReq.Params[paramName] = []string{payload}
				break // 命中一个关键字就行
			}
		}
	}
	return modifiedReq
}

// isLFIResponse 检查响应是否表明 LFI 成功（使用配置的匹配关键词）
func isLFIResponse(body string, matchKeywords []string) bool {
	// 使用配置中的匹配关键词
	if len(matchKeywords) == 0 {
		// 如果配置为空，使用默认特征
		matchKeywords = []string{
			"root:x:",
			"[fonts]",
			"[extensions]",
		}
	}

	bodyLower := strings.ToLower(body)

	// 检查是否包含配置的匹配关键词
	for _, keyword := range matchKeywords {
		if strings.Contains(bodyLower, strings.ToLower(keyword)) {
			return true
		}
	}

	return false
}

// containsFileSystemError 检查是否包含文件系统相关错误
func containsFileSystemError(body string) bool {
	errorPatterns := []string{
		"no such file or directory",
		"file not found",
		"invalid path",
		"directory traversal",
		"path traversal",
		"../",
		"..\\",
		"cannot find",
		"failed to open",
	}

	bodyLower := strings.ToLower(body)

	for _, pattern := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			return true
		}
	}

	return false
}

// isLFIMatchedByRegex 使用正则表达式匹配响应体
func isLFIMatchedByRegex(body string, regexPatterns []string) bool {
	if len(regexPatterns) == 0 {
		return false
	}

	for _, pattern := range regexPatterns {
		matched, err := regexp.MatchString(pattern, body)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// isLFIMatchedByWords 使用关键词匹配响应体
func isLFIMatchedByWords(body string, words []string, condition string) bool {
	if len(words) == 0 {
		return false
	}

	bodyLower := strings.ToLower(body)

	// 默认使用 or 条件
	if condition == "" {
		condition = "or"
	}

	if condition == "and" {
		// 所有关键词都需要匹配
		for _, word := range words {
			if !strings.Contains(bodyLower, strings.ToLower(word)) {
				return false
			}
		}
		return true
	} else {
		// or: 任意一个关键词匹配即可
		for _, word := range words {
			if strings.Contains(bodyLower, strings.ToLower(word)) {
				return true
			}
		}
		return false
	}
}

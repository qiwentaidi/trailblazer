package xss

import (
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/config"
	"github.com/qiwentaidi/trailblazer/pkg/core/structs"
	"github.com/qiwentaidi/trailblazer/pkg/core/vuln"
	"html"
	"net/url"
	"strings"
	"testing"
)

// TestReflectedXSS 测试反射型XSS检测
// 靶场地址: http://localhost:8081/xss?input=
func TestReflectedXSS(t *testing.T) {
	t.Skip("manual integration test: requires local xss lab on localhost:8081")
	// 构造API请求
	apiReq := structs.APIRequest{
		URL:    "http://localhost:8081/xss",
		Method: "GET",
		Params: url.Values{
			"input": []string{"test"}, // 初始测试值
		},
		Headers: make(map[string]string),
		Body:    "",
	}

	// 配置XSS检测（启用并使用默认payload）
	cfg := config.XSSConfig{
		Enabled:  true,
		Payloads: []string{}, // 使用内置payload
		Rules:    []config.XSSPayloadRule{},
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("开始测试反射型XSS检测")
	fmt.Printf("目标URL: %s\n", apiReq.URL)
	fmt.Printf("参数: %v\n", apiReq.Params)
	fmt.Println(strings.Repeat("=", 70))

	// 执行XSS检测
	result, err := TestXSS(apiReq, cfg)
	if err != nil {
		t.Fatalf("XSS检测失败: %v", err)
	}

	// 打印结果
	fmt.Println("\n" + strings.Repeat("-", 70))
	fmt.Println("检测结果")
	fmt.Println(strings.Repeat("-", 70))

	if result == nil {
		fmt.Println("结果: nil (可能没有参数或未检测到反射)")
		t.Log("未检测到反射，可能原因：")
		t.Log("1. 靶场未运行或URL不正确")
		t.Log("2. 参数值未在响应中反射")
		t.Log("3. 响应被转义或过滤")
		return
	}

	fmt.Printf("是否检测到漏洞: %v\n", result.Vulnerable)
	fmt.Printf("漏洞类型: %s\n", result.Type)
	fmt.Printf("使用的Payload: %s\n", result.Payload)
	fmt.Printf("检测原因: %s\n", result.Reason)
	if result.Response != "" {
		responsePreview := result.Response
		if len(responsePreview) > 300 {
			responsePreview = responsePreview[:300] + "..."
		}
		fmt.Printf("\n响应内容预览:\n%s\n", responsePreview)
	}
	fmt.Println(strings.Repeat("-", 70))

	// 如果检测到漏洞，输出详细信息
	if result.Vulnerable {
		fmt.Println("\n✅ 成功检测到反射型XSS漏洞！")
		fmt.Printf("Payload: %s\n", result.Payload)
		if len(result.Response) > 500 {
			fmt.Printf("响应内容（前500字符）: %s...\n", result.Response[:500])
		} else {
			fmt.Printf("完整响应: %s\n", result.Response)
		}
		t.Logf("检测到XSS漏洞，Payload: %s", result.Payload)
	} else {
		fmt.Println("\n❌ 未检测到反射型XSS漏洞")
		fmt.Printf("原因: %s\n", result.Reason)
		t.Logf("未检测到漏洞，原因: %s", result.Reason)
	}
}

// TestReflectedXSSDebug 带详细调试信息的XSS测试
func TestReflectedXSSDebug(t *testing.T) {
	t.Skip("manual integration test: requires local xss lab on localhost:8081")
	apiReq := structs.APIRequest{
		URL:    "http://localhost:8081/xss",
		Method: "GET",
		Params: url.Values{
			"input": []string{"test"},
		},
		Headers: make(map[string]string),
		Body:    "",
	}

	cfg := config.XSSConfig{
		Enabled:  true,
		Payloads: []string{},
		Rules:    []config.XSSPayloadRule{},
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("开始调试XSS检测过程")
	fmt.Printf("目标URL: %s\n", apiReq.URL)
	fmt.Printf("参数: %v\n", apiReq.Params)
	fmt.Println(strings.Repeat("=", 70))

	// 手动测试探测阶段
	paramName := "input"
	probePayload := "XSS_PROBE_TRAILBLAZER_" + paramName

	fmt.Printf("\n[阶段1] 发送探测Payload: %s\n", probePayload)
	probeReq := apiReq
	probeReq.Params[paramName] = []string{probePayload}

	// 手动发送请求查看响应
	resp, err := vuln.SendAPIRequest(probeReq, false)
	if err != nil {
		fmt.Printf("❌ 请求失败: %v\n", err)
		fmt.Println("\n可能的原因：")
		fmt.Println("1. 靶场未运行在 http://localhost:8081/xss")
		fmt.Println("2. 网络连接问题")
		fmt.Println("3. URL或参数名不正确")
		t.Fatalf("请求失败: %v", err)
	}

	body := string(resp.Body())
	fmt.Printf("响应状态码: %d\n", resp.StatusCode())
	fmt.Printf("响应长度: %d 字节\n", len(body))

	if len(body) > 500 {
		fmt.Printf("响应内容预览（前500字符）:\n%s\n", body[:500])
	} else {
		fmt.Printf("响应内容:\n%s\n", body)
	}

	// 检查探测payload是否被反射
	if strings.Contains(body, probePayload) {
		fmt.Printf("\n✅ 探测Payload被反射！位置: %d\n", strings.Index(body, probePayload))

		// 分析上下文
		fmt.Println("\n[阶段2] 分析上下文...")
		contextInfo := analyzeContext(body, probePayload)
		fmt.Printf("上下文类型: %s\n", getContextName(contextInfo.ContextType))
		fmt.Printf("是否被转义: %v\n", contextInfo.IsEscaped)
		fmt.Printf("标签名: %s\n", contextInfo.TagName)
		fmt.Printf("属性名: %s\n", contextInfo.AttributeName)
		fmt.Printf("引号类型: %s\n", contextInfo.QuoteType)

		if contextInfo.ContextType == ContextHTMLComment {
			fmt.Println("⚠️  Payload在HTML注释中，跳过检测")
		} else if contextInfo.ContextType == ContextSafeTag {
			fmt.Printf("⚠️  Payload在安全标签中 (%s)，跳过检测\n", contextInfo.TagName)
		} else if contextInfo.IsEscaped {
			fmt.Println("⚠️  Payload被转义，跳过检测")
		} else {
			fmt.Println("✅ 上下文分析通过，继续生成Payload...")
		}

		// 继续测试
		fmt.Println("\n[阶段3] 生成针对性Payload并测试...")
		result, err := TestXSS(apiReq, cfg)
		if err != nil {
			t.Fatalf("XSS检测失败: %v", err)
		}

		if result != nil {
			fmt.Println("\n" + strings.Repeat("-", 70))
			fmt.Println("最终检测结果")
			fmt.Println(strings.Repeat("-", 70))
			fmt.Printf("是否检测到漏洞: %v\n", result.Vulnerable)
			fmt.Printf("漏洞类型: %s\n", result.Type)
			fmt.Printf("使用的Payload: %s\n", result.Payload)
			fmt.Printf("检测原因: %s\n", result.Reason)

			if result.Vulnerable {
				fmt.Println("\n✅ 成功检测到反射型XSS漏洞！")
				t.Logf("检测到XSS漏洞，Payload: %s", result.Payload)
			} else {
				fmt.Println("\n❌ 未检测到XSS漏洞")
				fmt.Printf("原因: %s\n", result.Reason)

				// 手动测试一个payload
				fmt.Println("\n[调试] 手动测试一个Payload...")
				testPayload := "<script>/*__TB_XSS__*/document.body.innerHTML+='XSS_VULNERABILITY_DETECTED_BY_TRAILBLAZER_2024_UNIQUE_STRING'</script>"
				testReq := apiReq
				testReq.Params[paramName] = []string{testPayload}
				testResp, err := vuln.SendAPIRequest(testReq, false)
				if err == nil {
					testBody := string(testResp.Body())
					fmt.Printf("测试Payload: %s\n", testPayload)
					fmt.Printf("Payload是否在响应中: %v\n", strings.Contains(testBody, testPayload))
					if strings.Contains(testBody, testPayload) {
						fmt.Printf("响应片段（包含payload的部分）:\n")
						idx := strings.Index(testBody, testPayload)
						start := idx - 50
						if start < 0 {
							start = 0
						}
						end := idx + len(testPayload) + 50
						if end > len(testBody) {
							end = len(testBody)
						}
						fmt.Printf("...%s...\n", testBody[start:end])

						// 检查是否被转义
						escaped := html.EscapeString(testPayload)
						fmt.Printf("HTML转义后的Payload: %s\n", escaped)
						fmt.Printf("响应中是否包含转义形式: %v\n", strings.Contains(testBody, escaped))
					}
				}

				fmt.Println("\n可能的原因：")
				fmt.Println("1. Payload被转义或过滤")
				fmt.Println("2. 响应在安全上下文中（如HTML注释、安全标签）")
				fmt.Println("3. 检测逻辑需要优化")
			}
		}
	} else {
		fmt.Printf("\n❌ 探测Payload未被反射\n")
		fmt.Println("\n可能的原因：")
		fmt.Println("1. 参数名不正确（当前使用: input）")
		fmt.Println("2. 靶场没有将参数值反射到响应中")
		fmt.Println("3. 响应格式与预期不符")
		fmt.Printf("\n尝试在浏览器中访问: %s?input=%s\n", apiReq.URL, probePayload)
		fmt.Println("查看响应中是否包含探测字符串")
	}
}

// TestReflectedXSSWithCustomPayload 使用自定义payload测试
func TestReflectedXSSWithCustomPayload(t *testing.T) {
	t.Skip("manual integration test: requires local xss lab on localhost:8081")
	apiReq := structs.APIRequest{
		URL:    "http://localhost:8081/xss",
		Method: "GET",
		Params: url.Values{
			"input": []string{"test"},
		},
		Headers: make(map[string]string),
		Body:    "",
	}

	// 使用自定义payload
	cfg := config.XSSConfig{
		Enabled: true,
		Payloads: []string{
			"<script>alert('XSS')</script>",
			"<img src=x onerror=alert('XSS')>",
			"<svg onload=alert('XSS')>",
		},
		Rules: []config.XSSPayloadRule{},
	}

	result, err := TestXSS(apiReq, cfg)
	if err != nil {
		t.Fatalf("XSS检测失败: %v", err)
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("使用自定义Payload的XSS检测结果")
	fmt.Println(strings.Repeat("=", 60))

	if result != nil {
		fmt.Printf("检测到漏洞: %v\n", result.Vulnerable)
		if result.Vulnerable {
			fmt.Printf("Payload: %s\n", result.Payload)
			fmt.Printf("原因: %s\n", result.Reason)
		}
	}
}

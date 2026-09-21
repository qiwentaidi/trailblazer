package main

import (
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/sdk"
	"log"
	"os"
	"sync"
	"time"
)

// 带回调的使用示例：实时获取扫描结果，类似nuclei
func main() {
	fmt.Println("=== Trailblazer SDK 回调示例 ===")

	// 创建扫描选项
	options := sdk.NewScanOptions()

	// 配置黑名单域名（来自 config.yaml black-domain）
	options.BlackDomain = []string{
		"github.com",
		"google.com",
		"amazon.com",
		"gitee.com",
		"w3.org",
		"qq.com",
		"tianditu.gov.cn",
		"amap.com",
		"alicdn.com",
		"ding.zj.gov.cn",
		"zjzwfw.gov.cn",
	}

	// 配置高风险路由关键词（来自 config.yaml high-risk-router）
	options.HighRiskRouter = []string{
		"logout",
		"loginout",
		"insert",
		"update",
		"remove",
		"add",
		"change",
		"save",
		"import",
		"create",
		"enable",
		"del",
		"disable",
	}

	// 配置认证关键词（来自 config.yaml authentication）
	options.Authentication = []string{
		"token不能为空",
		"token失效",
		"令牌不能为空",
		"令牌已过期",
		"Unauthorized",
		"Access Denied",
		"认证失败",
		`"code":(4[0-9]{2})`,
		`"code":"(4[0-9]{2})"`,
		"未登录",
		"没有登录",
		"token verify fail",
		"身份验证失败",
		"404 NOT_FOUND",
		"accessToken错误",
		"请登录",
		"登录状态异常",
		"登录异常",
		"没有令牌",
		"登录信息已失效",
		"登录信息失效",
	}

	// 配置占位符（来自 config.yaml placeholder）
	options.Placeholder = map[string]string{
		"default":   "test",
		"id":        "1",
		"keyword":   "test",
		"name":      "test",
		"time":      "2020-01-01 10:10:10",
		"timestamp": "1758791720",
	}

	// 配置漏洞检测模块（来自 config.yaml vuln-detection）
	// payload、参数关键词与匹配规则已全部内置，这里只需开关。
	options.VulnDetection.SQLInjection.Enabled = true // SQL 注入检测
	options.VulnDetection.LFI.Enabled = true          // LFI 本地文件包含检测
	options.VulnDetection.SSRF.Enabled = true         // SSRF 检测（可选回连：SSRF.CallbackURL）
	options.VulnDetection.Redirect.Enabled = true     // 重定向检测
	options.VulnDetection.XSS.Enabled = true          // XSS 检测
	options.VulnDetection.Upload.Enabled = true       // 上传漏洞检测

	// 使用互斥锁保护共享数据（如果需要）
	var mu sync.Mutex
	var vulnCount, assetCount int

	// 设置回调函数（类似nuclei的方式）
	options.OnResult = func(event sdk.ScanEvent) bool {
		mu.Lock()
		defer mu.Unlock()

		switch event.Type {
		case sdk.EventTypeVulnerability:
			// 发现漏洞
			vulnCount++
			vuln, ok := event.Data.(sdk.VulnerabilityItem)
			if !ok {
				fmt.Printf("[警告] 无法解析漏洞数据\n")
				return true
			}

			// 根据漏洞级别使用不同颜色（终端输出）
			levelColor := getLevelColor(vuln.Level)
			fmt.Printf("[%s] [%s%s%s] %s - %s\n",
				event.Timestamp.Format("15:04:05"),
				levelColor,
				vuln.Level,
				"\033[0m", // 重置颜色
				vuln.Title,
				vuln.URL)

			// 可以在这里进行自定义处理，比如：
			// - 发送到消息队列
			// - 写入数据库
			// - 发送通知
			// - 触发其他操作

			// 示例：如果是高危漏洞，立即处理
			if vuln.Level == "high" {
				fmt.Printf("  ⚠️  高危漏洞！立即处理: %s\n", vuln.URL)
				// 可以在这里添加紧急处理逻辑
			}

		case sdk.EventTypeAsset:
			// 发现资产
			assetCount++
			asset := event.Data.(map[string]interface{})
			fmt.Printf("[%s] [资产] %s: %s (来源: %s)\n",
				event.Timestamp.Format("15:04:05"),
				asset["type"],
				asset["value"],
				asset["source"])

		case sdk.EventTypeAPIRecord:
			record, ok := event.Data.(sdk.APIRecord)
			if !ok {
				fmt.Printf("[警告] 无法解析接口记录数据\n")
				return true
			}
			fmt.Printf("[%s] [接口] [%s] %s (%d)\n",
				event.Timestamp.Format("15:04:05"),
				record.Method,
				record.URL,
				record.ResponseCode)

		case sdk.EventTypeProtocolTrace:
			trace, ok := event.Data.(sdk.ProtocolTrace)
			if !ok {
				fmt.Printf("[警告] 无法解析协议轨迹数据\n")
				return true
			}
			fmt.Printf("[%s] [协议] [%s] %s\n",
				event.Timestamp.Format("15:04:05"),
				trace.Method,
				trace.RequestURL)
			if plaintext := trace.SessionMaterials["latest_response_plaintext"]; plaintext != "" {
				fmt.Printf("  已捕获响应明文，长度: %d\n", len(plaintext))
			}

		case sdk.EventTypeProgress:
			// 进度更新
			progress := event.Data.(map[string]interface{})
			if status, ok := progress["status"].(string); ok {
				if status == "started" {
					fmt.Printf("[%s] [进度] 开始扫描: %s (%v/%v)\n",
						event.Timestamp.Format("15:04:05"),
						progress["url"],
						progress["current"],
						progress["total"])
				} else if status == "completed" {
					// Summary 在进度事件中可能不存在，这里只是示例
					fmt.Printf("\n[%s] [完成] 扫描完成！\n", event.Timestamp.Format("15:04:05"))
				}
			}

		case sdk.EventTypeError:
			// 错误信息
			errData := event.Data.(map[string]interface{})
			fmt.Printf("[%s] [错误] %s: %s\n",
				event.Timestamp.Format("15:04:05"),
				errData["url"],
				errData["error"])
		}

		return true
	}

	// 执行扫描
	targets := []string{
		"https://hfi-health.diandianys.com/medical-butler/",
	}

	fmt.Printf("开始扫描 %d 个目标（实时回调模式）...\n\n", len(targets))

	startTime := time.Now()
	result, err := sdk.PerformScan(targets, options)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	duration := time.Since(startTime)

	// 显示统计信息
	fmt.Printf("\n=== 实时统计 ===\n")
	fmt.Printf("扫描耗时: %v\n", duration)
	fmt.Printf("实时统计 - 漏洞: %d, 资产: %d\n", vulnCount, assetCount)
	fmt.Printf("最终结果 - 漏洞: %d\n", result.Summary.TotalVulnerabilities)

	// 保存结果到文件
	if len(result.Targets) > 0 {
		outputFile := "callback_result.json"
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("序列化结果失败: %v", err)
		} else {
			if err := os.WriteFile(outputFile, jsonData, 0644); err != nil {
				log.Printf("保存结果失败: %v", err)
			} else {
				fmt.Printf("\n结果已保存到: %s\n", outputFile)
			}
		}
	}
}

// getLevelColor 根据漏洞级别返回终端颜色代码
func getLevelColor(level string) string {
	switch level {
	case "high":
		return "\033[31m" // 红色
	case "medium":
		return "\033[33m" // 黄色
	case "low":
		return "\033[36m" // 青色
	case "info":
		return "\033[34m" // 蓝色
	default:
		return "\033[0m" // 默认
	}
}

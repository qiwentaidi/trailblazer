package main

import (
	"encoding/json"
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/sdk"
	"log"
)

// 基本使用示例：不使用回调，只获取最终结果
func main() {
	fmt.Println("=== Trailblazer SDK 基本使用示例 ===")

	// 1. 创建扫描选项
	options := sdk.NewScanOptions()

	// 2. 配置OpenAI（可选）
	options.OpenAI.Enabled = false // 设置为true并配置API密钥以启用AI检测

	// 3. 配置黑名单域名（可选）
	options.BlackDomain = []string{
		"github.com",
		"google.com",
		"amazon.com",
	}

	// 4. 配置高风险路由关键词（可选）
	options.HighRiskRouter = []string{
		"logout",
		"delete",
		"remove",
		"admin",
	}

	// 5. 配置认证失败关键词（可选）
	options.Authentication = []string{
		"Unauthorized",
		"Access Denied",
		"未登录",
		"token失效",
	}

	// 6. 配置占位符（可选）
	options.Placeholder = map[string]string{
		"id":        "1",
		"keyword":   "test",
		"name":      "test",
		"timestamp": "1758791720",
	}

	// 7. 配置输出路径（可选）
	options.OutputPath = "scan_result.json"

	// 8. 执行扫描
	targets := []string{
		"https://example.com",
		// 可以添加多个目标
	}

	fmt.Printf("开始扫描 %d 个目标...\n\n", len(targets))

	result, err := sdk.PerformScan(targets, options)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 9. 处理扫描结果
	fmt.Println("=== 扫描结果摘要 ===")
	fmt.Printf("扫描时间: %s\n", result.ScanTime)
	fmt.Printf("目标数量: %d\n", result.Summary.TotalTargets)
	fmt.Printf("树节点数: %d\n", result.Summary.TotalTreeNodes)
	fmt.Printf("漏洞数量: %d\n", result.Summary.TotalVulnerabilities)
	fmt.Printf("资产统计:\n")
	fmt.Printf("  - 邮箱: %d\n", result.Summary.TotalAssets.Email)
	fmt.Printf("  - 身份证: %d\n", result.Summary.TotalAssets.IDCard)
	fmt.Printf("  - 手机号: %d\n", result.Summary.TotalAssets.Phone)
	fmt.Printf("  - IP/URL: %d\n", result.Summary.TotalAssets.IPURL)
	fmt.Printf("  - 敏感信息: %d\n", result.Summary.TotalAssets.Sensitive)
	fmt.Printf("  - API路由: %d\n", result.Summary.TotalAssets.APIRoutes)
	fmt.Printf("  - API根路径: %d\n", result.Summary.TotalAssets.APIRoots)

	// 10. 详细查看每个目标的漏洞
	fmt.Println("\n=== 漏洞详情 ===")
	for i, target := range result.Targets {
		fmt.Printf("\n目标 %d: %s\n", i+1, target.Target)
		if len(target.Vulnerabilities) > 0 {
			fmt.Printf("  发现 %d 个漏洞:\n", len(target.Vulnerabilities))
			for j, vuln := range target.Vulnerabilities {
				fmt.Printf("    [%d] [%s] %s - %s\n", j+1, vuln.Level, vuln.Title, vuln.URL)
			}
		} else {
			fmt.Println("  未发现漏洞")
		}
	}

	// 11. 将结果保存为JSON（如果未指定输出路径）
	if options.OutputPath == "" {
		jsonData, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("序列化结果失败: %v", err)
		} else {
			fmt.Printf("\n=== 完整JSON结果 ===\n%s\n", string(jsonData))
		}
	} else {
		fmt.Printf("\n结果已保存到: %s\n", options.OutputPath)
	}
}

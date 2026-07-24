package main

import (
	"fmt"
	"github.com/qiwentaidi/trailblazer/pkg/sdk"
	"log"
	"os"
	"path/filepath"
)

// 从配置文件加载的示例
func main() {
	fmt.Println("=== Trailblazer SDK 配置文件示例 ===")

	// 获取配置文件路径（相对于当前工作目录）
	configPath := "config.yaml"

	// 如果配置文件不存在，尝试从项目根目录查找
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		rootConfig := filepath.Join("..", "..", "config.yaml")
		if _, err := os.Stat(rootConfig); err == nil {
			configPath = rootConfig
		} else {
			log.Fatalf("配置文件不存在: %s\n请确保配置文件存在，或使用代码方式配置选项", configPath)
		}
	}

	fmt.Printf("从配置文件加载: %s\n", configPath)

	// 从配置文件加载选项
	options, err := sdk.LoadScanOptionsFromFile(configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 可以在此基础上修改配置
	options.OutputPath = "config_scan_result.json"

	// 设置回调函数（可选）
	options.OnResult = func(event sdk.ScanEvent) bool {
		switch event.Type {
		case sdk.EventTypeVulnerability:
			if vuln, ok := event.Data.(sdk.VulnerabilityItem); ok {
				fmt.Printf("[漏洞] [%s] %s - %s\n", vuln.Level, vuln.Title, vuln.URL)
			}
		case sdk.EventTypeAsset:
			if asset, ok := event.Data.(map[string]interface{}); ok {
				fmt.Printf("[资产] %s: %s\n", asset["type"], asset["value"])
			}
		case sdk.EventTypeProgress:
			progress := event.Data.(map[string]interface{})
			if status, ok := progress["status"].(string); ok {
				if status == "started" {
					fmt.Printf("[进度] 开始扫描: %s\n", progress["url"])
				}
			}
		}
		return true
	}

	// 执行扫描
	targets := []string{
		"https://example.com",
	}

	fmt.Printf("\n开始扫描 %d 个目标...\n\n", len(targets))

	result, err := sdk.PerformScan(targets, options)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	// 显示结果摘要
	fmt.Printf("\n=== 扫描结果 ===\n")
	fmt.Printf("目标数量: %d\n", result.Summary.TotalTargets)
	fmt.Printf("漏洞数量: %d\n", result.Summary.TotalVulnerabilities)
	fmt.Printf("结果已保存到: %s\n", options.OutputPath)
}

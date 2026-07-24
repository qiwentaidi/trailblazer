package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

func main() {
	urls := flag.String("urls", "", "逗号分隔的目标 URL 列表")
	urlsShort := flag.String("u", "", "逗号分隔的目标 URL 列表")
	file := flag.String("file", "", "目标 URL 文件，每行一个 URL")
	fileShort := flag.String("f", "", "目标 URL 文件，每行一个 URL")
	output := flag.String("output", "", "JSON 输出文件；为空时输出到标准输出")
	outputShort := flag.String("o", "", "JSON 输出文件；为空时输出到标准输出")
	configPath := flag.String("config", "", "SDK 配置文件路径，可选")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Trailblazer 安全扫描 CLI\n\n用法:\n  trailblazer -u https://example.com\n  trailblazer -f urls.txt -o result.json\n\n参数:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	urlList, err := collectURLs(firstNonEmpty(*urls, *urlsShort), firstNonEmpty(*file, *fileShort))
	if err != nil {
		log.Fatal(err)
	}

	options := sdk.NewScanOptions()
	if strings.TrimSpace(*configPath) != "" {
		options, err = sdk.LoadScanOptionsFromFile(*configPath)
		if err != nil {
			log.Fatalf("加载配置失败: %v", err)
		}
	}
	options.OutputPath = firstNonEmpty(*output, *outputShort)

	result, err := sdk.PerformScan(urlList, options)
	if err != nil {
		log.Fatalf("扫描失败: %v", err)
	}

	if options.OutputPath == "" {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			log.Fatalf("输出扫描结果失败: %v", err)
		}
	}
}

func collectURLs(rawURLs, filePath string) ([]string, error) {
	var urls []string
	for _, rawURL := range strings.Split(rawURLs, ",") {
		if value := strings.TrimSpace(rawURL); value != "" {
			urls = append(urls, value)
		}
	}

	if strings.TrimSpace(filePath) != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("读取 URL 文件失败: %w", err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	}

	seen := make(map[string]struct{}, len(urls))
	result := make([]string, 0, len(urls))
	for _, url := range urls {
		if _, exists := seen[url]; exists {
			continue
		}
		seen[url] = struct{}{}
		result = append(result, url)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("至少提供一个目标 URL：使用 -u/--urls 或 -f/--file")
	}
	return result, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

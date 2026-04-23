package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"trailblazer/pkg/lib"
)

const defaultTarget = "http://prfm.caocaokeji.cn/"

type demoOutput struct {
	Target       string          `json:"target"`
	GeneratedAt  string          `json:"generatedAt"`
	ConfigSource string          `json:"configSource,omitempty"`
	Events       []lib.ScanEvent `json:"events"`
	Result       *lib.ScanResult `json:"result"`
}

func main() {
	target := flag.String("target", defaultTarget, "scan target")
	output := flag.String("output", defaultOutputPath(), "output json path")
	flag.Parse()

	options, configSource, err := loadOptions()
	if err != nil {
		log.Fatalf("加载 SDK 配置失败: %v", err)
	}

	events := make([]lib.ScanEvent, 0, 256)
	options.OutputPath = ""
	options.OnResult = func(event lib.ScanEvent) bool {
		events = append(events, event)
		return true
	}

	result, err := lib.PerformScan([]string{*target}, options)
	if err != nil {
		log.Fatalf("SDK 扫描失败: %v", err)
	}

	payload := demoOutput{
		Target:       *target,
		GeneratedAt:  time.Now().Format(time.RFC3339),
		ConfigSource: configSource,
		Events:       events,
		Result:       result,
	}

	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		log.Fatalf("创建输出目录失败: %v", err)
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Fatalf("序列化 JSON 失败: %v", err)
	}

	if err := os.WriteFile(*output, data, 0o644); err != nil {
		log.Fatalf("写入结果文件失败: %v", err)
	}

	fmt.Printf("PRFM demo 扫描完成，结果已写入: %s\n", *output)
}

func loadOptions() (*lib.ScanOptions, string, error) {
	for _, path := range candidateConfigPaths() {
		if _, err := os.Stat(path); err == nil {
			options, loadErr := lib.LoadScanOptionsFromFile(path)
			if loadErr != nil {
				return nil, "", loadErr
			}
			return options, path, nil
		}
	}

	options := lib.NewScanOptions()
	return options, "", nil
}

func candidateConfigPaths() []string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return []string{"config.yaml"}
	}

	exampleDir := filepath.Dir(currentFile)
	backendRoot := filepath.Clean(filepath.Join(exampleDir, "..", ".."))

	return []string{
		filepath.Join(backendRoot, "config.yaml"),
		filepath.Join(exampleDir, "config.yaml"),
		"config.yaml",
	}
}

func defaultOutputPath() string {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return "prfm_scan_result.json"
	}
	return filepath.Join(filepath.Dir(currentFile), "prfm_scan_result.json")
}

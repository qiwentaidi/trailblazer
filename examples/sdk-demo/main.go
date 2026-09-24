// sdk-demo 演示 Trailblazer SDK 从接口资产采集到漏洞检测的完整链路。
//
// 链路总览（采集/检测分离架构，选项 B）：
//
//	① 采集  sdk.CrawlAPIAssets       运行时流量 + JS 静态分析，只读、不探测
//	② 分析  sdk.AnalyzeSensitiveAssets  已采集 JS 的纯静态敏感资产分析
//	③ 文档  sdk.ExportOpenAPIAssets  运行时观测 + 静态模板 + 推断 API Root 导出
//	④ 检测  sdk.DetectOperationVulns  认证对照 + 匿名运行时响应判定 + 参数 fuzz，事件实时回调
//
// 用法：
//
//	go run ./examples/sdk-demo http://192.168.2.101:3000/#
//
// 注意：第③步会向目标发送真实探测 payload（SQLi/LFI/SSRF/XSS），
// 仅对明确授权的测试目标运行。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/qiwentaidi/trailblazer/pkg/core/database"
	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: sdk-demo <target-url>")
		fmt.Println("example: sdk-demo http://192.168.2.101:3000/#")
		os.Exit(1)
	}
	target := os.Args[1]
	start := time.Now()

	// ============================================================
	// ① 资产采集（只读）：运行时 API Context + JS 蓝图 + OperationSpec
	// ============================================================
	assets, err := sdk.CrawlAPIAssets(target, &sdk.APICrawlOptions{
		MaxDepth:       2,
		Timeout:        10,
		Concurrency:    4,
		RateLimit:      50,
		MaxJSResources: 0, // 默认递归采集上限 512 个 JS
		// Headers: 登录态注入，例如 map[string]string{"Cookie": "session=..."}
		// OnAPIContext: 每观测到一个接口上下文回调一次（返回 false 仅跳过入库）
	})
	if err != nil {
		fmt.Println("crawl error:", err)
		os.Exit(1)
	}

	// 采集产物一览：
	fmt.Printf("== 采集完成 (%s)\n", time.Since(start).Round(time.Millisecond))
	fmt.Printf("   网站树根节点: %d\n", len(assets.SiteTree))
	fmt.Printf("   运行时 API Context: %d（去重合并后的接口上下文）\n", assets.Store.Len())
	for _, ctx := range assets.Store.List() {
		fmt.Printf("     %s %s (观测 %d 次)\n", ctx.Method, ctx.PathTemplate, ctx.Observations)
	}
	fmt.Printf("   JS 资源: %d\n", len(assets.JSResources))
	fmt.Printf("   JS 请求蓝图: %d（含 method/path/参数/置信度/源码偏移）\n", len(assets.RequestBlueprints))
	fmt.Printf("   锚点候选证据: %d（预算内未深挖的请求锚点，覆盖面不丢失）\n", len(assets.AnchorCandidates))
	fmt.Printf("   OperationSpec: %d（可持久化接口模板，动态值已剥离）\n", len(assets.OperationSpecs))
	for _, spec := range assets.OperationSpecs {
		fmt.Printf("     %s %s (params=%d requiresRuntime=%v)\n",
			spec.Method, spec.PathTemplate, len(spec.Params), spec.RequiresRuntime)
	}
	fmt.Printf("   API Root 候选（推断，需验证）: %d\n", len(assets.APIRootCandidates))
	for _, root := range assets.APIRootCandidates {
		fmt.Printf("     %s\n", root)
	}

	// ============================================================
	// ② 敏感资产分析：只读取已采集 JS，不发起额外网络请求
	// ============================================================
	sensitiveAssets, err := sdk.AnalyzeSensitiveAssets(assets, nil)
	if err != nil {
		fmt.Println("sensitive asset analysis error:", err)
		os.Exit(1)
	}
	fmt.Printf("== 敏感资产候选: %d（分析 JS %d 个，原文输出，需人工验证）\n",
		len(sensitiveAssets.Items), sensitiveAssets.ResourcesAnalyzed)
	sensitiveTypeCounts := make(map[string]int)
	for _, item := range sensitiveAssets.Items {
		sensitiveTypeCounts[item.Type]++
	}
	types := make([]string, 0, len(sensitiveTypeCounts))
	for kind := range sensitiveTypeCounts {
		types = append(types, kind)
	}
	sort.Strings(types)
	for _, kind := range types {
		fmt.Printf("   %s: %d\n", kind, sensitiveTypeCounts[kind])
	}
	for _, item := range sensitiveAssets.Items {
		fmt.Printf("     [%s] %s (%s @ %d, rule=%s)\n", item.Type, item.Value, item.Source, item.Offset, item.Rule)
	}

	// ============================================================
	// ③ OpenAPI 导出：运行时观测优先，静态模板补全未观测接口
	// ============================================================
	openapi, err := sdk.ExportOpenAPIAssets(assets, "sdk-demo")
	if err != nil {
		fmt.Println("openapi error:", err)
		os.Exit(1)
	}
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	_ = json.Unmarshal(openapi, &doc)
	outFile := "sdk-demo-openapi.json"
	if err := os.WriteFile(outFile, openapi, 0o644); err == nil {
		fmt.Printf("== OpenAPI 导出: %d 个 paths -> %s\n", len(doc.Paths), outFile)
	}

	// ============================================================
	// ④ 漏洞检测：认证对照（带认证接口）+ 匿名运行时响应判定 + 参数 fuzz（静态模板）
	//    漏洞事件经 OnFinding 实时回调，与 PerformScan 的 OnResult 同构：
	//    ScanEvent{Type: EventTypeVulnerability, Data: database.VulnRecord}
	// ============================================================
	fmt.Println("== 开始漏洞检测（仅授权目标！）")
	detectResult, err := sdk.DetectOperationVulns(assets, &sdk.DetectOptions{
		Target: target,
		// TaskID/Version: 嵌入业务系统时传入业务侧任务标识，写入漏洞记录
		TaskID: "sdk-demo",
		// Sender: 可注入自带代理/Cookie 池/限速的 HTTP 客户端（AuthzSender）
		Fuzzers: []sdk.OperationFuzzer{
			sdk.NewSQLInjectionFuzzer(sdk.SQLInjectionConfig{Enabled: true}),
			sdk.NewLFIFuzzer(sdk.LFIConfig{Enabled: true}),
			sdk.NewSSRFFuzzer(sdk.SSRFConfig{Enabled: true}),
			sdk.NewXSSFuzzer(sdk.XSSConfig{Enabled: true}),
			sdk.NewRedirectFuzzer(sdk.RedirectConfig{Enabled: true}),
			// 文件上传检测需要传入 FileUploadAIChecker 才会确认并上报漏洞。
			sdk.NewFileUploadFuzzer(sdk.UploadConfig{Enabled: true}, nil),
		},
		OnFinding: func(event sdk.ScanEvent) bool {
			record, ok := event.Data.(database.VulnRecord)
			if !ok {
				return true
			}
			fmt.Printf("   [漏洞] [%s] %s %s — %s (payload 见 record.Request)\n",
				record.Level, record.Method, record.URL, record.Title)
			return true // 返回 false 可立即停止检测
		},
	})
	if err != nil {
		fmt.Println("detect error:", err)
		os.Exit(1)
	}

	fmt.Printf("== 检测完成: 漏洞 %d 条，授权对照实验 %d 次\n",
		len(detectResult.Vulnerabilities), len(detectResult.Checks))
	fmt.Printf("== 全程耗时: %s\n", time.Since(start).Round(time.Millisecond))
}

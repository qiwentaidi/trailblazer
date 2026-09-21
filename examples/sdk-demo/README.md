# SDK Demo：从接口资产采集到漏洞检测

`main.go` 演示 Trailblazer SDK 的完整三步链路（采集/检测分离架构）：

| 步骤 | API | 说明 |
|---|---|---|
| ① 资产采集 | `sdk.CrawlAPIAssets(target, opts)` | 只读。运行时流量捕获 + 大 bundle 锚点切片静态分析，产出 API Context、JS 蓝图、OperationSpec 模板、锚点候选证据 |
| ② 文档导出 | `sdk.ExportOpenAPIWithSpecs(store, specs, title)` | OpenAPI 3.1。运行时观测优先，静态模板补全未观测接口；动态参数带 `dynamic` 标记、不落值 |
| ③ 漏洞检测 | `sdk.DetectOperationVulns(assets, opts)` | 认证对照实验（带认证接口）+ 匿名运行时响应判定（无认证接口）+ 参数 fuzz（SQLi/LFI/SSRF/XSS），漏洞经 `OnFinding` 事件回调 |

## 运行

```bash
go run ./examples/sdk-demo http://192.168.2.101:3000/#
```

> 第③步会发送真实探测 payload，仅对明确授权的测试目标运行。

## 漏洞事件接收

与旧入口 `PerformScan` 的 `OnResult` 完全同构，`Data` 载荷为 `database.VulnRecord`：

```go
OnFinding: func(event sdk.ScanEvent) bool {
    record := event.Data.(database.VulnRecord) // VulnID/Level/Type/URL/Request/Response...
    return true                                // 返回 false 立即停止检测
}
```

## 关键约束

- `OperationSpec` 是**模板**：token/签名/nonce 等动态值（`requiresRuntime` 标记）必须由运行时流量补全后才允许构造真实请求；fuzzer 不会伪造凭证命名参数与动态请求头。
- 需要登录态的目标，通过 `APICrawlOptions.Headers` 注入 Cookie/Token，运行时才能捕获带认证的接口上下文，授权对照实验才有基线。
- 无凭证场景下，已实际捕获到的匿名 API 会使用原有未授权响应判定逻辑复核，不会因缺少认证基线被跳过；仅有静态模板、没有运行时请求/响应证据的接口不会被该分支判定。

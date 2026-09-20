# Trailblazer SDK 调用文档

## 1. 适用范围

本文档说明如何在其他 Go 程序中调用 Trailblazer SDK，完成以下能力：

- 目标站点扫描
- 资产提取
- 风险项提取
- 基于认证基线的未授权访问对照检测
- 浏览器运行时 API 请求/响应抓取
- OpenAPI 3.1 接口文档导出

本文档对应当前仓库中的 SDK 实现：

- SDK 入口文件: [`pkg/sdk/sdk.go`](../pkg/sdk/sdk.go)
- SDK 实现文件: [`pkg/lib/sdk.go`](../pkg/lib/sdk.go)

## 2. 接口总览

SDK 当前主要导出以下能力：

- `NewScanOptions() *ScanOptions`
- `LoadScanOptionsFromFile(configPath string) (*ScanOptions, error)`
- `PerformScan(urls []string, options *ScanOptions) (*ScanResult, error)`
- `PerformScanWithConfigFile(urls []string, configPath string, outputPath string) error`

同时，SDK 现在支持通过 `DataStore` 注入扫描结果存储读取能力，用于在漏洞分析和运行时上下文补全阶段复用已有采集结果，而不强依赖 ES。

## 3. 接入要求

### 3.1 Go 版本

当前模块 `go.mod` 要求：

```go
go 1.26.0
```

### 3.2 运行环境

SDK 的扫描链路依赖浏览器运行时抓取能力，因此运行环境需要：

- 可执行 Go 程序
- 可访问目标站点网络
- 本机可启动浏览器环境

如果运行环境本身无法启动浏览器，运行时 API 抓取能力会受影响。

### 3.3 导入方式

当前仓库模块名为：

```go
module github.com/qiwentaidi/trailblazer
```

在同仓库内调用时，导入路径为：

```go
import "github.com/qiwentaidi/trailblazer/pkg/sdk"
```

如果你要把 SDK 独立发布到其他仓库，请按你实际发布后的 module path 修改导入路径。

### 3.4 本地引入

如果你的主程序和 Trailblazer 目前都还是本地开发态，推荐直接在业务项目里用 `replace` 做本地引用。

假设目录结构如下：

```text
workspace/
├── your-app/
└── trailblazer/
    └──
```

则 `your-app/go.mod` 可写成：

```go
module your-app

go 1.24.0

require github.com/qiwentaidi/trailblazer v0.1.0

replace github.com/qiwentaidi/trailblazer => ../trailblazer
```

之后你的业务代码中直接：

```go
import "github.com/qiwentaidi/trailblazer/pkg/sdk"
```

即可完成本地联调。

建议：

- 开发联调阶段用 `replace`
- 准备交付或给其他团队复用时，再切换到明确版本依赖

## 4. 接入策略：最小入侵

如果你的目标是把 SDK 接进现有系统，而不是把 Trailblazer 平台整体嵌进去，建议采用最小入侵接入。

原则：

- 保留你现有的任务调度、日志、数据库、消息队列
- 只在现有扫描入口新增一次 `sdk.PerformScan`
- 用 `options.OnResult` 把结果桥接回你的系统
- 不要求接入 Trailblazer 的前端、任务表、ES 存储
- 如果你已有自己的数据库，可以实现 `database.ScanDataStore` 直接接入运行时上下文

推荐接入点：

- 你现有 worker 的 `Scan(url)` 或 `RunTask(taskID)` 方法
- 你现有插件式框架中的一个新 provider
- 你现有自动化测试平台里的一个扫描步骤

不推荐：

- 为了接 SDK 先重构你现有平台
- 把 Trailblazer 的前后端结构一起搬入主程序
- 先做一层中间库再二次转存

SDK 化接入的核心是能力复用，不是平台耦合。

## 5.1 DataStore 存储抽象

SDK 运行时会用到三类上下文数据：

- JS 资源
- API 请求/响应记录

这些数据不仅用于结果展示，也会参与：

- JS 中接口上下文补全
- 未授权等漏洞检测时的请求/响应复用

当前统一通过 `database.ScanDataStore` 抽象读取：

```go
type ScanDataStore interface {
	ListJSResources(taskID string, versions ...int) ([]database.JSResource, error)
	ListAPIResources(taskID string, versions ...int) ([]database.APIResource, error)
}
```

默认行为：

- 平台内运行时，默认实现仍然是 ES
- SDK 独立运行时，如果你没有显式传入 `options.DataStore`，会自动创建一个内存版 `MemoryScanDataStore`
- SDK 在浏览器抓取阶段捕获到的 API 请求/响应，会先写入这个内存存储，再继续后续分析

这意味着：

- SDK 现在不会因为没有 ES 而丢失分析所需的运行时上下文
- 如果你想把 JS 和接口记录改存到 MySQL、PostgreSQL、SQLite 或自定义存储，只需要实现这个接口

### 5.1.2 接口资产、OpenAPI 与授权对照

`PerformScan` 的每个 `TargetResult` 现在都会保留 `APIContexts`：它们来自
同一次浏览器运行时抓取，按 `method + pathTemplate` 去重合并，且已脱敏。原有的
`RequestBlueprints` 仍保留静态 JS 参数识别和补全证据。

```go
result, err := sdk.PerformScan([]string{"https://example.com"}, options)
if err != nil { panic(err) }

store := sdk.NewAPIStore()
for _, ctx := range result.Targets[0].APIContexts {
	store.Add(ctx)
}
openapiJSON, err := sdk.ExportOpenAPI(store, "Example observed API")
if err != nil { panic(err) }
```

将 `openapiJSON` 交给 Swagger UI、Redoc 或任意 OpenAPI 3.1 工具即可生成接口文档。
文档中的字段、requiredness 和示例是观测推断。

授权检测由 `options.VulnDetection.Authorization.Enabled` 控制，默认开启。它只会对
爬取期实际观察到认证证据且带认证响应为 2xx 的接口，发起去除认证材料的匿名变体，
并比较状态码、内容类型和 JSON 业务字段结构。没有低权限账号时不会猜测或尝试 IDOR。
每次结论（包括 inconclusive）写入 `TargetResult.AuthorizationChecks`，确认命中的项目
才会写入漏洞结果。

需要同时取得 JS 资源、静态请求蓝图和运行时接口时，使用 `CrawlAPIAssets`；
`CrawlAPIContexts` 为兼容接口，只返回可导出 OpenAPI 的 `APIStore`。

```go
assets, err := sdk.CrawlAPIAssets("https://example.com", &sdk.APICrawlOptions{})
if err != nil { panic(err) }
fmt.Println(len(assets.JSResources), len(assets.RequestBlueprints), len(assets.RuntimeRecords))
openapiJSON, err := sdk.ExportOpenAPI(assets.Store, "Observed API")
```

## 5. 最小调用示例

```go
package main

import (
	"fmt"
	"log"

	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

func main() {
	options := sdk.NewScanOptions()
	options.VulnDetection.Enabled = true

	result, err := sdk.PerformScan([]string{
		"https://example.com",
	}, options)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	fmt.Printf("targets=%d vulns=%d\n",
		result.Summary.TotalTargets,
		result.Summary.TotalVulnerabilities,
	)
}
```

如果你不传 `options.DataStore`，SDK 会自动使用内存存储完成一次扫描过程中的上下文复用。

### 5.1.1 平台任务标识

如果 SDK 被任务平台嵌入，建议显式设置任务 ID 和版本，使扫描引擎与 `DataStore` 使用同一组查询条件：

```go
options := sdk.NewScanOptions()
options.TaskID = taskID
options.Version = currentVersion
options.DataStore = myStore

result, err := sdk.PerformScan(targets, options)
```

未设置时，SDK 使用 `TaskID=cli-mode` 和 `Version=0`，适合 CLI 或单次本地扫描。

## 5.2 自定义 DataStore 示例

如果你的系统不使用 ES，而是使用自己的数据库，可以实现 `sdk.ScanDataStore`：

```go
package main

import (
	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

type MyStore struct{}

func (s *MyStore) ListJSResources(taskID string, versions ...int) ([]sdk.JSResource, error) {
	return nil, nil
}

func (s *MyStore) ListAPIResources(taskID string, versions ...int) ([]sdk.APIResource, error) {
	return nil, nil
}

func (s *MyStore) ListProtocolTraces(taskID string, versions ...int) ([]sdk.ProtocolTraceRecord, error) {
	return nil, nil
}

func main() {
	options := sdk.NewScanOptions()
	options.DataStore = &MyStore{}
	_, _ = sdk.PerformScan([]string{"https://example.com"}, options)
}
```

如果你希望在 SDK 外部持久化浏览器抓到的上下文，推荐做法是：

- 在 `options.OnResult` 中接收 `EventTypeAPIRecord`
- 同步写入你自己的数据库
- 让 `DataStore` 从你的数据库读回这些内容

这样可以做到任务重载后仍然复用历史分析上下文。

## 6. 最小入侵桥接示例

下面这个写法适合接入现有业务系统。你自己的业务层只需要依赖一个桥接函数，不必把 SDK 结构直接扩散到所有模块。

```go
package scanner

import (
	"log"

	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

type EventSink interface {
	OnAsset(event sdk.ScanEvent)
	OnRisk(event sdk.ScanEvent)
	OnVulnerability(event sdk.ScanEvent)
	OnAPIRecord(event sdk.ScanEvent)
}

func RunTrailblazerScan(target string, sink EventSink) (*sdk.ScanResult, error) {
	options := sdk.NewScanOptions()
	options.OpenAI.Enabled = false
	options.VulnDetection.Enabled = true
	options.OutputPath = ""

	options.OnResult = func(event sdk.ScanEvent) bool {
		switch event.Type {
		case sdk.EventTypeAsset:
			sink.OnAsset(event)
		case sdk.EventTypeVulnerability:
			sink.OnVulnerability(event)
		case sdk.EventTypeAPIRecord:
			sink.OnAPIRecord(event)
		case sdk.EventTypeError:
			log.Printf("[trailblazer] %v", event.Data)
		}
		return true
	}

	return sdk.PerformScan([]string{target}, options)
}
```

这个模式的价值：

- 改动点少，只新增一个桥接层
- 你的业务系统继续用自己的事件模型
- 后续 SDK 升级时，收敛到一个改动面
- 可以在桥接层里顺手把 API 记录持久化到你自己的存储

## 7. 从配置文件加载

### 5.1 调用方式

```go
options, err := sdk.LoadScanOptionsFromFile("config.yaml")
if err != nil {
	log.Fatalf("load config failed: %v", err)
}

result, err := sdk.PerformScan([]string{"https://example.com"}, options)
if err != nil {
	log.Fatalf("scan failed: %v", err)
}
```

### 5.2 直接输出结果文件

```go
err := sdk.PerformScanWithConfigFile(
	[]string{"https://example.com"},
	"config.yaml",
	"./result.json",
)
if err != nil {
	log.Fatalf("scan failed: %v", err)
}
```

## 8. ScanOptions 说明

`ScanOptions` 定义位置：

- [`pkg/sdk/sdk.go`](../pkg/sdk/sdk.go)

核心字段如下。

### 6.1 OpenAI

```go
type OpenAIOptions struct {
	APIKey  string
	BaseURL string
	Model   string
	Enabled bool
}
```

用途：

- AI 辅助敏感信息过滤

说明：

- `Enabled=false` 时，不调用 AI
- 若只使用扫描和抓包能力，可不配置 OpenAI

### 6.2 BlackDomain

黑名单域名列表，用于过滤无价值或不希望分析的域名，例如：

```go
options.BlackDomain = []string{
	"github.com",
	"google.com",
	"alicdn.com",
}
```

### 6.3 HighRiskRouter

高风险路由关键词列表。命中后会跳过主动漏洞测试，避免对敏感接口直接发探测请求。

示例：

```go
options.HighRiskRouter = []string{
	"delete",
	"remove",
	"disable",
	"logout",
}
```

### 6.4 Authentication

认证失败关键词列表。用于辅助判断未授权接口返回是否属于“正常业务数据”还是“登录失效/鉴权失败”。

示例：

```go
options.Authentication = []string{
	"Unauthorized",
	"token失效",
	"请登录",
}
```

### 6.5 Placeholder

占位符替换规则，用于静态路由、参数补全和未授权测试中的默认值填充。

示例：

```go
options.Placeholder = map[string]string{
	"default":   "test",
	"id":        "1",
	"name":      "test",
	"keyword":   "test",
	"timestamp": "1758791720",
}
```

规则特点：

- 对 `:id`、`{id}`、`<id>` 这类占位符会自动替换
- 静态 payload hint 构造请求体时也会复用这套规则

### 6.6 VulnDetection

```go
type VulnDetectionOptions struct {
	Enabled      bool
	SQLInjection config.SQLInjectionConfig
	LFI          config.LFIConfig
	SSRF         config.SSRFConfig
	Redirect     config.RedirectConfig
	XSS          config.XSSConfig
	Upload       config.UploadConfig
}
```

说明：

- `Enabled=false` 时，会关闭全部漏洞模块
- 即使关闭漏洞模块，资产提取和 API 记录抓取仍然会继续执行

### 6.7 OutputPath

可选字段。若设置，`PerformScan` 会把结果写入指定路径。

```go
options.OutputPath = "./scan-result.json"
```

### 6.8 LogOutput / LogOutputPath

可选字段。若设置，`PerformScan` 会在扫描期间接管 `fmt.Printf`、标准库 `log`、`stdout`、`stderr`，统一输出到外部 writer 或指定日志文件，扫描结束后自动恢复。

```go
options.LogOutput = myWriter
options.LogOutputPath = "./trailblazer.log"
```

也可以在配置文件中设置：

```yaml
log:
  output-path: "./trailblazer.log"
```

### 6.9 OnResult

回调函数，用于实时消费扫描过程中的事件。

```go
options.OnResult = func(event sdk.ScanEvent) bool {
	// 返回 true 继续
	// 返回 false 停止
	return true
}
```

### 6.10 Proxy

`ScanOptions.Proxy` 当前为预留字段。

说明：

- 字段已经存在
- 当前版本 SDK 主扫描链路尚未统一接入该字段
- 如果你对代理有强依赖，当前需要在调用环境或底层 HTTP 客户端层面自行控制

## 9. 扫描事件回调

### 7.1 事件类型

当前支持：

- `EventTypeVulnerability`
- `EventTypeAsset`
- `EventTypeAPIRecord`
- `EventTypeProgress`
- `EventTypeError`

### 7.2 ScanEvent 结构

```go
type ScanEvent struct {
	Type      ScanEventType
	Target    string
	Timestamp time.Time
	Data      interface{}
}
```

### 7.3 回调返回值

- 返回 `true`: 继续扫描
- 返回 `false`: 停止扫描

### 7.4 回调示例

```go
options.OnResult = func(event sdk.ScanEvent) bool {
	switch event.Type {
	case sdk.EventTypeProgress:
		fmt.Printf("[progress] %#v\n", event.Data)
	case sdk.EventTypeAPIRecord:
		record, ok := event.Data.(sdk.APIRecord)
		if ok {
			fmt.Printf("[api] %s %s\n", record.Method, record.URL)
		}
	case sdk.EventTypeVulnerability:
		vuln, ok := event.Data.(sdk.VulnerabilityItem)
		if ok {
			fmt.Printf("[vuln] %s %s\n", vuln.Level, vuln.URL)
		}
	}
	return true
}
```

## 10. ScanResult 结果结构

### 8.1 顶层结果

```go
type ScanResult struct {
	Targets  []TargetResult
	ScanTime string
	Summary  Summary
}
```

### 8.2 单目标结果

```go
type TargetResult struct {
	Target          string
	SiteTree        []crawl.ElTreeNode
	APIRecords      []APIRecord
	ProtocolTraces  []ProtocolTrace
	Assets          AssetInfo
	Vulnerabilities []VulnerabilityItem
}
```

### 8.3 APIRecords

`APIRecords` 表示浏览器运行时实际抓到的接口请求/响应。

典型字段：

- `URL`
- `Method`
- `RequestHeaders`
- `RequestBody`
- `ResponseHeaders`
- `ResponseBody`
- `ResponseCode`
- `TraceID`
- `HasProtocolTrace`

### 8.4 Vulnerabilities

漏洞结果中的常用复核字段：

- `TraceID`
- `HasProtocolTrace`
- `ResponseCiphertext`
- `DecryptionStatus`
- `DecryptionDetail`
- `ResponseLength`

## 11. 静态上下文增强

SDK 当前已接入静态 hint 构建，用于增强：

- 方法识别
- 请求头 hint
- 常量参数 hint
- 请求体/参数结构 hint

当前实现策略：

- JS 不长期保存在内存或数据库
- 每个 JS 先下载到临时文件
- 分析后只保留 `hint/result`
- 单文件分析完成立即删除
- 任务结束后清理临时目录

这意味着：

- 不依赖保存完整 JS 才能做上下文补全
- 但仍然保留静态上下文增强能力

## 14. 静态上下文支持范围

当前 SDK 复用的静态提取器可以识别以下类型：

- `axios.get/post/put/delete/patch`
- `axios(config)`
- `axios.create(...).get/post/...`
- `fetch(url, config)`
- `$.ajax`
- `jQuery.ajax`
- `uni.request`
- `postRequest`
- `rn({...})`
- `wrapper({ type/method, url, body/data/params })`

注意：

- 这里是“上下文增强能力”，不是“任意 JS 语义执行器”
- 对复杂对象合并、深层运行时计算、跨文件极复杂依赖，仍然可能只能部分还原

## 15. 使用建议

### 13.1 只要结果，不要实时事件

直接用：

```go
result, err := sdk.PerformScan(urls, options)
```

### 13.2 要把结果写到其他平台

建议使用 `OnResult` 回调，按事件流实时写入：

- 数据库
- 消息队列
- 风险中心
- 任务系统

### 13.3 只关心接口上下文

优先关注：

- `TargetResult.APIRecords`

### 13.4 不想做主动漏洞测试

可以关闭：

```go
options.VulnDetection.Enabled = false
```

这样仍然保留：

- 资产提取
- API 记录抓取
- 静态上下文增强

## 16. 当前限制

以下点需要接入方明确知晓：

- `Proxy` 字段当前为预留，尚未在 SDK 主链路统一生效
- SDK 依赖浏览器运行时环境，纯无头受限环境下抓取能力会下降
- 静态上下文增强不是完整 JS 解释执行器
- 极复杂跨文件上下文可能仍需后续继续增强

## 17. 示例代码位置

参考目录：

- [example/basic/main.go](/Users/qwtd/WorkManageCode/trailblazer/example/basic/main.go)
- [example/callback/main.go](/Users/qwtd/WorkManageCode/trailblazer/example/callback/main.go)
- [example/config/main.go](/Users/qwtd/WorkManageCode/trailblazer/example/config/main.go)
- [example/local-import/main.go](/Users/qwtd/WorkManageCode/trailblazer/example/local-import/main.go)

## 18. 推荐接入顺序

建议按下面顺序接入：

1. 先用 `NewScanOptions()` 跑通最小扫描
2. 再接入 `OnResult` 做事件消费
3. 再按需要开启或关闭漏洞模块

## 19. 一份完整示例

```go
package main

import (
	"fmt"
	"log"

	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

func main() {
	options := sdk.NewScanOptions()
	options.VulnDetection.Enabled = true
	options.BlackDomain = []string{"github.com", "google.com"}
	options.Placeholder = map[string]string{
		"default": "test",
		"id":      "1",
		"name":    "test",
	}

	options.OnResult = func(event sdk.ScanEvent) bool {
		switch event.Type {
		case sdk.EventTypeProgress:
			fmt.Printf("[progress] %#v\n", event.Data)
		case sdk.EventTypeAPIRecord:
			if record, ok := event.Data.(sdk.APIRecord); ok {
				fmt.Printf("[api] %s %s code=%d\n", record.Method, record.URL, record.ResponseCode)
			}
		case sdk.EventTypeVulnerability:
			if vuln, ok := event.Data.(sdk.VulnerabilityItem); ok {
				fmt.Printf("[vuln] %s %s %s\n", vuln.Level, vuln.Type, vuln.URL)
			}
		}
		return true
	}

	result, err := sdk.PerformScan([]string{
		"https://example.com",
	}, options)
	if err != nil {
		log.Fatalf("scan failed: %v", err)
	}

	fmt.Printf("scan finished: targets=%d vulns=%d\n",
		result.Summary.TotalTargets,
		result.Summary.TotalVulnerabilities,
	)
}
```

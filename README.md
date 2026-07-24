# Trailblazer

Trailblazer 是一个面向 Web 资产发现、API 探测、运行时请求/响应抓取和漏洞检测的 Go SDK，同时提供一个类似 nuclei 的命令行入口。

当前仓库只负责核心扫描能力：

- SDK：供 Go 程序嵌入调用
- CLI：供命令行或脚本直接执行扫描
- 配置解析：支持可选的 YAML 配置文件
- 事件回调：实时消费资产、接口、协议轨迹和漏洞结果
- 协议能力：协议轨迹分析和离线解密
- 存储抽象：默认使用单次扫描内存存储，也可以接入业务方自己的存储

Web API、Gin、认证、任务管理、SQLite/Elasticsearch 持久化和管理前端属于独立项目 [`trailblazer-server`](../trailblazer-server)，依赖方向为：

```text
trailblazer-server -> trailblazer
```

## 1. 环境要求

- Go 1.24 或更高版本
- 可访问目标站点的网络环境
- 可启动 Chromium/Chrome 的运行环境

Trailblazer 的浏览器运行时能力依赖 `chromedp`。如果目标站点需要执行 JavaScript、加载异步接口或分析协议轨迹，必须保证本机可以启动浏览器。

只扫描你有权测试的目标，并确保目标方允许主动探测、漏洞验证和浏览器访问。

## 2. 安装与版本

Go 程序依赖 SDK：

```bash
go get github.com/qiwentaidi/trailblazer@v0.1.0
```

如果当前还没有发布 tag，可在本地联调时使用 `replace`：

```go
require github.com/qiwentaidi/trailblazer v0.1.0

replace github.com/qiwentaidi/trailblazer => ../trailblazer
```

正式环境建议始终依赖明确的 SemVer tag，例如 `v0.1.0`，不要长期依赖 `main` 或未固定的 pseudo-version。

## 3. SDK 最小调用

SDK 不要求 `config.yaml`。最简单的方式是使用 `NewScanOptions()` 创建默认配置：

```go
package main

import (
	"fmt"
	"log"

	"github.com/qiwentaidi/trailblazer/pkg/sdk"
)

func main() {
	options := sdk.NewScanOptions()

	result, err := sdk.PerformScan([]string{
		"https://example.com",
	}, options)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("targets=%d vulnerabilities=%d\n",
		result.Summary.TotalTargets,
		result.Summary.TotalVulnerabilities,
	)
}
```

`NewScanOptions()` 的默认行为：

- 漏洞检测总开关开启
- SQL 注入、LFI、SSRF、开放重定向、XSS 和上传检测开启
- OpenAI 辅助验证关闭
- 未指定 `DataStore` 时使用单次扫描内存存储
- 不需要 Elasticsearch、Gin、Web 服务或前端

如果只想进行资产/API 抓取，可以关闭漏洞检测：

```go
options := sdk.NewScanOptions()
options.VulnDetection.Enabled = false
```

## 4. 目标输入与结果输出

`PerformScan` 接收 URL 列表：

```go
result, err := sdk.PerformScan([]string{
	"https://example.com",
	"https://demo.example.org",
}, options)
```

结果对象通常从以下字段开始消费：

```go
for _, target := range result.Targets {
	fmt.Println("target:", target.URL)
	fmt.Println("assets:", len(target.Assets))
	fmt.Println("vulnerabilities:", len(target.Vulnerabilities))
}
```

如果业务方需要实时落库、告警或展示，使用 `OnResult`，不要等扫描结束后再解析全部结果。

## 5. 实时事件回调

回调返回 `false` 可以停止后续扫描，返回 `true` 表示继续：

```go
options := sdk.NewScanOptions()
options.OnResult = func(event sdk.ScanEvent) bool {
	switch event.Type {
	case sdk.EventTypeProgress:
		fmt.Printf("progress: %#v\n", event.Data)
	case sdk.EventTypeAsset:
		fmt.Printf("asset: %#v\n", event.Data)
	case sdk.EventTypeAPIRecord:
		fmt.Printf("api record: %#v\n", event.Data)
	case sdk.EventTypeProtocolTrace:
		fmt.Printf("protocol trace: %#v\n", event.Data)
	case sdk.EventTypeVulnerability:
		fmt.Printf("vulnerability: %#v\n", event.Data)
	case sdk.EventTypeError:
		fmt.Printf("error: %#v\n", event.Data)
	}
	return true
}
```

推荐的业务接入流程：

1. 创建业务任务并生成自己的 `taskID`
2. 调用 `sdk.PerformScan`
3. 在 `OnResult` 中将事件映射到业务事件模型
4. 扫描结束后保存 `ScanResult` 摘要
5. 对漏洞事件做去重、告警和人工复核

## 6. 配置文件

配置文件是可选的。仓库提供不含敏感信息的 [`config.example.yaml`](./config.example.yaml)：

```bash
cp config.example.yaml config.yaml
```

然后可以从代码加载：

```go
options, err := sdk.LoadScanOptionsFromFile("config.yaml")
if err != nil {
	log.Fatal(err)
}

result, err := sdk.PerformScan([]string{"https://example.com"}, options)
```

或者使用封装方法：

```go
err := sdk.PerformScanWithConfigFile(
	[]string{"https://example.com"},
	"config.yaml",
	"result.json",
)
```

配置文件的安全边界：

- `config.example.yaml` 可以提交
- `config.yaml` 只在本地使用，已加入 `.gitignore`
- `openai.api_key` 不要写入 Git、日志或错误信息
- Elasticsearch 的账号密码不属于 SDK 单次扫描的必需配置
- `web`、Gin、端口和前端配置属于 `trailblazer-server`，不应放入 SDK 使用说明

注意：`LoadScanOptionsFromFile` 是“按配置文件构建选项”，不是把文件内容叠加到 `NewScanOptions()`。使用配置文件时，建议显式填写各漏洞模块的 `enabled`；未填写的模块可能保持零值关闭。需要完整默认行为时，优先使用 `NewScanOptions()`，再在代码中覆盖少量字段。

## 7. 常用配置项

代码配置适合需要精细控制的场景：

```go
options := sdk.NewScanOptions()
options.BlackDomain = []string{"example.org"}
options.HighRiskRouter = []string{"delete", "remove", "create"}
options.Authentication = []string{"Unauthorized", "token expired"}
options.Placeholder = map[string]string{
	"id":   "1",
	"name": "trailblazer",
}
options.OpenAI.Enabled = false
options.VulnDetection.Upload.Enabled = false
```

建议配置分层：

- 基础扫描：使用 `NewScanOptions()`
- 环境差异：通过代码覆盖黑名单、认证关键词和目标特有参数
- 规则调优：使用 YAML 配置文件维护漏洞模块开关和规则
- 密钥管理：使用环境变量或密钥服务，不写进 YAML 示例

## 8. 自定义 DataStore

SDK 默认使用内存存储复用单次扫描过程中捕获的 JS、API 请求/响应和协议轨迹，因此单次扫描不依赖 Elasticsearch。

如果需要跨任务保存这些上下文，可以实现 `database.ScanDataStore` 并注入：

```go
import "github.com/qiwentaidi/trailblazer/pkg/core/database"

type MyStore struct{}

func (s *MyStore) ListJSResources(taskID string, versions ...int) ([]database.JSResource, error) {
	return nil, nil
}

func (s *MyStore) ListAPIResources(taskID string, versions ...int) ([]database.APIResource, error) {
	return nil, nil
}

func (s *MyStore) ListProtocolTraces(taskID string, versions ...int) ([]database.ProtocolTraceRecord, error) {
	return nil, nil
}

options := sdk.NewScanOptions()
options.DataStore = &MyStore{}
```

真实实现中应将上述方法连接到业务数据库，并保证读取结果与扫描任务的标识规则一致。

## 9. CLI 使用

CLI 位于 [`cmd/trailblazer`](./cmd/trailblazer)，不启动 Gin，也不依赖 `trailblazer-server`：

直接运行源码：

```bash
go run ./cmd/trailblazer -u "https://example.com"
go run ./cmd/trailblazer -u "https://example.com,https://demo.example.org"
go run ./cmd/trailblazer -f urls.txt -o result.json
go run ./cmd/trailblazer -f urls.txt --config config.yaml -o result.json
```

构建并安装：

```bash
go build -o trailblazer ./cmd/trailblazer
./trailblazer -u "https://example.com"

# 发布 tag 后，也可以安装指定版本
go install github.com/qiwentaidi/trailblazer/cmd/trailblazer@v0.1.0
```

参数说明：

| 参数 | 说明 |
| --- | --- |
| `-u`, `--urls` | 逗号分隔的目标 URL |
| `-f`, `--file` | URL 文件，每行一个目标，空行和 `#` 注释会跳过 |
| `-o`, `--output` | JSON 输出文件；不指定时输出到标准输出 |
| `--config` | 可选 YAML 配置文件 |

示例 URL 文件：

```text
# authorized targets only
https://example.com
https://demo.example.org
```

## 10. 协议轨迹能力

SDK 可对扫描过程中获取的协议轨迹做离线分析：

```go
evidence := sdk.AnalyzeProtocolTrace(trace)
fmt.Println(evidence.Status, evidence.Summary)
```

如果已经获得密钥和密文，也可以调用：

```go
result, err := sdk.DecryptProtocolTrace(trace, keyHex, ciphertext)
```

密钥、密文和响应内容可能包含敏感信息，生产环境中应限制日志输出并做好访问控制。

## 11. 与 trailblazer-server 的关系

如果需要 Web 任务管理、Gin API、登录认证、数据库持久化或管理前端，请使用独立的 `trailblazer-server` 项目。

服务端项目通过 Go module 依赖核心 SDK：

```text
trailblazer-server -> github.com/qiwentaidi/trailblazer
```

服务端不应复制 SDK 的扫描实现；升级时只需要更新 SDK 的 Git tag，并在服务端执行依赖更新和回归测试。

## 12. 开发与发布

本地验证：

```bash
go test ./...
go vet ./...
go build ./cmd/trailblazer
```

发布版本：

```bash
git tag v0.1.0
git push origin v0.1.0
```

发布新版本前建议确认：

1. SDK 公共 API 没有无意变更
2. CLI 参数仍然兼容
3. `config.example.yaml` 不包含密钥、密码、真实地址或内部域名
4. `go test ./...` 和 `go vet ./...` 通过
5. `trailblazer-server` 已使用目标 tag 完成联调

更细的接口说明见 [`docs/sdk-usage.md`](./docs/sdk-usage.md)。

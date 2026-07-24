# Trailblazer SDK

Trailblazer 是面向 Web 资产发现、API 探测和漏洞检测的核心 Go SDK。它提供扫描引擎、漏洞检测器、协议分析能力以及可被上层应用消费的结果模型。

Web API、Gin、认证、任务管理、SQLite/Elasticsearch 持久化和管理前端已经迁移到独立项目 [`trailblazer-server`](../trailblazer-server)。依赖方向保持为：

```text
trailblazer-server -> trailblazer
```

## 使用

```go
import "github.com/qiwentaidi/trailblazer/pkg/sdk"

options := sdk.NewScanOptions()
result, err := sdk.PerformScan([]string{"https://example.com"}, options)
```

更完整的示例位于 [`example`](./example)，SDK 使用说明位于 [`docs/sdk-usage.md`](./docs/sdk-usage.md)。

## CLI

核心项目同时提供独立 CLI，入口位于 [`cmd/trailblazer`](./cmd/trailblazer)，不依赖 Gin 或 Web 服务：

```bash
go run ./cmd/trailblazer -u "https://example.com"
go run ./cmd/trailblazer -f urls.txt -o result.json
go build -o trailblazer ./cmd/trailblazer
```

## 开发

```bash
go test ./...
go vet ./...
```

当前 module path 为：

```text
github.com/qiwentaidi/trailblazer
```

发布版本时使用 Go module 兼容的 SemVer tag，例如：

```bash
git tag v0.1.0
git push origin v0.1.0
```

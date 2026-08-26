# Trailblazer SDK 使用示例

本目录包含了 Trailblazer SDK 的各种使用示例。

## 目录结构

```
example/
├── README.md          # 本文件
├── basic/             # 基本使用示例
│   └── main.go
├── callback/          # 回调函数示例（类似nuclei）
│   └── main.go
└── config/            # 从配置文件加载示例
    └── main.go
```

## 运行示例

### 前置要求

1. 确保已安装 Go 1.24.0 或更高版本
2. 确保项目已正确编译（`go mod tidy` 和 `go build`）

### 基本使用示例

```bash
cd example/basic
go run main.go
```

这个示例展示了：
- 如何创建扫描选项
- 如何配置各种选项（OpenAI、黑名单、高风险路由等）
- 如何使用默认内存 `DataStore` 复用运行时上下文
- 如何执行扫描并获取结果
- 如何处理和显示扫描结果

### 回调函数示例

```bash
cd example/callback
go run main.go
```

这个示例展示了：
- 如何使用回调函数实时获取扫描结果（类似nuclei）
- 如何处理不同类型的事件（漏洞、资产、风险、进度、错误）
- 如何根据回调结果控制扫描流程
- 如何实现自定义的处理逻辑
- 如何把接口请求/响应和协议轨迹写回你自己的数据库

### 配置文件示例

```bash
cd example/config
go run main.go
```

这个示例展示了：
- 如何从配置文件加载扫描选项
- 如何在加载配置后修改选项
- 如何结合配置文件和回调函数使用

## 使用场景

### 1. 基本扫描

适用于简单的扫描需求，只需要最终结果：

```go
options := sdk.NewScanOptions()
result, err := sdk.PerformScan([]string{"https://example.com"}, options)
```

### 2. 实时回调

适用于需要实时处理结果的场景，比如：
- 实时显示扫描进度
- 发现漏洞立即通知
- 实时写入数据库
- 发送到消息队列

```go
options.OnResult = func(event sdk.ScanEvent) bool {
    // 处理事件
    return true // 继续扫描
}
```

### 3. 配置文件

适用于需要统一管理配置的场景：

```go
options, err := sdk.LoadScanOptionsFromFile("config.yaml")
```

### 4. 自定义存储

适用于你不希望依赖 ES，而要把上下文存到自己的数据库：

```go
options := sdk.NewScanOptions()
options.DataStore = myStore
```

这里的 `myStore` 需要实现：

- `ListJSResources`
- `ListAPIResources`
- `ListProtocolTraces`

如果你不传 `DataStore`，SDK 会自动创建内存版存储，并在单次扫描过程中复用浏览器抓到的 API 请求/响应与协议轨迹。

## 事件类型

SDK 支持以下事件类型：

- `EventTypeVulnerability`: 漏洞发现
  - 数据: `VulnerabilityItem`
  
- `EventTypeAsset`: 资产发现
  - 数据: `map[string]interface{}` (包含 type, value, source)

- `EventTypeAPIRecord`: 接口请求/响应记录
  - 数据: `APIRecord`

- `EventTypeProtocolTrace`: 协议轨迹
  - 数据: `ProtocolTrace`
  
- `EventTypeProgress`: 进度更新
  - 数据: `map[string]interface{}` (包含 status, current, total 等)
  
- `EventTypeError`: 错误信息
  - 数据: `map[string]interface{}` (包含 error, url)

## 回调函数返回值

- `true`: 继续扫描
- `false`: 停止扫描

## 注意事项

1. **OpenAI配置**: 如果启用AI检测，需要配置有效的API密钥
2. **并发安全**: 如果回调函数中需要访问共享数据，请使用互斥锁保护
3. **性能考虑**: 回调函数应该快速执行，避免阻塞扫描流程
4. **错误处理**: 建议在回调函数中添加错误处理逻辑
5. **上下文复用**: 漏洞分析和静态协议分析会读取 `DataStore` 中的 JS/API/协议轨迹；如果你要跨任务重载结果，建议把这些事件持久化
6. **本地存储**: SDK 默认内存存储适合单次扫描；Web 管理端使用 SQLite，自定义 `DataStore` 适合平台化接入

## 更多信息

更多详细信息请参考：

- SDK 入口: [`pkg/sdk/sdk.go`](../pkg/sdk/sdk.go)
- SDK 文档: [`docs/sdk-usage.md`](../docs/sdk-usage.md)
- Web 管理端: [`docs/web.md`](../docs/web.md)

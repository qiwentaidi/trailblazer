# Trailblazer

Trailblazer 是一个面向 Web 资产发现、API 探测、运行时请求/响应抓取和漏洞检测的 Go SDK，同时提供一个类似 nuclei 的命令行入口。

当前仓库包含核心扫描能力和 Web 管理端：

- SDK：供 Go 程序嵌入调用
- CLI：供命令行或脚本直接执行扫描
- 配置解析：支持可选的 YAML 配置文件
- 事件回调：实时消费资产、接口、协议轨迹和漏洞结果
- 协议能力：协议轨迹分析和离线解密
- 存储抽象：默认使用单次扫描内存存储，也可以接入业务方自己的存储
- Web 管理端：HTTP API、认证、SQLite 持久化和管理前端

## 1. 环境要求

- Go 1.24 或更高版本
- 可访问目标站点的网络环境
- 可启动 Chromium/Chrome 的运行环境

Trailblazer 的浏览器运行时能力依赖 `chromedp`。如果目标站点需要执行 JavaScript、加载异步接口或分析协议轨迹，必须保证本机可以启动浏览器。

只扫描你有权测试的目标，并确保目标方允许主动探测、漏洞验证和浏览器访问。

## 2. 安装与版本

Go 程序依赖 SDK：

```bash
go get github.com/qiwentaidi/trailblazer@lastest
```

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

### 平台嵌入：自定义 TaskID 和 Version

如果 SDK 被任务平台、Web 服务或 worker 嵌入，建议传入业务侧的任务标识：

```go
options := sdk.NewScanOptions()
options.TaskID = taskID
options.Version = currentVersion
options.DataStore = myStore

result, err := sdk.PerformScan(targets, options)
```

SDK 会使用这两个值：

- 传给扫描引擎，关联 JS、API 和协议轨迹
- 作为 `DataStore` 查询条件
- 写入 `ScanResult.TaskID` 和 `ScanResult.Version`
- 在未设置时回退到 `TaskID=cli-mode`、`Version=0`

`Version` 小于等于 0 表示不限定版本，适合 CLI；平台任务建议传入正数版本。

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

## 5. JS Request Blueprint 参数识别能力图谱

`RequestBlueprints` 用于描述“JS 中如何构造请求”，不直接产出漏洞。它适合在 SDK 输出后做二次分析、覆盖率对比、AI 发散推理和后续未授权检测前的参数补全。

```go
result, err := sdk.PerformScan(targets, options)
for _, target := range result.Targets {
	fmt.Println(target.RequestBlueprintCount)
	for _, blueprint := range target.RequestBlueprints {
		fmt.Println(blueprint.Method, blueprint.Path, blueprint.Params)
	}
}
```

也可以只对已保存的 JS 内容做离线提取：

```go
blueprints := sdk.BuildJSRequestBlueprints(jsResources)
```

### 5.1 能力总览

```mermaid
mindmap
  root((JS Request Blueprint))
    请求入口
      axios.get/post/put/delete/patch
      axios(config)
      axios.create 实例
      webpack axios default
      fetch
      $.ajax 和 jQuery.ajax
      uni.request
      postRequest
      Object(wrapper)({url,type,body})
      通用 get/post/put/delete/patch 封装
    参数来源
      path
        "/user/:id"
        动态模板占位 "/role/{id}"
      query
        URL query string
        params 对象
        GET/DELETE 的 body-like 字段
      json/body
        直接对象字面量
        JSON.stringify(object)
        data/body 字段
        嵌套对象字段
      form
        $("#form").serialize()
        jQuery("#form").serializeArray()
      变量形态
        函数形参
        本地对象变量
        变量属性赋值
        封装函数调用点实参
        同文件和跨文件常量
    输出标记
      location
      source
      valueExpr
      value
      resolved/resolvedFrom
      confidence
      unresolvedSymbols
```

纯文本版本，方便不支持 Mermaid 的环境查看和维护：

```text
JS Request Blueprint
├─ 请求入口
│  ├─ axios 方法调用：axios.get/post/put/delete/patch(url, data/config)
│  ├─ axios 配置调用：axios({ url, method, params, data, body, headers })
│  ├─ axios.create 实例：client.post(...)，并关联 baseURL、headers、interceptors
│  ├─ webpack axios default：axios__WEBPACK_IMPORTED_MODULE__["default"].get/post(...)
│  ├─ fetch：fetch(url, { method, headers, body, params })
│  ├─ jQuery：$.ajax({ url, type/method, data, headers }) / jQuery.ajax(...)
│  ├─ 小程序/封装：uni.request、postRequest、rn
│  ├─ Object 包装封装：Object(f.d)({ url, type, body, params })
│  └─ 通用方法封装：api.get/post/put/delete/patch/silentGet/upload/download(...)
├─ 参数来源
│  ├─ path：/user/:id、/role/{id}
│  ├─ query：URL 查询串、config.params、GET/DELETE 中按查询参数处理的字段
│  ├─ body/json：data/body 对象、JSON.stringify({...})、嵌套对象字段
│  ├─ form：$("#login-form").serialize() / serializeArray() 展开 input/select/textarea name
│  ├─ 本地变量：const params = {...}; axios.get(url, { params })
│  ├─ 属性赋值：requestData.id = id; requestData.name = name
│  ├─ 调用点实参：function add(e){post(url,e)}; add({ domains:e })
│  └─ 常量解析：同文件/跨文件静态字符串、模板字符串、concat、webpack export 常量
├─ 输出字段
│  ├─ location：path/query/json/body/unknown
│  ├─ source：path/query/body/body.nested/body.form/variable/callsite-body
│  ├─ valueExpr：原始表达式，例如 s、form.name、[]、`test`
│  ├─ value：能静态解析出的字面值
│  ├─ resolved/resolvedFrom：是否已解析及来源
│  ├─ confidence：high/medium
│  └─ unresolvedSymbols：仍需运行时或 AI 补全的符号
└─ 当前边界
   ├─ 复杂运行时计算、闭包状态、异步赋值不保证能静态还原
   ├─ 跨文件解析会受 JS 数量、bundle 体积和静态窗口限制影响
   ├─ serialize 目前主要支持 #id form 选择器
   └─ valueExpr 会保留不清晰形参，后续请求构造阶段可再结合占位符或运行时样本替换
```

### 5.2 当前可捕获的参数形式

| 类型 | 示例 | 输出位置 | 说明 |
| --- | --- | --- | --- |
| Path 参数 | `/user/:id`、`` `/role/${id}` `` | `path` | 静态 `:id` 会直接作为参数；动态模板会保留为 `{id}` 并进入 `unresolvedSymbols` |
| URL Query | `/list?page=1&size=20` | `query` | 从 URL 查询串提取参数名 |
| Axios params | `axios.get("/list", { params: { page, size } })` | `query` | 支持直接对象、变量对象和本地变量回溯 |
| Axios body | `axios.post("/add", { name, roleId })` | `json` 或 `body` | 结合 payload 格式判断，JSON 场景标记为 `json` |
| Axios config | `axios({ url, method:"post", data:{ id } })` | `json/body/query` | 从 `url/method/type/params/data/body` 中提取 |
| Fetch body | `fetch("/add", { method:"POST", body: JSON.stringify({ id }) })` | `json` | 可识别 `JSON.stringify` 内对象字段 |
| jQuery ajax | `$.ajax({ url, type:"POST", data:{ id } })` | `body/json/query` | 支持 `type`/`method`、`data`、`body`、`params` |
| 表单序列化 | `$("#login-form").serialize()` | `body` | 从同一 HTML/JS 内容中按 form `id` 展开 `input/select/textarea` 的 `name` |
| 本地对象变量 | `const data = { id }; api.post("/add", data)` | `json/body/query` | 会在调用点前一定窗口内回溯变量赋值 |
| 属性追加 | `data.id = id; data.name = name` | `json/body/query` | 可识别对象变量的简单属性赋值 |
| 封装函数实参 | `function add(e){return post("/add", e)}; add({ domains:e })` | `callsite-body` | 用调用点对象字段替换 `e` 这种压缩形参 |
| 嵌套对象 | `{ user: { id, name } }` | `body.nested` | 会提取顶层和一层嵌套字段 |
| 常量值 | `{ appName: "test", status: [] }` | `json/body/query` | `value` 保存可解析字面值，`valueExpr` 保存原表达式 |
| 请求头上下文 | `headers: { "X-Token": token }`、interceptor | `headers` | 参数以外的信息，用于判断鉴权上下文和后续构造请求 |

### 5.3 输出字段约定

每个参数会尽量同时保留“名字、位置、原始表达式和解析状态”：

```json
{
  "name": "domains",
  "location": "json",
  "source": "callsite-body",
  "valueExpr": "e",
  "resolved": true,
  "resolvedFrom": "callsite-object-field:e",
  "confidence": "high"
}
```

字段含义：

| 字段 | 含义 |
| --- | --- |
| `name` | 参数名 |
| `location` | 请求位置：`path`、`query`、`json`、`body`、`unknown` |
| `source` | 参数来源：`path`、`query`、`body`、`body.nested`、`body.form`、`variable`、`callsite-body` 等 |
| `valueExpr` | JS 中捕获到的原始表达式，形参、变量和压缩变量名会保留在这里 |
| `value` | 已静态解析出的字面值，例如 `"test"`、`[]`、`true`、`1` |
| `resolved` | 当前是否已有可解释来源 |
| `resolvedFrom` | 解析来源，例如 `literal`、`function-parameter`、`symbol:constant`、`local-variable:data`、`dom-form:#login-form` |
| `confidence` | 参数识别置信度；明确对象字段通常为 `high`，仅变量承载通常为 `medium` |

### 5.4 维护规则

后续新增参数识别能力时，建议同步更新三处：

1. 在本节“能力总览”和“当前可捕获的参数形式”中追加新分支。
2. 在 [`pkg/core/crawl/request_blueprint_test.go`](./pkg/core/crawl/request_blueprint_test.go) 增加最小样例，固定输出数量和参数字段。
3. 如果新增了 `source` 或 `location`，同步补充“输出字段约定”，避免 SDK 下游出现歧义。

## 6. 实时事件回调

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

## 7. 配置文件

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
- Web 服务使用 SQLite，不需要额外的搜索服务账号

注意：`LoadScanOptionsFromFile` 是“按配置文件构建选项”，不是把文件内容叠加到 `NewScanOptions()`。使用配置文件时，建议显式填写各漏洞模块的 `enabled`；未填写的模块可能保持零值关闭。需要完整默认行为时，优先使用 `NewScanOptions()`，再在代码中覆盖少量字段。

## 8. 常用配置项

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

## 9. 自定义 DataStore

SDK 默认使用内存存储复用单次扫描过程中捕获的 JS、API 请求/响应和协议轨迹，因此单次扫描不依赖 Elasticsearch。

如果需要跨任务保存这些上下文，可以实现 `sdk.ScanDataStore` 并注入：

```go
import "github.com/qiwentaidi/trailblazer/pkg/sdk"

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

options := sdk.NewScanOptions()
options.DataStore = &MyStore{}
```

真实实现中应将上述方法连接到业务数据库，并保证读取结果与扫描任务的标识规则一致。

## 10. CLI 使用

CLI 位于 [`cmd/trailblazer`](./cmd/trailblazer)，同时提供扫描和 Web 服务子命令：

直接运行源码：

```bash
go run ./cmd/trailblazer -u "https://example.com"
go run ./cmd/trailblazer -u "https://example.com,https://demo.example.org"
go run ./cmd/trailblazer -f urls.txt -o result.json
go run ./cmd/trailblazer -f urls.txt --config config.yaml -o result.json
```

启动 Web 管理端：

```bash
go run ./cmd/trailblazer web --config config.yaml
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

## 11. 协议轨迹能力

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

更细的接口说明见 [`docs/sdk-usage.md`](./docs/sdk-usage.md)。

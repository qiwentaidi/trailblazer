# 协议轨迹中的明文响应是如何抓取到的

本文说明 Trailblazer 后端是如何拿到协议轨迹里的响应明文，以及为什么有时候能看到原始响应包、有时候能看到解密后的明文。

## 目标

协议轨迹希望尽量同时保留两类信息：

- 原始响应包：浏览器真正收到的响应体，通常是密文、Base64、十六进制串或压缩后的文本
- 响应明文：运行时经过页面自身逻辑处理后，能够被业务代码消费的明文结果

对于类似下面这种接口：

```json
{
  "response_steps": [
    {
      "source": "JSON.stringify",
      "algorithm": "json.stringify",
      "input_preview": "{\"code\":\"err.common.system.error\",\"msg\":\"系统错误\",\"success\":false}",
      "output_preview": "{\"code\":\"err.common.system.error\",\"msg\":\"系统错误\",\"success\":false}"
    }
  ]
}
```

我们希望最终输出里能稳定得到：

- `session_materials.latest_response_ciphertext`：原始响应包
- `session_materials.latest_response_plaintext`：更可信的明文响应

## 整体链路

明文响应的来源不是单一阶段，而是三层协同：

1. 浏览器运行时协议钩子采集
2. chromedp 网络层抓包补充
3. 出库前归一化与质量选择

### 1. 浏览器运行时协议钩子

核心入口在：

- [backend/pkg/core/crawl/protocol_hooks.go](backend/pkg/core/crawl/protocol_hooks.go)

后端会在页面加载前，通过 `page.AddScriptToEvaluateOnNewDocument` 注入协议钩子脚本。这个脚本会包装和监听常见的前端处理路径，例如：

- `JSON.parse`
- `JSON.stringify`
- `TextDecoder.decode`
- `window.atob` / `window.btoa`
- `fetch`
- `XMLHttpRequest`
- `SubtleCrypto.decrypt`

一旦这些调用发生，脚本会记录成 `response_steps`，每一步包含：

- `source`
- `algorithm`
- `input_preview`
- `output_preview`
- `stack`
- `captured_at_ms`

对应的 Go 结构体在：

- [backend/pkg/core/crawl/protocol_hooks.go](backend/pkg/core/crawl/protocol_hooks.go)

这一步的价值是：即使浏览器网络层只拿到了密文，页面在 JS 里自己完成了解码、解密、JSON 解析，我们依然能从运行时调用链中看到“明文是怎么出来的”。

### 2. session_materials 的实时写入

协议钩子不仅记录步骤，还会尝试把关键材料写进 `session_materials`，例如：

- `latest_response_ciphertext`
- `latest_response_plaintext`
- `crypto_key_base64`
- `crypto_iv_base64`

其中响应明文相关逻辑的核心点是：

- 对运行时可读文本进行预览和判定
- 对多个候选明文做质量比较，避免更完整的明文被后续的 `{}` 之类占位结果覆盖

这部分逻辑也在：

- [backend/pkg/core/crawl/protocol_hooks.go](backend/pkg/core/crawl/protocol_hooks.go)

目前对于 `latest_response_plaintext`，后写入不会无条件覆盖前一个值，而是会比较候选质量：

- 更长、更像 JSON、更包含业务字段的值优先
- `{}`、`[]`、`null` 这类占位结果优先级更低

这就是为什么首个 `response_steps` 里已经拿到业务错误 JSON 时，后面的 `{}` 不应该再把它冲掉。

### 3. chromedp 网络层抓原始响应包

核心入口在：

- [backend/pkg/core/crawl/handless.go](backend/pkg/core/crawl/handless.go)

Trailblazer 还会通过 Chrome DevTools Protocol 监听：

- `network.EventRequestWillBeSent`
- `network.EventResponseReceived`
- `network.EventLoadingFinished`

在 `LoadingFinished` 后调用：

- `network.GetRequestPostData`
- `network.GetResponseBody`

抓到的内容会先落到 `apiRecords`：

- `RequestBody`
- `ResponseBody`
- `MIMEType`
- `ResponseCode`

这一层的主要目标不是直接拿明文，而是尽量保留浏览器收到的原始请求包和原始响应包。

因此：

- 如果响应是 JSON/文本，`ResponseBody` 通常就是文本
- 如果响应是二进制，`ResponseBody` 会转成 Base64 存储
- 如果响应其实是带引号的十六进制密文，后端会尽量识别它是“编码后的 payload”，而不是误判成普通明文

### 4. 网络层结果回填协议轨迹

浏览器网络层抓到响应体后，还要把它补到协议轨迹里：

- [backend/pkg/core/crawl/handless.go](backend/pkg/core/crawl/handless.go)

对应方法：

- `backfillProtocolTraceResponsesFromAPIRecords`

现在的规则是：

- 缺原始响应包，就补 `latest_response_ciphertext`
- 缺响应明文，就补 `latest_response_plaintext`
- 不会因为已经有一个字段就放弃补另一个字段

这解决了一个常见问题：

- 运行时步骤已经拿到了明文
- chromedp 又拿到了原始响应包
- 两者应该同时保留，而不是二选一

### 5. 出库前的归一化

协议轨迹在查询返回前，还会做一次视图归一化：

- [backend/pkg/core/database/models.go](backend/pkg/core/database/models.go)

核心方法：

- `NormalizeForView`

这里会做几件事：

- 清理明显不可读的伪明文
- 压缩无意义步骤
- 从 `response_steps` 中再挑一遍更高质量的明文候选
- 把更可信的值写回 `session_materials.latest_response_plaintext`

也就是说，最终前端看到的“响应解密结果”，理论上应该直接信任后端给出的 `latest_response_plaintext`，而不是前端再自己推理一次。

## 为什么明文响应有时来自 response_steps，而不是网络层

因为这两者抓到的是不同阶段的数据。

### 网络层抓到的是“收到的内容”

例如：

- 十六进制密文
- Base64 密文
- 压缩后的字节流

### response_steps 抓到的是“页面处理后的内容”

例如页面会执行：

1. `window.atob`
2. `TextDecoder.decode`
3. `crypto.decrypt`
4. `JSON.parse`
5. `JSON.stringify`

那么真正的业务明文，往往要到第 3、4、5 步之后才出现。

所以“明文响应是如何抓取到的”这个问题的准确答案是：

- 原始响应包主要来自 chromedp 网络抓包
- 响应明文主要来自运行时协议钩子记录的 `response_steps` 和 `session_materials`
- 最终由后端归一化层做一次质量选择

## 当前明文字段的优先级

后端现在的设计原则是：

1. 优先保留更高质量的 `latest_response_plaintext`
2. 如果 `response_steps` 中有更完整的可读明文，允许覆盖低质量占位值
3. 原始响应包和响应明文同时保留，不互相覆盖

## 常见抓不到明文的场景

如果最终还是没有 `latest_response_plaintext`，通常是以下几类原因：

### 1. 页面没有在 JS 层真正完成解密

例如：

- 解密在原生容器中完成
- 结果直接传入闭源 SDK / wasm / worker，外层拿不到文本

### 2. 响应被处理成不可逆的中间结构

例如：

- TypedArray 只短暂存在
- 后续没有可读文本输出

### 3. chromedp 网络层拿 body 失败

目前后端已经加了诊断日志，可定位：

- `GetResponseBody` 失败
- 响应完成但 body 为空
- API 记录没有匹配到协议轨迹
- 响应回填没有成功

对应逻辑在：

- [backend/pkg/core/crawl/handless.go](backend/pkg/core/crawl/handless.go)

## 关键字段说明

### `response_steps`

表示响应处理链路中的每一步。

常见来源：

- `JSON.parse`
- `JSON.stringify`
- `window.atob`
- `TextDecoder.decode`
- `webcrypto.decrypt`

### `session_materials.latest_response_ciphertext`

表示更接近浏览器收到的原始响应包。

常见形式：

- 引号包裹的十六进制字符串
- Base64 字符串
- 二进制转 Base64

### `session_materials.latest_response_plaintext`

表示当前后端认为最可信的响应明文。

它可能来自：

- 运行时钩子直接捕获
- 网络层抓到的纯文本响应
- `response_steps` 中更高质量的输出，经 `NormalizeForView` 选出

## 推荐排障顺序

如果页面上“原始响应包”或“响应解密结果”不对，建议按这个顺序查：

1. 看 `apiRecords.ResponseBody` 是否抓到原始响应
2. 看 `response_steps` 是否已经出现可读明文
3. 看 `session_materials.latest_response_plaintext` 是否被低质量值覆盖
4. 看后端 WARN 日志属于哪一类

## 相关代码位置

- 网络采集入口：[backend/pkg/core/crawl/handless.go](backend/pkg/core/crawl/handless.go)
- 协议钩子脚本：[backend/pkg/core/crawl/protocol_hooks.go](backend/pkg/core/crawl/protocol_hooks.go)
- 出库归一化：[backend/pkg/core/database/models.go](backend/pkg/core/database/models.go)
- 协议轨迹查询：[backend/pkg/core/database/query.go](backend/pkg/core/database/query.go)
- SDK 输出结构：[backend/pkg/lib/sdk.go](backend/pkg/lib/sdk.go)

## 一句话总结

Trailblazer 里的“明文响应”不是单靠 chromedp 抓包得到的，而是：

- 用 chromedp 保住原始响应包
- 用运行时协议钩子跟踪页面自己的解码/解密/解析过程
- 再由后端归一化逻辑选出最可信的明文结果

这样既能保留原始证据，也能尽量还原业务真正消费的响应内容。

## 基于钩子的二次解密能力

可以，而且当前仓库已经具备一半基础能力。

如果后续对某个接口做未授权访问测试，只拼了接口路由或只带了部分参数，服务端仍然返回一段密文响应，那么可以尝试利用历史协议轨迹中的材料，对这段密文做二次解密。

这类能力可以分成两种模式：

1. 离线二次解密
2. 在线 runtime 解密

### 模式一：离线二次解密

适用于：

- 正常业务流量里已经抓到过同类接口的协议轨迹
- 轨迹里已经有足够的解密材料，例如：
  - `latest_response_ciphertext`
  - `latest_response_plaintext`
  - `sm4_key_hex`
  - `crypto_key_base64`
  - `crypto_iv_base64`
  - `crypto_aad_base64`
- 未授权测试接口返回的密文格式，与正常业务流量中的密文格式一致或兼容

当前项目里已经有现成入口：

- 解密核心：[backend/pkg/core/protocoltool/tool.go](backend/pkg/core/protocoltool/tool.go)
- Web 接口：[backend/pkg/web/protocol_tools.go](backend/pkg/web/protocol_tools.go)

现有接口：

- `POST /api/task/:taskId/protocol-tools/decrypt`

它会读取：

- `traceId`
- `ciphertext`
- `keyHex`

然后走 `DecryptWithTrace`，优先使用 trace 里已有的：

- 明文缓存
- 对称密钥材料
- IV/AAD
- 已识别算法
- 前端 runtime 留下的上下文

换句话说，今天就已经可以做这种事情：

1. 正常浏览页面，抓一条协议轨迹
2. 记住该轨迹的 `traceId`
3. 对同接口做未授权访问测试，拿到一段密文响应
4. 调用解密工具接口，把这段密文和 `traceId` 传进去
5. 尝试还原明文

### 模式二：在线 runtime 解密

离线模式并不能覆盖所有站点。

有些站点虽然能抓到 `response_steps`，但解密并不是单纯依赖固定 key/iv，而是依赖：

- 当前页面 JS 上下文
- 闭包变量
- worker / wasm 内部状态
- 登录态、cookie、token
- 一次性 nonce、timestamp、签名链路

这种情况下，适合做“类 JSRPC”的在线 runtime 解密。

本质思路是：

1. 保持一个带协议钩子的浏览器上下文活着
2. 把未授权测试返回的密文重新喂给页面自己的解密逻辑
3. 在页面里拿到明文结果
4. 回传给后端

当前代码里已经预留了这类设计方向：

- [backend/pkg/core/protocoltool/tool.go](backend/pkg/core/protocoltool/tool.go)

其中：

- `decryptStoredBrowserRuntime`
- `decryptStoredFrontendRuntime`

说明架构上已经考虑过“不是只用静态密钥，而是尝试依赖存储的前端 runtime 环境去解密”。

## 推荐能力拆分

建议不要一开始就做成完整 JSRPC，而是分两层建设。

### 第一层：未授权结果复用历史 trace 做离线解密

这是最容易落地的版本。

#### 后端数据流

1. 扫描阶段抓到 `APIRecord`
2. `APIRecord` 通过 `TraceID` 和 `HasProtocolTrace` 关联到协议轨迹
3. 未授权访问结果新增“关联 trace”能力
4. 若响应内容疑似密文，允许用户选择一条候选 `traceId`
5. 后端调用 `decryptProtocolPayload`
6. 返回解密结果和采用的材料来源

#### 建议新增字段

如果要把这套能力真正接到漏洞流里，建议给漏洞或未授权测试结果增加这些字段：

```json
{
  "traceId": "trace-xxx",
  "hasProtocolTrace": true,
  "responseCiphertext": "...",
  "decryptionStatus": "not_tried|succeeded|failed",
  "decryptionDetail": "..."
}
```

其中最重要的是：

- `traceId`
- `hasProtocolTrace`
- `responseCiphertext`

#### 候选 trace 的推荐策略

如果当前漏洞结果没有直接挂上 trace，可按以下顺序匹配候选轨迹：

1. 同 `method + url`
2. 同域名、同路由模板
3. 同一任务内最近一次正常业务轨迹
4. 同算法指纹、同响应密文形态

### 第二层：在线 runtime 解密服务

这层才是真正更像 JSRPC 的能力。

#### 目标

即使当前密文无法通过固定 key/iv 离线解开，也能借助仍然存活的前端 JS 上下文再次解密。

#### 推荐接口

建议新增一个 runtime 工具接口，例如：

```http
POST /api/task/:taskId/protocol-tools/runtime-decrypt
```

请求体建议：

```json
{
  "traceId": "trace-xxx",
  "ciphertext": "...",
  "pageUrl": "https://target/page",
  "requestUrl": "https://target/api/xxx",
  "mode": "auto"
}
```

返回值建议：

```json
{
  "data": {
    "traceId": "trace-xxx",
    "ciphertext": "...",
    "plaintext": "...",
    "mode": "runtime",
    "source": "browser-context",
    "functionHint": "window.xxx.decrypt"
  }
}
```

#### 后端运行方式

建议新增一个“浏览器上下文池”，每个任务最多保留少量可复用上下文：

1. 扫描时建立上下文
2. 将 `taskId -> browser session` 建立映射
3. 保存页面 URL、域名、cookie、localStorage、可能的解密入口线索
4. 当收到 runtime 解密请求时，把密文注入到该上下文执行

#### runtime 解密的三种尝试顺序

建议按以下顺序尝试：

1. 直接使用已知算法材料离线解密
2. 调用页面已识别的解密链路入口
3. 重放捕获到的 response processing path

第三种的意思不是机械回放所有步骤，而是依据 `response_steps` 中出现的关键处理节点，尝试找到对应函数入口。

## 这个能力能解决什么，不能解决什么

### 能解决的

- 未授权访问接口返回密文，看不懂具体业务错误或数据结构
- 正常流量里已经抓到解密材料，希望复用到主动测试结果
- 页面本身能解密，但主动扫描阶段只看到了密文结果

### 不能直接解决的

- 请求本身缺必要参数，服务端只返回通用错误密文
- 参数签名链路不成立，解出来也只是“验签失败”
- key/iv 与当前请求强绑定，历史轨迹材料无法复用
- 解密必须依赖外部原生容器、插件、私有 worker 状态

也就是说，二次解密能力解决的是“密文看不懂”，不是“请求一定能变成正常业务请求”。

## 对未授权访问模块的建议接入点

如果后续要真正接到未授权访问测试流程，建议按下面顺序接：

### 第一步：让未授权结果带上 trace 关联

当前 API 记录本身已经有：

- `traceId`
- `hasProtocolTrace`

位置在：

- [backend/pkg/lib/sdk.go](backend/pkg/lib/sdk.go)

建议未授权访问结果直接沿用这套关联字段，避免后面再做二次模糊匹配。

### 第二步：给未授权结果增加“尝试解密”动作

建议前端交互是：

1. 发现响应疑似密文
2. 如果已有 `traceId`，直接显示“尝试二次解密”按钮
3. 点击后调用协议工具解密接口
4. 若失败，再提示是否尝试 runtime 解密

### 第三步：保存解密结果，避免重复计算

建议将主动测试产生的二次解密结果也落库，至少保留：

- 原始密文
- 解密后的明文
- 关联 traceId
- 解密模式（offline/runtime）
- 解密失败原因

## 最小可行方案

如果只追求最短路径上线，建议先做下面这版：

1. 未授权访问结果挂 `traceId`
2. 直接复用已有 `decryptProtocolPayload`
3. 仅支持离线二次解密
4. 失败时展示“缺少 key/iv/runtime 材料”的明确原因

这版已经能覆盖很多：

- SM4
- AES-CBC
- AES-GCM
- 已在 trace 中抓到明文缓存的响应

等这版跑通后，再决定是否继续上在线 runtime 解密。

## 一句话建议

你完全可以利用现在的钩子体系去做“类似 JSRPC 的二次解密能力”，但建议分阶段建设：

- 第一阶段先做“基于历史 trace 的离线二次解密”
- 第二阶段再做“保活浏览器上下文的在线 runtime 解密”

前者已经有基础设施，后者则是下一步的体系化增强。
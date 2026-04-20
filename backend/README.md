# Trailblazer - 探路者

一款功能强大的 Web 安全测试平台，专注于前端资产发现与 API 漏洞检测。集成 AI 智能分析，自动检测敏感信息泄露、SQL注入、未授权访问等常见安全问题。

## ✨ 核心功能

### 🎯 智能资产发现
- **动态网络捕获**：基于 Chrome 无头浏览器，自动捕获页面加载时的所有网络请求
- **智能资源分类**：自动识别并分类 API 接口、JS 文件、静态资源等
- **网站结构树**：可视化展示网站目录结构，类似 Burp Suite 的站点地图
- **SourceMap 泄露检测**：自动检测并恢复 Webpack SourceMap，还原前端源码
- **API 根路径提取**：智能提取 API 根路径，便于后续漏洞测试

### 🔐 敏感信息检测
- **多维信息提取**：检测手机号、身份证、邮箱、IP 地址、API 密钥等敏感信息
- **AI 智能过滤**：集成大语言模型，自动过滤变量名、占位符、测试数据等误报
- **准确率提升**：通过 AI 二次确认，显著降低误报率
- **多模型支持**：兼容 OpenAI、DeepSeek、通义千问等主流 AI 服务商

### 🛡️ 漏洞检测能力
- **SQL 注入检测**：支持 Error-based、Time-based、Boolean-based、Union-based 等多种注入类型
- **未授权访问检测**：智能识别接口鉴权缺失，支持页面相似度分析、关键词匹配等多种判断策略
- **LFI 漏洞检测**：检测本地文件包含漏洞，支持多平台 payload
- **SSRF 漏洞检测**：检测服务端请求伪造漏洞
- **重定向漏洞检测**：检测开放重定向漏洞

### 📊 可视化平台
- **任务管理**：创建、执行、暂停、删除扫描任务，支持批量导入
- **实时监控**：实时显示扫描进度、发现的资产数量、风险数量等关键指标
- **资产展示**：树形结构展示网站资源，支持节点展开/折叠
- **风险分析**：按高危/中危/低危分类展示漏洞，支持查看详细响应内容
- **数据检索**：支持正则表达式搜索 JS 内容，高亮显示匹配结果
- **配置中心**：可视化配置数据库连接、AI 服务、安全策略等

### ⚙️ 企业级功能
- **任务持久化**：基于 SQLite 本地存储，基于 Elasticsearch 云端存储
- **智能去重**：自动去重已测试的接口，避免重复扫描
- **黑名单管理**：自定义域名黑名单，过滤不需要扫描的域名
- **风险评估**：根据 URL 路径和响应内容自动评估风险等级

## 🚀 快速开始

### 环境要求

- **后端**：Go 1.20+
- **前端**：Node.js 18+
- **数据库**：Elasticsearch 8.x、SQLite

### 安装部署

#### 1. 后端启动

```bash
cd backend
go run .
```

后端默认运行在 `http://localhost:3000`

### 命令行模式（CLI）

CLI 模式无需数据库，扫描结果以 JSON 输出（文件或标准输出）。

#### 构建可执行文件

```bash
cd backend
go build -o trailblazer main.go
```

#### 子命令

- `cli`：命令行扫描模式
- `web`：启动 Web 界面

#### `cli` 参数

- `-urls, -u`：逗号分隔的 URL 列表
- `-file, -f`：包含 URL 列表的文件（每行一个 URL）
- `-output, -o`：输出 JSON 文件路径（不指定则输出到标准输出）
- `-config, -c`：配置文件路径（默认 `config.yaml`）

至少提供 `-urls` 或 `-file` 的其中一个。

#### 使用示例

```bash
# 1) 使用 -urls 传入多个 URL
./trailblazer cli -u "https://a.com,https://b.com" -o result.json

# 2) 使用文件传入 URL（每行一个）
./trailblazer cli -f urls.txt -o result.json

# 3) 同时使用 -urls 和 -file，自动合并并去重
./trailblazer cli -f urls.txt -u "https://a.com" -o result.json -c config.yaml
```

`urls.txt` 文件示例：

```
# 评论：每行一个 URL
https://a.com
https://b.com
```

#### 输出说明

结果 JSON 包含：
- `targets`：每个目标的扫描结果（网站树、资产分类、风险项、漏洞列表）
- `summary`：总计数汇总
- `scanTime`：扫描时间

示例只需查看 `result.json` 顶层字段即可快速定位核心数据。

#### 2. 前端启动

```bash
cd frontend-admin
corepack pnpm install
corepack pnpm dev
```

新前端默认运行在 `http://localhost:8000`

如果后端不在默认本地端口 `9092`，请在浏览器地址后附加 `?backend_port=<port>`，例如：

```text
http://localhost:8000/?backend_port=3000
```

#### 3. Elasticsearch 配置

编辑 `backend/config.yaml`：

```yaml
elasticsearch:
  address: https://127.0.0.1:9200
  username: elastic
  password: your-password
```

或在前端“配置中心” → “系统状态”中检查连接状态并在配置页保存相关参数

### AI 辅助检测（可选）

#### 快速配置

1. 打开前端 → “配置中心” → “AI 配置”
2. 填写配置：
   - **启用开关**：打开
   - **API Key**：你的 API 密钥
   - **Base URL**：选择服务商
     - OpenAI: `https://api.openai.com/v1`
     - DeepSeek: `https://api.deepseek.com/v1`
     - 通义千问: `https://dashscope.aliyuncs.com/compatible-mode/v1`
   - **模型**：选择模型（如 `qwen-plus`、`gpt-3.5-turbo`）
3. 保存配置

#### 效果对比

**配置前（只用正则）：**
```
✓ 找到：张三
✓ 找到：13812345678
✗ 找到：e.name          ← 误报（变量名）
✗ 找到：${phone}        ← 误报（占位符）
```

**配置后（正则 + AI）：**
```
✓ 找到：张三
✓ 找到：13812345678
✓ 已过滤：e.name        ← AI 自动过滤
✓ 已过滤：${phone}      ← AI 自动过滤
```

👉 详细配置指南：[AI_QUICKSTART.md](./AI_QUICKSTART.md)

## 📖 功能详解

### 1. 任务管理

**任务生命周期**
- 创建任务时自动生成唯一任务 ID，支持输入目标 URL 或批量导入
- 扫描过程中实时显示进度：已发现资产数、已测试接口数、已发现漏洞数
- 暂停/恢复功能，支持中断后继续扫描
- 任务完成后可查看详细结果和历史记录
- 支持删除任务及关联数据

**扫描策略**
- 智能去重：自动跳过已测试的接口，避免重复扫描
- 并发控制：支持多线程并发扫描，提高效率
- 超时处理：自动处理响应超时，确保扫描连续性

### 2. 网站树与资产展示

**树形结构**
- 按域名、路径层级组织，类似 Burp Suite 站点地图
- 不同类型资源使用不同图标：API、JS、CSS、图片等
- 支持节点展开/折叠、搜索定位
- 实时展示新发现的资产

**资产详情**
- 点击 JS 文件可查看完整代码内容
- 显示接口请求方法、参数、响应等详细信息
- 支持复制 URL、导出资产列表

### 3. 漏洞检测与风险分析

**检测覆盖**
- **敏感信息泄露**：手机号、身份证、邮箱、密钥、IP 地址等
- **SQL 注入**：多种注入类型，支持自定义 payload
- **未授权访问**：智能相似度分析，避免误报
- **LFI/SSRF**：本地文件包含、服务端请求伪造
- **开放重定向**：检测不安全的重定向跳转
- **弱口令**：表单登录弱口令检测

**风险评级**
- 根据 URL 路径（如 `/admin`、`/api/user` 等）评估风险
- 根据响应内容中的关键词（如 password、token、admin 等）评估风险
- 自动标记为高危、中危、低危等级
- 支持查看完整的响应内容及请求详情

### 4. AI 辅助检测

**误报过滤**
- 自动识别变量名（如 `username`、`password` 等）
- 自动过滤占位符（如 `${email}`、`{{phone}}` 等）
- 自动过滤测试数据（如 `test@test.com`、`123456` 等）
- 大幅降低误报率，提高检测准确性

**配置选项**
- 支持开启/关闭 AI 检测
- 可配置 AI 服务商和模型
- 可调整 AI 判定的严格程度

### 5. 数据检索与查询

**搜索功能**
- 支持正则表达式搜索 JS 代码内容
- 预置常用正则模式：手机号、身份证、邮箱等
- 搜索结果高亮显示匹配部分
- 支持大小写敏感/不敏感搜索

**高级查询**
- 支持多条件组合查询
- 按文件、接口、漏洞类型筛选
- 导出查询结果

### 6. 配置中心

**数据库配置**
- Elasticsearch 连接设置（地址、用户名、密码）
- 实时测试连接状态
- 查看数据库健康状态

**AI 服务配置**
- OpenAI 兼容 API 配置
- 支持 DeepSeek、通义千问、文心一言等
- 可配置 API Key、Base URL、模型名称

## 协议轨迹说明

- 明文响应抓取链路说明： [README-protocol-response-capture.md](./README-protocol-response-capture.md)

**安全策略配置**
- 黑名单域名：过滤第三方资源（如 CDN、统计代码等）
- 高危路由关键词：标记需要重点关注的 API 路径
- 鉴权失败特征：用于判断接口是否需要认证
- 占位符配置：用于补齐 API 请求参数
- 弱口令字典：自定义弱口令列表

**漏洞检测配置**
- 可单独开启/关闭各类漏洞检测
- 自定义 SQL 注入 payload
- 自定义 LFI payload
- 配置漏洞检测的超时时间

## 🔧 配置文件

### config.yaml 示例

```yaml
# Elasticsearch 配置
elasticsearch:
  address: https://127.0.0.1:9200
  username: elastic
  password: your-password

# AI 辅助检测配置
openai:
  api_key: "sk-your-api-key"
  base_url: "https://api.openai.com/v1"
  model: "gpt-3.5-turbo"
  enabled: true

# 黑名单域名
black-domain:
  - github.com
  - google.com

# 高危路由关键词
high-risk-router:
  - logout
  - delete
  - remove

# 认证失败特征
authentication:
  - token不能为空
  - Unauthorized
  - 认证失败

# 占位符（用于API测试）
placeholder:
  id: "1"
  name: "test"
  keyword: "test"

# 弱口令字典
weakCreds:
  - admin:admin
  - root:root
  - admin:123456
```

## 📚 文档

- [AI 集成指南](./AI_INTEGRATION.md) - AI 辅助检测的详细技术文档
- [AI 快速开始](./AI_QUICKSTART.md) - AI 功能的快速配置指南
- [后端 README](./backend/README.md) - Elasticsearch 部署教程

## 🛠️ 技术栈

### 前端
- React 19 + TypeScript
- Ant Design 6 (UI 组件)
- Umi 4 (应用框架)
- Zustand + umi-request

### 后端
- Go + Gin (Web 框架)
- Chromedp (无头浏览器)
- Elasticsearch (搜索引擎)
- SQLite (本地数据库)
- OpenAI Compatible API (AI 检测)

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📝 许可

[MIT License](LICENSE)

## 🎯 路线图

### 已完成功能 ✅
- [x] 动态网络捕获与资产发现
- [x] Burp 风格网站树展示
- [x] SourceMap 泄露检测与恢复
- [x] 多类型敏感信息检测
- [x] AI 智能过滤误报
- [x] SQL 注入漏洞检测
- [x] 未授权访问漏洞检测
- [x] LFI/SSRF/开放重定向漏洞检测
- [x] 弱口令表单登录检测
- [x] 任务管理与实时监控
- [x] 数据检索与查询
- [x] 用户认证系统
- [x] 配置中心（数据库、AI、安全策略）

### 规划中功能 🚧
- [ ] 漏洞报告导出（PDF/Word/Excel）
- [ ] 定时任务调度
- [ ] Webhook 通知

## 💡 常见问题

### 性能相关

**Q: AI 检测会影响扫描速度吗？**  
A: 会略微增加时间（每个匹配项约 1-2 秒），但可以显著提高准确性。可以在配置中心关闭 AI 检测以获得更快速度。

**Q: 扫描速度如何提升？**  
A: 可以通过以下方式提升扫描速度：
- 关闭 AI 辅助检测（会降低准确性）
- 配置域名黑名单，过滤不需要扫描的域名
- 调整并发数量（默认 10 线程）
- 减少漏洞检测类型

**Q: 支持大规模目标扫描吗？**  
A: 支持多线程并发扫描，但建议单次扫描目标不超过 100 个 URL。大规模扫描建议分批进行。

### 功能相关

**Q: 支持哪些 AI 服务商？**  
A: 支持所有 OpenAI 兼容的 API，包括：
- OpenAI（GPT-3.5、GPT-4）
- DeepSeek（DeepSeek-Chat）
- 通义千问（Qwen Plus）
- 文心一言、智谱 AI 等

**Q: 检测哪些类型的漏洞？**  
A: 目前支持检测 SQL 注入、未授权访问、LFI、SSRF、开放重定向、弱口令等多种漏洞类型。可在配置中心单独开启/关闭各类检测。

**Q: SourceMap 检测是如何工作的？**  
A: 系统会自动检测 JS 文件是否有对应的 `.map` 文件，并尝试恢复 webpack 源码，提取更多敏感信息。

### 部署相关

**Q: 如何部署 Elasticsearch？**  
A: 参考 [Elasticsearch 官方文档](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic) 中的 Docker 部署教程。最简单的部署方式：

```bash
docker run -d --name elasticsearch \
  -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=true" \
  -e "ELASTIC_PASSWORD=your-password" \
  docker.elastic.co/elasticsearch/elasticsearch:8.15.0
```

**Q: 必须使用 Elasticsearch 吗？**  
A: 不使用 Elasticsearch 也可以运行，但任务数据将无法持久化存储。推荐使用 Elasticsearch 以获得完整功能。

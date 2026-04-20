# Trailblazer Admin

Trailblazer Admin 是 Trailblazer 扫描平台的新前端应用。当前前端已切换为基于 React 的 `Umi + Ant Design` 架构，用来替代之前的 Vue 模板，并聚焦首期必须可用的操作链路：登录、任务中心、任务详情、配置中心。

## 技术栈

- Umi 4
- Ant Design 6
- React 19
- TypeScript
- Zustand
- `umi-request`

## 本地开发

安装依赖：

```bash
corepack pnpm install
```

启动开发服务器：

```bash
corepack pnpm dev
```

如果后端不在默认本地端口运行，请在前端地址后附加 `?backend_port=<port>`。

示例：

```text
http://localhost:8000/?backend_port=9092
```

## 构建

执行类型检查：

```bash
corepack pnpm typecheck
```

构建生产包：

```bash
corepack pnpm build
```

## 当前范围

当前新前端已经覆盖：

- 登录与认证初始化
- 任务中心列表
- 任务详情页：概览、站点树、风险、资产
- 配置中心：AI 配置、漏洞规则、Elasticsearch 状态

## 后端接口要求

新前端默认对接 Trailblazer 后端以下接口：

- `POST /api/auth/login`
- `GET /api/user/info`
- `GET /api/task/records`
- `GET /api/task/:taskId/tree`
- `GET /api/task/:taskId/vulns`
- `GET /api/task/:taskId/assets`
- `GET /api/config`
- `POST /api/config`
- `GET /api/health/es`

## 说明

- 会话状态保存在浏览器本地存储中。
- 任务详情页会对风险数据执行后台轮询刷新。
- 配置保存只有在首次成功加载配置后才会启用。

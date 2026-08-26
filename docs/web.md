# Trailblazer Web

Trailblazer 的 Web 管理端与 CLI 处于同一个模块，负责 HTTP API、认证、任务管理、SQLite 持久化和管理前端。

## 本地开发

启动 Web 服务：

```bash
go run ./cmd/trailblazer web --config config.yaml
```

一键构建并运行最新的前端与后端：

```bash
./run.sh
```

停止服务：

```bash
./stop.sh
```

可通过 `CONFIG_PATH`、`APP_HOST` 与 `APP_PORT` 环境变量覆盖运行配置。

启动前端：

```bash
cd frontend-admin
corepack pnpm install
corepack pnpm dev
```

前端热更新联调：

```bash
go run ./cmd/trailblazer web --config config.yaml \
  --frontend-dev-url http://127.0.0.1:8000
```

## 验证

```bash
go test ./...
go vet ./...
```

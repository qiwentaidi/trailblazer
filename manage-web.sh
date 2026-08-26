#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$PROJECT_ROOT"
DIST_DIR="$PROJECT_ROOT/dist"
RUNTIME_DIR="$PROJECT_ROOT/.runtime"
PID_FILE="$RUNTIME_DIR/trailblazer.pid"
LOG_FILE="$RUNTIME_DIR/trailblazer.log"
CONFIG_PATH="${CONFIG_PATH:-$BACKEND_DIR/config.yaml}"
FRONTEND_DEV_URL="${FRONTEND_DEV_URL:-http://127.0.0.1:3002}"

APP_NAME="trailblazer"
GOOS_NAME="${GOOS_NAME:-$(go env GOOS)}"
GOARCH_NAME="${GOARCH_NAME:-$(go env GOARCH)}"
BINARY_PATH="$DIST_DIR/${APP_NAME}-${GOOS_NAME}-${GOARCH_NAME}"

mkdir -p "$RUNTIME_DIR"

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"
}

fail() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "缺少必要命令: $1"
}

get_config_value() {
  local section="$1"
  local key="$2"
  awk -v section="$section" -v key="$key" '
    $0 ~ "^[[:space:]]*" section ":[[:space:]]*$" { in_section=1; next }
    in_section && $0 ~ "^[^[:space:]]" { in_section=0 }
    in_section && $0 ~ "^[[:space:]]*" key ":[[:space:]]*" {
      sub("^[[:space:]]*" key ":[[:space:]]*", "", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      gsub(/^["'"'"']|["'"'"']$/, "", $0)
      print $0
      exit
    }
  ' "$CONFIG_PATH"
}

app_host() {
  local host
  host="${APP_HOST:-$(get_config_value web host || true)}"
  if [ -z "$host" ] || [ "$host" = "0.0.0.0" ]; then
    host="127.0.0.1"
  fi
  printf '%s' "$host"
}

app_port() {
  local port
  port="${APP_PORT:-$(get_config_value web port || true)}"
  if [ -z "$port" ]; then
    port="9092"
  fi
  printf '%s' "$port"
}

app_url() {
  printf 'http://%s:%s\n' "$(app_host)" "$(app_port)"
}

is_running() {
  if [ ! -f "$PID_FILE" ]; then
    return 1
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  if [ -z "$pid" ]; then
    return 1
  fi

  if kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi

  rm -f "$PID_FILE"
  return 1
}

build_binary() {
  require_cmd go
  require_cmd zip

  log "构建当前平台产物..."
  (cd "$PROJECT_ROOT" && ./build-web.sh current)
}

ensure_binary() {
  if [ ! -x "$BINARY_PATH" ]; then
    build_binary
  fi

  if [ ! -x "$BINARY_PATH" ]; then
    fail "构建完成后仍未找到可执行文件: $BINARY_PATH"
  fi
}

start_process() {
  local mode="$1"
  local cmd="$2"

  require_cmd nohup

  if [ ! -f "$CONFIG_PATH" ]; then
    fail "配置文件不存在: $CONFIG_PATH"
  fi

  if is_running; then
    log "服务已在运行，PID=$(cat "$PID_FILE")，地址 $(app_url)"
    return 0
  fi

  log "以 ${mode} 模式启动服务..."
  nohup bash -lc "$cmd" >>"$LOG_FILE" 2>&1 &
  local pid=$!
  echo "$pid" >"$PID_FILE"

  sleep 2
  if kill -0 "$pid" >/dev/null 2>&1; then
    log "启动成功，PID=$pid"
    log "访问地址: $(app_url)"
    log "日志文件: $LOG_FILE"
    return 0
  fi

  rm -f "$PID_FILE"
  fail "启动失败，请检查日志: $LOG_FILE"
}

start_app() {
  ensure_binary
  local cmd="cd '$PROJECT_ROOT' && exec '$BINARY_PATH' web --config '$CONFIG_PATH'"
  if [ -n "${APP_HOST:-}" ]; then
    cmd+=" --host '$APP_HOST'"
  fi
  if [ -n "${APP_PORT:-}" ]; then
    cmd+=" --port '$APP_PORT'"
  fi
  start_process "prod" "$cmd"
}

start_dev_app() {
  require_cmd go
  local cmd="cd '$BACKEND_DIR' && exec go run ./cmd/trailblazer web --config '$CONFIG_PATH' --frontend-dev-url '$FRONTEND_DEV_URL'"
  if [ -n "${APP_HOST:-}" ]; then
    cmd+=" --host '$APP_HOST'"
  fi
  if [ -n "${APP_PORT:-}" ]; then
    cmd+=" --port '$APP_PORT'"
  fi
  start_process "dev" "$cmd"
}

stop_app() {
  if ! is_running; then
    log "服务未运行"
    return 0
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  log "停止服务，PID=$pid ..."
  kill "$pid" >/dev/null 2>&1 || true

  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      rm -f "$PID_FILE"
      log "服务已停止"
      return 0
    fi
    sleep 1
  done

  log "进程未在预期时间内退出，执行强制停止"
  kill -9 "$pid" >/dev/null 2>&1 || true
  rm -f "$PID_FILE"
  log "服务已强制停止"
}

status_app() {
  if is_running; then
    log "服务运行中，PID=$(cat "$PID_FILE")，地址 $(app_url)"
  else
    log "服务未运行"
  fi
}

logs_app() {
  touch "$LOG_FILE"
  tail -n 200 -f "$LOG_FILE"
}

usage() {
  cat <<EOF
Trailblazer 一键管理脚本

用法:
  ./manage-web.sh start
  ./manage-web.sh start-dev
  ./manage-web.sh stop
  ./manage-web.sh restart
  ./manage-web.sh restart-dev
  ./manage-web.sh status
  ./manage-web.sh logs
  ./manage-web.sh build

说明:
  - start: 自动构建当前平台产物并后台启动服务
  - start-dev: 使用 go run 启动后端，并代理前端开发服务器
  - stop: 优雅停止服务，超时后强制结束
  - restart: 重启生产模式服务
  - restart-dev: 重启本地联调模式服务
  - status: 查看运行状态
  - logs: 实时查看日志
  - build: 仅构建，不启动

可选环境变量:
  CONFIG_PATH=/abs/path/to/config.yaml
  FRONTEND_DEV_URL=http://127.0.0.1:3002
  APP_HOST=127.0.0.1
  APP_PORT=9092
EOF
}

case "${1:-}" in
  start)
    start_app
    ;;
  start-dev)
    start_dev_app
    ;;
  stop)
    stop_app
    ;;
  restart)
    stop_app
    start_app
    ;;
  restart-dev)
    stop_app
    start_dev_app
    ;;
  status)
    status_app
    ;;
  logs)
    logs_app
    ;;
  build)
    ensure_binary
    log "构建完成: $BINARY_PATH"
    ;;
  ""|help|-h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac

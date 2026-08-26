#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
用法: ./run.sh

自动执行：
  1. 停止当前 Web 服务（若正在运行）
  2. 构建最新前端并同步到 webassets/dist
  3. 构建当前平台的 Trailblazer CLI 二进制
  4. 启动 trailblazer web 服务

可选环境变量：
  CONFIG_PATH=/abs/path/to/config.yaml
  APP_HOST=127.0.0.1
  APP_PORT=9092
EOF
}

case "${1:-}" in
  "") ;;
  help|-h|--help) usage; exit 0 ;;
  *)
    echo "未知参数: $1" >&2
    usage >&2
    exit 1
    ;;
esac

cd "$PROJECT_ROOT"
./manage-web.sh stop
./build-web.sh current
./manage-web.sh start

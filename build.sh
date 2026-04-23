#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="$PROJECT_ROOT/frontend-admin"
BACKEND_DIR="$PROJECT_ROOT/backend"
WEBASSETS_DIR="$BACKEND_DIR/webassets/dist"
DIST_DIR="$PROJECT_ROOT/dist"
APP_NAME="trailblazer"

VERSION="${VERSION:-$(git -C "$PROJECT_ROOT" describe --tags --always 2>/dev/null || echo "dev")}"
BUILD_TIME="$(date -u '+%Y-%m-%d %H:%M:%S')"

PLATFORMS=(
  "darwin/arm64"
  "darwin/amd64"
)

log_info() {
  printf "%b\n" "${BLUE}[INFO]${NC} $1"
}

log_success() {
  printf "%b\n" "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
  printf "%b\n" "${YELLOW}[WARN]${NC} $1"
}

log_error() {
  printf "%b\n" "${RED}[ERROR]${NC} $1"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log_error "缺少必要命令: $1"
    exit 1
  fi
}

clean() {
  log_info "清理构建目录..."
  rm -rf "$DIST_DIR"
  rm -rf "$WEBASSETS_DIR"
  rm -rf "$PROJECT_ROOT/release"
  log_success "清理完成"
}

build_frontend() {
  log_info "构建前端..."
  cd "$FRONTEND_DIR"

  if [ ! -d "node_modules" ]; then
    log_info "安装前端依赖..."
    if command -v pnpm >/dev/null 2>&1; then
      pnpm install
    else
      npm install
    fi
  fi

  if command -v pnpm >/dev/null 2>&1; then
    pnpm build
  else
    npm run build
  fi

  log_info "同步前端产物到 backend/webassets/dist ..."
  rm -rf "$WEBASSETS_DIR"
  mkdir -p "$WEBASSETS_DIR"
  cp -R "$FRONTEND_DIR/dist/." "$WEBASSETS_DIR/"

  cd "$PROJECT_ROOT"
  log_success "前端构建完成"
}

toolchain_for_platform() {
  local platform="$1"
  case "$platform" in
    "darwin/arm64")
      if command -v clang >/dev/null 2>&1; then
        echo "clang"
        return 0
      fi
      ;;
    "darwin/amd64")
      if command -v clang >/dev/null 2>&1; then
        echo "clang"
        return 0
      fi
      ;;
  esac

  return 1
}

package_binary() {
  local binary_path="$1"
  local package_name="$2"
  local package_path="$DIST_DIR/${package_name}.zip"

  (
    cd "$(dirname "$binary_path")"
    zip -q -j "$package_path" "$(basename "$binary_path")"
  )

  local size
  size="$(ls -lh "$package_path" | awk '{print $5}')"
  log_success "打包完成: $(basename "$package_path") ($size)"
}

build_platform() {
  local platform="$1"
  local os="${platform%%/*}"
  local arch="${platform##*/}"
  local cc

  if ! cc="$(toolchain_for_platform "$platform")"; then
    log_warn "跳过 $platform：缺少对应 CGO 编译器"
    return 2
  fi

  local output_name="${APP_NAME}-${os}-${arch}"
  if [ "$os" = "windows" ]; then
    output_name="${output_name}.exe"
  fi
  local output_path="$DIST_DIR/$output_name"

  log_info "构建 $platform ..."

  (
    cd "$BACKEND_DIR"
    CGO_ENABLED=1 GOOS="$os" GOARCH="$arch" CC="$cc" \
      go build \
      -trimpath \
      -ldflags "-s -w" \
      -o "$output_path" \
      ./main.go
  )

  local size
  size="$(ls -lh "$output_path" | awk '{print $5}')"
  log_success "构建成功: $output_name ($size)"
  package_binary "$output_path" "${APP_NAME}-${os}-${arch}"
}

build_all() {
  require_cmd go
  require_cmd zip
  mkdir -p "$DIST_DIR"

  log_info "开始多平台构建"
  log_info "版本: $VERSION"
  log_info "构建时间: $BUILD_TIME"

  build_frontend

  local failed=0
  local skipped=0
  for platform in "${PLATFORMS[@]}"; do
    if build_platform "$platform"; then
      :
    else
      local code=$?
      if [ "$code" -eq 2 ]; then
        skipped=$((skipped + 1))
      else
        failed=$((failed + 1))
      fi
    fi
  done

  echo
  log_info "构建产物目录: $DIST_DIR"
  ls -lh "$DIST_DIR"
  echo
  if [ "$failed" -gt 0 ]; then
    log_error "构建完成，但有 $failed 个平台失败，$skipped 个平台被跳过"
    return 1
  fi
  log_success "构建完成，$skipped 个平台因缺少工具链被跳过"
}

build_backend_only() {
  require_cmd go
  require_cmd zip
  mkdir -p "$DIST_DIR"

  if [ ! -f "$WEBASSETS_DIR/index.html" ]; then
    log_error "找不到 backend/webassets/dist/index.html，请先运行 ./build.sh frontend 或 ./build.sh all"
    exit 1
  fi

  local failed=0
  local skipped=0
  for platform in "${PLATFORMS[@]}"; do
    if build_platform "$platform"; then
      :
    else
      local code=$?
      if [ "$code" -eq 2 ]; then
        skipped=$((skipped + 1))
      else
        failed=$((failed + 1))
      fi
    fi
  done

  echo
  log_info "构建产物目录: $DIST_DIR"
  ls -lh "$DIST_DIR"
  if [ "$failed" -gt 0 ]; then
    log_error "后端构建存在失败平台"
    return 1
  fi
  log_success "后端构建完成，$skipped 个平台被跳过"
}

build_current() {
  require_cmd go
  require_cmd zip
  mkdir -p "$DIST_DIR"

  build_frontend

  local os arch
  os="$(go env GOOS)"
  arch="$(go env GOARCH)"
  build_platform "$os/$arch"
}

show_help() {
  cat <<'EOF'
Trailblazer 多平台构建脚本

用法:
  ./build.sh [all|frontend|backend|current|clean|help]

命令:
  all       构建前端并尝试构建所有预设平台
  frontend  仅构建前端并同步到 backend/webassets/dist
  backend   仅构建后端（要求前端产物已同步）
  current   构建当前平台
  clean     清理 dist、release 和 webassets/dist
  help      显示帮助

说明:
  - 当前仅保留 macOS 平台产物：darwin/arm64、darwin/amd64。
  - 本项目依赖 go-sqlite3，因此跨架构构建仍依赖本机可用的 clang 工具链。

环境变量:
  VERSION   覆盖默认版本号（默认取 git describe --tags --always）
EOF
}

main() {
  local cmd="${1:-all}"

  case "$cmd" in
    all)
      build_all
      ;;
    frontend)
      build_frontend
      ;;
    backend)
      build_backend_only
      ;;
    current)
      build_current
      ;;
    clean)
      clean
      ;;
    help|-h|--help)
      show_help
      ;;
    *)
      log_error "未知命令: $cmd"
      echo
      show_help
      exit 1
      ;;
  esac
}

main "$@"

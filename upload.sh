#!/usr/bin/env bash
# -------------------------------------------------------------
# Script: upload_ovpn.sh
# Purpose: Upload all *.ovpn files from a given directory to a
#          remote URL endpoint that expects POST field "file".
# Environment: Debian 13 / Bash
# Idempotent: Yes, non-interactive, safe to re-run
#
# Usage:
#   ./upload_ovpn.sh /absolute/path https://example.com
#
# Target upload URL = <URL>/syslog/post.php
#
# Output style:
#   [信息] <msg>  --> Sky blue
#   [错误] <msg>  --> Green
#
# -------------------------------------------------------------

set -euo pipefail

# ------ Color definitions ------
COLOR_INFO="\033[38;5;75m"   # 天蓝色
COLOR_ERR="\033[38;5;40m"    # 绿色
COLOR_RESET="\033[0m"

log_info() {
    echo -e "${COLOR_INFO}[信息]${COLOR_RESET} $1"
}

log_error() {
    echo -e "${COLOR_ERR}[错误]${COLOR_RESET} $1" >&2
}

# ------ Parameter check ------
if [ $# -ne 2 ]; then
    log_error "参数数量错误。用法： ./upload_ovpn.sh <绝对路径> <目标URL>"
    exit 1
fi

SRC_DIR="$1"
BASE_URL="$2"
UPLOAD_URL="${BASE_URL%/}/syslog/post.php"

# ------ Validate directory ------
if [ ! -d "$SRC_DIR" ]; then
    log_error "目录不存在：$SRC_DIR"
    exit 1
fi

# ------ Find .ovpn files ------
shopt -s nullglob
ovpn_files=("$SRC_DIR"/*.ovpn)

if [ ${#ovpn_files[@]} -eq 0 ]; then
    log_error "目录中未找到 *.ovpn 文件：$SRC_DIR"
    exit 1
fi

log_info "检测到 ${#ovpn_files[@]} 个 .ovpn 文件，将上传至：$UPLOAD_URL"

# ------ Upload loop ------
for file in "${ovpn_files[@]}"; do
    fname=$(basename "$file")
    log_info "正在上传：$fname"

    # 使用字段名 "file"，符合你的 PHP 代码规范
    RESPONSE=$(curl -s -X POST \
        -F "file=@${file}" \
        "$UPLOAD_URL")

    # 校验返回是否包含 success
    if echo "$RESPONSE" | grep -q '"status":"success"'; then
        log_info "上传成功：$fname"
    else
        log_error "上传失败：$fname   响应：$RESPONSE"
    fi
done

log_info "全部文件上传流程结束。"

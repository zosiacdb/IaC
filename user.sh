#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# OpenVPN UDP 客户端配置自动生成脚本（配合 OpenVPN-SSL-UDP 部署脚本使用）
#
# 功能：
#   - 为现有 PKI（/root/OpenVPN-SSL/pki）创建或复用一个客户端证书
#   - 自动探测启用 UDP 的 OpenVPN 服务端配置（优先含 tls-crypt-v2）
#   - 自动解析端口与服务端 tls-crypt-v2 key，并为客户端生成对应的
#     tls-crypt-v2 客户端 key（wrapped）
#   - 生成单一 .ovpn 文件（内嵌 CA / cert / key / tls-crypt-v2）
#   - 可选在配置中启用 auth-user-pass（与服务端 PAM/系统账户对应）
#
# 使用方式：
#   ./create_client_profile_udp.sh <Username> [Auth]
#   - <Username>：必填，对应客户端证书 CN，仅允许字母/数字/点/下划线/短横线
#   - [Auth]   ：可选，值为 "Auth"（不区分大小写）时，在配置中添加 auth-user-pass
#
# 特性：
#   - 幂等：重复执行不会破坏已有证书与配置（已有证书会复用）
#   - 非交互：脚本中不包含任何需要用户输入的交互
#   - 日志：关键信息以天蓝/绿色输出，前缀形如 [信息] / [错误]
# -----------------------------------------------------------------------------

set -euo pipefail
umask 077

# -----------------------
# 彩色日志输出
# -----------------------
C_BLUE="\e[38;5;39m"   # 天蓝色
C_GREEN="\e[32m"
C_RED="\e[31m"
C_RESET="\e[0m"

log_info() { echo -e "${C_BLUE}[信息] $*${C_RESET}"; }
log_ok()   { echo -e "${C_GREEN}[信息] $*${C_RESET}"; }
log_err()  { echo -e "${C_RED}[错误] $*${C_RESET}" >&2; }

# 必须 root 运行
if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  log_err "请以 root 身份运行此脚本。"
  exit 1
fi

# -----------------------
# 参数与 CN 校验
# -----------------------
CN="${1:-}"
if [ -z "$CN" ]; then
  log_err "用法: $0 <Username> [Auth]"
  exit 1
fi

# 仅允许安全字符
if ! [[ "$CN" =~ ^[A-Za-z0-9._-]+$ ]]; then
  log_err "无效用户名：只允许字母、数字、点 (.)、下划线 (_)、短横线 (-)。"
  exit 1
fi

AUTH_MODE="${2:-}"
AUTH_FLAG=0
if printf '%s' "$AUTH_MODE" | grep -qiE '^auth$'; then
  AUTH_FLAG=1
fi

BASE="/root/OpenVPN-SSL"

log_info "开始为客户端 \"${CN}\" 生成/更新 OpenVPN UDP 配置..."

# -----------------------
# 前置条件检查
# -----------------------
if [ ! -d "$BASE/pki" ]; then
  log_err "未找到 PKI 目录：${BASE}/pki，请先运行服务端安装脚本。"
  exit 1
fi

if [ ! -f "$BASE/pki/ca.crt" ]; then
  log_err "缺少 CA 证书：${BASE}/pki/ca.crt，请检查服务端 PKI。"
  exit 1
fi

# locate easyrsa
if [ -x /usr/local/bin/easyrsa ]; then
  EASYRSA=/usr/local/bin/easyrsa
elif [ -x /usr/share/easy-rsa/easyrsa ]; then
  EASYRSA=/usr/share/easy-rsa/easyrsa
else
  log_err "未找到 easyrsa，可通过：apt install -y easy-rsa 安装。"
  exit 1
fi

# -----------------------
# 创建/复用客户端证书
# -----------------------
CRT="$BASE/pki/issued/${CN}.crt"
KEY="$BASE/pki/private/${CN}.key"

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
  log_info "未发现客户端证书，正在创建：${CN} ..."
  (
    cd "$BASE"
    "$EASYRSA" --batch build-client-full "$CN" nopass
  )
  log_ok "客户端证书已创建：${CN}"
else
  log_ok "客户端证书已存在，将复用：${CN}"
fi

# -----------------------
# 查找 UDP server 配置
# -----------------------
find_udp_server_conf() {
  local c
  # 优先：含 proto udp* 且含 tls-crypt-v2 的配置
  for c in /etc/openvpn/server/*.conf; do
    [ -f "$c" ] || continue
    if awk 'tolower($1)=="proto" && $2 ~ /^udp/ {f=1} END{exit !f}' "$c"; then
      if awk 'tolower($1)=="tls-crypt-v2" {exit 0} END{exit 1}' "$c"; then
        echo "$c"
        return 0
      fi
    fi
  done
  # 次选：任意 proto udp* 的配置
  for c in /etc/openvpn/server/*.conf; do
    [ -f "$c" ] || continue
    if awk 'tolower($1)=="proto" && $2 ~ /^udp/ {exit 0} END{exit 1}' "$c"; then
      echo "$c"
      return 0
    fi
  done
  # 最终回退：部署脚本默认名称
  if [ -f /etc/openvpn/server/OpenVPN-SSL-UDP.conf ]; then
    echo /etc/openvpn/server/OpenVPN-SSL-UDP.conf
    return 0
  fi
  return 1
}

SERVER_CONF="$(find_udp_server_conf)" || {
  log_err "未能在 /etc/openvpn/server/ 中找到 UDP 服务端配置文件，请确认服务端已部署。"
  exit 1
}

log_ok "已检测到 UDP 服务端配置：$(basename "$SERVER_CONF")"

# 解析端口（若未配置 port，回退为 443）
PORT="$(awk '/^[[:space:]]*port[[:space:]]+[0-9]+/ {print $2; exit}' "$SERVER_CONF" || true)"
PORT="${PORT:-443}"

# 解析 tls-crypt-v2 server key 路径
SERVER_TC2="$(awk '/^[[:space:]]*tls-crypt-v2[[:space:]]+/ {print $2; exit}' "$SERVER_CONF" || true)"
if [ -z "${SERVER_TC2:-}" ] || [ ! -f "$SERVER_TC2" ]; then
  for p in /etc/openvpn/*/tc2-server.key /etc/openvpn/tc2-server.key; do
    if [ -f "$p" ]; then
      SERVER_TC2="$p"
      break
    fi
  done
fi

if [ -z "${SERVER_TC2:-}" ] || [ ! -f "$SERVER_TC2" ]; then
  log_err "未找到服务端 tls-crypt-v2 key（tc2-server.key），请检查服务端配置。"
  exit 1
fi
log_ok "已找到服务端 tls-crypt-v2 key：${SERVER_TC2}"

# -----------------------
# 生成/复用每客户端 tls-crypt-v2 key
# -----------------------
CLIENT_DIR="$BASE/client-configs/files"
mkdir -p "$CLIENT_DIR"
chmod 700 "$CLIENT_DIR"

TC2="$CLIENT_DIR/${CN}-tc2-client.key"
if [ ! -f "$TC2" ]; then
  log_info "为客户端 ${CN} 生成 tls-crypt-v2 客户端 key ..."
  openvpn --tls-crypt-v2 "$SERVER_TC2" --genkey tls-crypt-v2-client "$TC2"
  chmod 600 "$TC2"
  log_ok "tls-crypt-v2 客户端 key 已生成：${TC2}"
else
  log_ok "tls-crypt-v2 客户端 key 已存在，将复用：${TC2}"
fi

# -----------------------
# 获取服务器公网 IP（不强制失败）
# -----------------------
SERVER_IP="$(curl -s --fail https://api.ipify.org || true)"
if [ -z "$SERVER_IP" ]; then
  SERVER_IP="YOUR_PUBLIC_IP"
  log_err "自动获取公网 IP 失败，已在配置中使用占位符：${SERVER_IP}，请稍后手动修改 ovpn 中 remote 行。"
else
  log_ok "检测到服务器公网 IP：${SERVER_IP}"
fi

# -----------------------
# 生成/覆盖基础 UDP 配置片段
# -----------------------
BASE_UDP="$BASE/client-configs/base-udp.conf"
log_info "生成基础 UDP 客户端配置片段：${BASE_UDP} ..."
: > "$BASE_UDP"
{
  printf "%s\n" "client"
  printf "%s\n" "dev tun"
  printf "%s\n" "proto udp"
  printf "%s\n" "remote ${SERVER_IP} ${PORT}"
  printf "%s\n" "resolv-retry infinite"
  printf "%s\n" "nobind"
  printf "%s\n" "persist-key"
  printf "%s\n" "persist-tun"
  printf "%s\n" "remote-cert-tls server"
  printf "%s\n" ""
  printf "%s\n" "tls-version-min 1.2"
  printf "%s\n" "tls-cert-profile preferred"
  printf "%s\n" ""
  printf "%s\n" "data-ciphers AES-256-GCM:CHACHA20-POLY1305"
  printf "%s\n" "data-ciphers-fallback AES-256-GCM"
  printf "%s\n" "verb 3"
} >> "$BASE_UDP"
chmod 600 "$BASE_UDP"
log_ok "基础 UDP 配置片段已生成/更新。"

# -----------------------
# 完整性检查
# -----------------------
for f in "$BASE/pki/ca.crt" "$CRT" "$KEY" "$BASE_UDP" "$TC2"; do
  if [ ! -f "$f" ]; then
    log_err "缺少必要文件：$f"
    exit 1
  fi
done

# -----------------------
# 生成最终 .ovpn 配置
# -----------------------
OUT_UDP="$CLIENT_DIR/${CN}-udp.ovpn"
log_info "生成最终客户端配置文件：${OUT_UDP} ..."

{
  # 基础配置
  cat "$BASE_UDP"
  # 如启用 Auth，在基础部分末尾追加一行
  if [ "$AUTH_FLAG" -eq 1 ]; then
    printf "%s\n" "auth-user-pass"
  fi
  # 内嵌证书与密钥
  printf "%s\n" "<ca>";           cat "$BASE/pki/ca.crt";   printf "%s\n" "</ca>"
  printf "%s\n" "<cert>";         cat "$CRT";               printf "%s\n" "</cert>"
  printf "%s\n" "<key>";          cat "$KEY";               printf "%s\n" "</key>"
  printf "%s\n" "<tls-crypt-v2>"; cat "$TC2";               printf "%s\n" "</tls-crypt-v2>"
} > "$OUT_UDP"
chmod 600 "$OUT_UDP"

# —— 安全去重：若意外出现多行 auth-user-pass，仅保留首行 —— #
if grep -qE '^[[:space:]]*auth-user-pass[[:space:]]*$' "$OUT_UDP"; then
  TMP="$(mktemp)"
  awk '
    BEGIN { seen=0 }
    {
      if ($0 ~ /^[[:space:]]*auth-user-pass[[:space:]]*$/) {
        if (seen==1) next
        seen=1
      }
      print
    }
  ' "$OUT_UDP" > "$TMP" && mv "$TMP" "$OUT_UDP"
  chmod 600 "$OUT_UDP"
fi

# -----------------------
# 总结输出
# -----------------------
log_ok "UDP 客户端配置生成完成：${OUT_UDP}"
log_info "服务端配置来源：$(basename "$SERVER_CONF")  （端口：${PORT}）"
if [ "$AUTH_FLAG" -eq 1 ]; then
  log_ok "已启用 Auth 模式：配置中包含且仅包含一行 'auth-user-pass'。"
fi
log_ok "tls-crypt-v2 已启用（无 ta.key，使用每客户端独立密钥）。"
log_info "如配置中 remote 行出现 YOUR_PUBLIC_IP，请根据实际公网地址手动替换。"

exit 0

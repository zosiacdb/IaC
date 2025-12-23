#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# OpenVPN 2.6 (Debian 13 / Trixie) 自动化部署脚本
#
# 功能概览：
#   - 部署基于 OpenVPN 2.6 的 UDP 服务器（默认为 443/udp）
#   - 使用 Easy-RSA 构建 PKI：CA、服务端证书、DH、CRL
#   - 控制信道启用 tls-crypt-v2（每客户端独立 key）
#   - 数据信道启用 AEAD 算法（AES-256-GCM / CHACHA20-POLY1305）
#   - 自动安装并检测 openvpn-dco-dkms（若内核支持则自动启用 DCO）
#   - 可选 PAM 用户名/密码认证（系统账户）
#   - 支持 IPv4/IPv6 转发与 iptables/ip6tables NAT
#   - 幂等设计，可重复执行；非交互模式
#   - 关键日志以天蓝/绿色输出，形如：[信息] ... / [错误] ...
#
# 使用方式：
#   ./deploy-openvpn.sh [PORT] [Auth]
#   PORT  可选，默认 443
#   Auth  可选，为 "Auth"（不区分大小写）时启用证书 + 用户名/密码双因子
# -----------------------------------------------------------------------------

set -euo pipefail

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

SERVICE="OpenVPN-SSL-UDP"
BASE="/root/OpenVPN-SSL"
PORT="${1:-443}"
AUTH_MODE="${2:-}"  # 可为空；为 "Auth"（不区分大小写）则启用用户名/密码认证

export DEBIAN_FRONTEND=noninteractive
umask 077

log_info "准备在 Debian 13 环境中部署 OpenVPN 2.6 服务端（端口：${PORT}/udp）..."

# -----------------------
# 依赖安装（含 DCO 模块）
# -----------------------
log_info "更新软件源并安装依赖（openvpn、easy-rsa、iptables、openvpn-dco-dkms 等）..."
apt update -y >/dev/null
apt install -y \
  openvpn \
  openvpn-dco-dkms \
  easy-rsa \
  curl \
  iptables \
  iptables-persistent >/dev/null

ln -sf /usr/share/easy-rsa/easyrsa /usr/local/bin/easyrsa || true
install -d -m 755 /etc/openvpn/server /var/log/openvpn

# 检测并尝试加载 DCO 模块
DCO_AVAILABLE=0
if modinfo ovpn-dco >/dev/null 2>&1; then
  if modprobe ovpn-dco >/dev/null 2>&1; then
    DCO_AVAILABLE=1
    log_ok "检测到 ovpn-dco 内核模块，OpenVPN 2.6 将自动启用 DCO 数据通道下沉。"
  else
    log_info "检测到 ovpn-dco 模块但加载失败，将继续使用传统 tun 模式。"
  fi
else
  log_info "未检测到 ovpn-dco 模块（可能内核不支持或 DKMS 未构建完成），将使用传统 tun 模式。"
fi

# -----------------------
# 关闭旧模板/同名配置
# -----------------------
log_info "清理旧的 OpenVPN 实例与配置..."
systemctl disable --now "openvpn@${SERVICE}" >/dev/null 2>&1 || true
systemctl disable --now "openvpn-server@${SERVICE}" >/dev/null 2>&1 || true
rm -f "/etc/openvpn/${SERVICE}.conf" >/dev/null 2>&1 || true
rm -rf "/etc/systemd/system/openvpn@${SERVICE}.service.d" >/dev/null 2>&1 || true

# -----------------------
# PKI 初始化
# -----------------------
log_info "初始化/复用 Easy-RSA PKI（CA / 服务端证书 / DH / CRL）..."
[ -d "$BASE" ] || make-cadir "$BASE"
cd "$BASE"

[ -d pki ] || easyrsa init-pki
[ -f pki/ca.crt ] || EASYRSA_BATCH=1 EASYRSA_REQ_CN="OpenVPN-SSL-CA" easyrsa --batch build-ca nopass
[ -f pki/dh.pem ] || easyrsa gen-dh

SERVER_CN="${SERVICE}-server"
[ -f "pki/issued/${SERVER_CN}.crt" ] || easyrsa --batch build-server-full "${SERVER_CN}" nopass

# 生成 CRL（证书撤销列表）
if [ ! -f pki/crl.pem ]; then
  EASYRSA_BATCH=1 easyrsa gen-crl
fi

# -----------------------
# 安装证书与密钥
# -----------------------
log_info "安装服务端证书、私钥、DH 参数与 CRL..."
CONF_DIR="/etc/openvpn/${SERVICE}"
install -d -m 700 "$CONF_DIR"
install -m 600 -D "$BASE/pki/ca.crt"                   "$CONF_DIR/ca.crt"
install -m 600 -D "$BASE/pki/issued/${SERVER_CN}.crt"  "$CONF_DIR/server.crt"
install -m 600 -D "$BASE/pki/private/${SERVER_CN}.key" "$CONF_DIR/server.key"
install -m 600 -D "$BASE/pki/dh.pem"                   "$CONF_DIR/dh.pem"
install -m 600 -D "$BASE/pki/crl.pem"                  "$CONF_DIR/crl.pem"

# -----------------------
# tls-crypt-v2（替代 ta.key）
# -----------------------
log_info "配置 tls-crypt-v2 控制信道密钥..."
TC2_SERVER_KEY="${CONF_DIR}/tc2-server.key"
if [ ! -f "$TC2_SERVER_KEY" ]; then
  openvpn --genkey tls-crypt-v2-server "$TC2_SERVER_KEY"
  chmod 600 "$TC2_SERVER_KEY"
fi

# -----------------------
# IPv4 / IPv6 出口网卡探测
# -----------------------
OUT_IF="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
if [ -z "${OUT_IF:-}" ]; then
  OUT_IF="$(ip route show default 2>/dev/null | awk '/default/ {for(i=1;i<=NF;i++){if($i=="dev"){print $(i+1); exit}}}')"
fi

OUT_IF6="$(ip -6 route show default 2>/dev/null | awk '{print $5; exit}' || true)"
ENABLE_V6=0
if [ -n "${OUT_IF6:-}" ] && ip6tables -t nat -L >/dev/null 2>&1; then
  ENABLE_V6=1
fi

if [ "$ENABLE_V6" -eq 1 ]; then
  V6_BLOCK='server-ipv6 fd00:beef:1234:5680::/64'
  V6_PUSH=$'push "route-ipv6 ::/0"\npush "dhcp-option DNS6 2606:4700:4700::1111"\npush "dhcp-option DNS6 2606:4700:4700::1001"'
  log_info "检测到 IPv6 出口 ${OUT_IF6}，将启用 IPv6 VPN 网络。"
else
  V6_BLOCK=''
  V6_PUSH=''
  log_info "未启用 IPv6 转发或 NAT，将仅配置 IPv4 VPN 网络。"
fi

# -----------------------
# PAM 插件路径探测（仅当启用 Auth 时用到）
# -----------------------
find_pam_plugin() {
  local cands=(
    "/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"
    "/usr/lib/openvpn/openvpn-plugin-auth-pam.so"
  )
  local p
  for p in "${cands[@]}"; do
    [ -f "$p" ] && { echo "$p"; return 0; }
  done
  # 兜底：通过 dpkg 查询
  local dp
  dp="$(dpkg -L openvpn 2>/dev/null | grep -m1 'openvpn-plugin-auth-pam.so' || true)"
  [ -n "$dp" ] && { echo "$dp"; return 0; }
  return 1
}

AUTH_FLAG=0
if printf '%s' "$AUTH_MODE" | grep -qiE '^auth$'; then
  AUTH_FLAG=1
  PAM_SO="$(find_pam_plugin)" || { log_err "未找到 openvpn PAM 插件库（openvpn-plugin-auth-pam.so）。"; exit 1; }
  log_info "启用证书 + 用户名/密码双因子认证（PAM / 系统账户）..."

  # 生成 /etc/pam.d/openvpn（使用系统账户认证）
  if [ ! -f /etc/pam.d/openvpn ]; then
    install -m 644 /dev/stdin /etc/pam.d/openvpn <<'PAMCFG'
# OpenVPN PAM profile - 基于系统账户（/etc/shadow）
auth     required pam_unix.so
account  required pam_unix.so
PAMCFG
  fi
fi

# -----------------------
# Server 配置（仅 UDP）
# -----------------------
log_info "生成 OpenVPN 服务端配置文件..."
cat > "/etc/openvpn/server/${SERVICE}.conf" <<EOF
port ${PORT}
proto udp
dev tun

server 10.10.0.0 255.255.255.0
${V6_BLOCK}

ca ${CONF_DIR}/ca.crt
cert ${CONF_DIR}/server.crt
key ${CONF_DIR}/server.key
dh ${CONF_DIR}/dh.pem

topology subnet
ifconfig-pool-persist /var/log/openvpn/${SERVICE}-ipp.txt

push "redirect-gateway def1 bypass-dhcp"
${V6_PUSH}

push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"

keepalive 10 120
persist-key
persist-tun

# 控制信道：tls-crypt-v2（更强反探测）
tls-crypt-v2 ${CONF_DIR}/tc2-server.key

# 最小 TLS 1.2，并显式提供 TLS 1.3 套件与现代密钥交换组
tls-version-min 1.2
tls-cert-profile preferred
tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
tls-groups X25519:secp256r1

# 数据信道（AEAD 优先，兼容 DCO 限制）
data-ciphers AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM

# 禁用压缩（Voracle 风险，且 DCO 不支持压缩）
allow-compression no

# 证书撤销列表（CRL）
crl-verify ${CONF_DIR}/crl.pem

# 非特权运行
user nobody
group nogroup

verb 3
status /var/log/openvpn/${SERVICE}-status.log
explicit-exit-notify 1
EOF

# 如果启用 Auth：加载 PAM 插件（证书 + 用户名密码 双因子）
if [ "$AUTH_FLAG" -eq 1 ]; then
  {
    echo "plugin ${PAM_SO} openvpn"
    # 如需仅用户名/密码而无需客户端证书，可改为：
    # echo "client-cert-not-required"
    # echo "username-as-common-name"
  } >> "/etc/openvpn/server/${SERVICE}.conf"
fi

# -----------------------
# sysctl
# -----------------------
log_info "启用内核 IPv4/IPv6 转发..."
install -m 644 /dev/stdin /etc/sysctl.d/99-openvpn-forward.conf <<SYSCTL
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = ${ENABLE_V6}
net.ipv6.conf.default.forwarding = ${ENABLE_V6}
SYSCTL
sysctl --system >/dev/null

# -----------------------
# 防火墙（10.10.0.0/24）+ 放行入站 ${PORT}/udp
# -----------------------
CIDR_V4="10.10.0.0/24"

if [ -n "${OUT_IF:-}" ]; then
  log_info "配置 IPv4 防火墙与 NAT（出口：${OUT_IF}，网段：${CIDR_V4}）..."
  # 入站
  iptables -C INPUT -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p udp --dport "${PORT}" -j ACCEPT
  # 转发/MSS/NAT
  iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  iptables -C FORWARD -s "$CIDR_V4" -j ACCEPT 2>/dev/null || iptables -I FORWARD 2 -s "$CIDR_V4" -j ACCEPT
  iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  iptables -t nat -C POSTROUTING -s "$CIDR_V4" -o "$OUT_IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$CIDR_V4" -o "$OUT_IF" -j MASQUERADE
else
  log_err "无法检测 IPv4 默认出口网卡，未配置 NAT 规则，请手工检查路由与 iptables。"
fi

if [ "$ENABLE_V6" -eq 1 ]; then
  V6CIDR="fd00:beef:1234:5680::/64"
  log_info "配置 IPv6 防火墙与 NAT（出口：${OUT_IF6}，网段：${V6CIDR}）..."
  ip6tables -C INPUT -p udp --dport "${PORT}" -j ACCEPT 2>/dev/null || ip6tables -I INPUT 1 -p udp --dport "${PORT}" -j ACCEPT
  ip6tables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  ip6tables -C FORWARD -s "$V6CIDR" -j ACCEPT 2>/dev/null || ip6tables -I FORWARD 2 -s "$V6CIDR" -j ACCEPT
  ip6tables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || ip6tables -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  if [ -n "${OUT_IF6:-}" ] && ip6tables -t nat -L >/dev/null 2>&1; then
    ip6tables -t nat -C POSTROUTING -s "$V6CIDR" -o "$OUT_IF6" -j MASQUERADE 2>/dev/null || ip6tables -t nat -A POSTROUTING -s "$V6CIDR" -o "$OUT_IF6" -j MASQUERADE
  fi
fi

netfilter-persistent save >/dev/null || true

# -----------------------
# 启动服务
# -----------------------
log_info "启用并重启 OpenVPN 服务..."
systemctl daemon-reload
systemctl enable "openvpn-server@${SERVICE}" >/dev/null
systemctl restart "openvpn-server@${SERVICE}"

# -----------------------
# 客户端配置（仅 UDP）
# 为每个已签发的客户端证书生成独立 ovpn（含 tls-crypt-v2 客户端密钥）。
# 若启用 Auth，会在客户端配置中加入 auth-user-pass。
# -----------------------
log_info "生成基础客户端配置与每个客户端的 .ovpn 文件..."
CLIENT_DIR="$BASE/client-configs/files"
mkdir -p "$CLIENT_DIR"; chmod 700 "$CLIENT_DIR"

SERVER_IP="$(curl -s --fail https://api.ipify.org || true)"
[ -n "$SERVER_IP" ] || SERVER_IP="YOUR_PUBLIC_IP"

BASE_UDP="$BASE/client-configs/base-udp.conf"
cat > "$BASE_UDP" <<EOF
client
dev tun
proto udp
remote ${SERVER_IP} ${PORT}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
tls-version-min 1.2
data-ciphers AES-256-GCM:CHACHA20-POLY1305
data-ciphers-fallback AES-256-GCM
verb 3
EOF

# 若启用 Auth，在客户端配置里启用用户名密码提示
if [ "$AUTH_FLAG" -eq 1 ]; then
  echo "auth-user-pass" >> "$BASE_UDP"
fi

# 为每个客户端生成 tls-crypt-v2 client key，并生成 ovpn
gen_profile() {
  local CN="$1"
  local KEY="$BASE/pki/private/${CN}.key"
  local CRT="$BASE/pki/issued/${CN}.crt"
  local OUT="$CLIENT_DIR/${CN}-udp.ovpn"
  [ -f "$KEY" ] && [ -f "$CRT" ] || return 0

  local TC2="$CLIENT_DIR/${CN}-tc2-client.key"
  if [ ! -f "$TC2" ]; then
    # 按官方推荐：用服务端 tls-crypt-v2 key 包裹客户端专用 key
    openvpn --tls-crypt-v2 "${TC2_SERVER_KEY}" --genkey tls-crypt-v2-client "$TC2"
    chmod 600 "$TC2"
  fi

  {
    cat "$BASE_UDP"
    echo "<ca>";           cat "$BASE/pki/ca.crt";          echo "</ca>"
    echo "<cert>";         cat "$CRT";                      echo "</cert>"
    echo "<key>";          cat "$KEY";                      echo "</key>"
    echo "<tls-crypt-v2>"; cat "$TC2";                      echo "</tls-crypt-v2>"
  } > "$OUT"
  chmod 600 "$OUT"
}

shopt -s nullglob
for crt in "$BASE/pki/issued/"*.crt; do
  CN="$(basename "$crt" .crt)"
  [[ "$CN" == *server* ]] && continue
  gen_profile "$CN"
done
shopt -u nullglob

log_ok "${SERVICE} 已启动，端口 ${PORT}${AUTH_FLAG:+，已启用用户名/密码认证（PAM）}。"
log_ok "客户端配置目录：${CLIENT_DIR}"
if [ "$AUTH_FLAG" -eq 1 ]; then
  log_info "如启用了 Auth，请使用系统账户（/etc/passwd）凭据登录；可用 adduser 创建或管理。"
fi

if [ "$DCO_AVAILABLE" -eq 1 ]; then
  log_info "提示：服务器侧已具备 DCO 能力，OpenVPN 2.6 会在条件满足时自动启用内核数据通道加速。"
fi

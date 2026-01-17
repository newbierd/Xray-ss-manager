#!/usr/bin/env bash
# ============================================================
#  Xray + Shadowsocks/SS2022 管理脚本（安装 / 卸载 / 无人值守）
# ============================================================
# 功能概述：
#  1) 交互式菜单：可选择安装或卸载
#  2) 安装：自动安装 Xray、创建/追加 inbound、安装 systemd/OpenRC 服务
#  3) 安装完成：同时输出两种 ss:// 分享链接（类型1/类型2），并保存到 /root/xray_ss_link.txt
#  4) 卸载：停止并移除 systemd/OpenRC 服务、备份并删除配置与二进制、可选彻底清理用户组
#  5) 无人值守：支持完全不交互批量部署（--non-interactive / -n）
#
# 默认行为（安装）：
#  - 默认端口：40000（可用 -p/--port 指定）
#  - 默认协议：ss2022
#  - 默认加密：2022-blake3-chacha20-poly1305（32 字节密钥）
#  - 默认密码：若未指定则自动生成随机 Base64（32 字节）
#  - 默认分享地址：若未指定域名/IP，则自动探测公网 IPv4（失败则用 <SERVER_IP>）
#  - 默认分享标签(tag)：若未指定则为 xray-<协议>（例如 xray-ss2022）
#
# 参数说明：
#  动作：
#    install | --install | -i               执行安装/追加入站
#    uninstall | --uninstall | -u           执行卸载
#
#  卸载可选：
#    --purge                                卸载同时尝试删除 xray 用户与组（默认保留）
#
#  安装可选（交互/无人值守均可用）：
#    -n | --non-interactive                 无人值守（不询问，直接使用默认值或参数值）
#    -p <端口> | --port <端口>              指定端口（默认 40000；无人值守建议用 -p 指定）
#    -d <域名或IP> | --domain <域名或IP>    指定写入分享链接的域名/IP（不影响实际监听）
#    --password <密码>                      指定密码（建议传 Base64；脚本不做格式校验）
#    -t <标签> | --tag <标签>               指定输出分享链接的 tag（# 后的备注；不影响服务端配置）
#
# 分享链接输出说明：
#  安装完成后会同时输出两条 ss:// 链接，并写入 /root/xray_ss_link.txt：
#   - 类型1：明文 method + URL 编码 password
#     ss://method:URLEncoded(password)@host:port#tag
#   - 类型2：SIP002 Base64（更通用）
#     ss://BASE64(method:password@host:port)#tag
#
# 重要路径：
#  - 二进制：/usr/local/bin/xray
#  - 配置： /usr/local/etc/xray/config.json
#  - 卸载备份：/root/xray-config-backup-<时间>.tar.gz
#  - 分享链接记录：/root/xray_ss_link.txt
# ============================================================

set -euo pipefail

# -------------------- 基础工具函数 --------------------
die()  { echo -e "\e[31m[错误]\e[0m $*" >&2; exit 1; }
info() { echo -e "\e[32m[信息]\e[0m $*"; }
warn() { echo -e "\e[33m[警告]\e[0m $*"; }
note() { echo -e "\e[34m[提示]\e[0m $*"; }

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "请以 root 身份运行（建议使用 sudo）。"
  fi
}

usage() {
  cat <<'EOF'
用法：
  ./xray_ss_manager.sh                         # 交互式菜单
  ./xray_ss_manager.sh install                 # 交互安装（默认端口 40000，默认 ss2022 + chacha20）
  ./xray_ss_manager.sh uninstall               # 卸载（保留 xray 用户/组）
  ./xray_ss_manager.sh uninstall --purge       # 卸载并删除 xray 用户/组

无人值守安装（推荐）：
  sudo ./xray_ss_manager.sh install -n
  sudo ./xray_ss_manager.sh install -n -p 30833
  sudo ./xray_ss_manager.sh install -n -d example.com
  sudo ./xray_ss_manager.sh install -n --password '你的Base64密码'
  sudo ./xray_ss_manager.sh install -n -p 30833 -d example.com --password '你的Base64密码' -t 'niubi-ss2022'

可选参数（安装）：
  -n, --non-interactive                 无人值守（不询问）
  -d <域名或IP>, --domain <域名或IP>     指定用于分享链接的域名/IP（不填则自动探测公网 IP）
  --password <密码>                      指定密码（不填则自动生成随机 Base64）
  -p <端口>, --port <端口>               指定端口（默认 40000；无人值守下可用 -p 指定）
  -t <标签>, --tag <标签>                指定分享链接的 tag（# 后面的备注，不影响服务端配置）

别名：
  install   = --install, -i
  uninstall = --uninstall, -u
  --help, -h
EOF
}

# -------------------- 默认值 --------------------
DEFAULT_PORT="40000"
DEFAULT_PROTOCOL="ss2022"
DEFAULT_METHOD="2022-blake3-chacha20-poly1305"
DEFAULT_KEY_BYTES=32

# -------------------- 运行参数 --------------------
ACTION=""
PURGE="false"
NON_INTERACTIVE="false"
DOMAIN=""
PASSWORD=""
PORT="$DEFAULT_PORT"
SHARE_TAG=""

# -------------------- 安装逻辑 --------------------
detect_os() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID,,}"
  else
    die "无法检测系统类型（缺少 /etc/os-release）。"
  fi

  case "$OS_ID" in
    debian|ubuntu) OS_FAMILY="debian" ;;
    alpine)        OS_FAMILY="alpine" ;;
    *)             die "当前系统不受支持：$OS_ID（仅支持 Debian/Ubuntu/Alpine）。" ;;
  esac

  info "检测到系统：${PRETTY_NAME:-$OS_ID}"
}

install_deps() {
  case "$OS_FAMILY" in
    debian)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip xz-utils openssl python3 jq net-tools iproute2
      ;;
    alpine)
      apk add --no-cache ca-certificates curl unzip xz openssl python3 jq iproute2 net-tools
      ;;
  esac
}

ensure_xray_user() {
  if id -u xray >/dev/null 2>&1; then return; fi
  case "$OS_FAMILY" in
    debian) adduser --system --no-create-home --shell /usr/sbin/nologin --group xray ;;
    alpine) addgroup -S xray || true; adduser -S -H -s /sbin/nologin -G xray xray ;;
  esac
}

port_in_config_inuse() {
  local cfg="/usr/local/etc/xray/config.json" p="$1"
  [[ -s "$cfg" ]] || return 1
  jq -e --argjson p "$p" '
    try (
      if .inbounds == null then
        false
      elif (.inbounds|type)!="array" then
        (.inbounds.port? // empty) == $p
      else
        any(.inbounds[]?; (.port? // empty) == $p)
      end
    ) catch false
  ' "$cfg" >/dev/null 2>&1
}

port_in_system_inuse() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    return 1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)"
    return $?
  else
    return 1
  fi
}

read_port_interactive() {
  local input
  read -rp "请输入入站端口（1-65535，默认 ${DEFAULT_PORT}）： " input || true
  input="${input:-$DEFAULT_PORT}"
  [[ "$input" =~ ^[0-9]+$ ]] && (( input>=1 && input<=65535 )) || die "端口无效：$input"
  echo "$input"
}

select_port() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    local p="$PORT"
    if port_in_config_inuse "$p"; then
      die "无人值守模式：端口 $p 已在 Xray 现有配置 inbounds 中使用，请更换端口（-p/--port）或先调整配置。"
    fi
    if port_in_system_inuse "$p"; then
      die "无人值守模式：端口 $p 已被其它进程监听（TCP/UDP），请释放端口或使用 -p/--port 指定其它端口。"
    fi
    IN_PORT="$p"
    info "无人值守：使用端口 ${IN_PORT}"
    return
  fi

  while :; do
    local p; p="$(read_port_interactive)"
    if port_in_config_inuse "$p"; then
      warn "端口 $p 已在 Xray 现有配置 inbounds 中使用，请换一个。"
      continue
    fi
    if port_in_system_inuse "$p"; then
      warn "端口 $p 已被系统中其它进程监听（TCP/UDP），请换一个。"
      continue
    fi
    IN_PORT="$p"
    info "将使用端口：$IN_PORT"
    break
  done
}

install_xray() {
  local arch machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64)   arch="64" ;;
    aarch64|arm64)  arch="arm64-v8a" ;;
    *) die "不支持的 CPU 架构：$machine" ;;
  esac

  local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
  info "获取 Xray 最新版本信息..."
  local tag
  tag="$(curl -fsSL "$api" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4)" || true
  [[ -n "${tag:-}" ]] && info "最新版本：$tag" || warn "无法从 GitHub API 获取最新版本，将使用 latest 直链"

  local tmpdir
  tmpdir="$(mktemp -d)"
  # 修复点：在 set -u 下，trap 引用变量必须做防御；同时仅在目录存在时删除
  trap 'if [[ -n "${tmpdir:-}" && -d "${tmpdir:-}" ]]; then rm -rf "$tmpdir"; fi' EXIT

  local zipname="Xray-linux-${arch}.zip"
  local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
  local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

  info "下载 Xray（${zipname}）..."
  if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then :; \
  elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then :; else die "下载 Xray 失败。"; fi

  info "解压并安装到 /usr/local/bin ..."
  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir"
  install -m 0755 "$tmpdir/xray" /usr/local/bin/xray

  ensure_xray_user
  mkdir -p /usr/local/etc/xray
  chown -R xray:xray /usr/local/etc/xray
}

select_protocol_and_method() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    PROTOCOL="$DEFAULT_PROTOCOL"
    METHOD="$DEFAULT_METHOD"
    KEY_BYTES="$DEFAULT_KEY_BYTES"
    info "无人值守：协议=${PROTOCOL}，加密=${METHOD}"
    return
  fi

  echo
  echo "================ 请选择协议类型（默认：2） ================"
  echo "  1) Shadowsocks（ss）"
  echo "  2) Shadowsocks 2022（ss2022）"
  echo "==========================================================="
  local sel
  read -rp "请输入编号（1/2，默认 2）： " sel || true
  sel="${sel:-2}"

  case "$sel" in
    1) PROTOCOL="ss";     info "已选择：ss" ;;
    2) PROTOCOL="ss2022"; info "已选择：ss2022" ;;
    *) die "输入无效：必须是 1 或 2。" ;;
  esac

  if [[ "$PROTOCOL" == "ss2022" ]]; then
    echo
    echo "================ SS2022 加密方式（默认：3） ================"
    echo "  1) 2022-blake3-aes-128-gcm（16 字节密钥）"
    echo "  2) 2022-blake3-aes-256-gcm（32 字节密钥）"
    echo "  3) 2022-blake3-chacha20-poly1305（32 字节密钥）"
    echo "==========================================================="
    local msel
    read -rp "请输入编号（1/2/3，默认 3）： " msel || true
    msel="${msel:-3}"
    case "$msel" in
      1) METHOD="2022-blake3-aes-128-gcm";       KEY_BYTES=16 ;;
      2) METHOD="2022-blake3-aes-256-gcm";       KEY_BYTES=32 ;;
      3) METHOD="2022-blake3-chacha20-poly1305"; KEY_BYTES=32 ;;
      *) die "输入无效：必须是 1/2/3。" ;;
    esac
  else
    echo
    echo "================ ss 加密方式（默认：2） ==================="
    echo "  1) aes-128-gcm（16 字节密钥）"
    echo "  2) aes-256-gcm（32 字节密钥）"
    echo "  3) chacha20-ietf-poly1305（32 字节密钥）"
    echo "==========================================================="
    local msel
    read -rp "请输入编号（1/2/3，默认 2）： " msel || true
    msel="${msel:-2}"
    case "$msel" in
      1) METHOD="aes-128-gcm";            KEY_BYTES=16 ;;
      2) METHOD="aes-256-gcm";            KEY_BYTES=32 ;;
      3) METHOD="chacha20-ietf-poly1305"; KEY_BYTES=32 ;;
      *) die "输入无效：必须是 1/2/3。" ;;
    esac
  fi

  info "最终选择：协议=${PROTOCOL}，加密=${METHOD}"
}

# 新增：交互式安装过程中引导指定分享 tag（仅影响链接 #tag，不影响服务端）
prompt_share_tag_interactive() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    return 0
  fi
  if [[ -n "${SHARE_TAG:-}" ]]; then
    return 0
  fi

  local default_tag="xray-${PROTOCOL:-ss2022}"
  local input

  echo
  echo "================ 分享链接标签（tag）设置 ================"
  echo "说明：tag 仅用于分享链接中的 #tag 备注，不影响服务端监听与配置。"
  read -rp "请输入分享链接的 tag（默认：${default_tag}）： " input || true
  input="$(echo -n "${input:-}" | awk '{$1=$1;print}')"
  SHARE_TAG="${input:-$default_tag}"

  info "将使用分享链接 tag：${SHARE_TAG}"
}

generate_or_read_password() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ -n "${PASSWORD:-}" ]]; then
      PSK="$PASSWORD"
      info "无人值守：使用你指定的密码。"
    else
      PSK="$(openssl rand -base64 "$DEFAULT_KEY_BYTES" | tr -d '\n')"
      [[ -n "$PSK" ]] || die "密码生成失败。"
      info "无人值守：已自动生成随机密码（Base64，${DEFAULT_KEY_BYTES} 字节）。"
    fi
    return
  fi

  echo
  echo "================ 密码设置 ================="
  local input
  read -rp "请输入密码（留空则自动生成随机 Base64）： " input || true
  input="$(echo -n "${input:-}" | awk '{$1=$1;print}')"

  if [[ -n "$input" ]]; then
    PSK="$input"
    info "使用你输入的密码。"
  else
    PSK="$(openssl rand -base64 "$KEY_BYTES" | tr -d '\n')"
    [[ -n "$PSK" ]] || die "密码生成失败。"
    info "已自动生成随机密码（Base64，${KEY_BYTES} 字节）。"
  fi
}

backup_config_if_exists() {
  local cfg="/usr/local/etc/xray/config.json"
  if [[ -s "$cfg" ]]; then
    local ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="/root/xray-config-backup-${ts}.json"
    cp -a "$cfg" "$backup"
    info "已备份现有配置：$backup"
  fi
}

generate_unique_inbound_tag() {
  local cfg="/usr/local/etc/xray/config.json"
  local base="ss-in-${IN_PORT}"
  INBOUND_TAG="$base"

  if [[ -s "$cfg" ]] && jq empty "$cfg" >/dev/null 2>&1; then
    if jq -e --arg t "$INBOUND_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) != null' "$cfg" >/dev/null; then
      local n=2
      while :; do
        INBOUND_TAG="${base}-${n}"
        jq -e --arg t "$INBOUND_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) == null' "$cfg" >/dev/null && break
        n=$((n+1))
      done
    fi
  fi
  info "将使用 inbound tag：$INBOUND_TAG"
}

write_or_append_config() {
  local cfg="/usr/local/etc/xray/config.json"

  local new_inbound
  new_inbound="$(cat <<EOF
{
  "port": ${IN_PORT},
  "protocol": "shadowsocks",
  "settings": {
    "method": "${METHOD}",
    "password": "${PSK}",
    "network": "tcp,udp"
  },
  "tag": "${INBOUND_TAG}"
}
EOF
)"

  if [[ -s "$cfg" ]]; then
    info "检测到已有 Xray 配置，将追加一个入站（inbound）..."
    jq empty "$cfg" >/dev/null 2>&1 || die "现有配置不是有效 JSON，请检查：$cfg"

    local tmp; tmp="$(mktemp)"
    jq --argjson inbound "$new_inbound" '
      if .inbounds == null then
        .inbounds = [$inbound]
      elif (.inbounds|type) != "array" then
        .inbounds = [ .inbounds, $inbound ]
      else
        .inbounds += [ $inbound ]
      end
    ' "$cfg" > "$tmp"
    mv "$tmp" "$cfg"
    info "已成功追加 inbound。"
  else
    info "未检测到现有配置，将生成新的配置文件..."
    cat > "$cfg" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [ $new_inbound ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
  fi

  chown xray:xray "$cfg"
  chmod 0644 "$cfg"
  info "配置已写入：$cfg"
}

install_systemd_service() {
  cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray 服务
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray -config /usr/local/etc/xray/config.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now xray
}

install_openrc_service() {
  cat >/etc/init.d/xray <<'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray 服务"
command="/usr/local/bin/xray"
command_args="-config /usr/local/etc/xray/config.json"
command_user="xray:xray"
command_background=true
pidfile="/run/xray.pid"
start_stop_daemon_args="--make-pidfile --background"

depend() {
  need net
  use dns
}

start_pre() {
  checkpath --directory --owner ${command_user} /run
}
EOF
  chmod +x /etc/init.d/xray
  rc-update add xray default
  rc-service xray restart || rc-service xray start
}

setup_service() {
  if command -v systemctl >/dev/null 2>&1; then
    install_systemd_service
  elif command -v rc-update >/dev/null 2>&1; then
    install_openrc_service
  else
    die "未检测到 systemd 或 OpenRC，无法安装服务。"
  fi
}

determine_server_addr() {
  if [[ -n "${DOMAIN:-}" ]]; then
    SERVER_ADDR="$DOMAIN"
    info "使用指定域名/IP：$SERVER_ADDR"
    return
  fi

  if [[ "$NON_INTERACTIVE" != "true" ]]; then
    local input
    read -rp "请输入要写入分享链接的域名或IP（留空则自动探测公网 IP）： " input || true
    input="$(echo -n "${input:-}" | awk '{$1=$1;print}')"
    if [[ -n "$input" ]]; then
      SERVER_ADDR="${input,,}"
      info "将使用：$SERVER_ADDR"
      return
    fi
  fi

  local ipv4=""
  ipv4="$(curl -fsSL http://api.ipify.org || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ip.sb || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ifconfig.me || true)"
  [[ -n "$ipv4" ]] || ipv4="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  SERVER_ADDR="${ipv4:-<SERVER_IP>}"

  if [[ "$SERVER_ADDR" = "<SERVER_IP>" ]]; then
    warn "未能自动探测公网 IP，请手动替换分享链接中的 <SERVER_IP>。"
  else
    info "自动探测到公网 IP：$SERVER_ADDR"
  fi
}

print_links_and_save() {
  local tag_raw="${SHARE_TAG:-xray-${PROTOCOL:-ss2022}}"

  local enc_pw tag_enc
  enc_pw="$(python3 - <<'PY'
import urllib.parse, os
print(urllib.parse.quote(os.environ.get("PW",""), safe=''))
PY
)"
  tag_enc="$(python3 - <<'PY'
import urllib.parse, os
print(urllib.parse.quote(os.environ.get("TAG","xray-ss2022"), safe=''))
PY
)"

  local uri_plain="ss://${METHOD}:${enc_pw}@${SERVER_ADDR}:${IN_PORT}#${tag_enc}"

  local b64_userinfo
  b64_userinfo="$(python3 - <<'PY'
import base64, os
method = os.environ.get("METHOD","")
pw = os.environ.get("PW","")
host = os.environ.get("HOST","")
port = os.environ.get("PORT","")
s = f"{method}:{pw}@{host}:{port}".encode("utf-8")
print(base64.urlsafe_b64encode(s).decode("utf-8").rstrip("="))
PY
)"
  local uri_sip002="ss://${b64_userinfo}#${tag_enc}"

  echo
  echo "================ 安装结果（关键信息） ================"
  echo "协议/实现     : Xray inbound (shadowsocks)"
  echo "加密方式      : ${METHOD}"
  echo "端口          : ${IN_PORT}"
  echo "入站Tag       : ${INBOUND_TAG}"
  echo "分享备注(tag) : ${tag_raw}"
  echo "密码(Base64)  : ${PSK}"
  echo "服务器        : ${SERVER_ADDR}"
  echo
  echo "【类型1】明文 method + URL 编码 password："
  echo "${uri_plain}"
  echo
  echo "【类型2】SIP002 Base64（ss://BASE64(method:password@host:port)#tag）："
  echo "${uri_sip002}"
  echo "======================================================"

  local link_file="/root/xray_ss_link.txt"
  {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]"
    echo "类型1（明文+URL编码密码）：$uri_plain"
    echo "类型2（SIP002 Base64）：   $uri_sip002"
    echo
  } >> "$link_file"
  info "已保存两种分享链接到：$link_file"
}

restart_and_show_status() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart xray || true
    systemctl status xray --no-pager -l || true
  else
    rc-service xray restart || true
    rc-service xray status || true
  fi
}

run_install() {
  require_root
  detect_os
  install_deps
  select_port
  install_xray
  select_protocol_and_method
  prompt_share_tag_interactive
  generate_or_read_password
  backup_config_if_exists
  generate_unique_inbound_tag
  write_or_append_config
  setup_service
  determine_server_addr

  PW="$PSK" TAG="${SHARE_TAG:-xray-${PROTOCOL:-ss2022}}" METHOD="$METHOD" HOST="$SERVER_ADDR" PORT="$IN_PORT" \
    print_links_and_save

  restart_and_show_status

  echo
  info "安装完成。常用命令："
  if command -v systemctl >/dev/null 2>&1; then
    echo "  systemctl status xray"
    echo "  journalctl -u xray -e"
  else
    echo "  rc-service xray status"
    echo "  rc-service xray restart"
  fi
}

# -------------------- 卸载逻辑 --------------------
has_systemd() { command -v systemctl >/dev/null 2>&1; }

collect_systemd_units() {
  has_systemd || return 0
  systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -E '.*xray.*\.service$' || true
  systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -E '.*xray.*\.service$' || true
  for f in /etc/systemd/system/*xray*.service /lib/systemd/system/*xray*.service /usr/lib/systemd/system/*xray*.service; do
    [[ -f "$f" ]] && basename "$f"
  done
}

stop_disable_systemd_units() {
  has_systemd || { warn "未检测到 systemd。"; return 0; }

  mapfile -t units < <(collect_systemd_units | awk 'NF && !seen[$0]++')
  if ((${#units[@]}==0)); then
    warn "未检测到已注册的 Xray systemd 服务。"
    return 0
  fi

  info "将停止并禁用以下 systemd 单元："
  for u in "${units[@]}"; do echo "  - $u"; done

  for u in "${units[@]}"; do
    systemctl stop "$u" --no-block 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true
    systemctl reset-failed "$u" 2>/dev/null || true
  done

  for wants in /etc/systemd/system/*/*xray*.service; do
    [[ -L "$wants" || -f "$wants" ]] && { info "移除残留链接/文件：$wants"; rm -f "$wants" || true; }
  done
}

remove_systemd_files() {
  has_systemd || return 0
  local removed=false
  for f in /etc/systemd/system/*xray*.service /lib/systemd/system/*xray*.service /usr/lib/systemd/system/*xray*.service; do
    if [[ -f "$f" ]]; then
      info "删除 systemd 单元文件：$f"
      rm -f "$f" || true
      removed=true
    fi
  done
  $removed && systemctl daemon-reload || true
}

stop_remove_openrc() {
  if command -v rc-update >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    info "检测到 OpenRC 服务，停止并取消开机自启..."
    rc-service xray stop || true
    rc-update del xray default || true
  else
    warn "未检测到 OpenRC 的 Xray 服务。"
  fi
}

remove_openrc_files() {
  [[ -f /etc/init.d/xray ]] && { info "删除 OpenRC 脚本：/etc/init.d/xray"; rm -f /etc/init.d/xray || true; }
  [[ -f /run/xray.pid ]] && rm -f /run/xray.pid || true
}

backup_and_remove_config_dir() {
  local cfg_dir="/usr/local/etc/xray"
  if [[ -d "$cfg_dir" ]]; then
    local ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="/root/xray-config-backup-${ts}.tar.gz"
    info "备份配置目录到：$backup"
    tar -czf "$backup" -C "$(dirname "$cfg_dir")" "$(basename "$cfg_dir")" || true
    info "删除配置目录：$cfg_dir"
    rm -rf "$cfg_dir" || true
    note "备份已保存：$backup"
  else
    warn "未找到配置目录：$cfg_dir"
  fi
}

remove_binary_and_logs() {
  local bin="/usr/local/bin/xray"
  [[ -f "$bin" ]] && { info "删除二进制文件：$bin"; rm -f "$bin" || true; } || warn "未找到二进制：$bin"

  for d in /usr/local/share/xray /usr/share/xray /var/lib/xray; do
    [[ -d "$d" ]] && { info "删除目录：$d"; rm -rf "$d" || true; }
  done

  for f in /var/log/xray.log /var/log/xray/xray.log; do
    [[ -f "$f" ]] && { info "删除日志：$f"; rm -f "$f" || true; }
  done
  [[ -d /var/log/xray ]] && { info "删除日志目录：/var/log/xray"; rm -rf /var/log/xray || true; }
}

remove_user_group_if_purge() {
  local purge="$1"
  if [[ "$purge" != "true" ]]; then
    info "保留 xray 用户/组（未使用 --purge）。"
    return 0
  fi

  info "执行 --purge：尝试删除 xray 用户与组..."
  pkill -u xray 2>/dev/null || true

  if command -v deluser >/dev/null 2>&1; then
    deluser xray 2>/dev/null || true
  elif command -v userdel >/dev/null 2>&1; then
    userdel xray 2>/dev/null || true
  fi

  if command -v delgroup >/dev/null 2>&1; then
    delgroup xray 2>/dev/null || true
  elif command -v groupdel >/dev/null 2>&1; then
    groupdel xray 2>/dev/null || true
  fi
}

run_uninstall() {
  local purge="$1"
  require_root

  (
    set +e
    set -u -o pipefail

    stop_disable_systemd_units
    remove_systemd_files
    stop_remove_openrc
    remove_openrc_files
    backup_and_remove_config_dir
    remove_binary_and_logs
    remove_user_group_if_purge "$purge"
    has_systemd && systemctl daemon-reload || true

    echo
    echo "================ 卸载完成 ================"
    echo "已停止并移除服务、删除二进制与配置（配置已备份到 /root）。"
    if [[ "$purge" == "true" ]]; then
      echo "已尝试删除 xray 用户/组。"
    else
      echo "保留 xray 用户/组（如需删除，请使用 uninstall --purge）。"
    fi
    echo "=========================================="
  )
}

# -------------------- 参数解析/交互菜单 --------------------
if [[ $# -gt 0 ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      install|--install|-i) ACTION="install"; shift ;;
      uninstall|--uninstall|-u) ACTION="uninstall"; shift ;;
      --purge) PURGE="true"; shift ;;
      -n|--non-interactive) NON_INTERACTIVE="true"; shift ;;
      --domain|-d)
        shift; [[ $# -gt 0 ]] || die "-d/--domain 需要参数"
        DOMAIN="$1"; shift ;;
      --tag|-t)
        shift; [[ $# -gt 0 ]] || die "-t/--tag 需要参数"
        SHARE_TAG="$1"; shift ;;
      --password)
        shift; [[ $# -gt 0 ]] || die "--password 需要参数"
        PASSWORD="$1"; shift ;;
      --port|-p)
        shift; [[ $# -gt 0 ]] || die "-p/--port 需要参数"
        PORT="$1"; shift ;;
      --help|-h) usage; exit 0 ;;
      *) die "未知参数：$1（使用 --help 查看用法）。" ;;
    esac
  done
else
  echo
  echo "================ Xray SS 管理脚本 ================"
  echo "  1) 安装（默认端口 ${DEFAULT_PORT}，默认 ss2022 + chacha20）"
  echo "  2) 卸载（保留 xray 用户/组）"
  echo "  3) 卸载（--purge：同时删除 xray 用户/组）"
  echo "  0) 退出"
  echo "=================================================="
  read -rp "请输入编号（0/1/2/3）： " choice || true
  case "${choice:-}" in
    1) ACTION="install" ;;
    2) ACTION="uninstall" ;;
    3) ACTION="uninstall"; PURGE="true" ;;
    0) exit 0 ;;
    *) die "输入无效：必须是 0/1/2/3。" ;;
  esac
fi

# 端口参数校验
if [[ "$ACTION" == "install" ]]; then
  [[ "$PORT" =~ ^[0-9]+$ ]] && (( PORT>=1 && PORT<=65535 )) || die "端口无效：$PORT"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    info "无人值守模式已启用：端口=${PORT}，默认协议=${DEFAULT_PROTOCOL}，默认加密=${DEFAULT_METHOD}"
    [[ -n "${DOMAIN:-}" ]] && info "无人值守：分享域名/IP=${DOMAIN}"
    [[ -n "${SHARE_TAG:-}" ]] && info "无人值守：分享tag=${SHARE_TAG}"
    [[ -n "${PASSWORD:-}" ]] && info "无人值守：使用指定密码（已接收）"
  fi
fi

# -------------------- 动作执行 --------------------
case "$ACTION" in
  install)   run_install ;;
  uninstall) run_uninstall "$PURGE" ;;
  *) usage; exit 1 ;;
esac

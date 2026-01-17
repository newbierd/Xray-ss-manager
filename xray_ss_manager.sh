#!/usr/bin/env bash
# ============================================================
#  Xray + Shadowsocks/SS2022 管理脚本（安装 / 卸载 / 无人值守）
# ============================================================
# 功能概述：
#  1) 交互式菜单：可选择安装或卸载
#  2) 安装：自动安装 Xray、创建/追加 inbound、安装 systemd/OpenRC 服务、输出并保存分享链接
#  3) 卸载：停止并移除 systemd/OpenRC 服务、备份并删除配置与二进制、可选彻底清理用户组
#  4) 无人值守：支持完全不交互批量部署（--non-interactive / -n）
#
# 默认行为（安装）：
#  - 默认端口：40000（可用 -p/--port 指定）
#  - 默认协议：ss2022
#  - 默认加密：2022-blake3-chacha20-poly1305（32 字节密钥）
#  - 默认密码：若未指定则自动生成随机 Base64（32 字节）
#  - 默认分享地址：若未指定域名/IP，则自动探测公网 IPv4（探测失败则用 <SERVER_IP>）
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
# 用法示例：
#  交互式菜单：
#    sudo ./xray_ss_manager.sh
#
#  交互安装（默认端口 40000；默认 ss2022 + chacha20）：
#    sudo ./xray_ss_manager.sh install
#
#  无人值守安装（全默认）：
#    sudo ./xray_ss_manager.sh install -n
#
#  无人值守安装（自定义端口 + 自定义域名 + 自定义密码 + 自定义 tag）：
#    sudo ./xray_ss_manager.sh install -n -p 30833 -d example.com --password '你的Base64密码' -t 'niubi-ss2022'
#
#  卸载（保留用户组）：
#    sudo ./xray_ss_manager.sh uninstall
#
#  卸载（彻底清理用户组）：
#    sudo ./xray_ss_manager.sh uninstall --purge
#
#  重要路径：
#    二进制：/usr/local/bin/xray
#    配置： /usr/local/etc/xray/config.json
#    卸载备份：/root/xray-config-backup-<时间>.tar.gz
#    分享链接记录：/root/xray_ss_link.txt
# ============================================================

set -euo pipefail

# -------------------- 基础工具函数 --------------------
报错退出() { echo -e "\e[31m[错误]\e[0m $*" >&2; exit 1; }
信息提示() { echo -e "\e[32m[信息]\e[0m $*"; }
警告提示() { echo -e "\e[33m[警告]\e[0m $*"; }
普通提示() { echo -e "\e[34m[提示]\e[0m $*"; }

必须root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    报错退出 "请以 root 身份运行（建议使用 sudo）。"
  fi
}

用法() {
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

# -------------------- 全局默认值 --------------------
默认端口="40000"
默认协议="ss2022"
默认加密="2022-blake3-chacha20-poly1305"
默认密钥字节=32

# 运行参数（可被 CLI 覆盖）
动作=""
是否彻底清理="false"
无人值守="false"
指定域名或IP=""
指定密码=""
指定端口="$默认端口"
指定分享标签=""

# -------------------- 安装逻辑（命名空间 install_） --------------------
install_检测系统() {
  if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    INSTALL_OS_ID="${ID,,}"
  else
    报错退出 "无法检测系统类型（缺少 /etc/os-release）。"
  fi
  case "$INSTALL_OS_ID" in
    debian|ubuntu) INSTALL_OS_FAMILY="debian" ;;
    alpine)        INSTALL_OS_FAMILY="alpine" ;;
    *)             报错退出 "当前系统不受支持：$INSTALL_OS_ID（仅支持 Debian/Ubuntu/Alpine）。" ;;
  esac
  信息提示 "检测到系统：${PRETTY_NAME:-$INSTALL_OS_ID}"
}

install_安装依赖() {
  case "$INSTALL_OS_FAMILY" in
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

install_创建xray用户() {
  if id -u xray >/dev/null 2>&1; then return; fi
  case "$INSTALL_OS_FAMILY" in
    debian) adduser --system --no-create-home --shell /usr/sbin/nologin --group xray ;;
    alpine) addgroup -S xray || true; adduser -S -H -s /sbin/nologin -G xray xray ;;
  esac
}

install_端口是否在配置中占用() {
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

install_端口是否被系统监听() {
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

install_交互读取端口() {
  local input
  read -rp "请输入入站端口（1-65535，默认 ${默认端口}）： " input || true
  input="${input:-$默认端口}"
  [[ "$input" =~ ^[0-9]+$ ]] && (( input>=1 && input<=65535 )) || 报错退出 "端口无效：$input"
  echo "$input"
}

install_选择端口并校验() {
  # 无人值守：使用指定端口（默认 40000 或 -p/--port 覆盖），若冲突则直接失败
  if [[ "$无人值守" == "true" ]]; then
    local p="$指定端口"
    if install_端口是否在配置中占用 "$p"; then
      报错退出 "无人值守模式：端口 $p 已在 Xray 现有配置 inbounds 中使用，请更换端口（-p/--port）或先调整配置。"
    fi
    if install_端口是否被系统监听 "$p"; then
      报错退出 "无人值守模式：端口 $p 已被其它进程监听（TCP/UDP），请释放端口或使用 -p/--port 指定其它端口。"
    fi
    INSTALL_SS_PORT="$p"
    信息提示 "无人值守：使用端口 ${INSTALL_SS_PORT}"
    return
  fi

  # 交互模式：可反复输入直到找到空闲端口（默认 40000）
  while :; do
    local p; p="$(install_交互读取端口)"
    if install_端口是否在配置中占用 "$p"; then
      警告提示 "端口 $p 已在 Xray 现有配置 inbounds 中使用，请换一个。"
      continue
    fi
    if install_端口是否被系统监听 "$p"; then
      警告提示 "端口 $p 已被系统中其它进程监听（TCP/UDP），请换一个。"
      continue
    fi
    INSTALL_SS_PORT="$p"
    信息提示 "将使用端口：$INSTALL_SS_PORT"
    break
  done
}

install_安装xray二进制() {
  local arch machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64)   arch="64" ;;
    aarch64|arm64)  arch="arm64-v8a" ;;
    *) 报错退出 "不支持的 CPU 架构：$machine" ;;
  esac

  local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
  信息提示 "获取 Xray 最新版本信息..."
  local tag
  tag="$(curl -fsSL "$api" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4)" || true
  [[ -n "${tag:-}" ]] && 信息提示 "最新版本：$tag" || 警告提示 "无法从 GitHub API 获取最新版本，将使用 latest 直链"

  local tmpdir=""
  tmpdir="$(mktemp -d)"
  trap 'test -n "${tmpdir:-}" && rm -rf "$tmpdir"' EXIT

  local zipname="Xray-linux-${arch}.zip"
  local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
  local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

  信息提示 "下载 Xray（${zipname}）..."
  if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then :; \
  elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then :; else 报错退出 "下载 Xray 失败。"; fi

  信息提示 "解压并安装到 /usr/local/bin ..."
  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir"
  install -m 0755 "$tmpdir/xray" /usr/local/bin/xray

  install_创建xray用户
  mkdir -p /usr/local/etc/xray
  chown -R xray:xray /usr/local/etc/xray
}

install_确定协议与加密() {
  # 无人值守：直接使用默认（ss2022 + 2022-blake3-chacha20-poly1305）
  if [[ "$无人值守" == "true" ]]; then
    INSTALL_PROTOCOL="$默认协议"
    INSTALL_SS_METHOD="$默认加密"
    INSTALL_KEY_BYTES="$默认密钥字节"
    信息提示 "无人值守：协议=${INSTALL_PROTOCOL}，加密=${INSTALL_SS_METHOD}"
    return
  fi

  echo
  echo "================ 请选择协议类型（默认：2） ================"
  echo "  1) Shadowsocks（ss）"
  echo "  2) Shadowsocks 2022（ss2022）"
  echo "==========================================================="
  read -rp "请输入编号（1/2，默认 2）： " sel || true
  sel="${sel:-2}"

  case "$sel" in
    1) INSTALL_PROTOCOL="ss";     信息提示 "已选择：ss" ;;
    2) INSTALL_PROTOCOL="ss2022"; 信息提示 "已选择：ss2022" ;;
    *) 报错退出 "输入无效：必须是 1 或 2。" ;;
  esac

  if [[ "$INSTALL_PROTOCOL" == "ss2022" ]]; then
    echo
    echo "================ SS2022 加密方式（默认：3） ================"
    echo "  1) 2022-blake3-aes-128-gcm（16 字节密钥）"
    echo "  2) 2022-blake3-aes-256-gcm（32 字节密钥）"
    echo "  3) 2022-blake3-chacha20-poly1305（32 字节密钥）"
    echo "==========================================================="
    read -rp "请输入编号（1/2/3，默认 3）： " msel || true
    msel="${msel:-3}"

    case "$msel" in
      1) INSTALL_SS_METHOD="2022-blake3-aes-128-gcm";       INSTALL_KEY_BYTES=16 ;;
      2) INSTALL_SS_METHOD="2022-blake3-aes-256-gcm";       INSTALL_KEY_BYTES=32 ;;
      3) INSTALL_SS_METHOD="2022-blake3-chacha20-poly1305"; INSTALL_KEY_BYTES=32 ;;
      *) 报错退出 "输入无效：必须是 1/2/3。" ;;
    esac
  else
    echo
    echo "================ ss 加密方式（默认：2） ==================="
    echo "  1) aes-128-gcm（16 字节密钥）"
    echo "  2) aes-256-gcm（32 字节密钥）"
    echo "  3) chacha20-ietf-poly1305（32 字节密钥）"
    echo "==========================================================="
    read -rp "请输入编号（1/2/3，默认 2）： " msel || true
    msel="${msel:-2}"

    case "$msel" in
      1) INSTALL_SS_METHOD="aes-128-gcm";            INSTALL_KEY_BYTES=16 ;;
      2) INSTALL_SS_METHOD="aes-256-gcm";            INSTALL_KEY_BYTES=32 ;;
      3) INSTALL_SS_METHOD="chacha20-ietf-poly1305"; INSTALL_KEY_BYTES=32 ;;
      *) 报错退出 "输入无效：必须是 1/2/3。" ;;
    esac
  fi

  信息提示 "最终选择：协议=${INSTALL_PROTOCOL}，加密=${INSTALL_SS_METHOD}"
}

install_生成或读取密码() {
  # 无人值守：优先使用 CLI 指定密码，否则自动生成（默认 32 字节 base64）
  if [[ "$无人值守" == "true" ]]; then
    if [[ -n "${指定密码:-}" ]]; then
      INSTALL_SS_KEY_B64="$指定密码"
      信息提示 "无人值守：使用你指定的密码。"
    else
      INSTALL_SS_KEY_B64="$(openssl rand -base64 "$默认密钥字节" | tr -d '\n')"
      [[ -n "$INSTALL_SS_KEY_B64" ]] || 报错退出 "密码生成失败。"
      信息提示 "无人值守：已自动生成随机密码（Base64，${默认密钥字节} 字节）。"
    fi
    return
  fi

  echo
  echo "================ 密码设置 ================="
  read -rp "请输入密码（留空则自动生成随机 Base64）： " input || true
  input="$(echo -n "${input:-}" | awk '{$1=$1;print}')"

  if [[ -n "$input" ]]; then
    INSTALL_SS_KEY_B64="$input"
    信息提示 "使用你输入的密码。"
  else
    INSTALL_SS_KEY_B64="$(openssl rand -base64 "$INSTALL_KEY_BYTES" | tr -d '\n')"
    [[ -n "$INSTALL_SS_KEY_B64" ]] || 报错退出 "密码生成失败。"
    信息提示 "已自动生成随机密码（Base64，${INSTALL_KEY_BYTES} 字节）。"
  fi
}

install_备份现有配置() {
  local cfg="/usr/local/etc/xray/config.json"
  if [[ -s "$cfg" ]]; then
    local ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="/root/xray-config-backup-${ts}.json"
    cp -a "$cfg" "$backup"
    信息提示 "已备份现有配置：$backup"
  fi
}

install_生成唯一tag() {
  local cfg="/usr/local/etc/xray/config.json"
  local base="ss-in-${INSTALL_SS_PORT}"
  INSTALL_SS_TAG="$base"

  if [[ -s "$cfg" ]] && jq empty "$cfg" >/dev/null 2>&1; then
    if jq -e --arg t "$INSTALL_SS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) != null' "$cfg" >/dev/null; then
      local n=2
      while :; do
        INSTALL_SS_TAG="${base}-${n}"
        jq -e --arg t "$INSTALL_SS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) == null' "$cfg" >/dev/null && break
        n=$((n+1))
      done
    fi
  fi
  信息提示 "将使用 inbound tag：$INSTALL_SS_TAG"
}

install_写入配置_追加或新建() {
  local cfg="/usr/local/etc/xray/config.json"

  local new_inbound
  new_inbound="$(cat <<EOF
{
  "port": ${INSTALL_SS_PORT},
  "protocol": "shadowsocks",
  "settings": {
    "method": "${INSTALL_SS_METHOD}",
    "password": "${INSTALL_SS_KEY_B64}",
    "network": "tcp,udp"
  },
  "tag": "${INSTALL_SS_TAG}"
}
EOF
)"

  if [[ -s "$cfg" ]]; then
    信息提示 "检测到已有 Xray 配置，将追加一个入站（inbound）..."
    if ! jq empty "$cfg" >/dev/null 2>&1; then
      报错退出 "现有配置不是有效 JSON，请手动检查：$cfg"
    fi
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
    信息提示 "已成功追加 inbound。"
  else
    信息提示 "未检测到现有配置，将生成新的配置文件..."
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
  信息提示 "配置已写入：$cfg"
}

install_安装systemd服务() {
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

install_安装openrc服务() {
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

install_部署服务() {
  if command -v systemctl >/dev/null 2>&1; then
    install_安装systemd服务
  elif command -v rc-update >/dev/null 2>&1; then
    install_安装openrc服务
  else
    报错退出 "未检测到 systemd 或 OpenRC，无法安装服务。"
  fi
}

install_确定分享地址() {
  if [[ -n "${指定域名或IP:-}" ]]; then
    INSTALL_SERVER_ADDR="$指定域名或IP"
    信息提示 "使用指定域名/IP：$INSTALL_SERVER_ADDR"
    return
  fi

  if [[ "$无人值守" != "true" ]]; then
    local input
    read -rp "请输入要写入分享链接的域名或IP（留空则自动探测公网 IP）： " input || true
    input="$(echo -n "${input:-}" | awk '{$1=$1;print}')"
    if [[ -n "$input" ]]; then
      INSTALL_SERVER_ADDR="${input,,}"
      信息提示 "将使用：$INSTALL_SERVER_ADDR"
      return
    fi
  fi

  local ipv4=""
  ipv4="$(curl -fsSL http://api.ipify.org || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ip.sb || true)"
  [[ -n "$ipv4" ]] || ipv4="$(curl -fsSL http://ifconfig.me || true)"
  [[ -n "$ipv4" ]] || ipv4="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  INSTALL_SERVER_ADDR="${ipv4:-<SERVER_IP>}"

  if [[ "$INSTALL_SERVER_ADDR" = "<SERVER_IP>" ]]; then
    警告提示 "未能自动探测公网 IP，请手动替换分享链接中的 <SERVER_IP>。"
  else
    信息提示 "自动探测到公网 IP：$INSTALL_SERVER_ADDR"
  fi
}

install_输出分享链接并保存() {
  # 分享标签(tag)优先级：用户 -t/--tag > 默认 xray-<协议>
  local tag_raw=""
  if [[ -n "${指定分享标签:-}" ]]; then
    tag_raw="$指定分享标签"
  else
    tag_raw="xray-${INSTALL_PROTOCOL:-ss2022}"
  fi

  # 类型1：明文 method:password@host:port（password 做 URL 编码）
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
  local uri_plain="ss://${INSTALL_SS_METHOD}:${enc_pw}@${INSTALL_SERVER_ADDR}:${INSTALL_SS_PORT}#${tag_enc}"

  # 类型2：SIP002 Base64
  # ss://BASE64(method:password@host:port)#tag
  # 使用 URL-safe Base64 且去掉 '='，兼容性更好
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
  echo "加密方式      : ${INSTALL_SS_METHOD}"
  echo "端口          : ${INSTALL_SS_PORT}"
  echo "入站Tag       : ${INSTALL_SS_TAG}"
  echo "分享备注(tag) : ${tag_raw}"
  echo "密码(Base64)  : ${INSTALL_SS_KEY_B64}"
  echo "服务器        : ${INSTALL_SERVER_ADDR}"
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
  信息提示 "已保存两种分享链接到：$link_file"
}

install_重启并显示状态() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart xray || true
    systemctl status xray --no-pager -l || true
  else
    rc-service xray restart || true
    rc-service xray status || true
  fi
}

执行安装() {
  必须root
  install_检测系统
  install_安装依赖
  install_选择端口并校验
  install_安装xray二进制
  install_确定协议与加密
  install_生成或读取密码
  install_备份现有配置
  install_生成唯一tag
  install_写入配置_追加或新建
  install_部署服务
  install_确定分享地址

  PW="$INSTALL_SS_KEY_B64" \
  METHOD="$INSTALL_SS_METHOD" \
  HOST="$INSTALL_SERVER_ADDR" \
  PORT="$INSTALL_SS_PORT" \
  TAG="${指定分享标签:-xray-${INSTALL_PROTOCOL:-ss2022}}" \
  install_输出分享链接并保存

  install_重启并显示状态

  echo
  信息提示 "安装完成。常用命令："
  if command -v systemctl >/dev/null 2>&1; then
    echo "  systemctl status xray"
    echo "  journalctl -u xray -e"
  else
    echo "  rc-service xray status"
    echo "  rc-service xray restart"
  fi
}

# -------------------- 卸载逻辑（命名空间 uninstall_） --------------------
uninstall_是否systemd() { command -v systemctl >/dev/null 2>&1; }

uninstall_收集systemd单元() {
  if ! uninstall_是否systemd; then return 0; fi

  systemctl list-unit-files --type=service --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -E '.*xray.*\.service$' || true

  systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null \
    | awk '{print $1}' | grep -E '.*xray.*\.service$' || true

  for f in /etc/systemd/system/*xray*.service /lib/systemd/system/*xray*.service /usr/lib/systemd/system/*xray*.service; do
    [[ -f "$f" ]] && basename "$f"
  done
}

uninstall_停止并禁用systemd() {
  uninstall_是否systemd || { 警告提示 "未检测到 systemd。"; return 0; }

  mapfile -t units < <(uninstall_收集systemd单元 | awk 'NF && !seen[$0]++')
  if ((${#units[@]}==0)); then
    警告提示 "未检测到已注册的 Xray systemd 服务。"
    return 0
  fi

  信息提示 "将停止并禁用以下 systemd 单元："
  for u in "${units[@]}"; do echo "  - $u"; done

  for u in "${units[@]}"; do
    systemctl stop "$u" --no-block 2>/dev/null || true
    systemctl disable "$u" 2>/dev/null || true
    systemctl reset-failed "$u" 2>/dev/null || true
  done

  for wants in /etc/systemd/system/*/*xray*.service; do
    [[ -L "$wants" || -f "$wants" ]] && { 信息提示 "移除残留链接/文件：$wants"; rm -f "$wants" || true; }
  done
}

uninstall_删除systemd文件() {
  uninstall_是否systemd || return 0
  local removed=false
  for f in /etc/systemd/system/*xray*.service /lib/systemd/system/*xray*.service /usr/lib/systemd/system/*xray*.service; do
    if [[ -f "$f" ]]; then
      信息提示 "删除 systemd 单元文件：$f"
      rm -f "$f" || true
      removed=true
    fi
  done
  $removed && systemctl daemon-reload || true
}

uninstall_停止并移除openrc() {
  if command -v rc-update >/dev/null 2>&1 && [[ -f /etc/init.d/xray ]]; then
    信息提示 "检测到 OpenRC 服务，停止并取消开机自启..."
    rc-service xray stop || true
    rc-update del xray default || true
  else
    警告提示 "未检测到 OpenRC 的 Xray 服务。"
  fi
}

uninstall_删除openrc文件() {
  [[ -f /etc/init.d/xray ]] && { 信息提示 "删除 OpenRC 脚本：/etc/init.d/xray"; rm -f /etc/init.d/xray || true; }
  [[ -f /run/xray.pid ]] && rm -f /run/xray.pid || true
}

uninstall_备份并删除配置目录() {
  local cfg_dir="/usr/local/etc/xray"
  if [[ -d "$cfg_dir" ]]; then
    local ts backup
    ts="$(date +%Y%m%d-%H%M%S)"
    backup="/root/xray-config-backup-${ts}.tar.gz"
    信息提示 "备份配置目录到：$backup"
    tar -czf "$backup" -C "$(dirname "$cfg_dir")" "$(basename "$cfg_dir")" || true
    信息提示 "删除配置目录：$cfg_dir"
    rm -rf "$cfg_dir" || true
    普通提示 "备份已保存：$backup"
  else
    警告提示 "未找到配置目录：$cfg_dir"
  fi
}

uninstall_删除二进制与残留() {
  local bin="/usr/local/bin/xray"
  [[ -f "$bin" ]] && { 信息提示 "删除二进制文件：$bin"; rm -f "$bin" || true; } || 警告提示 "未找到二进制：$bin"

  for d in /usr/local/share/xray /usr/share/xray /var/lib/xray; do
    [[ -d "$d" ]] && { 信息提示 "删除目录：$d"; rm -rf "$d" || true; }
  done

  for f in /var/log/xray.log /var/log/xray/xray.log; do
    [[ -f "$f" ]] && { 信息提示 "删除日志：$f"; rm -f "$f" || true; }
  done
  [[ -d /var/log/xray ]] && { 信息提示 "删除日志目录：/var/log/xray"; rm -rf /var/log/xray || true; }
}

uninstall_可选删除用户组() {
  local purge_flag="$1"
  if [[ "$purge_flag" != "true" ]]; then
    信息提示 "保留 xray 用户/组（未使用 --purge）。"
    return 0
  fi

  信息提示 "执行 --purge：尝试删除 xray 用户与组..."
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

执行卸载() {
  local purge_flag="$1"
  必须root

  (
    set +e
    set -u -o pipefail

    uninstall_停止并禁用systemd
    uninstall_删除systemd文件
    uninstall_停止并移除openrc
    uninstall_删除openrc文件
    uninstall_备份并删除配置目录
    uninstall_删除二进制与残留
    uninstall_可选删除用户组 "$purge_flag"
    uninstall_是否systemd && systemctl daemon-reload || true

    echo
    echo "================ 卸载完成 ================"
    echo "已停止并移除服务、删除二进制与配置（配置已备份到 /root）。"
    if [[ "$purge_flag" == "true" ]]; then
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
      install|--install|-i) 动作="install"; shift ;;
      uninstall|--uninstall|-u) 动作="uninstall"; shift ;;
      --purge) 是否彻底清理="true"; shift ;;
      -n|--non-interactive) 无人值守="true"; shift ;;
      --domain|-d)
        shift; [[ $# -gt 0 ]] || 报错退出 "-d/--domain 需要参数"
        指定域名或IP="$1"; shift ;;
      --tag|-t)
        shift; [[ $# -gt 0 ]] || 报错退出 "-t/--tag 需要参数"
        指定分享标签="$1"; shift ;;
      --password)
        shift; [[ $# -gt 0 ]] || 报错退出 "--password 需要参数"
        指定密码="$1"; shift ;;
      --port|-p)
        shift; [[ $# -gt 0 ]] || 报错退出 "-p/--port 需要参数"
        指定端口="$1"; shift ;;
      --help|-h) 用法; exit 0 ;;
      *) 报错退出 "未知参数：$1（使用 --help 查看用法）。" ;;
    esac
  done
else
  echo
  echo "================ Xray SS 管理脚本 ================"
  echo "  1) 安装（默认端口 ${默认端口}，默认 ss2022 + chacha20）"
  echo "  2) 卸载（保留 xray 用户/组）"
  echo "  3) 卸载（--purge：同时删除 xray 用户/组）"
  echo "  0) 退出"
  echo "=================================================="
  read -rp "请输入编号（0/1/2/3）： " choice || true
  case "${choice:-}" in
    1) 动作="install" ;;
    2) 动作="uninstall" ;;
    3) 动作="uninstall"; 是否彻底清理="true" ;;
    0) exit 0 ;;
    *) 报错退出 "输入无效：必须是 0/1/2/3。" ;;
  esac
fi

# -------------------- 动作执行 --------------------
case "$动作" in
  install)
    [[ "$指定端口" =~ ^[0-9]+$ ]] && (( 指定端口>=1 && 指定端口<=65535 )) || 报错退出 "端口无效：$指定端口"
    if [[ "$无人值守" == "true" ]]; then
      信息提示 "无人值守模式已启用：端口=${指定端口}，默认协议=ss2022，默认加密=${默认加密}"
      if [[ -n "${指定域名或IP:-}" ]]; then 信息提示 "无人值守：分享域名/IP=${指定域名或IP}"; fi
      if [[ -n "${指定分享标签:-}" ]]; then 信息提示 "无人值守：分享tag=${指定分享标签}"; fi
      if [[ -n "${指定密码:-}" ]]; then 信息提示 "无人值守：使用指定密码（已接收）"; fi
    fi
    执行安装
    ;;
  uninstall)
    执行卸载 "$是否彻底清理"
    ;;
  *)
    用法
    exit 1
    ;;
esac

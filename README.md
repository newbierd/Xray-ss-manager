# Xray SS/SS2022 一键安装与卸载脚本（支持无人值守）

本仓库提供一个整合后的运维脚本，用于在服务器上快速安装/卸载 Xray，并创建 Shadowsocks / SS2022 inbound。脚本支持交互式菜单与无人值守部署，安装完成后同时输出两种常见格式的 `ss://` 分享链接（类型1 明文+URL 编码、类型2 SIP002 Base64），并保存到本地文件便于后续取用。

## 特性

- 安装/卸载整合为一个脚本
- 交互式菜单：运行时选择安装或卸载
- 无人值守：`-n/--non-interactive` 全自动部署
- 默认端口 `40000`，支持 `-p/--port` 自定义端口
- 默认协议 `ss2022`，默认加密 `2022-blake3-chacha20-poly1305`（32 字节密钥）
- 分享地址支持 `-d/--domain` 指定（用于链接输出，不影响实际监听）
- 分享 tag 支持 `-t/--tag` 指定（仅影响链接 `#tag`）
- 同时输出两种链接类型并标注：
  - 类型1：`ss://method:URLEncoded(password)@host:port#tag`
  - 类型2（更通用）：SIP002 `ss://BASE64(method:password@host:port)#tag`
- 配置默认写入/追加到：`/usr/local/etc/xray/config.json`
- 支持 Debian/Ubuntu/Alpine，自动适配 systemd / OpenRC
- 卸载时自动备份配置目录到：`/root/xray-config-backup-<时间>.tar.gz`

## 快速开始

> 下面示例会从本仓库的 `main` 分支下载脚本：`xray_ss_manager.sh`

### 1) 交互式运行（推荐新手）

```bash
curl -L https://raw.githubusercontent.com/newbierd/Xray-ss-manager/main/xray_ss_manager.sh -o xray_ss_manager.sh \
  && chmod +x xray_ss_manager.sh \
  && sudo ./xray_ss_manager.sh
```

运行后会出现菜单，可选择安装或卸载。

### 2) 交互安装（默认端口 40000）

```bash
curl -L https://raw.githubusercontent.com/newbierd/Xray-ss-manager/main/xray_ss_manager.sh -o xray_ss_manager.sh \
  && chmod +x xray_ss_manager.sh \
  && sudo ./xray_ss_manager.sh install
```

### 3) 无人值守安装（全默认）

```bash
curl -L https://raw.githubusercontent.com/newbierd/Xray-ss-manager/main/xray_ss_manager.sh -o xray_ss_manager.sh \
  && chmod +x xray_ss_manager.sh \
  && sudo ./xray_ss_manager.sh install -n
```

### 4) 无人值守安装（自定义端口 / 域名 / tag / 密码）

```bash
curl -L https://raw.githubusercontent.com/newbierd/Xray-ss-manager/main/xray_ss_manager.sh -o xray_ss_manager.sh \
  && chmod +x xray_ss_manager.sh \
  && sudo ./xray_ss_manager.sh install -n \
    -p 30833 \
    -d example.com \
    -t "newbie-ss2022" \
    --password "你的Base64密码"
```

### 5) 卸载（保留 xray 用户/组）

```bash
curl -L https://raw.githubusercontent.com/newbierd/Xray-ss-manager/main/xray_ss_manager.sh -o xray_ss_manager.sh \
  && chmod +x xray_ss_manager.sh \
  && sudo ./xray_ss_manager.sh uninstall
```

### 6) 卸载（彻底清理：删除 xray 用户/组）

```bash
curl -L https://raw.githubusercontent.com/newbierd/Xray-ss-manager/main/xray_ss_manager.sh -o xray_ss_manager.sh \
  && chmod +x xray_ss_manager.sh \
  && sudo ./xray_ss_manager.sh uninstall --purge
```

## 参数说明

安装相关参数：

- `-n, --non-interactive`：无人值守模式（不进行交互询问）
- `-p <端口>, --port <端口>`：指定端口（默认 40000）
- `-d <域名或IP>, --domain <域名或IP>`：指定分享链接中的域名或 IP（不影响实际监听）
- `-t <标签>, --tag <标签>`：指定分享链接 `#tag` 备注
- `--password <密码>`：指定密码（建议 Base64；脚本不做格式校验）

卸载相关参数：

- `--purge`：卸载时尝试删除 `xray` 用户与组（默认保留）

帮助：

- `-h, --help`

## 输出内容与文件位置

安装完成后脚本会输出并保存两种链接：

- 【类型1】明文 method + URL 编码 password  
- 【类型2】SIP002 Base64（更通用）

并追加写入到：

- `/root/xray_ss_link.txt`

核心路径：

- Xray 二进制：`/usr/local/bin/xray`
- 配置文件：`/usr/local/etc/xray/config.json`
- 卸载备份：`/root/xray-config-backup-<时间>.tar.gz`

## 注意事项

1. 本脚本会自动追加 inbound 到现有 `config.json`（如果已存在且是合法 JSON）。
2. 无人值守模式下，如果端口已被占用（系统监听或配置中已使用），脚本会直接退出并提示你更换端口。
3. `-d/--domain` 仅用于“生成分享链接”，不会更改服务端实际监听地址。
4. 建议在受控环境中使用；如有更严格的供应链安全要求，可自行增加下载校验或固定版本安装策略。

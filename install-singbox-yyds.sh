#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ============================================================
# sing-box 多协议一键部署脚本（Reality Safe Edition）
#
# 设计重点：
#   1. 支持 Shadowsocks / Hysteria2 / TUIC / VLESS Reality / AnyTLS Reality
#   2. Reality target 不再按“单次 curl 最快”直接推荐
#   3. 自动检查 TLS 1.3、ALPN h2、证书、重定向、共享 CDN 特征
#   4. 对候选目标进行多次 TLS 握手采样，以中位数排序
#   5. 真实 Reality 自测采用单 sing-box 进程闭环 + GOMAXPROCS=1；低资源自动 DEFERRED
#   6. 共享 CDN 特征作为回落滥用提示，自动选择保守排除，不代表客户端封锁判断
#   7. 已知存在 Reality 兼容性争议的目标默认不参与自动推荐
#   8. 允许手动指定 target；兼容性、名单和回落观察分别说明
#   9. 配置原子写入，sing-box check 失败不覆盖工作配置
#  10. 自带 sb 管理命令，可重新审计/切换 Reality target
#  11. 自动生成 Mihomo/Clash YAML，支持 sb mihomo 一键输出与 OSC 52 剪贴板复制
#  12. 标准化节点命名：地区｜角色｜简称；SS 可选 dialer-proxy（默认“中转”）
#  13. 中国大陆 Reality 候选分核心/扩展池；动态同前缀/同 ASN 被动发现 + 评分
#  14. 周期 Reality target 健康检查，只告警不自动切换，避免客户端 serverName 失配
#
# 目标 sing-box：稳定版 1.14+（默认 stable；不自动追 alpha/testing）。
# ============================================================

# install-latest.sh 传入真实 Release 标签；直接运行源文件时标记为 latest。
SCRIPT_VERSION="${SINGBOX_DEPLOY_VERSION:-latest}"
CONFIG_DIR="/etc/sing-box"
CONFIG_PATH="${CONFIG_DIR}/config.json"
STATE_PATH="${CONFIG_DIR}/install-state.env"
URI_PATH="${CONFIG_DIR}/uris.txt"
MIHOMO_DIR="${CONFIG_DIR}/mihomo"
MIHOMO_VLESS_PATH="${MIHOMO_DIR}/vless.yaml"
MIHOMO_SS_PATH="${MIHOMO_DIR}/ss.yaml"
MIHOMO_HY2_PATH="${MIHOMO_DIR}/hysteria2.yaml"
MIHOMO_TUIC_PATH="${MIHOMO_DIR}/tuic.yaml"
MIHOMO_ALL_PATH="${MIHOMO_DIR}/all.yaml"
MIHOMO_FULL_PATH="${MIHOMO_DIR}/full.yaml"
CERT_DIR="${CONFIG_DIR}/certs"
SB_PATH="/usr/local/bin/sb"
NODE_NAME_FILE="/root/node_names.txt"
BACKUP_DIR="${CONFIG_DIR}/backups"
REALITY_DISCOVERY_CACHE="${CONFIG_DIR}/reality-discovery.tsv"
REALITY_GFWLIST_CACHE="${CONFIG_DIR}/reality-gfw.txt"

# Reality 动态发现/健康检查。动态发现只读取公开被动数据，不主动扫描 ASN/IP 网段。
# 被动发现参数由统一策略在运行时读取；年龄/排名不再作为安全分或门槛。
REALITY_HEALTH_INTERVAL_HOURS="${SINGBOX_REALITY_HEALTH_INTERVAL_HOURS:-24}"
REALITY_HEALTH_AUTO_ENABLE="${SINGBOX_REALITY_HEALTH_AUTO_ENABLE:-1}"
REALITY_GFWLIST_CHECK="${SINGBOX_REALITY_GFWLIST_CHECK:-1}"
REALITY_GFWLIST_READY=false

# 候选元数据仅记录发现来源。Bash 4+（本脚本强制 bash）支持关联数组。
declare -A REALITY_CANDIDATE_SOURCE=()
declare -A REALITY_CANDIDATE_AGE=()
declare -A REALITY_CANDIDATE_RANK=()
REALITY_VPS_ASN="未知"
REALITY_VPS_PREFIX=""
REALITY_SELECTED_SOURCE=""
REALITY_SELECTED_ASN=""
REALITY_SELECTED_AT=""
REALITY_SELECTED_AGE_DAYS="0"
REALITY_SELECTED_UMBRELLA_RANK="0"
LOCK_FILE="/run/lock/sing-box-deploy.lock"
MIN_SINGBOX_VERSION="1.14.0"
REALITY_AUDIT_JOBS="${SINGBOX_REALITY_AUDIT_JOBS:-auto}"
BACKUP_KEEP="${SINGBOX_BACKUP_KEEP:-10}"
LOW_RESOURCE_MODE=false
SINGBOX_STABLE_FALLBACK_VERSION="1.14.2"

# Reality 真握手自测资源策略：auto 会在 PID/Tasks 或内存余量不足时自动降级为 DEFERRED，
# 不再为了“强行自测”把低配 VPS 的 shell / curl / sing-box 一起拖入 fork exhaustion。
REALITY_SELFTEST_MODE="${SINGBOX_REALITY_SELFTEST_MODE:-auto}"   # auto|on|off|force
# 真握手自测会短暂启动一个 Go 进程。默认阈值刻意保守：资源不足时宁可 DEFERRED，
# 也不要让低配/严格 TasksMax 的 VPS 因“额外自测”影响安装 shell 或正式服务。

# HY2/TUIC TLS：selfsigned（零依赖）或 existing（真实证书，推荐）。
QUIC_TLS_MODE="${SINGBOX_QUIC_TLS_MODE:-selfsigned}"
QUIC_TLS_SERVER_NAME="${SINGBOX_QUIC_TLS_SERVER_NAME:-}"
QUIC_CERT_SOURCE="${SINGBOX_QUIC_CERT_PATH:-}"
QUIC_KEY_SOURCE="${SINGBOX_QUIC_KEY_PATH:-}"
QUIC_TLS_INSECURE=true
HY2_OBFS="${SINGBOX_HY2_OBFS:-none}"
HY2_OBFS_PASSWORD="${SINGBOX_HY2_OBFS_PASSWORD:-}"
HY2_BBR_PROFILE="${SINGBOX_HY2_BBR_PROFILE:-standard}"

# 默认值只用于兜底展示；真正安装 Reality 时仍会执行完整审计。
# 面向中国大陆客户端时，默认 target 必须优先考虑“客户端侧 SNI 合理性”，
# 因此不再使用 google.com / gstatic.com / wikipedia.org 等长期受限或高度不稳定域名。
DEFAULT_REALITY_SNI="www.debian.org"

# Reality 客户端网络画像：
#   cn     = 中国大陆客户端（默认，候选池更保守，排除长期受限/高度不稳定域名）
#   global = 海外/不受中国大陆网络限制的客户端
# 可用环境变量 SINGBOX_REALITY_CLIENT_PROFILE=cn|global 非交互指定。
REALITY_CLIENT_PROFILE="${SINGBOX_REALITY_CLIENT_PROFILE:-cn}"

# 中国大陆画像下，以下域名即使 VPS 侧 TLS/Reality 自测通过，也不应作为自动推荐 SNI。
# 这里采用“保守排除”：既包括长期明确受限，也包括在大陆网络中高度不稳定、容易形成异常 SNI 的站点。

# 中国大陆候选池：优先选择大陆网络通常可直接访问、且不是典型翻墙/受限站点的 HTTPS 域名。
# 注意：这仍只是“待审计输入”，不是永久白名单。网络可达性会随运营商/地区/时间变化，
# 最终仍需满足 TLS1.3 + H2 + 有效证书 + 不跨域跳转 + 低 CDN 滥用风险 + Reality 真实自测。
# 中国大陆“核心候选池”：优先放入网络行为自然、长期正常用途明显、且不是典型受限站点的域名。
# 这些仍不是永久白名单；运行时必须继续通过 TLS1.3/H2/证书/不跨域/共享 CDN/Reality 真握手审计。
# 排序只影响测试先后，不会绕过任何硬条件。


# 扩展候选池：核心池无严格命中时再测试。
REALITY_CANDIDATES_CN_EXTENDED=(
  # 兼容性/拓扑可能随地区变化的公共候选，只有核心+动态池不足时才审计。
  "www.freebsd.org"
  "www.kernel.org"
  "www.openbsd.org"
  "www.netbsd.org"
  "www.apple.com"
  "support.apple.com"
  "appleid.apple.com"
  "captive.apple.com"
  "www.archlinux.org"
  "www.gentoo.org"
  "www.opensuse.org"
  "www.ubuntu.com"
  "www.centos.org"
  "www.videolan.org"
  "www.gnu.org"
  "www.sqlite.org"
  "www.php.net"
  "www.perl.org"
  "www.ruby-lang.org"
  "www.rust-lang.org"
  "www.libreoffice.org"
  "www.documentfoundation.org"
  "www.gnome.org"
  "www.kde.org"
  "www.vim.org"
  "git-scm.com"
  "www.cmake.org"
  "www.llvm.org"
  "gcc.gnu.org"
  "www.ietf.org"
  "www.iana.org"
  "www.icann.org"
  "www.ripe.net"
  "www.apnic.net"
  "www.arin.net"
  "www.lacnic.net"
  "www.afrinic.net"
  "www.rfc-editor.org"
  "www.openstreetmap.org"

  # Apple 扩展目标。gateway.icloud.com 在大陆可达性存在波动，因此明确降级到扩展池，
  # 按独立规则提示 CAUTION，不代表已实测客户端阻断。
  "developer.apple.com"
  "weather.apple.com"
  "gateway.icloud.com"
)

# 海外画像：在大陆画像基础上增加一些大陆可达性并非主要约束的候选。
# 仍然不默认加入 Google/大型下载域名，因为 fallback 滥用风险与“海外/大陆”无关。


REALITY_CANDIDATES_GLOBAL_EXTENDED=(
  "www.alpinelinux.org"
  "www.gentoo.org"
  "www.opensuse.org"
  "www.ubuntu.com"
  "www.centos.org"
  "www.gnu.org"
  "www.sqlite.org"
  "www.php.net"
  "www.perl.org"
  "www.ruby-lang.org"
  "www.rust-lang.org"
  "www.libreoffice.org"
  "www.documentfoundation.org"
  "www.gnome.org"
  "www.kde.org"
  "www.vim.org"
  "git-scm.com"
  "www.cmake.org"
  "www.llvm.org"
  "gcc.gnu.org"
  "www.ietf.org"
  "www.iana.org"
  "www.icann.org"
  "www.ripe.net"
  "www.apnic.net"
  "www.arin.net"
  "www.lacnic.net"
  "www.afrinic.net"
  "www.rfc-editor.org"
  "www.openstreetmap.org"
  "www.w3.org"
  "www.eff.org"
  "www.apple.com"
  "support.apple.com"
  "developer.apple.com"
  "appleid.apple.com"
  "weather.apple.com"
  "captive.apple.com"
)

# 明确不进入自动推荐的域名。用户仍可手工强制使用，但会看到风险提示。

C_RESET='\033[0m'
C_BLUE='\033[1;34m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'

info(){ echo -e "${C_BLUE}[INFO]${C_RESET} $*"; }
ok(){ echo -e "${C_GREEN}[ OK ]${C_RESET} $*"; }
warn(){ echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
err(){ echo -e "${C_RED}[ERR ]${C_RESET} $*" >&2; }
die(){ err "$*"; exit 1; }

TMP_FILES=()
TMP_PIDS=()
cleanup(){
  rp_cleanup_selftest
  local p f
  for p in "${TMP_PIDS[@]:-}"; do
    [ -n "${p:-}" ] && kill "$p" 2>/dev/null || true
    [ -n "${p:-}" ] && wait "$p" 2>/dev/null || true
  done
  for f in "${TMP_FILES[@]:-}"; do
    [ -n "${f:-}" ] && rm -rf "$f" 2>/dev/null || true
  done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'err "第 ${LINENO} 行执行失败：${BASH_COMMAND}"' ERR

check_root(){ [ "$(id -u)" -eq 0 ] || die "请使用 root 运行此脚本。"; }


version_ge(){
  # 纯 Bash 语义版本比较，避免 Alpine Tiny 模式依赖 GNU sort -V。
  local cur="${1%%-*}" req="${2%%-*}" a b c x y z
  IFS=. read -r a b c <<<"$cur"; IFS=. read -r x y z <<<"$req"
  a="${a:-0}"; b="${b:-0}"; c="${c:-0}"; x="${x:-0}"; y="${y:-0}"; z="${z:-0}"
  ((10#$a > 10#$x)) && return 0
  ((10#$a < 10#$x)) && return 1
  ((10#$b > 10#$y)) && return 0
  ((10#$b < 10#$y)) && return 1
  ((10#$c >= 10#$z))
}

singbox_version_number(){
  sing-box version 2>/dev/null | head -n1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

acquire_lock(){
  mkdir -p "$(dirname "$LOCK_FILE")" 2>/dev/null || true
  if command -v flock >/dev/null 2>&1; then
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "检测到另一个 sing-box 部署/管理任务正在运行，请稍后重试。"
  else
    local d="${LOCK_FILE}.d"
    mkdir "$d" 2>/dev/null || die "检测到另一个 sing-box 部署/管理任务正在运行，请稍后重试。"
    TMP_FILES+=("$d")
  fi
}

prune_backups(){
  # BusyBox find 不保证支持 -printf；用 Bash + ls 时间排序，兼容 Alpine 最小系统。
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  local keep="${BACKUP_KEEP:-10}" f i=0
  local -a files=()
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=10
  while IFS= read -r f; do [ -n "$f" ] && files+=("$f"); done < <(ls -1t "$BACKUP_DIR"/* 2>/dev/null || true)
  for f in "${files[@]}"; do
    i=$((i+1))
    [ "$i" -le "$keep" ] || rm -f -- "$f"
  done
}

cleanup_stale_reality_selftests(){
  # 清理旧版本或异常中断遗留的临时 Reality 自测进程。
  # 只匹配 sing-box + /tmp + reality + test/selftest，绝不碰正式 /etc/sing-box 服务。
  local p pid joined killed=0
  local -a argv=()
  for p in /proc/[0-9]*; do
    [ -r "$p/cmdline" ] || continue
    pid="${p##*/}"
    [ "$pid" = "$$" ] && continue
    argv=()
    mapfile -d '' -t argv <"$p/cmdline" 2>/dev/null || true
    [ "${#argv[@]}" -gt 0 ] || continue
    joined=" ${argv[*]} "
    [[ "$joined" == *sing-box* ]] || continue
    [[ "$joined" == *"/tmp/"* ]] || continue
    [[ "${joined,,}" == *reality* ]] || continue
    [[ "${joined,,}" == *selftest* || "${joined,,}" == *"reality-test"* || "${joined,,}" == *"reality_test"* ]] || continue
    if kill "$pid" 2>/dev/null; then killed=$((killed+1)); fi
  done
  [ "$killed" -eq 0 ] || { warn "已清理 ${killed} 个旧版/异常中断遗留的 Reality 临时测试进程。"; }
}

mem_total_kb(){
  local key val
  [ -r /proc/meminfo ] || { printf '0'; return 0; }
  while read -r key val _; do
    if [ "$key" = "MemTotal:" ]; then printf '%s' "${val:-0}"; return 0; fi
  done </proc/meminfo
  printf '0'
}

detect_low_resource_mode(){
  local mem total
  mem="$(mem_total_kb)"
  total="$(df -Pk / 2>/dev/null | awk 'NR==2{print $2}' || true)"
  LOW_RESOURCE_MODE=false
  if { [[ "$mem" =~ ^[0-9]+$ ]] && [ "$mem" -gt 0 ] && [ "$mem" -lt 262144 ]; } || \
     { [[ "$total" =~ ^[0-9]+$ ]] && [ "$total" -gt 0 ] && [ "$total" -lt 1048576 ]; }; then
    LOW_RESOURCE_MODE=true
  fi
}

preflight(){
  local arch free_kb year headroom mem totalmem
  [ "${OS:-}" = alpine ] && cleanup_stale_singbox_packages
  cleanup_stale_reality_selftests
  arch="$(uname -m 2>/dev/null || true)"
  case "$arch" in x86_64|amd64|aarch64|arm64|armv7l|armv6l|i386|i686) :;; *) warn "较少见的 CPU 架构：$arch；请确认官方 sing-box 提供对应构建。";; esac
  free_kb="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}')"
  [ -z "$free_kb" ] || [ "$free_kb" -ge 92160 ] || die "根分区剩余空间不足 90 MiB；sing-box 二进制无法安全落盘。"
  year="$(date +%Y 2>/dev/null || echo 0)"
  [ "$year" -ge 2024 ] || die "系统时间明显异常；TLS/Reality 依赖正确时间，请先同步系统时钟。"
  command -v systemctl >/dev/null 2>&1 || command -v rc-service >/dev/null 2>&1 || warn "未检测到 systemd/OpenRC，服务管理可能不可用。"
  headroom="$(pid_headroom_fast)"; mem="$(mem_available_kb)"; totalmem="$(mem_total_kb)"
  info "资源预检：PID/Tasks 余量=${headroom}；MemAvailable≈$((mem/1024)) MiB；MemTotal≈$((totalmem/1024)) MiB。"
  if $LOW_RESOURCE_MODE; then
    warn "检测到 Tiny VPS（低内存/小磁盘）：启用低资源模式，Alpine 使用流式 musl 二进制安装、最小依赖、Reality 真握手默认 DEFERRED。"
    REALITY_AUDIT_JOBS=1
    if [ "${REALITY_SELFTEST_MODE:-auto}" = auto ]; then REALITY_SELFTEST_MODE=off; fi
  fi
  if [ "$headroom" -lt 48 ]; then
    warn "当前 PID/Tasks 余量极低；Reality 真握手将自动 DEFERRED，避免触发 fork exhaustion。"
  elif [ "$headroom" -lt 96 ]; then
    warn "当前 PID/Tasks 余量偏低；静态审计将强制串行，真实握手默认安全延后。"
  fi
}

# BEGIN REALITY_POLICY
# Canonical REALITY policy. Embedded into the standalone installer; generated
# panel/relay scripts receive these same functions, without runtime downloads.
rp_valid_host(){ [[ "${1:-}" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$ ]]; }
rp_ip_key(){
  local ip="${1,,}" a b c d tail left right group missing i key=""
  local -a groups=() lhs=() rhs=()
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS=. read -r a b c d <<<"$ip"
    for group in "$a" "$b" "$c" "$d"; do [ "$((10#$group))" -le 255 ] || return 1; done
    printf 'v4:%d.%d.%d.%d' "$((10#$a))" "$((10#$b))" "$((10#$c))" "$((10#$d))"; return 0
  fi
  [[ "$ip" == *:* && "$ip" =~ ^[[:xdigit:]:.]+$ ]] || return 1
  if [[ "$ip" == *.* ]]; then
    tail="${ip##*:}"; [[ "$tail" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<<"$tail"
    for group in "$a" "$b" "$c" "$d"; do [ "$((10#$group))" -le 255 ] || return 1; done
    printf -v tail '%x:%x' "$((10#$a*256+10#$b))" "$((10#$c*256+10#$d))"; ip="${ip%:*}:$tail"
  fi
  if [[ "$ip" == *::* ]]; then
    left="${ip%%::*}"; right="${ip#*::}"; [[ "$right" != *::* ]] || return 1
    [ -z "$left" ] || IFS=: read -r -a lhs <<<"$left"
    [ -z "$right" ] || IFS=: read -r -a rhs <<<"$right"
    missing=$((8-${#lhs[@]}-${#rhs[@]})); [ "$missing" -gt 0 ] || return 1
    groups=("${lhs[@]}"); for ((i=0;i<missing;i++)); do groups+=(0); done; groups+=("${rhs[@]}")
  else
    [[ "$ip" != :* && "$ip" != *: ]] || return 1
    IFS=: read -r -a groups <<<"$ip"; [ "${#groups[@]}" -eq 8 ] || return 1
  fi
  for group in "${groups[@]}"; do [[ "$group" =~ ^[[:xdigit:]]{1,4}$ ]] || return 1; printf -v group '%04x' "$((16#$group))"; key+="$group"; done
  printf 'v6:%s' "$key"
}
rp_valid_ip(){ rp_ip_key "${1:-}" >/dev/null; }
rp_public_ip(){
  local ip="$1" a b c d key first
  key="$(rp_ip_key "$ip")" || return 1
  if [[ "$key" == v4:* ]]; then
    IFS=. read -r a b c d <<<"${key#v4:}"
    case "$a" in 0|10|127) return 1;; esac
    [ "$a" -lt 224 ] || return 1
    if { [ "$a" -eq 100 ] && [ "$b" -ge 64 ] && [ "$b" -le 127 ]; } ||
       { [ "$a" -eq 169 ] && [ "$b" -eq 254 ]; } ||
       { [ "$a" -eq 172 ] && [ "$b" -ge 16 ] && [ "$b" -le 31 ]; } ||
       { [ "$a" -eq 192 ] && { [ "$b" -eq 168 ] || { [ "$b" -eq 0 ] && { [ "$c" -eq 0 ] || [ "$c" -eq 2 ]; }; }; }; } ||
       { [ "$a" -eq 198 ] && { [ "$b" -eq 18 ] || [ "$b" -eq 19 ] || { [ "$b" -eq 51 ] && [ "$c" -eq 100 ]; }; }; } ||
       { [ "$a" -eq 203 ] && [ "$b" -eq 0 ] && [ "$c" -eq 113 ]; }; then return 1; fi
  else
    key="${key#v6:}"; first=$((16#${key:0:4}))
    [ "$first" -ge 8192 ] && [ "$first" -lt 16384 ] || return 1
    case "$key" in 20010db8*|200100020000*) return 1;; esac
  fi
  return 0
}
rp_dns_ips(){
  local host="$1" family raw line
  for family in A AAAA; do
    raw="$(dig +time=2 +tries=1 +short "$family" "$host" 2>/dev/null || true)"
    while IFS= read -r line; do
      if rp_valid_ip "$line"; then printf '%s\n' "$line"; fi
    done <<<"$raw"
  done
  return 0
}
rp_resolve_ip(){
  local ip; while IFS= read -r ip; do printf '%s' "$ip"; return 0; done < <(rp_dns_ips "$1"); return 1
}
rp_dns_contains(){
  local ip key; key="$(rp_ip_key "$2")" || return 1
  while IFS= read -r ip; do [ "$(rp_ip_key "$ip")" != "$key" ] || return 0; done < <(rp_dns_ips "$1")
  return 1
}
rp_topology(){
  if [ -z "${1:-}" ] || [ "$1" = 未知 ] || [ -z "${2:-}" ] || [ "$2" = 未知 ]; then printf 'unknown'
  elif [ "$1" = "$2" ]; then printf 'same-asn'
  else printf 'cross-asn'; fi
}
rp_origin_info(){
  local ip="$1" a b c d raw n prefix=""
  rp_valid_ip "$ip" || { printf '未知|'; return 0; }
  if [[ "$ip" != *:* ]]; then
    IFS=. read -r a b c d <<<"$ip"
    raw="$(dig +time=2 +tries=1 +short TXT "$d.$c.$b.$a.origin.asn.cymru.com" 2>/dev/null || true)"
    raw="${raw//\"/}"; IFS='|' read -r n prefix _ <<<"$raw"; n="${n//[[:space:]]/}"; prefix="${prefix//[[:space:]]/}"
    if [[ "$n" =~ ^[0-9]+$ ]]; then printf 'AS%s|%s' "$n" "$prefix"; return 0; fi
  fi
  raw="$(curl --noproxy '*' -fsS --connect-timeout 3 --max-time 6 --get 'https://stat.ripe.net/data/network-info/data.json' --data-urlencode "resource=$ip" 2>/dev/null || true)"
  n="$(jq -r '.data.asns[0] // empty' <<<"$raw" 2>/dev/null || true)"; prefix="$(jq -r '.data.prefix // empty' <<<"$raw" 2>/dev/null || true)"
  if [[ "$n" =~ ^[0-9]+$ ]]; then printf 'AS%s|%s' "$n" "$prefix"; else printf '未知|'; fi
}
rp_asn_for_ip(){ local origin; origin="$(rp_origin_info "$1")"; printf '%s' "${origin%%|*}"; }
rp_vps_identity(){
  local host="${1:-}" ip="" origin
  if rp_valid_ip "$host"; then ip="$host"; elif [ -n "$host" ]; then ip="$(rp_resolve_ip "$host" || true)"; fi
  if [ -n "$host" ] && ! rp_valid_ip "$ip"; then printf '未知|未知|'; return 0; fi
  if [ -z "$ip" ]; then ip="$(curl --noproxy '*' -4 -fsS --connect-timeout 3 --max-time 7 https://api.ipify.org 2>/dev/null || true)"; fi
  if ! rp_valid_ip "$ip"; then ip="$(curl --noproxy '*' -6 -fsS --connect-timeout 3 --max-time 7 https://api64.ipify.org 2>/dev/null || true)"; fi
  if rp_valid_ip "$ip"; then origin="$(rp_origin_info "$ip")"; printf '%s|%s' "$ip" "$origin"; else printf '未知|未知|'; fi
}
rp_list_flagged(){
  local host="${1,,}" path="${2:-}" suffix
  local -a patterns=()
  [ -s "$path" ] || return 1
  suffix="$host"
  while [[ "$suffix" == *.* ]]; do patterns+=(-e "$suffix"); suffix="${suffix#*.}"; done
  [ "${#patterns[@]}" -gt 0 ] && grep -Fqx "${patterns[@]}" "$path"
}
rp_seconds_ms(){
  local x="$1" whole frac
  [[ "$x" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  whole="${x%%.*}"; frac=""; [[ "$x" != *.* ]] || frac="${x#*.}"; frac="${frac}000"
  printf '%d' "$((10#$whole*1000 + 10#${frac:0:3}))"
}
rp_median(){
  local -a values=("$@")
  local i j x
  for ((i=1;i<${#values[@]};i++)); do
    x="${values[i]}"; j=$((i-1))
    while [ "$j" -ge 0 ] && [ "${values[j]}" -gt "$x" ]; do values[j+1]="${values[j]}"; j=$((j-1)); done
    values[j+1]="$x"
  done
  [ "${#values[@]}" -gt 0 ] || return 1
  printf '%s' "${values[${#values[@]}/2]}"
}
rp_client_flagged(){
  local host="${1,,}" profile="${2:-cn}" gfw="${3:-}"
  [ "$profile" = cn ] || return 1
    case "$host" in
      google.com|*.google.com|gstatic.com|*.gstatic.com|googleapis.com|*.googleapis.com|googleusercontent.com|*.googleusercontent.com|youtube.com|*.youtube.com|ytimg.com|*.ytimg.com|wikipedia.org|*.wikipedia.org|wikimedia.org|*.wikimedia.org|facebook.com|*.facebook.com|instagram.com|*.instagram.com|whatsapp.com|*.whatsapp.com|twitter.com|*.twitter.com|x.com|*.x.com|t.co|*.t.co|telegram.org|*.telegram.org|t.me|*.t.me|signal.org|*.signal.org|torproject.org|*.torproject.org|reddit.com|*.reddit.com|discord.com|*.discord.com|medium.com|*.medium.com)
        return 0 ;;
    esac
  [ "${SINGBOX_REALITY_GFWLIST_CHECK:-1}" = 1 ] && rp_list_flagged "$host" "$gfw"
}
# Output globals form the public API used by the embedded panel and relay.
# shellcheck disable=SC2034
rp_probe_endpoint(){
  local host="${1,,}" profile="${2:-cn}" gfw="${3:-}" vasn="${4:-未知}" pin="${5:-}"
  local tls raw line code="" redir="" seconds="" remote="" headers="" resolve connect cname="" txt rest rh sample i ms
  local -a times=()
  RP_TLS13=NO RP_H2=NO RP_CERT=NO RP_REDIRECT=YES RP_MS=999999 RP_ASN=未知 RP_IP="" RP_FAMILY=""
  RP_RULE=CLEAR RP_CLIENT=UNMEASURED RP_ABUSE=UNTESTED RP_REASON="" RP_CNAME="" RP_OK=0 RP_TOTAL=0 RP_COMPAT=UNTESTED RP_ELIGIBLE=NO RP_TOPOLOGY=unknown
  rp_valid_host "$host" || { RP_RULE=EXCLUDED; RP_REASON='域名格式无效'; return 0; }
  if rp_client_flagged "$host" "$profile" "$gfw"; then RP_CLIENT=LIST_FLAGGED; fi
  if [ "$RP_CLIENT" = LIST_FLAGGED ]; then
    RP_RULE=EXCLUDED; RP_REASON='客户端名单排除信号；并非本次实测封锁'; return 0
  fi
  if [ "$host" = gateway.icloud.com ] || [[ "$host" == *microsoft.com || "$host" == *bing.com ]]; then RP_RULE=CAUTION; fi
  if [ -n "$pin" ]; then RP_IP="$pin"; else RP_IP="$(rp_resolve_ip "$host" || true)"; fi
  rp_valid_ip "$RP_IP" || { RP_REASON='无法取得可验证的实际目标IP'; RP_IP=""; return 0; }
  rp_public_ip "$RP_IP" || { RP_REASON='目标为非公网/测试保留地址，可能来自Fake-IP或代理DNS；请使用真实公网端点'; return 0; }
  RP_FAMILY=4; [[ "$RP_IP" != *:* ]] || RP_FAMILY=6
  resolve="$RP_IP"; connect="$RP_IP:443"
  if [ "$RP_FAMILY" = 6 ]; then resolve="[$RP_IP]"; connect="[$RP_IP]:443"; fi
  tls="$(timeout 5 openssl s_client -connect "$connect" -servername "$host" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
  [[ "$tls" != *TLSv1.3* && "$tls" != *TLS_AES_* ]] || RP_TLS13=YES
  [[ "${tls,,}" != *'alpn protocol: h2'* && "${tls,,}" != *'alpn: h2'* ]] || RP_H2=YES
  RP_COMPAT=FAIL; RP_TOTAL=1
  if raw="$(curl --noproxy '*' -sS --resolve "$host:443:$resolve" -D - -o /dev/null --connect-timeout 3 --max-time 7 \
      -w $'\n__RP__|%{http_code}|%{redirect_url}|%{time_appconnect}|%{remote_ip}\n' "https://$host/" 2>/dev/null)"; then
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" == '__RP__|'* ]]; then IFS='|' read -r _ code redir seconds remote <<<"$line"; else headers+="$line"$'\n'; fi
    done <<<"$raw"
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]] && rp_valid_ip "$remote"; then
      if [ "$(rp_ip_key "$remote")" != "$(rp_ip_key "$RP_IP")" ]; then RP_REASON='实际连接IP与TLS固定端点不一致'; return 0; fi
      RP_CERT=YES; RP_OK=1
      ms="$(rp_seconds_ms "$seconds" || true)"; [[ ! "$ms" =~ ^[0-9]+$ ]] || times+=("$ms")
    fi
    if [[ "$redir" =~ ^https?:// ]]; then
      rest="${redir#*://}"; rh="${rest%%/*}"; rh="${rh%%:*}"
      [ "${rh,,}" = "$host" ] || RP_REDIRECT=NO
    fi
  fi
  if [ "$RP_TLS13" != YES ] || [ "$RP_H2" != YES ] || [ "$RP_CERT" != YES ] || [ "$RP_REDIRECT" != YES ]; then
    RP_REASON='固定端点的TLS1.3/H2/证书/同域跳转条件未全部通过'; return 0
  fi
  sample="${SINGBOX_REALITY_PROBE_SAMPLES:-3}"; [[ "$sample" =~ ^[1-3]$ ]] || sample=3
  for ((i=1;i<sample;i++)); do
    RP_TOTAL=$((RP_TOTAL+1))
    if seconds="$(curl --noproxy '*' -sS --resolve "$host:443:$resolve" -o /dev/null --connect-timeout 2 --max-time 4 -w '%{time_appconnect}' "https://$host/" 2>/dev/null)"; then
      ms="$(rp_seconds_ms "$seconds" || true)"
      if [[ "$ms" =~ ^[0-9]+$ ]]; then times+=("$ms"); RP_OK=$((RP_OK+1)); fi
    fi
  done
  [ "${#times[@]}" -eq 0 ] || RP_MS="$(rp_median "${times[@]}")"
  cname="$(dig +time=1 +tries=1 +short CNAME "$host" 2>/dev/null || true)"; RP_CNAME="${cname//$'\n'/,}"
  RP_ABUSE=NO_RULE_MATCH
  txt="${host} ${headers} ${cname}"; txt="${txt,,}"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cloudfront*|*x-amz-cf-*|*fastly*|*x-served-by*|*x-timer*|*akamaiedge*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*akamaighost*|*x-akamai*|*azureedge*|*azurefd.net*|*x-azure-ref*|*trafficmanager.net*|*b-cdn.net*|*bunnycdn*|*cdn77*|*stackpath*|*incapdns*|*imperva*|*vercel.app*|*netlify.app*|*ghs.googlehosted.com*) RP_ABUSE=SHARED_EDGE ;;
  esac
  RP_ASN="$(rp_asn_for_ip "$RP_IP")"; RP_TOPOLOGY="$(rp_topology "$RP_ASN" "$vasn")"; RP_COMPAT=PASS
  RP_REASON='固定端点兼容；客户端路径未测；规则/回落观察均非安全保证'
  if [ "$RP_ABUSE" = SHARED_EDGE ]; then RP_REASON='共享边缘特征：自动选择保守排除，依据是回落转发滥用风险'; return 0; fi
  RP_ELIGIBLE=YES
}
rp_probe(){
  local host="$1" profile="${2:-cn}" gfw="${3:-}" vasn="${4:-未知}" pin="${5:-}" ip v4="" v6=""
  if [ -n "$pin" ] || ! rp_valid_host "$host" || rp_client_flagged "$host" "$profile" "$gfw"; then rp_probe_endpoint "$@"; return; fi
  # At most one endpoint per family. Each attempt remains pinned end to end.
  while IFS= read -r ip; do
    if [[ "$ip" == *:* ]]; then [ -n "$v6" ] || v6="$ip"; else [ -n "$v4" ] || v4="$ip"; fi
  done < <(rp_dns_ips "$host")
  for ip in "$v4" "$v6"; do
    [ -n "$ip" ] || continue
    rp_probe_endpoint "$host" "$profile" "$gfw" "$vasn" "$ip"
    [ "$RP_COMPAT" != PASS ] || return 0
  done
  if [ -z "$v4$v6" ]; then rp_probe_endpoint "$host" "$profile" "$gfw" "$vasn" ''; fi
  return 0
}
rp_probe_row(){
  local host="$1" status=SKIP
  rp_probe "$@"
  [ "$RP_ELIGIBLE" != YES ] || status=PENDING
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$host" "$RP_TLS13" "$RP_H2" "$RP_CERT" "$RP_REDIRECT" "$RP_MS" "$RP_RULE" "$status" "${RP_REASON//|/;}" "${RP_CNAME//|/;}" "$RP_ASN" "$RP_IP" "$RP_FAMILY" "$RP_CLIENT" "$RP_ABUSE" "$RP_OK" "$RP_TOTAL" "$RP_COMPAT"
}
rp_compare(){
  # No summed 'safety score': topology, rule evidence, sample success, latency.
  local ca="$1" cr="$2" co="$3" ct="$4" cm="$5" ba="$6" br="$7" bo="$8" bt="$9" bm="${10}" va="${11}" ctop=0 btop=0
  case "$(rp_topology "$ca" "$va")" in same-asn) ctop=2;; cross-asn) ctop=1;; esac
  case "$(rp_topology "$ba" "$va")" in same-asn) btop=2;; cross-asn) btop=1;; esac
  [ "$ctop" -eq "$btop" ] || { [ "$ctop" -gt "$btop" ]; return; }
  [ "$cr" = "$br" ] || { [ "$cr" = CLEAR ]; return; }
  [[ "$co:$ct:$bo:$bt" =~ ^[0-9]+:[1-9][0-9]*:[0-9]+:[1-9][0-9]*$ ]] || { co=0; ct=1; bo=0; bt=1; }
  [ "$((co*bt))" -eq "$((bo*ct))" ] || { [ "$((co*bt))" -gt "$((bo*ct))" ]; return; }
  [[ "$cm" =~ ^[0-9]+$ ]] || cm=999999; [[ "$bm" =~ ^[0-9]+$ ]] || bm=999999
  [ "$cm" -lt "$bm" ]
}
rp_best_row(){
  local file="$1" vasn="$2" wanted="$3" line best="" h tls h2 cert redir ms rule status reason cname asn ip family client abuse ok total compat
  local ba=未知 br=CLEAR bo=0 bt=1 bm=999999
  while IFS= read -r line; do
    IFS='|' read -r h tls h2 cert redir ms rule status reason cname asn ip family client abuse ok total compat <<<"$line"
    rp_valid_host "$h" && rp_valid_ip "$ip" || continue
    [ "$tls" = YES ] && [ "$h2" = YES ] && [ "$cert" = YES ] && [ "$redir" = YES ] || continue
    [ "$status" = "$wanted" ] && [ "$compat" = PASS ] && [ "$client" != LIST_FLAGGED ] && [ "$abuse" != SHARED_EDGE ] && [ "$rule" != EXCLUDED ] || continue
    if [ -z "$best" ] || rp_compare "$asn" "$rule" "$ok" "$total" "$ms" "$ba" "$br" "$bo" "$bt" "$bm" "$vasn"; then
      best="$line"; ba="$asn"; br="$rule"; bo="$ok"; bt="$total"; bm="$ms"
    fi
  done <"$file"
  [ -n "$best" ] || return 1
  printf '%s\n' "$best"
}
rp_mem_kb(){ local k v; while read -r k v _; do [ "$k" != MemAvailable: ] || { printf '%s' "$v"; return; }; done </proc/meminfo; printf 0; }
rp_pid_headroom(){
  local best=999999 path=/sys/fs/cgroup line max current head nproc p t uid key count=0
  while IFS= read -r line; do [[ "$line" != 0::* ]] || { path="/sys/fs/cgroup${line#0::}"; break; }; done </proc/self/cgroup
  while [[ "$path" == /sys/fs/cgroup* ]]; do
    max=""; current=""
    [ ! -r "$path/pids.max" ] || read -r max <"$path/pids.max" || true
    [ ! -r "$path/pids.current" ] || read -r current <"$path/pids.current" || true
    if [[ "$max:$current" =~ ^[0-9]+:[0-9]+$ ]]; then head=$((max-current)); [ "$head" -ge "$best" ] || best="$head"; fi
    [ "$path" != /sys/fs/cgroup ] || break
    path="${path%/*}"
  done
  nproc="$(ulimit -u 2>/dev/null || true)"
  if [ "${EUID:-0}" -ne 0 ] && [[ "$nproc" =~ ^[0-9]+$ ]]; then
    for p in /proc/[0-9]*; do
      [ -r "$p/status" ] || continue; uid=""
      while read -r key uid _; do [ "$key" != Uid: ] || break; done <"$p/status"
      [ "$uid" = "${EUID:-0}" ] || continue
      for t in "$p"/task/[0-9]*; do [ ! -d "$t" ] || count=$((count+1)); done
    done
    head=$((nproc-count)); [ "$head" -ge "$best" ] || best="$head"
  fi
  [ "$best" -ge 0 ] || best=0
  printf '%s' "$best"
}
rp_free_port(){
  local low="$1" high="$2" i p hex f addr used
  for ((i=0;i<64;i++)); do
    p=$((((RANDOM<<15)^RANDOM)%(high-low+1)+low)); printf -v hex '%04X' "$p"; used=false
    for f in /proc/net/tcp /proc/net/tcp6; do
      [ -r "$f" ] || continue
      while read -r _ addr _; do [ "${addr##*:}" != "$hex" ] || { used=true; break; }; done <"$f"
      ! $used || break
    done
    if ! $used; then RP_PORT="$p"; return 0; fi
  done
  return 1
}
rp_cleanup_selftest(){
  if [ -n "${RP_SELFTEST_PID:-}" ]; then kill "$RP_SELFTEST_PID" 2>/dev/null || true; wait "$RP_SELFTEST_PID" 2>/dev/null || true; RP_SELFTEST_PID=""; fi
  if [ -n "${RP_SELFTEST_DIR:-}" ]; then rm -rf "$RP_SELFTEST_DIR"; RP_SELFTEST_DIR=""; fi
}
# shellcheck disable=SC2034
rp_selftest(){
  local host="$1" ip="${2:-}" head mem d sp lp key val priv="" pub="" sid uuid code="" rc=0 line diag="" resolve family=4
  RP_TEST_REASON=""; RP_TEST_SCOPE=local-vless-reality
  case "${SINGBOX_REALITY_SELFTEST_MODE:-auto}" in off|0|false) RP_TEST_REASON='用户关闭本机回环测试，未验证'; return 75;; esac
  head="$(rp_pid_headroom)"; mem="$(rp_mem_kb)"
  if [ "${SINGBOX_REALITY_SELFTEST_MODE:-auto}" != force ] && { [ "$head" -lt "${SINGBOX_REALITY_SELFTEST_MIN_PID_HEADROOM:-96}" ] || { [ "$mem" -gt 0 ] && [ "$mem" -lt "${SINGBOX_REALITY_SELFTEST_MIN_MEM_KB:-131072}" ]; }; }; then
    RP_TEST_REASON="资源不足，延后本机测试（tasks余量=$head）"; return 75
  fi
  rp_valid_host "$host" || { RP_TEST_REASON='域名无效'; return 1; }
  [ -n "$ip" ] || ip="$(rp_resolve_ip "$host" || true)"
  rp_valid_ip "$ip" || { RP_TEST_REASON='缺少有效探测端点'; return 1; }
  [[ "$ip" != *:* ]] || family=6
  resolve="$ip"; [ "$family" != 6 ] || resolve="[$ip]"
  d="$(mktemp -d /tmp/sb-reality-test.XXXXXX)" || return 1; RP_SELFTEST_DIR="$d"
  rp_free_port 23000 43000 || { rp_cleanup_selftest; return 1; }; sp="$RP_PORT"
  rp_free_port 43001 62000 || { rp_cleanup_selftest; return 1; }; lp="$RP_PORT"
  if ! GODEBUG=netdns=go GOMAXPROCS=1 sing-box generate reality-keypair >"$d/keys" 2>"$d/log"; then
    RP_TEST_REASON='临时密钥生成失败'; if grep -Eqi 'newosproc|resource temporarily unavailable|failed to create new os thread' "$d/log"; then rp_cleanup_selftest; return 75; fi
    rp_cleanup_selftest; return 1
  fi
  while IFS=: read -r key val; do key="${key//[[:space:]]/}"; val="${val//[[:space:]]/}"; case "$key" in PrivateKey) priv="$val";; PublicKey) pub="$val";; esac; done <"$d/keys"
  [ -n "$priv" ] && [ -n "$pub" ] || { RP_TEST_REASON='临时密钥输出不完整'; rp_cleanup_selftest; return 1; }
  sid="$(openssl rand -hex 8)" || { RP_TEST_REASON='临时短ID生成失败'; rp_cleanup_selftest; return 1; }; uuid=""; [ ! -r /proc/sys/kernel/random/uuid ] || read -r uuid </proc/sys/kernel/random/uuid || true
  [ -n "$uuid" ] || uuid="$(sing-box generate uuid)"
  jq -n --arg host "$host" --arg ip "$ip" --arg priv "$priv" --arg pub "$pub" --arg sid "$sid" --arg uuid "$uuid" --argjson sp "$sp" --argjson lp "$lp" '
    {log:{level:"error"},inbounds:[{type:"mixed",tag:"rc",listen:"127.0.0.1",listen_port:$lp},{type:"vless",tag:"rs",listen:"127.0.0.1",listen_port:$sp,users:[{uuid:$uuid}],tls:{enabled:true,server_name:$host,reality:{enabled:true,handshake:{server:$ip,server_port:443},private_key:$priv,short_id:[$sid]}}}],outbounds:[{type:"direct",tag:"rd"},{type:"vless",tag:"rp",server:"127.0.0.1",server_port:$sp,uuid:$uuid,tls:{enabled:true,server_name:$host,utls:{enabled:true},reality:{enabled:true,public_key:$pub,short_id:$sid}}}],route:{rules:[{inbound:["rc"],action:"route",outbound:"rp"}],final:"rd"}}' >"$d/test.json" || { RP_TEST_REASON='临时配置生成失败'; rp_cleanup_selftest; return 1; }
  GODEBUG=netdns=go GOMAXPROCS=1 sing-box run -c "$d/test.json" >"$d/log" 2>&1 & RP_SELFTEST_PID=$!
  if curl "-$family" -sS --retry 3 --retry-connrefused --retry-delay 0 --retry-max-time 10 --proxy "socks5://127.0.0.1:$lp" --noproxy '' --resolve "$host:443:$resolve" --connect-timeout 2 --max-time 10 -o /dev/null -w $'%{http_code}\n' "https://$host/" >"$d/code" 2>"$d/curl.err"; then rc=0; else rc=$?; fi
  read -r code <"$d/code" || true
  if [ "$rc" -eq 0 ] && [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then RP_TEST_REASON='本机VLESS+REALITY回环通过；客户端公网路径和AnyTLS应用层未测'; rp_cleanup_selftest; return 0; fi
  if grep -Eqi 'newosproc|resource temporarily unavailable|failed to create new os thread' "$d/log"; then RP_TEST_REASON='临时进程触发资源限制'; rp_cleanup_selftest; return 75; fi
  while IFS= read -r line; do [[ "${line,,}" != *error* && "${line,,}" != *fatal* ]] || diag="$line"; done <"$d/log"
  RP_TEST_REASON="本机回环失败 HTTP=${code:-000} curl=$rc ${diag}"
  rp_cleanup_selftest; return 1
}
rp_set_status(){
  local file="$1" host="$2" status="$3" line joined
  local -a fields=()
  local tmp="${file}.status.$$"
  : >"$tmp"
  while IFS= read -r line; do IFS='|' read -r -a fields <<<"$line"; [ "${fields[0]}" != "$host" ] || fields[7]="$status"; printf -v joined '%s|' "${fields[@]}"; printf '%s\n' "${joined%|}" >>"$tmp"; done <"$file"
  mv "$tmp" "$file"
}
rp_test_pool(){
  local file="$1" vasn="$2" limit="${3:-${SINGBOX_REALITY_COMPARE_LIMIT:-3}}" row host ip rc n=0 found=false deferred=false head mem
  local -a fields=()
  [[ "$limit" =~ ^[1-5]$ ]] || limit=3
  head="$(rp_pid_headroom)"; mem="$(rp_mem_kb)"
  if [ "$head" -lt 128 ] || { [ "$mem" -gt 0 ] && [ "$mem" -lt 196608 ]; }; then limit=1; fi
  printf '本轮最多比较 %s 个候选；范围=本机VLESS+REALITY，客户端路径/AnyTLS应用层未测\n' "$limit"
  while [ "$n" -lt "$limit" ]; do
    row="$(rp_best_row "$file" "$vasn" PENDING || true)"; [ -n "$row" ] || break
    IFS='|' read -r -a fields <<<"$row"; host="${fields[0]}"; ip="${fields[11]}"; n=$((n+1))
    if rp_selftest "$host" "$ip"; then rc=0; else rc=$?; fi
    case "$rc" in
      0) rp_set_status "$file" "$host" PASS; found=true; printf '  %s [%s] PASS\n' "$host" "$ip" ;;
      75) rp_set_status "$file" "$host" DEFERRED; deferred=true; printf '  %s DEFERRED: %s\n' "$host" "${RP_TEST_REASON:-未测试}"; break ;;
      *) rp_set_status "$file" "$host" FAIL; printf '  %s FAIL: %s\n' "$host" "${RP_TEST_REASON:-回环失败}" ;;
    esac
  done
  $found && return 0
  $deferred && return 75
  return 1
}
rp_show_record(){
  local host tls h2 cert redir ms rule status reason cname asn ip family client abuse ok total compat
  IFS='|' read -r host tls h2 cert redir ms rule status reason cname asn ip family client abuse ok total compat <<<"$1"
  printf '%s: 兼容=%s 自测=%s 端点=%s/IPv%s ASN=%s 样本=%s/%s 建连≈%sms\n' "$host" "$compat" "$status" "${ip:-未知}" "${family:-?}" "$asn" "$ok" "$total" "$ms"
  printf '  TLS13=%s H2=%s CERT=%s RT=%s；客户端路径=UNMEASURED 名单信号=%s 规则=%s 回落滥用=%s；%s\n' "$tls" "$h2" "$cert" "$redir" "$client" "$rule" "$abuse" "$reason"
}
rp_public_candidates(){
  if [ "${1:-cn}" = global ]; then
    printf '%s\n' gateway.icloud.com www.debian.org www.freebsd.org www.kernel.org www.postgresql.org www.openssl.org www.openbsd.org www.netbsd.org www.videolan.org www.archlinux.org www.mozilla.org developer.mozilla.org
  else printf '%s\n' www.debian.org www.openssl.org www.postgresql.org www.alpinelinux.org; fi
}
rp_discover_candidates(){
  local asn="$1" prefix="$2" output="$3" max="${SINGBOX_REALITY_DYNAMIC_MAX:-12}" days="${SINGBOX_REALITY_URLSCAN_DAYS:-180}" source query raw host apex url status tlsdays malicious tasksource label count=0 esc
  local -a args=() sources=() queries=()
  local -A seen=()
  : >"$output"
  case "${SINGBOX_REALITY_DYNAMIC_DISCOVERY:-auto}" in off|0|false) return 0;; esac
  [[ "$max" =~ ^[0-9]+$ ]] || max=12; [ "$max" -le 24 ] || max=24
  [[ "$days" =~ ^[0-9]+$ ]] || days=180
  if [ "$(rp_mem_kb)" -lt 262144 ] && [ "$max" -gt 4 ]; then max=4; fi
  if [ -n "$prefix" ]; then esc="${prefix//\//\\/}"; queries+=("page.ip:$esc AND date:>now-${days}d"); sources+=(dynamic-prefix); fi
  if [[ "$asn" =~ ^AS[0-9]+$ ]]; then queries+=("page.asn:$asn AND date:>now-${days}d"); sources+=(dynamic-asn); fi
  local i
  for i in "${!queries[@]}"; do
    [ "$count" -lt "$max" ] || break
    source="${sources[i]}"; query="${queries[i]}"
    args=(--noproxy '*' -fsS --connect-timeout 4 --max-time 12 --get https://urlscan.io/api/v1/search/ --data-urlencode "q=$query" --data-urlencode size=50 --data-urlencode datasource=scans --data-urlencode collapse=page.domain.keyword)
    [ -z "${SINGBOX_URLSCAN_API_KEY:-}" ] || args+=(-H "api-key: $SINGBOX_URLSCAN_API_KEY")
    raw="$(curl "${args[@]}" 2>/dev/null || true)"
    if ! jq -e '.results|type=="array"' >/dev/null 2>&1 <<<"$raw"; then printf '被动发现 %s 无结果/接口不可用；保留公共兜底，客户端可达性仍未测。\n' "$source" >&2; continue; fi
    while IFS='|' read -r host apex url status tlsdays malicious tasksource; do
      [ "$count" -lt "$max" ] || break
      host="${host,,}"; host="${host%.}"; apex="${apex,,}"; apex="${apex%.}"; [ -n "$apex" ] || apex="$host"
      rp_valid_host "$host" && rp_valid_host "$apex" || continue
      { [ "$host" = "$apex" ] || [ "$host" = "www.$apex" ]; } || continue
      [ -z "${seen[$host]+x}" ] && [[ "$url" == https://* ]] || continue
      [[ "$status" =~ ^[23][0-9][0-9]$ && "$tlsdays" =~ ^[0-9]+$ ]] && [ "$tlsdays" -gt 0 ] || continue
      [ "$malicious" != true ] || continue
      case "${tasksource,,}" in *phishtank*|*certstream-suspicious*|*openphish*|*urlhaus*) continue;; esac
      label="${apex%%.*}"
      case "$label" in google*|youtube*|tiktok*|facebook*|instagram*|whatsapp*|telegram*|apple*|icloud*|microsoft*|openai*|chatgpt*|netflix*|paypal*|amazon*|cloudflare*|discord*|twitter*) continue;; esac
      seen["$host"]=1; printf '%s|%s\n' "$host" "$source" >>"$output"; count=$((count+1))
    done < <(jq -r '.results[]? | [(.page.domain//""),(.page.apexDomain//""),(.page.url//""),((.page.status//0)|tostring),((.page.tlsValidDays//0)|tostring),((.verdicts.malicious//.verdicts.overall.malicious//.verdicts.urlscan.malicious//false)|tostring),(.task.source//"")] | map(tostring|gsub("[|\r\n]";" ")) | join("|")' <<<"$raw")
  done
  return 0
}
# END REALITY_POLICY

emit_reality_policy(){
  local name
  while IFS= read -r name; do declare -f "$name"; done < <(compgen -A function rp_)
}
inject_reality_policy(){
  local file="$1" line tmp
  tmp="$(mktemp "${file}.policy.XXXXXX")" || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "# __REALITY_POLICY__" ]; then emit_reality_policy; else printf '%s\n' "$line"; fi
  done <"$file" >"$tmp"
  chmod 700 "$tmp"; mv -f "$tmp" "$file"
}

# ---------- 系统与依赖 ----------
detect_os(){
  local id="" like=""
  if [ -r /etc/os-release ]; then
    id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2);print tolower($2);exit}' /etc/os-release)"
    like="$(awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2);print tolower($2);exit}' /etc/os-release)"
  fi
  OS_ID="$id"
  case " $id $like " in
    *alpine*) OS="alpine" ;;
    *debian*|*ubuntu*) OS="debian" ;;
    *rhel*|*centos*|*fedora*|*rocky*|*almalinux*) OS="redhat" ;;
    *) OS="unknown" ;;
  esac
}

install_deps(){
  info "安装/检查依赖..."
  local -a pkgs=()
  case "$OS" in
    alpine)
      command -v bash >/dev/null 2>&1 || pkgs+=(bash)
      command -v curl >/dev/null 2>&1 || pkgs+=(curl)
      command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
      command -v jq >/dev/null 2>&1 || pkgs+=(jq)
      command -v dig >/dev/null 2>&1 || pkgs+=(bind-tools)
      [ -s /etc/ssl/certs/ca-certificates.crt ] || pkgs+=(ca-certificates)
      if ! command -v timeout >/dev/null 2>&1 || ! command -v base64 >/dev/null 2>&1; then pkgs+=(coreutils); fi
      command -v tar >/dev/null 2>&1 || pkgs+=(tar)
      if [ "${#pkgs[@]}" -gt 0 ]; then
        info "Alpine 最小依赖：${pkgs[*]}"
        apk add --no-cache "${pkgs[@]}"
      else
        info "Alpine 必要依赖已满足；跳过 apk 安装。"
      fi
      ;;
    debian)
      command -v curl >/dev/null 2>&1 || pkgs+=(curl)
      command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
      command -v jq >/dev/null 2>&1 || pkgs+=(jq)
      command -v dig >/dev/null 2>&1 || pkgs+=(dnsutils)
      if ! command -v timeout >/dev/null 2>&1 || ! command -v base64 >/dev/null 2>&1; then pkgs+=(coreutils); fi
      command -v tar >/dev/null 2>&1 || pkgs+=(tar)
      [ -s /etc/ssl/certs/ca-certificates.crt ] || pkgs+=(ca-certificates)
      if [ "${#pkgs[@]}" -gt 0 ]; then
        export DEBIAN_FRONTEND=noninteractive
        info "Debian 缺少依赖：${pkgs[*]}"
        apt-get update -y
        apt-get install -y "${pkgs[@]}"
      else
        info "Debian 必要依赖已满足；跳过 apt 更新。"
      fi
      ;;
    redhat)
      command -v curl >/dev/null 2>&1 || pkgs+=(curl)
      command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
      command -v jq >/dev/null 2>&1 || pkgs+=(jq)
      command -v dig >/dev/null 2>&1 || pkgs+=(bind-utils)
      if ! command -v timeout >/dev/null 2>&1 || ! command -v base64 >/dev/null 2>&1; then pkgs+=(coreutils); fi
      command -v tar >/dev/null 2>&1 || pkgs+=(tar)
      { [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ]; } || pkgs+=(ca-certificates)
      if [ "${#pkgs[@]}" -gt 0 ]; then
        info "Red Hat 系缺少依赖：${pkgs[*]}"
        if command -v dnf >/dev/null 2>&1; then dnf install -y "${pkgs[@]}"; else yum install -y "${pkgs[@]}"; fi
      else
        info "Red Hat 系必要依赖已满足；跳过包管理器。"
      fi
      ;;
    *) warn "未识别发行版；将尝试使用现有 curl/openssl/jq/timeout。" ;;
  esac
  local c
  for c in curl openssl jq timeout tar base64 dig; do command -v "$c" >/dev/null 2>&1 || die "缺少依赖：$c"; done
}

cleanup_stale_singbox_packages(){
  local d f
  for d in "${PWD:-/root}" /root /tmp; do
    [ -d "$d" ] || continue
    for f in "$d"/sing-box_[0-9]*_linux_*.apk "$d"/sing-box-[0-9]*-linux-*.tar.gz; do
      [ -f "$f" ] || continue
      warn "清理残留安装包：$f"
      rm -f -- "$f" || true
    done
  done
}

resolve_stable_singbox_version(){
  local v="" u=""
  if [ -n "${SINGBOX_VERSION:-}" ]; then
    v="${SINGBOX_VERSION#v}"
  else
    u="$(curl -fsSIL --retry 2 --connect-timeout 5 --max-time 15 -o /dev/null -w '%{url_effective}' \
      https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null || true)"
    case "$u" in
      */tag/v*) v="${u##*/tag/v}" ;;
      */v*) v="${u##*/v}" ;;
    esac
    if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      v="$(curl -fsSL --retry 2 --connect-timeout 5 --max-time 15 \
        https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
        | jq -r '.tag_name // empty' 2>/dev/null || true)"
      v="${v#v}"
    fi
  fi
  if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    v="$SINGBOX_STABLE_FALLBACK_VERSION"
    warn "无法在线解析最新 stable，使用脚本内置稳定版本 v${v}。"
  fi
  printf '%s' "$v"
}

singbox_release_arch(){
  case "$(uname -m 2>/dev/null || true)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    armv7l|armv7) printf 'armv7' ;;
    i386|i486|i586|i686) printf '386' ;;
    armv6l|armv6) printf 'armv6' ;;
    *) return 1 ;;
  esac
}

install_singbox_alpine_stream(){
  local ver arch flavor asset base url stage rootdir bin free_kb
  cleanup_stale_singbox_packages
  ver="$(resolve_stable_singbox_version)"
  arch="$(singbox_release_arch)" || die "当前 Alpine 架构 $(uname -m) 暂无本脚本已知的官方 release 映射。"
  flavor="-musl"
  [ "$arch" = armv6 ] && flavor=""
  base="sing-box-${ver}-linux-${arch}${flavor}"
  asset="${base}.tar.gz"
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${asset}"

  free_kb="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}' || true)"
  if [[ "$free_kb" =~ ^[0-9]+$ ]] && [ "$free_kb" -lt 92160 ]; then
    die "当前根分区仅剩约 $((free_kb/1024)) MiB；清理后仍不足 90 MiB，无法安全安装 sing-box。"
  fi

  mkdir -p /usr/local/bin /usr/local/lib
  stage="/usr/local/lib/.sing-box-stage.$$"
  rm -rf "$stage"; mkdir -p "$stage"; TMP_FILES+=("$stage")

  info "Alpine Tiny 模式：流式安装官方 sing-box v${ver} (${arch}${flavor})，不落盘完整 .apk/.tar.gz。"
  if ! curl -fL --retry 3 --retry-delay 1 --connect-timeout 8 --max-time 180 "$url" \
      | tar -xzf - -C "$stage"; then
    rm -rf "$stage"
    die "下载/解压官方 musl release 失败：$url"
  fi
  rootdir="$stage/$base"
  bin=""
  for candidate in "$rootdir/sing-box" "$stage/sing-box" "$stage"/*/sing-box; do
    if [ -f "$candidate" ]; then bin="$candidate"; break; fi
  done
  [ -n "$bin" ] && [ -s "$bin" ] || die "官方 release 中未找到 sing-box 二进制。"
  chmod 755 "$bin"
  GOMAXPROCS=1 "$bin" version >/dev/null 2>&1 || die "下载得到的 sing-box 二进制无法在当前 Alpine 上运行。"

  mv -f "$bin" /usr/local/bin/sing-box
  chmod 755 /usr/local/bin/sing-box
  ln -sf /usr/local/bin/sing-box /usr/bin/sing-box 2>/dev/null || true
  rm -rf "$stage"
}

install_singbox(){
  if command -v sing-box >/dev/null 2>&1; then
    info "检测到：$(sing-box version 2>/dev/null | head -n1 || true)"
    local current_ver ans="${SINGBOX_REINSTALL:-}"
    current_ver="$(singbox_version_number || true)"
    if [ -z "$current_ver" ] || ! version_ge "$current_ver" "$MIN_SINGBOX_VERSION"; then
      warn "当前 sing-box ${current_ver:-未知} 低于本脚本最低要求 $MIN_SINGBOX_VERSION，必须更新。"
      ans="y"
    else
      if [ -z "$ans" ]; then read -r -p "是否更新/重新安装到当前 stable？(y/N): " ans; fi
      if [[ ! "$ans" =~ ^[Yy]$ ]]; then return 0; fi
    fi
  fi

  if [ "$OS" = alpine ]; then
    install_singbox_alpine_stream
  else
    info "通过官方安装脚本安装 sing-box..."
    local tmp
    tmp="$(mktemp /tmp/sing-box-install.XXXXXX)"; TMP_FILES+=("$tmp")
    curl -fsSL --retry 3 --connect-timeout 8 https://sing-box.app/install.sh -o "$tmp" || die "下载 sing-box 官方安装脚本失败。"
    bash "$tmp"
  fi

  command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"
  local installed_ver
  installed_ver="$(singbox_version_number || true)"
  [ -n "$installed_ver" ] || die "无法识别 sing-box 版本。"
  version_ge "$installed_ver" "$MIN_SINGBOX_VERSION" || die "sing-box $installed_ver 过旧；本脚本要求 >= $MIN_SINGBOX_VERSION。"
  ok "$(sing-box version 2>/dev/null | head -n1)（stable 策略；脚本不自动追 alpha/testing）"
}

# ---------- 通用工具 ----------
rand_port(){
  local low="${1:-10000}" high="${2:-60000}" p i span
  span=$((high - low + 1))
  for ((i=0; i<96; i++)); do
    # 端口不属于密码学随机数据，使用 Bash RANDOM 可避免 seq/shuf 子进程。
    p=$(( ((RANDOM << 15) ^ RANDOM) % span + low ))
    if ! port_in_use "$p"; then printf '%s\n' "$p"; return 0; fi
  done
  return 1
}

port_in_use(){
  # 直接读取 procfs，避免低 PID 环境里为每次随机端口检测启动 ss|awk|grep 管道。
  local p="$1" hex f line local_addr
  printf -v hex '%04X' "$p"
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    while read -r _ local_addr _; do
      [ "${local_addr##*:}" = "$hex" ] && return 0
    done <"$f"
  done
  return 1
}

validate_port(){ [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

prompt_port(){
  local label="$1" envv="${2:-}" p
  if [ -n "$envv" ]; then p="$envv"; else
    while true; do
      p="$(rand_port 10000 60000)" || die "无法生成空闲端口。"
      read -r -p "${label} 端口 [默认 ${p}]: " input
      p="${input:-$p}"
      validate_port "$p" || { warn "端口无效。"; continue; }
      port_in_use "$p" && { warn "端口 ${p} 已被占用。"; continue; }
      break
    done
  fi
  validate_port "$p" || die "无效端口：$p"
  printf '%s' "$p"
}

rand_uuid(){
  if [ -r /proc/sys/kernel/random/uuid ]; then cat /proc/sys/kernel/random/uuid; else
    local h; h="$(openssl rand -hex 16)"
    printf '%s-%s-%s-%s-%s\n' "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
  fi
}
rand_pass(){ openssl rand -base64 24; }
url_encode(){
  # RFC 3986 percent-encoding，按 UTF-8 字节编码；中文节点名也能生成规范 URI fragment。
  local LC_ALL=C s="$1" out="" c hx i
  for ((i=0; i<${#s}; i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9.~_-]) out+="$c" ;;
      *) printf -v hx '%%%02X' "'$c"; out+="$hx" ;;
    esac
  done
  printf '%s' "$out"
}
format_uri_host(){
  local h="$1"
  h="${h#[}"; h="${h%]}"
  if [[ "$h" == *:* ]]; then printf '[%s]' "$h"; else printf '%s' "$h"; fi
}
normalize_host(){ local h="${1:-}"; h="${h#[}"; h="${h%]}"; printf '%s' "$h"; }

get_public_ipv4(){
  local u x
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
    x="$(curl -4 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null || true)"
    x="${x//$'\r'/}"; x="${x//$'\n'/}"; x="${x//[[:space:]]/}"
    [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$x"; return 0; }
  done
  return 1
}
get_public_ipv6(){
  local u x
  for u in https://api64.ipify.org https://ipv6.icanhazip.com https://ifconfig.co/ip; do
    x="$(curl -6 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null || true)"
    x="${x//$'\r'/}"; x="${x//$'\n'/}"; x="${x//[[:space:]]/}"
    [[ "$x" == *:* ]] && { printf '%s' "$x"; return 0; }
  done
  return 1
}

normalize_sni(){
  # 纯 Bash 规范化，避免在低 PID/TasksMax 环境里为简单字符串处理额外 fork。
  local s="${1:-}"
  s="${s//[[:space:]]/}"
  s="${s,,}"
  s="${s%.}"
  printf '%s' "$s"
}
validate_sni(){
  local s="$1" label
  [ -n "$s" ] && [ "${#s}" -le 253 ] || return 1
  [[ "$s" =~ ^[a-z0-9.-]+$ ]] || return 1
  [[ "$s" != .* && "$s" != *..* && "$s" != *-.* && "$s" != *.-* ]] || return 1
  IFS='.' read -r -a parts <<<"$s"
  [ "${#parts[@]}" -ge 2 ] || return 1
  for label in "${parts[@]}"; do
    [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
    [[ "$label" =~ ^[a-z0-9-]+$ ]] || return 1
    [[ "$label" != -* && "$label" != *- ]] || return 1
  done
}

seconds_to_ms(){
  # curl 的 time_appconnect 为十进制秒；纯 Bash 转成毫秒，避免 awk/sort 子进程。
  local x="${1:-}" whole frac fourth ms
  [[ "$x" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  whole="${x%%.*}"
  if [[ "$x" == *.* ]]; then frac="${x#*.}"; else frac=""; fi
  frac="${frac}0000"
  ms=$((10#$whole * 1000 + 10#${frac:0:3}))
  fourth="${frac:3:1}"
  [[ "$fourth" =~ ^[5-9]$ ]] && ms=$((ms + 1))
  printf '%d' "$ms"
}

median_ms(){
  # 候选测试通常只有 3 个样本；纯 Bash 排序，降低低配 VPS 的 fork 峰值。
  local x m i j tmp
  local -a vals=()
  for x in "$@"; do
    m="$(seconds_to_ms "$x" 2>/dev/null || true)"
    [[ "$m" =~ ^[0-9]+$ ]] && [ "$m" -gt 0 ] && vals+=("$m")
  done
  [ "${#vals[@]}" -gt 0 ] || { printf '999999'; return 0; }
  for ((i=0; i<${#vals[@]}; i++)); do
    for ((j=i+1; j<${#vals[@]}; j++)); do
      if [ "${vals[j]}" -lt "${vals[i]}" ]; then
        tmp="${vals[i]}"; vals[i]="${vals[j]}"; vals[j]="$tmp"
      fi
    done
  done
  if (( ${#vals[@]} % 2 == 1 )); then
    printf '%d' "${vals[${#vals[@]}/2]}"
  else
    i=$((${#vals[@]}/2))
    printf '%d' $(( (vals[i-1] + vals[i]) / 2 ))
  fi
}

# ---------- Reality target 兼容性与观测 ----------
resolve_cnames(){
  local host="$1"
  command -v dig >/dev/null 2>&1 || return 0
  # 跟随最多 3 层 CNAME；这里只用于 CDN 风险识别，避免在低资源 VPS 上做过深 DNS 链追踪。
  local cur="$host" nxt raw line i
  for i in 1 2 3; do
    raw="$(dig +time=1 +tries=1 +short CNAME "$cur" 2>/dev/null || true)"
    nxt=""
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      nxt="$line"; break
    done <<<"$raw"
    [ -n "$nxt" ] || break
    nxt="${nxt%.}"; nxt="${nxt,,}"
    printf '%s\n' "$nxt"
    [ "$nxt" = "$cur" ] && break
    cur="$nxt"
  done
}

lookup_ipv4(){
  local h="$1" raw line
  command -v dig >/dev/null 2>&1 || return 1
  raw="$(dig +time=2 +tries=1 +short A "$h" 2>/dev/null || true)"
  while IFS= read -r line; do
    if [[ "$line" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      printf '%s' "$line"
      return 0
    fi
  done <<<"$raw"
  return 1
}

first_nonempty_line(){
  local line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    printf '%s' "$line"
    return 0
  done
  return 1
}

trim_ws(){
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

origin_info_for_ipv4(){
  # 优先 Team Cymru；若 DNS 查询拿不到完整 BGP prefix，则回退 RIPEstat Network Info。
  # 输出：ASxxxxx|prefix。失败不影响主流程。
  local ip="$1" a b c d q raw ans n="" prefix="" rjson rasn rpfx
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

  if command -v dig >/dev/null 2>&1; then
    IFS='.' read -r a b c d <<<"$ip"
    q="${d}.${c}.${b}.${a}.origin.asn.cymru.com"
    raw="$(dig +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"
    ans="$(first_nonempty_line <<<"$raw" || true)"
    [ -n "$ans" ] || { raw="$(dig @1.1.1.1 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(first_nonempty_line <<<"$raw" || true)"; }
    [ -n "$ans" ] || { raw="$(dig @9.9.9.9 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(first_nonempty_line <<<"$raw" || true)"; }
    if [ -n "$ans" ]; then
      ans="${ans//\"/}"
      IFS='|' read -r n _ prefix _ <<<"$ans"
      n="$(trim_ws "$n")"; prefix="$(trim_ws "$prefix")"
      [[ "$n" =~ ^[0-9]+$ ]] || n=""
      [[ "$prefix" == */* ]] || prefix=""
    fi
  fi

  # 部分网络会拦截 Team Cymru DNS；RIPEstat 可直接返回 prefix + announcing ASNs。
  if [ -z "$n" ] || [ -z "$prefix" ]; then
    rjson="$(curl -fsS --connect-timeout 3 --max-time 7 --get \
      'https://stat.ripe.net/data/network-info/data.json' \
      --data-urlencode "resource=$ip" \
      --data-urlencode 'sourceapp=singbox-deploy' 2>/dev/null || true)"
    if [ -n "$rjson" ]; then
      rasn="$(jq -r '.data.asns[0] // empty' <<<"$rjson" 2>/dev/null || true)"
      rpfx="$(jq -r '.data.prefix // empty' <<<"$rjson" 2>/dev/null || true)"
      [[ "$rasn" =~ ^[0-9]+$ ]] && [ -z "$n" ] && n="$rasn"
      [[ "$rpfx" == */* ]] && [ -z "$prefix" ] && prefix="$rpfx"
    fi
  fi

  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  printf 'AS%s|%s' "$n" "$prefix"
}

asn_for_ipv4(){
  local info
  info="$(origin_info_for_ipv4 "$1" || true)"
  [ -n "$info" ] || return 1
  printf '%s' "${info%%|*}"
}

prefix_for_ipv4(){
  local info
  info="$(origin_info_for_ipv4 "$1" || true)"
  [ -n "$info" ] || return 1
  printf '%s' "${info#*|}"
}

refresh_reality_gfwlist(){
  # CN 画像的保守排除信号；文件不可用时 fail-open，不影响安装。
  [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] || return 0
  [ "${REALITY_GFWLIST_CHECK:-1}" = 1 ] || return 0
  $REALITY_GFWLIST_READY && return 0
  local tmp="${REALITY_GFWLIST_CACHE}.tmp.$$" url mtime now
  if [ -s "$REALITY_GFWLIST_CACHE" ]; then
    mtime="$(stat -c %Y "$REALITY_GFWLIST_CACHE" 2>/dev/null || true)"
    now="$(date +%s)"
    if [[ "$mtime" =~ ^[0-9]+$ ]] && [ "$now" -ge "$mtime" ] && [ $((now-mtime)) -lt 86400 ]; then
      REALITY_GFWLIST_READY=true
      return 0
    fi
  fi
  mkdir -p "$CONFIG_DIR" 2>/dev/null || true
  : >"$tmp" 2>/dev/null || return 0
  for url in \
    'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt' \
    'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt'; do
    if curl -fsSL --retry 1 --connect-timeout 4 --max-time 10 "$url" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
      # 纯文本域名列表；只保留看起来像域名的行，避免意外内容进入判断文件。
      local clean="${tmp}.clean" line d n=0
      : >"$clean"
      while IFS= read -r line || [ -n "$line" ]; do
        d="${line%$'\r'}"; d="${d,,}"; d="${d#.}"; d="${d%.}"
        [[ "$d" =~ ^[a-z0-9.-]+\.[a-z0-9-]+$ ]] || continue
        printf '%s\n' "$d" >>"$clean"; n=$((n+1))
      done <"$tmp"
      if [ "$n" -ge 100 ]; then
        install -m 600 "$clean" "$REALITY_GFWLIST_CACHE" 2>/dev/null || cp "$clean" "$REALITY_GFWLIST_CACHE"
        rm -f "$tmp" "$clean"; REALITY_GFWLIST_READY=true; return 0
      fi
      rm -f "$clean"
    fi
  done
  rm -f "$tmp"
  [ -s "$REALITY_GFWLIST_CACHE" ] && REALITY_GFWLIST_READY=true
  return 0
}

reality_host_in_gfwlist(){
  local host="${1,,}" suffix
  local -a patterns=()
  [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] || return 1
  [ "${REALITY_GFWLIST_CHECK:-1}" = 1 ] || return 1
  [ -s "$REALITY_GFWLIST_CACHE" ] || return 1
  # Bash 按行扫描整个域名表会为每个候选重复执行数万次循环。
  # 枚举完整域名和父域，以一次定行匹配保留原有的子域命中语义。
  suffix="$host"
  while [[ "$suffix" == *.* ]]; do
    patterns+=(-e "$suffix")
    suffix="${suffix#*.}"
  done
  [ "${#patterns[@]}" -gt 0 ] || return 1
  grep -Fqx "${patterns[@]}" "$REALITY_GFWLIST_CACHE"
}

candidate_set_meta(){
  local host="$1" source="${2:-unknown}" age="${3:-0}" rank="${7:-0}"
  REALITY_CANDIDATE_SOURCE["$host"]="$source"
  REALITY_CANDIDATE_AGE["$host"]="$age"
  REALITY_CANDIDATE_RANK["$host"]="$rank"
}

candidate_source(){ printf '%s' "${REALITY_CANDIDATE_SOURCE[$1]:-public}"; }

discover_reality_candidates(){
  local asn="$1" prefix="$2" output="$3" rows="${3}.sources" host source
  : >"$output"; TMP_FILES+=("$rows")
  rp_discover_candidates "$asn" "$prefix" "$rows"
  while IFS='|' read -r host source; do candidate_set_meta "$host" "$source"; printf '%s\n' "$host" >>"$output"; done <"$rows"
  cp "$rows" "$REALITY_DISCOVERY_CACHE" 2>/dev/null || true; rm -f "$rows"
}

pid_headroom_fast(){
  # 返回当前 shell 可用 PID/Tasks 余量的保守估计。
  # cgroup v2 的 pids 限制具有继承性：真正有效上限可能在 session.scope 的父级 user.slice，
  # 因此必须沿当前 cgroup 一直向上检查，而不能只读当前目录。
  # 999999 表示没有发现有限上限。
  local best=999999 headroom cgline cgrel cgbase cgmax cgcur parent
  local nproc_limit uid_tasks

  if [ -r /proc/self/cgroup ]; then
    while IFS= read -r cgline; do
      if [[ "$cgline" == 0::* ]]; then
        cgrel="${cgline#0::}"
        cgbase="/sys/fs/cgroup${cgrel}"
        break
      fi
    done </proc/self/cgroup
  fi
  cgbase="${cgbase:-/sys/fs/cgroup}"

  # 检查当前 cgroup 以及所有祖先的 pids.max/pids.current，取最小余量。
  while [[ "$cgbase" == /sys/fs/cgroup* ]]; do
    if [ -r "${cgbase}/pids.max" ] && [ -r "${cgbase}/pids.current" ]; then
      read -r cgmax <"${cgbase}/pids.max" || cgmax=max
      read -r cgcur <"${cgbase}/pids.current" || cgcur=0
      if [[ "$cgmax" =~ ^[0-9]+$ && "$cgcur" =~ ^[0-9]+$ ]]; then
        headroom=$((cgmax - cgcur))
        [ "$headroom" -lt "$best" ] && best="$headroom"
      fi
    fi
    [ "$cgbase" = /sys/fs/cgroup ] && break
    parent="${cgbase%/*}"
    [ "$parent" = "$cgbase" ] && break
    cgbase="$parent"
  done

  # RLIMIT_NPROC 是按同 UID 的 task/thread 计数，而不是简单的进程数。
  # root/CAP_SYS_RESOURCE 通常不受该限制，但对非特权运行环境仍做保守估计。
  nproc_limit="$(ulimit -u 2>/dev/null || true)"
  if [[ "$nproc_limit" =~ ^[0-9]+$ ]] && [ "${EUID:-0}" -ne 0 ]; then
    uid_tasks="$(uid_task_count_fast)"
    headroom=$((nproc_limit - uid_tasks))
    [ "$headroom" -lt "$best" ] && best="$headroom"
  fi

  [ "$best" -lt 0 ] && best=0
  printf '%d' "$best"
}

print_target_row(){
  printf '%-25s %-6s %-4s %-6s %-8s %-8s %-9s %-10s %s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}

proc_count_fast(){
  local p n=0
  for p in /proc/[0-9]*; do [ -d "$p" ] && n=$((n+1)); done
  printf '%d' "$n"
}

uid_task_count_fast(){
  # 统计当前 EUID 拥有的 Linux tasks（线程也计数），纯 Bash，不额外 fork。
  local p t key uid n=0 want="${EUID:-0}"
  for p in /proc/[0-9]*; do
    [ -r "$p/status" ] || continue
    uid=""
    while read -r key uid _; do
      [ "$key" = "Uid:" ] && break
    done <"$p/status"
    [ "$uid" = "$want" ] || continue
    for t in "$p"/task/[0-9]*; do [ -d "$t" ] && n=$((n+1)); done
  done
  printf '%d' "$n"
}

mem_available_kb(){
  local key val
  [ -r /proc/meminfo ] || { printf '0'; return 0; }
  while read -r key val _; do
    if [ "$key" = "MemAvailable:" ]; then printf '%s' "${val:-0}"; return 0; fi
  done </proc/meminfo
  printf '0'
}

cpu_count_fast(){
  local key rest n=0
  [ -r /proc/cpuinfo ] || { printf '1'; return 0; }
  while IFS=: read -r key rest; do
    key="${key//[[:space:]]/}"
    [ "$key" = "processor" ] && n=$((n+1))
  done </proc/cpuinfo
  [ "$n" -gt 0 ] || n=1
  printf '%d' "$n"
}

resolve_reality_audit_jobs(){
  # 静态审计可并发，但必须服从当前 cgroup/ulimit 的 PID 余量。
  # 真握手自测始终串行且单 sing-box 进程，与这里的并发完全解耦。
  local req="${REALITY_AUDIT_JOBS:-auto}" cpu mem jobs=1 headroom
  headroom="$(pid_headroom_fast)"
  if [[ "$req" =~ ^[1-9][0-9]*$ ]]; then
    jobs="$req"
    [ "$jobs" -le 4 ] || jobs=4
  else
    cpu="$(cpu_count_fast)"
    mem="$(mem_available_kb)"
    jobs=1
    if [ "$cpu" -ge 2 ] && [ "$mem" -ge 393216 ] && [ "$headroom" -ge 96 ]; then jobs=2; fi
    if [ "$cpu" -ge 4 ] && [ "$mem" -ge 786432 ] && [ "$headroom" -ge 160 ]; then jobs=3; fi
    if [ "$cpu" -ge 8 ] && [ "$mem" -ge 1572864 ] && [ "$headroom" -ge 256 ]; then jobs=4; fi
  fi
  # 显式设置并发也不能突破资源安全底线，避免用户误设造成 fork 风暴。
  [ "$headroom" -lt 64 ] && jobs=1
  [ "$headroom" -ge 64 ] && [ "$headroom" -lt 112 ] && [ "$jobs" -gt 2 ] && jobs=2
  [ "$headroom" -ge 112 ] && [ "$headroom" -lt 192 ] && [ "$jobs" -gt 3 ] && jobs=3
  [ "$jobs" -ge 1 ] || jobs=1
  printf '%d' "$jobs"
}

audit_reality_one(){ rp_probe_row "$1" "${REALITY_CLIENT_PROFILE:-cn}" "$REALITY_GFWLIST_CACHE" "$REALITY_VPS_ASN" >"$2"; }
audit_reality_candidates(){
  local file="$1"; shift
  local host row out pid jobs count=0
  local -a pids=() files=()
  local -A seen=()
  jobs="$(resolve_reality_audit_jobs)"
  while IFS='|' read -r host _; do [ -z "$host" ] || seen["$host"]=1; done <"$file"
  for host in "$@"; do
    host="$(normalize_sni "$host")"; rp_valid_host "$host" || continue
    [ -z "${seen[$host]+x}" ] || continue; seen["$host"]=1
    out="${file}.candidate.${count}"; TMP_FILES+=("$out"); count=$((count+1))
    audit_reality_one "$host" "$out" & pid=$!; pids+=("$pid"); files+=("$out")
    if [ "${#pids[@]}" -ge "$jobs" ]; then
      for pid in "${pids[@]}"; do wait "$pid" || true; done
      for out in "${files[@]}"; do if [ -s "$out" ]; then cat "$out" >>"$file"; row="$(cat "$out")"; rp_show_record "$row"; fi; rm -f "$out"; done
      pids=(); files=()
    fi
  done
  for pid in "${pids[@]}"; do wait "$pid" || true; done
  for out in "${files[@]}"; do if [ -s "$out" ]; then cat "$out" >>"$file"; row="$(cat "$out")"; rp_show_record "$row"; fi; rm -f "$out"; done
}
run_reality_selftests(){ SINGBOX_REALITY_SELFTEST_MODE="${REALITY_SELFTEST_MODE:-auto}" rp_test_pool "$1" "$2" "${SINGBOX_REALITY_COMPARE_LIMIT:-3}"; }
pick_reality_best(){ rp_best_row "$1" "$2" PASS || rp_best_row "$1" "$2" DEFERRED; }
record_reality_choice(){
  local row="$1" source="${2:-}"
  local -a f=()
  IFS='|' read -r -a f <<<"$row"
  REALITY_SNI="${f[0]}"; REALITY_TARGET_IP="${f[11]}"; REALITY_TARGET_FAMILY="${f[12]}"
  REALITY_SELECTED_ASN="${f[10]}"; REALITY_SELECTED_SOURCE="${source:-$(candidate_source "$REALITY_SNI")}"
  REALITY_SELECTED_RULE="${f[6]}"; REALITY_SELECTED_CLIENT_LIST_SIGNAL="${f[13]}"; REALITY_SELECTED_FALLBACK_ABUSE="${f[14]}"
  REALITY_SELECTED_SAMPLE_OK="${f[15]}"; REALITY_SELECTED_SAMPLE_TOTAL="${f[16]}"; REALITY_SELECTED_COMPAT="${f[17]}"
  REALITY_SELECTED_SELFTEST="${f[7]}";  REALITY_SELECTED_TLS_MS="${f[5]}"
  REALITY_SELECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  REALITY_SELECTED_AGE_DAYS="${REALITY_CANDIDATE_AGE[$REALITY_SNI]:-0}"; REALITY_SELECTED_UMBRELLA_RANK="${REALITY_CANDIDATE_RANK[$REALITY_SNI]:-0}"
}

select_reality_client_profile(){
  local raw="${SINGBOX_REALITY_CLIENT_PROFILE:-${REALITY_CLIENT_PROFILE:-cn}}"
  if [ -z "${SINGBOX_REALITY_CLIENT_PROFILE:-}" ]; then
    echo
    info "=== Reality 客户端主要网络环境 ==="
    echo "1) 中国大陆（默认/推荐：排除长期受限或高度不稳定 SNI）"
    echo "2) 海外 / 不受中国大陆网络限制"
    read -r -p "请选择 [默认 1]: " raw
    case "${raw:-1}" in
      1|cn|CN|china|mainland) raw="cn" ;;
      2|global|GLOBAL|overseas) raw="global" ;;
      *) warn "无效选择，使用中国大陆画像。"; raw="cn" ;;
    esac
  else
    case "$raw" in
      cn|CN|china|mainland|1) raw="cn" ;;
      global|GLOBAL|overseas|2) raw="global" ;;
      *) warn "SINGBOX_REALITY_CLIENT_PROFILE=$raw 无效，使用 cn。"; raw="cn" ;;
    esac
  fi
  REALITY_CLIENT_PROFILE="$raw"
  if [ "$raw" = "cn" ]; then
    info "Reality 客户端画像：中国大陆；受限/高度不稳定域名不会进入自动推荐。"
  else
    info "Reality 客户端画像：海外/不限制。"
  fi
  return 0
}

select_reality_sni(){
  local forced="${SINGBOX_REALITY_SNI:-}" file dyn host row picked="" alt entry="" vasn=未知 prefix="" origin choice rc=0 status source endpoint_label
  local -a primary=() extended=() dynamic=() extras=() f=()
  refresh_reality_gfwlist || true
  while IFS= read -r host; do primary+=("$host"); done < <(rp_public_candidates "${REALITY_CLIENT_PROFILE:-cn}")
  case "${REALITY_CLIENT_PROFILE:-cn}" in cn) extended=("${REALITY_CANDIDATES_CN_EXTENDED[@]}");; *) extended=("${REALITY_CANDIDATES_GLOBAL_EXTENDED[@]}");; esac
  for host in "${primary[@]}"; do candidate_set_meta "$host" public-core; done
  for host in "${extended[@]}"; do candidate_set_meta "$host" public-extended; done
  endpoint_label='配置的入口地址'
  [ -n "${CONNECTION_HOST:-}" ] || endpoint_label='公网出口（未确认入口，NAT/多出口需人工核对）'
  origin="$(rp_vps_identity "${CONNECTION_HOST:-}")"; IFS='|' read -r entry vasn prefix <<<"$origin"; vasn="${vasn:-未知}"
  REALITY_VPS_ASN="$vasn"; REALITY_VPS_PREFIX="$prefix"
  info "$endpoint_label：${entry:-未知} / ASN=$vasn；客户端公网路径未测。"
  if [ -n "${SINGBOX_REALITY_EXTRA_SNI:-}" ]; then
    host="${SINGBOX_REALITY_EXTRA_SNI//,/ }"; read -r -a extras <<<"$host"
    for host in "${extras[@]}"; do host="$(normalize_sni "$host")"; candidate_set_meta "$host" custom; done
    primary=("${extras[@]}" "${primary[@]}")
  fi
  file="$(mktemp /tmp/reality-audit.XXXXXX)"; TMP_FILES+=("$file")
  if [ -z "$forced" ]; then
    dyn="$(mktemp /tmp/reality-dynamic.XXXXXX)"; TMP_FILES+=("$dyn")
    discover_reality_candidates "$vasn" "$prefix" "$dyn" || true
    while IFS= read -r host; do [ -z "$host" ] || dynamic+=("$host"); done <"$dyn"
    info "被动候选=${#dynamic[@]}，公共/自定义候选=${#primary[@]}；来源仅为线索，按实际端点重新验证。"
    audit_reality_candidates "$file" "${dynamic[@]}" "${primary[@]}"
    run_reality_selftests "$file" "$vasn" || true
    picked="$(pick_reality_best "$file" "$vasn" || true)"
    if [ -z "$picked" ]; then
      local extended_limit="${SINGBOX_REALITY_EXTENDED_LIMIT:-8}"
      [[ "$extended_limit" =~ ^([1-9]|1[0-2])$ ]] || extended_limit=8
      warn "本轮没有通过/延后候选；最多追加 $extended_limit 个扩展候选。"
      audit_reality_candidates "$file" "${extended[@]:0:extended_limit}"
      run_reality_selftests "$file" "$vasn" || true
      picked="$(pick_reality_best "$file" "$vasn" || true)"
    fi
    echo '维度说明：兼容=固定端点检查；CLEAR=规则未命中；UNMEASURED=客户端路径未测；样本仅反映短时观测。'
    if [ -n "$picked" ]; then
      IFS='|' read -r -a f <<<"$picked"
      echo "本轮推荐：$(rp_topology "${f[10]}" "$vasn")（cross-asn 表示跨ASN兜底；unknown表示无法核实）"
      rp_show_record "$picked"
      local alternatives="${file}.alternatives" i
      TMP_FILES+=("$alternatives"); grep -Fvx -- "$picked" "$file" >"$alternatives" || true
      for i in 1 2; do
        alt="$(rp_best_row "$alternatives" "$vasn" PASS || true)"; [ -n "$alt" ] || break
        echo "已通过的备选 $i："; rp_show_record "$alt"
        grep -Fvx -- "$alt" "$alternatives" >"${alternatives}.tmp" || true; mv "${alternatives}.tmp" "$alternatives"
      done
    else warn '没有可推荐候选；可手工提供目标继续验证。'; fi
    read -r -p '使用本轮推荐？[Y/n/详情=d]: ' choice
    if [ "${choice,,}" = d ]; then while IFS= read -r row; do rp_show_record "$row"; done <"$file"; read -r -p '使用本轮推荐？[Y/n]: ' choice; fi
    if [ -n "$picked" ] && [[ ! "$choice" =~ ^[Nn]$ ]]; then record_reality_choice "$picked"; return 0; fi
  fi
  while true; do
    host="$forced"; [ -n "$host" ] || read -r -p '请输入 Reality target 域名: ' host
    host="$(normalize_sni "$host")"; rp_valid_host "$host" || { [ -z "$forced" ] || die '指定域名无效'; continue; }
    row="$(rp_probe_row "$host" "${REALITY_CLIENT_PROFILE:-cn}" "$REALITY_GFWLIST_CACHE" "$vasn")"; IFS='|' read -r -a f <<<"$row"; rp_show_record "$row"
    if [ "${f[7]}" = SKIP ]; then
      if [ -n "$forced" ]; then [ "${SINGBOX_REALITY_ALLOW_RISKY:-0}" = 1 ] || die '指定目标不满足自动规则，详见分维度观察'; else read -r -p '覆盖名单/回落规则继续探测？输入 OVERRIDE: ' choice; [ "$choice" = OVERRIDE ] || continue; fi
      row="$(rp_probe_row "$host" global '' "$vasn")"; IFS='|' read -r -a f <<<"$row"
      f[6]=CAUTION; f[13]=LIST_FLAGGED; f[8]='手动覆盖自动排除规则；客户端路径仍未测'
    fi
    [ "${f[17]}" = PASS ] && rp_valid_ip "${f[11]}" || { [ -z "$forced" ] || die '指定端点兼容性未通过'; continue; }
    if rp_selftest "$host" "${f[11]}"; then status=PASS; else rc=$?; if [ "$rc" -eq 75 ]; then status=DEFERRED; else status=FAIL; fi; fi
    if [ "$status" = FAIL ]; then
      echo "${RP_TEST_REASON:-本机回环失败}"
      if [ -n "$forced" ]; then [ "${SINGBOX_REALITY_ALLOW_INCOMPATIBLE:-0}" = 1 ] || die '指定目标本机回环失败'; else read -r -p '仍要使用？输入 FORCE: ' choice; [ "$choice" = FORCE ] || continue; fi
    fi
    f[7]="$status"; row="$(IFS='|'; printf '%s' "${f[*]}")"; source=manual; [ -z "$forced" ] || source=forced
    record_reality_choice "$row" "$source"; return 0
  done
}


# ---------- 交互参数 ----------
select_protocols(){
  echo
  info "=== 选择部署协议 ==="
  echo "1) Shadowsocks (SS/SS2022)"
  echo "2) Hysteria2"
  echo "3) TUIC"
  echo "4) VLESS Reality"
  echo "5) AnyTLS Reality"
  local input="${SINGBOX_PROTOCOLS:-}"
  [ -n "$input" ] || read -r -p "请输入编号，多个用空格分隔（如 1 4）: " input
  ENABLE_SS=false; ENABLE_HY2=false; ENABLE_TUIC=false; ENABLE_REALITY=false; ENABLE_ANYTLS=false
  local n
  for n in $input; do
    case "$n" in 1) ENABLE_SS=true;; 2) ENABLE_HY2=true;; 3) ENABLE_TUIC=true;; 4) ENABLE_REALITY=true;; 5) ENABLE_ANYTLS=true;; *) warn "忽略无效编号：$n";; esac
  done
  $ENABLE_SS || $ENABLE_HY2 || $ENABLE_TUIC || $ENABLE_REALITY || $ENABLE_ANYTLS || die "未选择协议。"
}

select_ss_method(){
  SS_METHOD="2022-blake3-aes-128-gcm"; $ENABLE_SS || return 0
  echo; echo "1) 2022-blake3-aes-128-gcm（推荐）"; echo "2) aes-128-gcm"
  local c="${SINGBOX_SS_METHOD:-}"; [ -n "$c" ] || read -r -p "请选择 [默认 1]: " c
  case "${c:-1}" in 2|aes-128-gcm) SS_METHOD="aes-128-gcm";; *) SS_METHOD="2022-blake3-aes-128-gcm";; esac
}

select_ss_ip_mode(){
  SS_IP_MODE="auto"; $ENABLE_SS || return 0
  echo; echo "SS 最终出口 IP 模式："; echo "1) 系统默认/双栈"; echo "2) IPv6 优先，可回退 IPv4"; echo "3) 仅 IPv6"
  local c="${SINGBOX_SS_IP_MODE:-}"; [ -n "$c" ] || read -r -p "请选择 [默认 1]: " c
  case "${c:-1}" in 2|prefer_ipv6) SS_IP_MODE="prefer_ipv6";; 3|ipv6_only) SS_IP_MODE="ipv6_only";; *) SS_IP_MODE="auto";; esac
  if [ "$SS_IP_MODE" != auto ]; then
    local v6
    v6="$(get_public_ipv6 || true)"
    [ -n "$v6" ] && ok "IPv6 出口正常：$v6" || warn "未检测到可用 IPv6；当前模式可能无法达到预期。"
  fi
}

prompt_node_name(){
  local region="${SINGBOX_NODE_REGION:-}" alias="${SINGBOX_NODE_ALIAS:-}" host_default role answer
  host_default="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
  [ -n "$host_default" ] || host_default="node"

  echo
  info "=== Mihomo / Clash 节点命名 ==="
  [ -n "$region" ] || read -r -p "节点地区（如 香港/荷兰；留空=未分类）: " region
  region="${region:-未分类}"

  # 兼容旧环境变量 SINGBOX_NODE_NAME：若新 alias 未设置，则把旧值当作简称。
  if [ -z "$alias" ] && [ -n "${SINGBOX_NODE_NAME:-}" ]; then alias="$SINGBOX_NODE_NAME"; fi
  [ -n "$alias" ] || read -r -p "节点简称 [默认 ${host_default}]: " alias
  alias="${alias:-$host_default}"
  [ -n "$alias" ] || alias="node"

  NODE_REGION="$region"
  NODE_ALIAS="$alias"
  NODE_NAME="${NODE_REGION}｜${NODE_ALIAS}"

  VLESS_ROLE="${SINGBOX_VLESS_ROLE:-线路}"
  if $ENABLE_REALITY && [ -z "${SINGBOX_VLESS_ROLE:-}" ]; then
    role=""
    read -r -p "VLESS Reality 角色 [默认 ${VLESS_ROLE}]: " role
    VLESS_ROLE="${role:-$VLESS_ROLE}"
  fi

  SS_ROLE="${SINGBOX_SS_ROLE:-落地}"
  SS_DIALER_PROXY_ENABLED=false
  SS_DIALER_PROXY="${SINGBOX_SS_DIALER_PROXY:-中转}"
  if $ENABLE_SS; then
    if [ -z "${SINGBOX_SS_ROLE:-}" ]; then
      role=""
      read -r -p "SS 角色 [默认 ${SS_ROLE}]: " role
      SS_ROLE="${role:-$SS_ROLE}"
    fi
    answer="${SINGBOX_SS_USE_DIALER_PROXY:-}"
    [ -n "$answer" ] || read -r -p "生成 SS YAML 时写入 dialer-proxy？[Y/n]: " answer
    case "${answer:-Y}" in
      n|N|no|NO|false|FALSE|0) SS_DIALER_PROXY_ENABLED=false ;;
      *) SS_DIALER_PROXY_ENABLED=true ;;
    esac
    if $SS_DIALER_PROXY_ENABLED && [ -z "${SINGBOX_SS_DIALER_PROXY:-}" ]; then
      local dp=""
      read -r -p "dialer-proxy 名称 [默认 ${SS_DIALER_PROXY}]: " dp
      SS_DIALER_PROXY="${dp:-$SS_DIALER_PROXY}"
    fi
  fi

  printf '%s\n' "$NODE_NAME" >"$NODE_NAME_FILE"
  if $ENABLE_REALITY; then
    info "VLESS YAML 名称：${NODE_REGION}｜${VLESS_ROLE}｜${NODE_ALIAS}"
  fi
  if $ENABLE_SS; then
    info "SS YAML 名称：${NODE_REGION}｜${SS_ROLE}｜${NODE_ALIAS}"
  fi
  # 显式返回成功，避免仅启用 VLESS/HY2/TUIC/AnyTLS 时，
  # 因最后一个未启用协议的条件表达式返回 1 而触发 set -e / ERR trap。
  return 0
}

select_quic_tls(){
  if ! $ENABLE_HY2 && ! $ENABLE_TUIC; then return 0; fi
  echo
  info "=== Hysteria2 / TUIC TLS 证书策略 ==="
  local c="${SINGBOX_QUIC_TLS_MODE:-}" sni cert key
  if [ -z "$c" ]; then
    echo "1) 自签名证书（零依赖；客户端需 skip-cert-verify）"
    echo "2) 使用已有真实证书（推荐；客户端正常验证证书）"
    read -r -p "请选择 [默认 1]: " c
  fi
  case "${c:-1}" in
    2|existing|cert) QUIC_TLS_MODE="existing" ;;
    *) QUIC_TLS_MODE="selfsigned" ;;
  esac

  if [ "$QUIC_TLS_MODE" = existing ]; then
    sni="${SINGBOX_QUIC_TLS_SERVER_NAME:-}"
    cert="${SINGBOX_QUIC_CERT_PATH:-}"
    key="${SINGBOX_QUIC_KEY_PATH:-}"
    [ -n "$sni" ] || read -r -p "证书对应域名/SNI: " sni
    [ -n "$cert" ] || read -r -p "证书 fullchain.pem 路径: " cert
    [ -n "$key" ] || read -r -p "证书私钥路径: " key
    sni="$(normalize_sni "$sni")"; validate_sni "$sni" || die "TLS SNI 域名格式无效。"
    [ -r "$cert" ] && [ -r "$key" ] || die "证书或私钥不可读。"
    openssl x509 -in "$cert" -noout >/dev/null 2>&1 || die "证书文件无法解析。"
    openssl pkey -in "$key" -noout >/dev/null 2>&1 || die "私钥文件无法解析。"
    local cpub kpub
    cpub="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')"
    kpub="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | awk '{print $NF}')"
    [ -n "$cpub" ] && [ "$cpub" = "$kpub" ] || die "证书与私钥不匹配。"
    QUIC_TLS_SERVER_NAME="$sni"; QUIC_CERT_SOURCE="$cert"; QUIC_KEY_SOURCE="$key"; QUIC_TLS_INSECURE=false
    ok "将使用真实证书：$sni"
  else
    sni="${SINGBOX_QUIC_TLS_SERVER_NAME:-}"
    if [ -z "$sni" ]; then
      [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] && sni="www.apple.com" || sni="www.debian.org"
      read -r -p "自签名模式 SNI [默认 $sni]: " c
      sni="${c:-$sni}"
    fi
    sni="$(normalize_sni "$sni")"; validate_sni "$sni" || die "TLS SNI 域名格式无效。"
    if [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] && [[ "$sni" =~ $REALITY_CN_INAPPROPRIATE_REGEX ]]; then
      die "该 SNI 不适合中国大陆画像：$sni"
    fi
    QUIC_TLS_SERVER_NAME="$sni"; QUIC_TLS_INSECURE=true
    warn "自签名模式仅为零依赖方案；如有自己的域名，推荐使用真实证书模式。"
  fi

  if $ENABLE_HY2; then
    local o="${SINGBOX_HY2_OBFS:-$HY2_OBFS}"
    case "$o" in none|""|0) HY2_OBFS="none";; gecko|salamander) HY2_OBFS="$o";; *) warn "无效 HY2 obfs=$o，使用 none"; HY2_OBFS="none";; esac
    HY2_BBR_PROFILE="${SINGBOX_HY2_BBR_PROFILE:-standard}"
    case "$HY2_BBR_PROFILE" in standard|conservative|aggressive) :;; *) HY2_BBR_PROFILE=standard;; esac
    if [ "$HY2_OBFS" != none ]; then
      HY2_OBFS_PASSWORD="${SINGBOX_HY2_OBFS_PASSWORD:-$(rand_pass)}"
      info "HY2 obfs：$HY2_OBFS；BBR profile：$HY2_BBR_PROFILE"
    else
      info "HY2 obfs：关闭；BBR profile：$HY2_BBR_PROFILE（更接近普通 HTTP/3 行为）"
    fi
  fi
}

prompt_connection_host(){
  local x="${SINGBOX_CONNECTION_HOST:-}"
  [ -n "$x" ] || read -r -p "请输入节点连接 IP/DDNS（留空自动检测）: " x
  x="${x//[[:space:]]/}"
  CONNECTION_HOST="$(normalize_host "$x")"
}

configure_values(){
  if $ENABLE_SS; then
    PORT_SS="$(prompt_port SS "${SINGBOX_PORT_SS:-}")"
    if [ "$SS_METHOD" = "2022-blake3-aes-128-gcm" ]; then
      # SS2022 AES-128 要求 16-byte PSK，使用标准 base64 表示。
      PSK_SS="$(openssl rand -base64 16)"
    else
      PSK_SS="$(rand_pass)"
    fi
  fi
  if $ENABLE_HY2; then PORT_HY2="$(prompt_port Hysteria2 "${SINGBOX_PORT_HY2:-}")"; PSK_HY2="$(rand_pass)"; fi
  if $ENABLE_TUIC; then PORT_TUIC="$(prompt_port TUIC "${SINGBOX_PORT_TUIC:-}")"; UUID_TUIC="$(rand_uuid)"; PSK_TUIC="$(rand_pass)"; fi
  if $ENABLE_REALITY; then PORT_REALITY="$(prompt_port 'VLESS Reality' "${SINGBOX_PORT_REALITY:-}")"; UUID_REALITY="$(rand_uuid)"; fi
  if $ENABLE_ANYTLS; then PORT_ANYTLS="$(prompt_port 'AnyTLS Reality' "${SINGBOX_PORT_ANYTLS:-}")"; ANYTLS_USER="user-$(openssl rand -hex 3)"; ANYTLS_PSK="$(rand_pass)"; fi
}

generate_reality_keys(){
  REALITY_PRIVATE=""; REALITY_PUBLIC=""; REALITY_SID=""
  if ! $ENABLE_REALITY && ! $ENABLE_ANYTLS; then return 0; fi
  local out key value
  out="$(GOMAXPROCS=1 sing-box generate reality-keypair 2>&1)" || die "生成 Reality 密钥失败：$out"
  while IFS=: read -r key value; do
    key="${key//[[:space:]]/}"; value="${value#${value%%[![:space:]]*}}"
    case "$key" in PrivateKey) REALITY_PRIVATE="$value";; PublicKey) REALITY_PUBLIC="$value";; esac
  done <<<"$out"
  REALITY_SID="$(openssl rand -hex 8 2>/dev/null || true)"
  [ -n "$REALITY_PRIVATE" ] && [ -n "$REALITY_PUBLIC" ] && [ -n "$REALITY_SID" ] || die "Reality 密钥输出异常。"
}

generate_cert(){
  if ! $ENABLE_HY2 && ! $ENABLE_TUIC; then return 0; fi
  mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
  if [ "$QUIC_TLS_MODE" = existing ]; then
    if [ "$(readlink -f "$QUIC_CERT_SOURCE" 2>/dev/null || echo "$QUIC_CERT_SOURCE")" != "$(readlink -f "$CERT_DIR/fullchain.pem" 2>/dev/null || echo "$CERT_DIR/fullchain.pem")" ]; then
      install -m 600 "$QUIC_CERT_SOURCE" "$CERT_DIR/fullchain.pem"
    fi
    if [ "$(readlink -f "$QUIC_KEY_SOURCE" 2>/dev/null || echo "$QUIC_KEY_SOURCE")" != "$(readlink -f "$CERT_DIR/privkey.pem" 2>/dev/null || echo "$CERT_DIR/privkey.pem")" ]; then
      install -m 600 "$QUIC_KEY_SOURCE" "$CERT_DIR/privkey.pem"
    fi
  else
    rm -f "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem"
    # ECDSA P-256：现代、轻量，且适合 QUIC/Chrome 指纹场景。
    if openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 825 \
      -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
      -subj "/CN=${QUIC_TLS_SERVER_NAME}" -addext "subjectAltName=DNS:${QUIC_TLS_SERVER_NAME}" >/dev/null 2>&1; then
      :
    else
      openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 \
        -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
        -subj "/CN=${QUIC_TLS_SERVER_NAME}" >/dev/null 2>&1
    fi
    chmod 600 "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem"
  fi
  openssl x509 -in "$CERT_DIR/fullchain.pem" -noout >/dev/null 2>&1 || die "最终 TLS 证书无效。"
}

# ---------- 配置生成 ----------
build_config(){
  # 一次 jq 生成全部入站及路由；避免每启用一个协议就启动两次 jq 并复制整个配置。
  local out="$1" loglevel="info"
  $LOW_RESOURCE_MODE && loglevel="warn"
  jq -n \
    --arg loglevel "$loglevel" \
    --argjson ss "${ENABLE_SS:-false}" --argjson hy2 "${ENABLE_HY2:-false}" \
    --argjson tuic "${ENABLE_TUIC:-false}" --argjson reality "${ENABLE_REALITY:-false}" \
    --argjson anytls "${ENABLE_ANYTLS:-false}" \
    --arg ss_method "${SS_METHOD:-}" --arg ss_password "${PSK_SS:-}" --argjson ss_port "${PORT_SS:-0}" \
    --arg ss_ip_mode "${SS_IP_MODE:-auto}" \
    --arg hy2_password "${PSK_HY2:-}" --arg hy2_bbr "${HY2_BBR_PROFILE:-standard}" \
    --arg hy2_obfs "${HY2_OBFS:-none}" --arg hy2_obfs_password "${HY2_OBFS_PASSWORD:-}" --argjson hy2_port "${PORT_HY2:-0}" \
    --arg tuic_uuid "${UUID_TUIC:-}" --arg tuic_password "${PSK_TUIC:-}" --argjson tuic_port "${PORT_TUIC:-0}" \
    --arg reality_target "${REALITY_TARGET_IP:-${REALITY_SNI:-}}" --arg reality_sni "${REALITY_SNI:-}" --arg reality_private "${REALITY_PRIVATE:-}" --arg reality_sid "${REALITY_SID:-}" \
    --arg reality_uuid "${UUID_REALITY:-}" --argjson reality_port "${PORT_REALITY:-0}" \
    --arg anytls_user "${ANYTLS_USER:-}" --arg anytls_password "${ANYTLS_PSK:-}" --argjson anytls_port "${PORT_ANYTLS:-0}" '
      def quic_tls: {enabled:true,alpn:["h3"],certificate_path:"/etc/sing-box/certs/fullchain.pem",key_path:"/etc/sing-box/certs/privkey.pem"};
      def reality_tls: {enabled:true,server_name:$reality_sni,reality:{enabled:true,handshake:{server:$reality_target,server_port:443},private_key:$reality_private,short_id:[$reality_sid]}};
      {
        log:{level:$loglevel,timestamp:true},
        dns:{servers:[{type:"local",tag:"local",prefer_go:true}],final:"local"},
        ntp:{enabled:true,server:"time.apple.com",server_port:123,interval:"30m"},
        inbounds:([]
          + (if $ss then [{type:"shadowsocks",tag:"ss-in",listen:"::",listen_port:$ss_port,method:$ss_method,password:$ss_password}] else [] end)
          + (if $hy2 then [{type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$hy2_port,users:[{name:"user",password:$hy2_password}],bbr_profile:$hy2_bbr,tls:quic_tls}
              | if $hy2_obfs!="none" then .obfs={type:$hy2_obfs,password:$hy2_obfs_password} else . end] else [] end)
          + (if $tuic then [{type:"tuic",tag:"tuic-in",listen:"::",listen_port:$tuic_port,users:[{name:"user",uuid:$tuic_uuid,password:$tuic_password}],congestion_control:"bbr",zero_rtt_handshake:false,tls:quic_tls}] else [] end)
          + (if $reality then [{type:"vless",tag:"vless-reality-in",listen:"::",listen_port:$reality_port,users:[{uuid:$reality_uuid,flow:"xtls-rprx-vision"}],tls:reality_tls}] else [] end)
          + (if $anytls then [{type:"anytls",tag:"anytls-reality-in",listen:"::",listen_port:$anytls_port,users:[{name:$anytls_user,password:$anytls_password}],tls:reality_tls}] else [] end)),
        outbounds:[{type:"direct",tag:"direct-out",domain_resolver:"local"}],
        route:{rules:[],final:"direct-out",default_domain_resolver:"local"}
      }
      | if $ss and $ss_ip_mode!="auto" then
          .dns.servers += [{type:"local",tag:"ss-local-dns",prefer_go:true}]
          | .route.rules += (if $ss_ip_mode=="ipv6_only" then [{inbound:["ss-in"],ip_version:4,action:"reject"}] else [] end)
          | .route.rules += [{inbound:["ss-in"],action:"resolve",server:"ss-local-dns",strategy:$ss_ip_mode}]
        else . end
    ' >"$out"
}

LAST_CONFIG_BACKUP=""
install_config_atomic(){
  local candidate="$1" backup=""
  sing-box check -c "$candidate" || return 1
  mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"; chmod 700 "$CONFIG_DIR" "$BACKUP_DIR"
  if [ -f "$CONFIG_PATH" ]; then backup="${BACKUP_DIR}/config.$(date +%Y%m%d_%H%M%S).json"; cp -a "$CONFIG_PATH" "$backup"; fi
  # candidate 与工作配置位于同一目录；rename 原子切换，避免读到部分复制的 JSON。
  chmod 600 "$candidate"
  mv -f "$candidate" "$CONFIG_PATH" || return 1
  if ! sing-box check -c "$CONFIG_PATH"; then
    if [ -n "$backup" ]; then
      cp -a "$backup" "$candidate" && mv -f "$candidate" "$CONFIG_PATH"
    else
      rm -f "$CONFIG_PATH"
    fi
    return 1
  fi
  LAST_CONFIG_BACKUP="$backup"
  prune_backups
  ok "配置已原子写入：$CONFIG_PATH"
}

setup_service(){
  local bin; bin="$(command -v sing-box)"
  if [ "$OS" = alpine ]; then
    cat >/etc/init.d/sing-box <<RC
#!/sbin/openrc-run
name="sing-box"
command="$bin"
command_args="run -c $CONFIG_PATH"
command_background=yes
pidfile="/run/sing-box.pid"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"
$(if $LOW_RESOURCE_MODE; then echo 'export GOMAXPROCS="${SINGBOX_GOMAXPROCS:-1}"'; fi)
depend(){ need net; }
RC
    chmod +x /etc/init.d/sing-box
    rc-update add sing-box default >/dev/null 2>&1 || true
    rc-service sing-box restart
  else
    cat >/etc/systemd/system/sing-box.service <<UNIT
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$bin run -c $CONFIG_PATH
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null
    systemctl restart sing-box
  fi
}

save_state(){
  cat >"$STATE_PATH" <<EOF_STATE
SCRIPT_VERSION=$(printf %q "$SCRIPT_VERSION")
NODE_NAME=$(printf %q "${NODE_NAME:-}")
NODE_REGION=$(printf %q "${NODE_REGION:-未分类}")
NODE_ALIAS=$(printf %q "${NODE_ALIAS:-node}")
VLESS_ROLE=$(printf %q "${VLESS_ROLE:-线路}")
SS_ROLE=$(printf %q "${SS_ROLE:-落地}")
SS_DIALER_PROXY_ENABLED=${SS_DIALER_PROXY_ENABLED:-false}
SS_DIALER_PROXY=$(printf %q "${SS_DIALER_PROXY:-中转}")
CONNECTION_HOST=$(printf %q "${CONNECTION_HOST:-}")
REALITY_SNI=$(printf %q "${REALITY_SNI:-}")
REALITY_CLIENT_PROFILE=$(printf %q "${REALITY_CLIENT_PROFILE:-cn}")
REALITY_VPS_ASN=$(printf %q "${REALITY_VPS_ASN:-未知}")
REALITY_VPS_PREFIX=$(printf %q "${REALITY_VPS_PREFIX:-}")
REALITY_TARGET_IP=$(printf %q "${REALITY_TARGET_IP:-}")
REALITY_TARGET_FAMILY=$(printf %q "${REALITY_TARGET_FAMILY:-}")
REALITY_SELECTED_RULE=$(printf %q "${REALITY_SELECTED_RULE:-UNKNOWN}")
REALITY_SELECTED_CLIENT_PATH=UNMEASURED
REALITY_SELECTED_CLIENT_LIST_SIGNAL=$(printf %q "${REALITY_SELECTED_CLIENT_LIST_SIGNAL:-UNMEASURED}")
REALITY_SELECTED_FALLBACK_ABUSE=$(printf %q "${REALITY_SELECTED_FALLBACK_ABUSE:-UNKNOWN}")
REALITY_SELECTED_COMPAT=$(printf %q "${REALITY_SELECTED_COMPAT:-UNTESTED}")
REALITY_SELECTED_SAMPLE_OK=$(printf %q "${REALITY_SELECTED_SAMPLE_OK:-0}")
REALITY_SELECTED_SAMPLE_TOTAL=$(printf %q "${REALITY_SELECTED_SAMPLE_TOTAL:-0}")
REALITY_SELECTED_TLS_MS=$(printf %q "${REALITY_SELECTED_TLS_MS:-999999}")
REALITY_SELECTED_SELFTEST=$(printf %q "${REALITY_SELECTED_SELFTEST:-UNTESTED}")
REALITY_SELECTED_SELFTEST_SCOPE=local-vless-reality
REALITY_SELECTED_SOURCE=$(printf %q "${REALITY_SELECTED_SOURCE:-}")
REALITY_SELECTED_ASN=$(printf %q "${REALITY_SELECTED_ASN:-}")
REALITY_SELECTED_AT=$(printf %q "${REALITY_SELECTED_AT:-}")
REALITY_SELECTED_AGE_DAYS=$(printf %q "${REALITY_SELECTED_AGE_DAYS:-0}")
REALITY_SELECTED_UMBRELLA_RANK=$(printf %q "${REALITY_SELECTED_UMBRELLA_RANK:-0}")
REALITY_PUBLIC=$(printf %q "${REALITY_PUBLIC:-}")
REALITY_SID=$(printf %q "${REALITY_SID:-}")
ENABLE_SS=$ENABLE_SS
ENABLE_HY2=$ENABLE_HY2
ENABLE_TUIC=$ENABLE_TUIC
ENABLE_REALITY=$ENABLE_REALITY
ENABLE_ANYTLS=$ENABLE_ANYTLS
SS_IP_MODE=$(printf %q "${SS_IP_MODE:-auto}")
SS_METHOD=$(printf %q "${SS_METHOD:-}")
PORT_SS=$(printf %q "${PORT_SS:-}")
PSK_SS=$(printf %q "${PSK_SS:-}")
PORT_HY2=$(printf %q "${PORT_HY2:-}")
PSK_HY2=$(printf %q "${PSK_HY2:-}")
PORT_TUIC=$(printf %q "${PORT_TUIC:-}")
UUID_TUIC=$(printf %q "${UUID_TUIC:-}")
PSK_TUIC=$(printf %q "${PSK_TUIC:-}")
PORT_REALITY=$(printf %q "${PORT_REALITY:-}")
UUID_REALITY=$(printf %q "${UUID_REALITY:-}")
PORT_ANYTLS=$(printf %q "${PORT_ANYTLS:-}")
ANYTLS_USER=$(printf %q "${ANYTLS_USER:-}")
ANYTLS_PSK=$(printf %q "${ANYTLS_PSK:-}")
QUIC_TLS_MODE=$(printf %q "${QUIC_TLS_MODE:-selfsigned}")
QUIC_TLS_SERVER_NAME=$(printf %q "${QUIC_TLS_SERVER_NAME:-}")
QUIC_TLS_INSECURE=${QUIC_TLS_INSECURE:-true}
HY2_OBFS=$(printf %q "${HY2_OBFS:-none}")
HY2_OBFS_PASSWORD=$(printf %q "${HY2_OBFS_PASSWORD:-}")
HY2_BBR_PROFILE=$(printf %q "${HY2_BBR_PROFILE:-standard}")
EOF_STATE
  chmod 600 "$STATE_PATH"
}

get_connection_host(){
  local h="${CONNECTION_HOST:-}"
  if [ -z "$h" ]; then h="$(get_public_ipv4 || get_public_ipv6 || true)"; fi
  [ -n "$h" ] || return 1
  printf '%s' "$h"
}

generate_uris(){
  local host uri_host suffix="" info64 insecure=0
  host="$(get_connection_host)" || die "无法获得公网连接地址，请设置 SINGBOX_CONNECTION_HOST 或重新安装时手动填写。"
  uri_host="$(format_uri_host "$host")"
  [ -n "${NODE_NAME:-}" ] && suffix="-$(url_encode "$NODE_NAME")"
  [ "${QUIC_TLS_INSECURE:-true}" != true ] || insecure=1
  : >"$URI_PATH"
  if $ENABLE_SS; then
    info64="$(printf '%s' "${SS_METHOD}:${PSK_SS}" | base64 | tr -d '\r\n')"
    echo "ss://${info64}@${uri_host}:${PORT_SS}#ss${suffix}" >>"$URI_PATH"
  fi
  if $ENABLE_HY2; then
    local hyq
    hyq="sni=${QUIC_TLS_SERVER_NAME}&alpn=h3&insecure=${insecure}"
    if [ "${HY2_OBFS:-none}" != none ]; then hyq="${hyq}&obfs=${HY2_OBFS}&obfs-password=$(url_encode "$HY2_OBFS_PASSWORD")"; fi
    echo "hy2://$(url_encode "$PSK_HY2")@${uri_host}:${PORT_HY2}/?${hyq}#hy2${suffix}" >>"$URI_PATH"
  fi
  if $ENABLE_TUIC; then echo "tuic://${UUID_TUIC}:$(url_encode "$PSK_TUIC")@${uri_host}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=${QUIC_TLS_SERVER_NAME}&insecure=${insecure}#tuic${suffix}" >>"$URI_PATH"; fi
  if $ENABLE_REALITY; then echo "vless://${UUID_REALITY}@${uri_host}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}#reality${suffix}" >>"$URI_PATH"; fi
  if $ENABLE_ANYTLS; then echo "anytls://$(url_encode "$ANYTLS_PSK")@${uri_host}:${PORT_ANYTLS}/?security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}#anytls${suffix}" >>"$URI_PATH"; fi
  chmod 600 "$URI_PATH"
}

yaml_quote(){
  local s="${1:-}"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '"%s"' "$s"
}

generate_mihomo_yaml(){
  local host vname sname hname tname qhost
  host="$(get_connection_host)" || { warn "无法获得连接地址，暂不能生成 Mihomo YAML。"; return 1; }
  mkdir -p "$MIHOMO_DIR"; chmod 700 "$MIHOMO_DIR"
  : >"$MIHOMO_VLESS_PATH"; : >"$MIHOMO_SS_PATH"; : >"$MIHOMO_HY2_PATH"; : >"$MIHOMO_TUIC_PATH"

  vname="${NODE_REGION:-未分类}｜${VLESS_ROLE:-线路}｜${NODE_ALIAS:-node}"
  sname="${NODE_REGION:-未分类}｜${SS_ROLE:-落地}｜${NODE_ALIAS:-node}"
  hname="${NODE_REGION:-未分类}｜HY2｜${NODE_ALIAS:-node}"
  tname="${NODE_REGION:-未分类}｜TUIC｜${NODE_ALIAS:-node}"
  qhost="$(yaml_quote "$host")"

  if $ENABLE_REALITY; then
    cat >"$MIHOMO_VLESS_PATH" <<EOF_YAML
  - name: $(yaml_quote "$vname")
    type: vless
    server: ${qhost}
    port: ${PORT_REALITY}
    uuid: $(yaml_quote "$UUID_REALITY")
    network: tcp
    udp: true
    tls: true
    servername: $(yaml_quote "$REALITY_SNI")
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: $(yaml_quote "$REALITY_PUBLIC")
      short-id: $(yaml_quote "$REALITY_SID")
EOF_YAML
  fi

  if $ENABLE_SS; then
    cat >"$MIHOMO_SS_PATH" <<EOF_YAML
  - name: $(yaml_quote "$sname")
    type: ss
    server: ${qhost}
    port: ${PORT_SS}
    cipher: $(yaml_quote "$SS_METHOD")
    password: $(yaml_quote "$PSK_SS")
    udp: true
EOF_YAML
    if ${SS_DIALER_PROXY_ENABLED:-false}; then
      printf '    dialer-proxy: %s\n' "$(yaml_quote "${SS_DIALER_PROXY:-中转}")" >>"$MIHOMO_SS_PATH"
    fi
  fi

  if $ENABLE_HY2; then
    cat >"$MIHOMO_HY2_PATH" <<EOF_YAML
  - name: $(yaml_quote "$hname")
    type: hysteria2
    server: ${qhost}
    port: ${PORT_HY2}
    password: $(yaml_quote "$PSK_HY2")
    sni: $(yaml_quote "$QUIC_TLS_SERVER_NAME")
    skip-cert-verify: ${QUIC_TLS_INSECURE}
    bbr-profile: $(yaml_quote "$HY2_BBR_PROFILE")
    alpn:
      - h3
EOF_YAML
    if [ "${HY2_OBFS:-none}" != none ]; then
      printf '    obfs: %s\n    obfs-password: %s\n' "$(yaml_quote "$HY2_OBFS")" "$(yaml_quote "$HY2_OBFS_PASSWORD")" >>"$MIHOMO_HY2_PATH"
    fi
  fi

  if $ENABLE_TUIC; then
    cat >"$MIHOMO_TUIC_PATH" <<EOF_YAML
  - name: $(yaml_quote "$tname")
    type: tuic
    server: ${qhost}
    port: ${PORT_TUIC}
    uuid: $(yaml_quote "$UUID_TUIC")
    password: $(yaml_quote "$PSK_TUIC")
    sni: $(yaml_quote "$QUIC_TLS_SERVER_NAME")
    skip-cert-verify: ${QUIC_TLS_INSECURE}
    alpn:
      - h3
    congestion-controller: bbr
    udp-relay-mode: native
EOF_YAML
  fi

  : >"$MIHOMO_ALL_PATH"
  local f
  for f in "$MIHOMO_VLESS_PATH" "$MIHOMO_SS_PATH" "$MIHOMO_HY2_PATH" "$MIHOMO_TUIC_PATH"; do
    if [ -s "$f" ]; then
      [ ! -s "$MIHOMO_ALL_PATH" ] || printf '\n' >>"$MIHOMO_ALL_PATH"
      cat "$f" >>"$MIHOMO_ALL_PATH"
    fi
  done

  if [ -s "$MIHOMO_ALL_PATH" ]; then
    { echo 'proxies:'; cat "$MIHOMO_ALL_PATH"; } >"$MIHOMO_FULL_PATH"
  else
    echo 'proxies: []' >"$MIHOMO_FULL_PATH"
  fi
  chmod 600 "$MIHOMO_DIR"/*.yaml 2>/dev/null || true

  if $ENABLE_ANYTLS; then
    warn "Mihomo 当前不支持 AnyTLS + Reality，因此未为 AnyTLS 生成错误的 YAML 节点；请使用 VLESS Reality 或其他 Mihomo 支持的协议。"
  fi
}

# ---------- 线路机 VLESS Reality -> 本机 SS ----------
generate_relay_installer(){
  $ENABLE_SS || return 0
  local landing_host out esc_host esc_method esc_pass esc_sni
  if [ -n "${CONNECTION_HOST:-}" ]; then
    landing_host="$CONNECTION_HOST"
  else
    landing_host="$(get_public_ipv4 || get_public_ipv6 || true)"
  fi
  [ -n "$landing_host" ] || { warn "无法取得落地机地址，跳过线路机脚本生成。"; return 0; }
  out="/root/install-singbox-relay.sh"
  cat >"$out" <<'RELAYEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# __REALITY_POLICY__
info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok(){ echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn(){ echo -e "\033[1;33m[WARN]\033[0m $*" >&2; }
die(){ echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "请使用 root 运行。"
relay_cleanup(){
  rp_cleanup_selftest || true
  local f
  for f in "${RELAY_GFW:-}" "${RELAY_AUDIT_TMP:-}" "${RELAY_DYNAMIC_TMP:-}"; do [ -z "$f" ] || rm -f "$f"; done
}
trap relay_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ -r /etc/os-release ]; then
  OS_ID="$(awk -F= '$1=="ID"{gsub(/"/,"",$2);print tolower($2);exit}' /etc/os-release)"
else OS_ID=""; fi
case "$OS_ID" in
  alpine)
    pkgs=()
    command -v curl >/dev/null 2>&1 || pkgs+=(curl)
    command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
    command -v jq >/dev/null 2>&1 || pkgs+=(jq)
    command -v dig >/dev/null 2>&1 || pkgs+=(bind-tools)
    [ -s /etc/ssl/certs/ca-certificates.crt ] || pkgs+=(ca-certificates)
    command -v timeout >/dev/null 2>&1 || pkgs+=(coreutils)
    [ "${#pkgs[@]}" -eq 0 ] || apk add --no-cache "${pkgs[@]}"
    ;;
  debian|ubuntu)
    pkgs=()
    command -v curl >/dev/null 2>&1 || pkgs+=(curl)
    command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
    command -v jq >/dev/null 2>&1 || pkgs+=(jq)
    command -v dig >/dev/null 2>&1 || pkgs+=(dnsutils)
    command -v timeout >/dev/null 2>&1 || pkgs+=(coreutils)
    [ -s /etc/ssl/certs/ca-certificates.crt ] || pkgs+=(ca-certificates)
    if [ "${#pkgs[@]}" -gt 0 ]; then
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y "${pkgs[@]}"
    fi
    ;;
  *)
    pkgs=()
    command -v curl >/dev/null 2>&1 || pkgs+=(curl)
    command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
    command -v jq >/dev/null 2>&1 || pkgs+=(jq)
    command -v dig >/dev/null 2>&1 || pkgs+=(bind-utils)
    command -v timeout >/dev/null 2>&1 || pkgs+=(coreutils)
    { [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ]; } || pkgs+=(ca-certificates)
    if [ "${#pkgs[@]}" -gt 0 ]; then
      if command -v dnf >/dev/null 2>&1; then dnf install -y "${pkgs[@]}"; elif command -v yum >/dev/null 2>&1; then yum install -y "${pkgs[@]}"; fi
    fi
    ;;
esac

install_core_alpine(){
  local v u arch flavor base url stage bin
  v=""; u="$(curl -fsSIL --retry 2 --connect-timeout 5 --max-time 15 -o /dev/null -w '%{url_effective}' https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null || true)"
  case "$u" in */tag/v*) v="${u##*/tag/v}";; */v*) v="${u##*/v}";; esac
  if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    v="$(curl -fsSL --retry 2 --connect-timeout 5 --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null || true)"; v="${v#v}"
  fi
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "无法解析 sing-box stable 版本。"
  case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7l|armv7) arch=armv7;; i?86) arch=386;; armv6l|armv6) arch=armv6;; *) die "不支持的 Alpine 架构：$(uname -m)";; esac
  flavor=-musl; [ "$arch" = armv6 ] && flavor=""
  base="sing-box-${v}-linux-${arch}${flavor}"; url="https://github.com/SagerNet/sing-box/releases/download/v${v}/${base}.tar.gz"
  mkdir -p /usr/local/bin /usr/local/lib; stage="/usr/local/lib/.sing-box-relay.$$"; rm -rf "$stage"; mkdir -p "$stage"
  info "Alpine：流式安装官方 musl sing-box v${v}..."
  curl -fL --retry 3 --retry-delay 1 --connect-timeout 8 --max-time 180 "$url" | tar -xzf - -C "$stage" || { rm -rf "$stage"; die "sing-box 下载/解压失败。"; }
  bin=""; for candidate in "$stage/$base/sing-box" "$stage/sing-box" "$stage"/*/sing-box; do [ -f "$candidate" ] && { bin="$candidate"; break; }; done
  [ -n "$bin" ] && [ -s "$bin" ] || die "release 中未找到 sing-box。"; chmod 755 "$bin"; GOMAXPROCS=1 "$bin" version >/dev/null 2>&1 || die "sing-box 无法运行。"
  mv -f "$bin" /usr/local/bin/sing-box; chmod 755 /usr/local/bin/sing-box; ln -sf /usr/local/bin/sing-box /usr/bin/sing-box 2>/dev/null || true; rm -rf "$stage"
}

if ! command -v sing-box >/dev/null 2>&1; then
  if [ "$OS_ID" = alpine ]; then
    install_core_alpine
  else
    t="$(mktemp)"; curl -fsSL --retry 3 https://sing-box.app/install.sh -o "$t"; bash "$t"; rm -f "$t"
  fi
fi
command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"
command -v timeout >/dev/null 2>&1 || die "缺少 timeout，无法进行有界 Reality 探测。"

# 线路机必须基于“线路机自身网络”重新选择 Reality target，不能盲目继承落地机结果。
# 动态发现只读取 urlscan 公开历史数据，不扫描 ASN/IP 网段。
RELAY_PROFILE="__PROFILE__"
INHERITED_SNI="__SNI__"
RELAY_GFW=""
declare -A RELAY_SRC=()
relay_mem_kb(){ local k v _; while read -r k v _; do [ "$k" = MemAvailable: ] && { printf '%s' "${v:-0}"; return 0; }; done </proc/meminfo 2>/dev/null; printf '0'; }
relay_validate_sni(){ [[ "$1" =~ ^[A-Za-z0-9.-]+$ ]] && [[ "$1" == *.* ]] && [[ "$1" != .* ]] && [[ "$1" != *. ]]; }
relay_refresh_gfwlist(){
  [ "$RELAY_PROFILE" = cn ] || return 0
  local url line d n=0 clean
  RELAY_GFW="$(mktemp)"; clean="${RELAY_GFW}.clean"; : >"$clean"
  for url in 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt' 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt'; do
    if curl -fsSL --retry 1 --connect-timeout 4 --max-time 10 "$url" -o "$RELAY_GFW" 2>/dev/null && [ -s "$RELAY_GFW" ]; then
      : >"$clean"; n=0
      while IFS= read -r line || [ -n "$line" ]; do d="${line%$'\r'}"; d="${d,,}"; d="${d#.}"; d="${d%.}"; [[ "$d" =~ ^[a-z0-9.-]+\.[a-z0-9-]+$ ]] || continue; printf '%s\n' "$d" >>"$clean"; n=$((n+1)); done <"$RELAY_GFW"
      if [ "$n" -ge 100 ]; then mv "$clean" "$RELAY_GFW"; return 0; fi
    fi
  done
  rm -f "$RELAY_GFW" "$clean"; RELAY_GFW=""; return 0
}
relay_discover(){
  local rows="${3}.sources" host source
  rp_discover_candidates "$1" "$2" "$rows"; : >"$3"
  while IFS='|' read -r host source; do RELAY_SRC["$host"]="$source"; printf '%s\n' "$host" >>"$3"; done <"$rows"
  rm -f "$rows"
}
relay_record_source(){
  local row="$1" h="${1%%|*}" src
  src="${RELAY_SRC[$h]:-manual}"
  if [[ "$src" == dynamic-* ]]; then printf '来源=%s（历史线索）；' "$src"; else printf '来源=%s；' "$src"; fi
  rp_show_record "$row"
}
select_relay_sni(){
  relay_refresh_gfwlist || true
  local vip oinfo vasn=未知 vpfx="" dynfile audit h row bestrow="" best="" chosen_status="" limit="${SINGBOX_REALITY_COMPARE_LIMIT:-3}"
  local status tasn ip topology
  oinfo="$(rp_vps_identity "${CONNECTION_HOST:-}")"; IFS='|' read -r vip vasn vpfx <<<"$oinfo"; vasn="${vasn:-未知}"
  info "线路机网络：ASN=${vasn}；BGP 前缀=${vpfx:-未知}。候选以当前地址、兼容性和采样结果比较。"
  echo '客户端可达性：UNMEASURED；规则未命中不代表不会被封锁；同 ASN 仅是拓扑信息。'
  dynfile="$(mktemp)"; RELAY_DYNAMIC_TMP="$dynfile"; audit="$(mktemp)"; RELAY_AUDIT_TMP="$audit"
  relay_discover "$vasn" "$vpfx" "$dynfile" || true
  local -a cands=()
  while IFS= read -r h; do [ -n "$h" ] && cands+=("$h"); done <"$dynfile"
  [ -z "$INHERITED_SNI" ] || { RELAY_SRC["$INHERITED_SNI"]="inherited"; cands+=("$INHERITED_SNI"); }
  while IFS= read -r h; do RELAY_SRC["$h"]=public-core; cands+=("$h"); done < <(rp_public_candidates "$RELAY_PROFILE")
  local -A seen=()
  : >"$audit"
  for h in "${cands[@]}"; do
    h="${h,,}"; h="${h%.}"
    relay_validate_sni "$h" || continue; [ -z "${seen[$h]+x}" ] || continue; seen["$h"]=1
    row="$(rp_probe_row "$h" "$RELAY_PROFILE" "$RELAY_GFW" "$vasn" || true)"
    [ -n "$row" ] || continue
    printf '%s\n' "$row" >>"$audit"
  done
  # 公共核心、继承目标与被动候选使用同一策略；比较数由统一策略限制并受资源余量保护。
  rp_test_pool "$audit" "$vasn" "$limit" || true
  echo; info '线路机候选结果（自测范围 local-vless-reality；不测中国大陆客户端链路）：'
  while IFS= read -r row; do [ -n "$row" ] && relay_record_source "$row"; done <"$audit"
  bestrow="$(rp_best_row "$audit" "$vasn" PASS || true)"
  if [ -z "$bestrow" ]; then bestrow="$(rp_best_row "$audit" "$vasn" DEFERRED || true)"; fi
  if [ -n "$bestrow" ]; then
    IFS='|' read -r best _ _ _ _ _ _ chosen_status _ _ tasn ip _ _ _ _ _ _ <<<"$bestrow"
    topology="$(rp_topology "$tasn" "$vasn")"
    info "推荐：${best}；目标IP=${ip}；${topology}；验证=${chosen_status}；来源=${RELAY_SRC[$best]:-public}"
    [ "$topology" != cross-asn ] || echo '此项为跨 ASN 兜底；公共候选或历史线索均不代表本机同网段站点，也不构成抗封锁保证。'
    [ "$chosen_status" != DEFERRED ] || warn '推荐仅通过静态兼容性采样；本机回环自测因资源限制延后。'
    info '通过本机回环自测的备选：'
    local alternatives=0
    while IFS= read -r row; do
      IFS='|' read -r h _ _ _ _ _ _ status _ _ _ _ _ _ _ _ _ _ <<<"$row"
      [ "$status" = PASS ] && [ "$h" != "$best" ] || continue
      relay_record_source "$row"; alternatives=$((alternatives+1))
    done <"$audit"
    [ "$alternatives" -gt 0 ] || echo '  暂无其他已测 PASS；未测试候选不等于失败。'
    read -r -p "Reality target [推荐 $best；回车采用，或输入其他域名]: " h
    SNI="${h:-$best}"
  else
    warn '比较范围内没有本机回环 PASS 或资源延后的合格候选。'
    read -r -p '请手动输入 Reality target（留空取消）: ' SNI
    [ -n "$SNI" ] || { rm -f "$dynfile" "$audit"; die '已取消线路机安装。'; }
  fi
  SNI="${SNI//[[:space:]]/}"; SNI="${SNI,,}"; SNI="${SNI%.}"
  relay_validate_sni "$SNI" || { rm -f "$dynfile" "$audit"; die 'Reality target 域名格式无效。'; }
  TARGET_IP=""
  if [ "$SNI" = "$best" ] && [ -n "$bestrow" ]; then
    IFS='|' read -r _ _ _ _ _ _ _ _ _ _ _ TARGET_IP _ _ _ _ _ _ <<<"$bestrow"
  else
    # 手动输入仍走同一地址固定、规则、采样与本机握手路径。
    rp_probe "$SNI" "$RELAY_PROFILE" "$RELAY_GFW" "$vasn" || true
    row="${SNI}|${RP_TLS13}|${RP_H2}|${RP_CERT}|${RP_REDIRECT}|${RP_MS}|${RP_RULE}|PENDING|${RP_REASON//|/;}|${RP_CNAME//|/;}|${RP_ASN}|${RP_IP}|${RP_FAMILY}|${RP_CLIENT}|${RP_ABUSE}|${RP_OK}|${RP_TOTAL}|${RP_COMPAT}"
    relay_record_source "$row"
    if [ "${RP_ELIGIBLE:-NO}" != YES ] || [ "${RP_COMPAT:-FAIL}" != PASS ]; then
      rm -f "$dynfile" "$audit"; die '手动 target 未通过统一规则和静态兼容性采样。'
    fi
    TARGET_IP="$RP_IP"
    local test_rc=0
    if rp_selftest "$SNI" "$TARGET_IP"; then test_rc=0; else test_rc=$?; fi
    case "$test_rc" in
      0) ok '手动 target 本机 VLESS REALITY 回环自测通过（local-vless-reality）。' ;;
      75) warn "本机回环自测因资源限制延后：${RP_TEST_REASON:-未知资源原因}" ;;
      *) rm -f "$dynfile" "$audit"; die "手动 target 本机回环自测失败：${RP_TEST_REASON:-未知错误}" ;;
    esac
  fi
  rm -f "$dynfile" "$audit"
  [ -n "$TARGET_IP" ] || die '没有固定的已测 target IP，取消生成配置。'
  ok "线路机 target：SNI=${SNI}；handshake=${TARGET_IP}:443；客户端链路未测。"
}
select_relay_sni
[ -n "${RELAY_GFW:-}" ] && rm -f "$RELAY_GFW" 2>/dev/null || true
relay_port_in_use(){
  local p="$1" hex f _ local_addr
  printf -v hex '%04X' "$p"
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    while read -r _ local_addr _; do [ "${local_addr##*:}" = "$hex" ] && return 0; done <"$f"
  done
  return 1
}
rand_port(){
  local p i span=$((65000-20000+1))
  for ((i=0;i<96;i++)); do
    p=$(( ((RANDOM << 15) ^ RANDOM) % span + 20000 ))
    if ! relay_port_in_use "$p"; then printf '%s\n' "$p"; return 0; fi
  done
  return 1
}
UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
[ -n "$UUID" ] || UUID="$(sing-box generate uuid 2>/dev/null)"
KEYS="$(GOMAXPROCS=1 sing-box generate reality-keypair)"
PRIV=""; PUB=""
while IFS=: read -r K V; do K="${K//[[:space:]]/}"; V="${V#${V%%[![:space:]]*}}"; case "$K" in PrivateKey) PRIV="$V";; PublicKey) PUB="$V";; esac; done <<<"$KEYS"
SID="$(openssl rand -hex 8)"
P="$(rand_port)"
read -r -p "线路机 VLESS Reality 端口 [默认 $P]: " x; P="${x:-$P}"
[[ "$P" =~ ^[0-9]+$ ]] && [ "$P" -ge 1 ] && [ "$P" -le 65535 ] || die "端口无效。"

mkdir -p /etc/sing-box; chmod 700 /etc/sing-box
cat >/etc/sing-box/config.json <<JSON
{
  "log":{"level":"info","timestamp":true},
  "dns":{"servers":[{"type":"local","tag":"local","prefer_go":true}]},
  "inbounds":[{
    "type":"vless","tag":"vless-reality-in","listen":"::","listen_port":${P},
    "users":[{"uuid":"${UUID}","flow":"xtls-rprx-vision"}],
    "tls":{
      "enabled":true,
      "server_name":"${SNI}",
      "reality":{
        "enabled":true,
        "handshake":{"server":"${TARGET_IP}","server_port":443},
        "private_key":"${PRIV}",
        "short_id":["${SID}"]
      }
    }
  }],
  "outbounds":[
    {
      "type":"shadowsocks","tag":"landing-ss",
      "server":"__LANDING_HOST__","server_port":__LANDING_PORT__,
      "method":"__LANDING_METHOD__","password":"__LANDING_PASS__",
      "domain_resolver":"local"
    },
    {"type":"direct","tag":"direct-out","domain_resolver":"local"}
  ],
  "route":{"rules":[{"inbound":["vless-reality-in"],"action":"route","outbound":"landing-ss"}],"final":"direct-out","default_domain_resolver":"local"}
}
JSON
sing-box check -c /etc/sing-box/config.json || die "配置校验失败。"
chmod 600 /etc/sing-box/config.json
BIN="$(command -v sing-box)"
if [ -f /etc/alpine-release ]; then
  cat >/etc/init.d/sing-box <<RC
#!/sbin/openrc-run
name="sing-box"
command="$BIN"
command_args="run -c /etc/sing-box/config.json"
command_background=yes
pidfile="/run/sing-box.pid"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"
depend(){ need net; }
RC
  chmod +x /etc/init.d/sing-box; rc-update add sing-box default >/dev/null 2>&1 || true; rc-service sing-box restart
else
  cat >/etc/systemd/system/sing-box.service <<UNIT
[Unit]
Description=sing-box relay
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$BIN run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable sing-box >/dev/null; systemctl restart sing-box
fi

get4(){ curl -4 -fsS --max-time 7 https://api.ipify.org 2>/dev/null || true; }
get6(){ curl -6 -fsS --max-time 7 https://api64.ipify.org 2>/dev/null || true; }
HOST="$(get4)"; [ -n "$HOST" ] || HOST="$(get6)"; [ -n "$HOST" ] || die "无法获取线路机公网 IP。"
if [[ "$HOST" == *:* ]]; then UH="[$HOST]"; else UH="$HOST"; fi
URI="vless://${UUID}@${UH}:${P}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=chrome&pbk=${PUB}&sid=${SID}#relay"
echo "$URI" >/etc/sing-box/relay_uri.txt; chmod 600 /etc/sing-box/relay_uri.txt

# 同时生成可直接粘贴到 Mihomo proxies: 下的 VLESS YAML。
def_region="__REGION__"
read -r -p "线路机节点地区 [默认 ${def_region}]: " R; R="${R:-$def_region}"
def_alias="$(hostname -s 2>/dev/null || echo relay)"
read -r -p "线路机节点简称 [默认 ${def_alias}]: " A; A="${A:-$def_alias}"
read -r -p "VLESS 角色 [默认 线路]: " ROLE; ROLE="${ROLE:-线路}"
yq(){ local z="$1"; z="${z//\\/\\\\}"; z="${z//\"/\\\"}"; printf '"%s"' "$z"; }
mkdir -p /etc/sing-box/mihomo; chmod 700 /etc/sing-box/mihomo
cat >/etc/sing-box/mihomo/vless.yaml <<YAML
  - name: $(yq "${R}｜${ROLE}｜${A}")
    type: vless
    server: $(yq "$HOST")
    port: ${P}
    uuid: $(yq "$UUID")
    network: tcp
    udp: true
    tls: true
    servername: $(yq "$SNI")
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: $(yq "$PUB")
      short-id: $(yq "$SID")
YAML
{ echo 'proxies:'; cat /etc/sing-box/mihomo/vless.yaml; } >/etc/sing-box/mihomo/full.yaml
chmod 600 /etc/sing-box/mihomo/*.yaml

echo; ok "线路机部署完成："; cat /etc/sing-box/relay_uri.txt
echo; ok "Mihomo YAML："; cat /etc/sing-box/mihomo/vless.yaml
RELAYEOF

  inject_reality_policy "$out"
  esc_host="$(printf '%s' "$landing_host" | sed 's/[&|]/\\&/g')"
  esc_method="$(printf '%s' "$SS_METHOD" | sed 's/[&|]/\\&/g')"
  esc_pass="$(printf '%s' "$PSK_SS" | sed 's/[&|]/\\&/g')"
  esc_sni="$(printf '%s' "$REALITY_SNI" | sed 's/[&|]/\\&/g')"
  sed -i \
    -e "s|__LANDING_HOST__|${esc_host}|g" \
    -e "s|__LANDING_PORT__|${PORT_SS}|g" \
    -e "s|__LANDING_METHOD__|${esc_method}|g" \
    -e "s|__LANDING_PASS__|${esc_pass}|g" \
    -e "s|__SNI__|${esc_sni}|g" \
    -e "s|__PROFILE__|${REALITY_CLIENT_PROFILE:-cn}|g" \
    -e "s|__REGION__|$(printf '%s' "${NODE_REGION:-未分类}" | sed 's/[&|]/\\&/g')|g" \
    "$out"
  chmod 700 "$out"
  ok "线路机安装脚本已生成：$out"
}

# ---------- sb 管理脚本 ----------
install_sb_panel(){
  cat >"$SB_PATH" <<'SBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
CONFIG_DIR="/etc/sing-box"; CONFIG_PATH="$CONFIG_DIR/config.json"; STATE_PATH="$CONFIG_DIR/install-state.env"; URI_PATH="$CONFIG_DIR/uris.txt"; MIHOMO_DIR="$CONFIG_DIR/mihomo"; BACKUP_DIR="$CONFIG_DIR/backups"; HEALTH_PATH="$CONFIG_DIR/reality-health.json"; DISCOVERY_CACHE="$CONFIG_DIR/reality-discovery.tsv"; GFWLIST_PATH="$CONFIG_DIR/reality-gfw.txt"
[ "$(id -u)" -eq 0 ] || { echo "需要 root"; exit 1; }
[ -f "$STATE_PATH" ] && source "$STATE_PATH" || true
# __REALITY_POLICY__
PANEL_SELFTEST_PID=""
panel_cleanup(){
  rp_cleanup_selftest
  if [ -n "${PANEL_SELFTEST_PID:-}" ]; then
    kill "$PANEL_SELFTEST_PID" 2>/dev/null || true
    wait "$PANEL_SELFTEST_PID" 2>/dev/null || true
    PANEL_SELFTEST_PID=""
  fi
}
trap panel_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
service_restart(){ sing-box check -c "$CONFIG_PATH" && { if command -v systemctl >/dev/null 2>&1; then systemctl restart sing-box; else rc-service sing-box restart; fi; }; }
show_status(){ if command -v systemctl >/dev/null 2>&1; then systemctl status sing-box --no-pager; else rc-service sing-box status; fi; }
show_logs(){ if command -v journalctl >/dev/null 2>&1; then journalctl -u sing-box -n 100 --no-pager; else tail -n 100 /var/log/messages 2>/dev/null || true; fi; }
doctor(){
  local fail=0 h
  echo "===== sing-box Doctor ====="
  echo "版本: $(sing-box version 2>/dev/null | head -n1 || echo 未安装)"
  echo "资源: PID/Tasks余量=$(panel_pid_headroom)；MemAvailable≈$(( $(panel_mem_kb) / 1024 )) MiB"
  if sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then echo "[OK] 配置校验"; else echo "[FAIL] 配置校验"; fail=1; fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet sing-box && echo "[OK] 服务运行" || { echo "[FAIL] 服务未运行"; fail=1; }
  else
    rc-service sing-box status >/dev/null 2>&1 && echo "[OK] 服务运行" || { echo "[FAIL] 服务未运行"; fail=1; }
  fi
  h="$(get_host)"; [ -n "$h" ] && echo "[OK] 对外地址: $h" || { echo "[WARN] 无法自动获取公网地址"; }
  [ -r "$STATE_PATH" ] && [ "$(stat -c '%a' "$STATE_PATH" 2>/dev/null || stat -f '%Lp' "$STATE_PATH" 2>/dev/null || echo 600)" = 600 ] && echo "[OK] 状态文件权限 600" || echo "[WARN] 状态文件权限建议 600"
  echo "监听端口:"
  command -v ss >/dev/null 2>&1 && ss -H -lntu 2>/dev/null | grep -E "(:${PORT_SS:-0}|:${PORT_HY2:-0}|:${PORT_TUIC:-0}|:${PORT_REALITY:-0}|:${PORT_ANYTLS:-0})([[:space:]]|$)" || true
  if [ "${ENABLE_REALITY:-false}" = true ] || [ "${ENABLE_ANYTLS:-false}" = true ]; then
    echo "Reality SNI: ${REALITY_SNI:-unknown}；握手端点: ${REALITY_TARGET_IP:-按域名解析}（IPv${REALITY_TARGET_FAMILY:-?}）"
    echo "本机诊断不覆盖客户端到 VPS 的公网路径；AnyTLS 应用层未测。"
    if [ -s "$HEALTH_PATH" ]; then echo "最近健康记录: $(jq -r '(.status//"unknown")+" / "+(.checked_at//"unknown")+" / "+(.message//"")' "$HEALTH_PATH" 2>/dev/null || echo 无法解析)"; fi
  fi
  return "$fail"
}

safe_update(){
  local oldbin realbin b tmp v u arch flavor base url stage newbin f i=0
  local -a backs=()
  oldbin="$(command -v sing-box)"; realbin="$(readlink -f "$oldbin" 2>/dev/null || echo "$oldbin")"
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  b="$BACKUP_DIR/sing-box.$(date +%Y%m%d_%H%M%S)"
  # 同一文件系统优先硬链接备份，Tiny VPS 不额外复制几十 MiB 二进制。
  if ! ln "$realbin" "$b" 2>/dev/null; then cp -a "$realbin" "$b" || { echo "无法创建更新备份。"; return 1; }; fi

  if [ -f /etc/alpine-release ]; then
    v=""; u="$(curl -fsSIL --retry 2 --connect-timeout 5 --max-time 15 -o /dev/null -w '%{url_effective}' https://github.com/SagerNet/sing-box/releases/latest 2>/dev/null || true)"
    case "$u" in */tag/v*) v="${u##*/tag/v}";; */v*) v="${u##*/v}";; esac
    if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      v="$(curl -fsSL --retry 2 --connect-timeout 5 --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null || true)"; v="${v#v}"
    fi
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "无法解析最新 stable 版本。"; rm -f "$b"; return 1; }
    case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; armv7l|armv7) arch=armv7;; i?86) arch=386;; armv6l|armv6) arch=armv6;; *) echo "不支持的架构"; rm -f "$b"; return 1;; esac
    flavor=-musl; [ "$arch" = armv6 ] && flavor=""
    base="sing-box-${v}-linux-${arch}${flavor}"
    url="https://github.com/SagerNet/sing-box/releases/download/v${v}/${base}.tar.gz"
    stage="/usr/local/lib/.sing-box-update.$$"; rm -rf "$stage"; mkdir -p "$stage"
    echo "Alpine：流式更新官方 musl stable v${v}..."
    if ! curl -fL --retry 3 --retry-delay 1 --connect-timeout 8 --max-time 180 "$url" | tar -xzf - -C "$stage"; then
      rm -rf "$stage"; echo "下载/解压失败，保留旧版本。"; rm -f "$b"; return 1
    fi
    newbin=""; for candidate in "$stage/$base/sing-box" "$stage/sing-box" "$stage"/*/sing-box; do [ -f "$candidate" ] && { newbin="$candidate"; break; }; done
    [ -n "$newbin" ] && [ -s "$newbin" ] && GOMAXPROCS=1 "$newbin" version >/dev/null 2>&1 || { rm -rf "$stage"; echo "新二进制校验失败。"; rm -f "$b"; return 1; }
    chmod 755 "$newbin"; mv -f "$newbin" "$realbin"; rm -rf "$stage"
  else
    tmp="$(mktemp /tmp/sing-box-update.XXXXXX)"
    if ! curl -fsSL --retry 3 --connect-timeout 8 https://sing-box.app/install.sh -o "$tmp" || ! bash "$tmp"; then
      rm -f "$tmp"; echo "更新器执行失败，旧二进制备份：$b"; return 1
    fi
    rm -f "$tmp"
  fi

  if ! sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1 || ! service_restart; then
    echo "新版本与当前配置/服务不兼容，正在恢复旧二进制。"
    rm -f "$realbin"; ln "$b" "$realbin" 2>/dev/null || cp -a "$b" "$realbin"; chmod 755 "$realbin"
    service_restart || true
    return 1
  fi
  echo "更新成功：$(sing-box version 2>/dev/null | head -n1)"
  while IFS= read -r f; do [ -n "$f" ] && backs+=("$f"); done < <(ls -1t "$BACKUP_DIR"/sing-box.* 2>/dev/null || true)
  for f in "${backs[@]}"; do i=$((i+1)); [ "$i" -le 3 ] || rm -f -- "$f"; done
}

urlenc(){
  local LC_ALL=C s="$1" out="" c hx i
  for ((i=0;i<${#s};i++)); do c="${s:i:1}"; case "$c" in [a-zA-Z0-9.~_-]) out+="$c";; *) printf -v hx '%%%02X' "'$c"; out+="$hx";; esac; done
  printf '%s' "$out"
}
uri_host(){ local h="$1"; h="${h#[}"; h="${h%]}"; [[ "$h" == *:* ]] && printf '[%s]' "$h" || printf '%s' "$h"; }
get_host(){
  local h="${CONNECTION_HOST:-}"
  if [ -z "$h" ]; then h="$(curl -4 -fsS --max-time 7 https://api.ipify.org 2>/dev/null || true)"; fi
  if [ -z "$h" ]; then h="$(curl -6 -fsS --max-time 7 https://api64.ipify.org 2>/dev/null || true)"; fi
  printf '%s' "$h"
}
regen_uris(){
  [ -f "$STATE_PATH" ] && source "$STATE_PATH" || return 1
  local h uh suf="" i64
  h="$(get_host)"; [ -n "$h" ] || { echo "无法获取连接地址"; return 1; }; uh="$(uri_host "$h")"
  [ -n "${NODE_NAME:-}" ] && suf="-$(urlenc "$NODE_NAME")"
  : >"$URI_PATH"
  if [ "${ENABLE_SS:-false}" = true ]; then i64="$(printf '%s' "${SS_METHOD}:${PSK_SS}" | base64 | tr -d '\r\n')"; echo "ss://${i64}@${uh}:${PORT_SS}#ss${suf}" >>"$URI_PATH"; fi
  if [ "${ENABLE_HY2:-false}" = true ]; then
    local iq; iq=$([ "${QUIC_TLS_INSECURE:-true}" = true ] && echo 1 || echo 0)
    local hyq="sni=${QUIC_TLS_SERVER_NAME}&alpn=h3&insecure=${iq}"
    if [ "${HY2_OBFS:-none}" != none ]; then hyq="${hyq}&obfs=${HY2_OBFS}&obfs-password=$(urlenc "$HY2_OBFS_PASSWORD")"; fi
    echo "hy2://$(urlenc "$PSK_HY2")@${uh}:${PORT_HY2}/?${hyq}#hy2${suf}" >>"$URI_PATH"
  fi
  if [ "${ENABLE_TUIC:-false}" = true ]; then
    local iq; iq=$([ "${QUIC_TLS_INSECURE:-true}" = true ] && echo 1 || echo 0)
    echo "tuic://${UUID_TUIC}:$(urlenc "$PSK_TUIC")@${uh}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=${QUIC_TLS_SERVER_NAME}&insecure=${iq}#tuic${suf}" >>"$URI_PATH"
  fi
  [ "${ENABLE_REALITY:-false}" = true ] && echo "vless://${UUID_REALITY}@${uh}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}#reality${suf}" >>"$URI_PATH"
  [ "${ENABLE_ANYTLS:-false}" = true ] && echo "anytls://$(urlenc "$ANYTLS_PSK")@${uh}:${PORT_ANYTLS}/?security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}#anytls${suf}" >>"$URI_PATH"
  chmod 600 "$URI_PATH"
}
panel_yaml_quote(){ local s="${1:-}"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; printf '"%s"' "$s"; }
regen_mihomo(){
  [ -f "$STATE_PATH" ] && source "$STATE_PATH" || return 1
  local h qh vname sname hname tname f
  h="$(get_host)"; [ -n "$h" ] || { echo "无法获取连接地址"; return 1; }; qh="$(panel_yaml_quote "$h")"
  mkdir -p "$MIHOMO_DIR"; chmod 700 "$MIHOMO_DIR"
  : >"$MIHOMO_DIR/vless.yaml"; : >"$MIHOMO_DIR/ss.yaml"; : >"$MIHOMO_DIR/hysteria2.yaml"; : >"$MIHOMO_DIR/tuic.yaml"
  vname="${NODE_REGION:-未分类}｜${VLESS_ROLE:-线路}｜${NODE_ALIAS:-node}"
  sname="${NODE_REGION:-未分类}｜${SS_ROLE:-落地}｜${NODE_ALIAS:-node}"
  hname="${NODE_REGION:-未分类}｜HY2｜${NODE_ALIAS:-node}"; tname="${NODE_REGION:-未分类}｜TUIC｜${NODE_ALIAS:-node}"
  if [ "${ENABLE_REALITY:-false}" = true ]; then cat >"$MIHOMO_DIR/vless.yaml" <<YAML
  - name: $(panel_yaml_quote "$vname")
    type: vless
    server: ${qh}
    port: ${PORT_REALITY}
    uuid: $(panel_yaml_quote "$UUID_REALITY")
    network: tcp
    udp: true
    tls: true
    servername: $(panel_yaml_quote "$REALITY_SNI")
    flow: xtls-rprx-vision
    client-fingerprint: chrome
    reality-opts:
      public-key: $(panel_yaml_quote "$REALITY_PUBLIC")
      short-id: $(panel_yaml_quote "$REALITY_SID")
YAML
  fi
  if [ "${ENABLE_SS:-false}" = true ]; then
    cat >"$MIHOMO_DIR/ss.yaml" <<YAML
  - name: $(panel_yaml_quote "$sname")
    type: ss
    server: ${qh}
    port: ${PORT_SS}
    cipher: $(panel_yaml_quote "$SS_METHOD")
    password: $(panel_yaml_quote "$PSK_SS")
    udp: true
YAML
    if [ "${SS_DIALER_PROXY_ENABLED:-false}" = true ]; then printf '    dialer-proxy: %s\n' "$(panel_yaml_quote "${SS_DIALER_PROXY:-中转}")" >>"$MIHOMO_DIR/ss.yaml"; fi
  fi
  if [ "${ENABLE_HY2:-false}" = true ]; then cat >"$MIHOMO_DIR/hysteria2.yaml" <<YAML
  - name: $(panel_yaml_quote "$hname")
    type: hysteria2
    server: ${qh}
    port: ${PORT_HY2}
    password: $(panel_yaml_quote "$PSK_HY2")
    sni: $(panel_yaml_quote "${QUIC_TLS_SERVER_NAME:-www.apple.com}")
    skip-cert-verify: ${QUIC_TLS_INSECURE:-true}
    bbr-profile: $(panel_yaml_quote "${HY2_BBR_PROFILE:-standard}")
    alpn:
      - h3
YAML
    if [ "${HY2_OBFS:-none}" != none ]; then printf '    obfs: %s\n    obfs-password: %s\n' "$(panel_yaml_quote "$HY2_OBFS")" "$(panel_yaml_quote "$HY2_OBFS_PASSWORD")" >>"$MIHOMO_DIR/hysteria2.yaml"; fi
  fi
  if [ "${ENABLE_TUIC:-false}" = true ]; then cat >"$MIHOMO_DIR/tuic.yaml" <<YAML
  - name: $(panel_yaml_quote "$tname")
    type: tuic
    server: ${qh}
    port: ${PORT_TUIC}
    uuid: $(panel_yaml_quote "$UUID_TUIC")
    password: $(panel_yaml_quote "$PSK_TUIC")
    sni: $(panel_yaml_quote "${QUIC_TLS_SERVER_NAME:-www.apple.com}")
    skip-cert-verify: ${QUIC_TLS_INSECURE:-true}
    alpn:
      - h3
    congestion-controller: bbr
    udp-relay-mode: native
YAML
  fi
  : >"$MIHOMO_DIR/all.yaml"
  for f in "$MIHOMO_DIR/vless.yaml" "$MIHOMO_DIR/ss.yaml" "$MIHOMO_DIR/hysteria2.yaml" "$MIHOMO_DIR/tuic.yaml"; do if [ -s "$f" ]; then [ ! -s "$MIHOMO_DIR/all.yaml" ] || printf '\n' >>"$MIHOMO_DIR/all.yaml"; cat "$f" >>"$MIHOMO_DIR/all.yaml"; fi; done
  if [ -s "$MIHOMO_DIR/all.yaml" ]; then { echo 'proxies:'; cat "$MIHOMO_DIR/all.yaml"; } >"$MIHOMO_DIR/full.yaml"; else echo 'proxies: []' >"$MIHOMO_DIR/full.yaml"; fi
  chmod 600 "$MIHOMO_DIR"/*.yaml 2>/dev/null || true
}
mihomo_file(){
  case "${1:-all}" in vless) echo "$MIHOMO_DIR/vless.yaml";; ss) echo "$MIHOMO_DIR/ss.yaml";; hy2|hysteria2) echo "$MIHOMO_DIR/hysteria2.yaml";; tuic) echo "$MIHOMO_DIR/tuic.yaml";; full) echo "$MIHOMO_DIR/full.yaml";; all|*) echo "$MIHOMO_DIR/all.yaml";; esac
}
show_mihomo(){ local f; f="$(mihomo_file "${1:-all}")"; [ -s "$f" ] || regen_mihomo >/dev/null 2>&1 || true; [ -s "$f" ] && cat "$f" || echo "没有可导出的 Mihomo 节点。"; }
osc52_copy(){
  local f data enc="${1:-all}"; f="$(mihomo_file "$enc")"; [ -s "$f" ] || regen_mihomo >/dev/null 2>&1 || true; [ -s "$f" ] || { echo "没有可复制的 Mihomo 节点。"; return 1; }
  if base64 --help 2>&1 | grep -q -- '-w'; then data="$(base64 -w0 "$f")"; else data="$(base64 <"$f" | tr -d '\r\n')"; fi
  printf '\033]52;c;%s\a' "$data"; echo; echo "已发送 OSC 52 剪贴板序列；若本地终端允许 OSC 52，现在可直接粘贴。"
}
edit_mihomo_meta(){
  local x
  read -r -p "地区 [${NODE_REGION:-未分类}]: " x; [ -z "$x" ] || set_state NODE_REGION "$x"
  source "$STATE_PATH"
  read -r -p "简称 [${NODE_ALIAS:-node}]: " x; [ -z "$x" ] || set_state NODE_ALIAS "$x"
  source "$STATE_PATH"
  if [ "${ENABLE_REALITY:-false}" = true ]; then read -r -p "VLESS 角色 [${VLESS_ROLE:-线路}]: " x; [ -z "$x" ] || set_state VLESS_ROLE "$x"; source "$STATE_PATH"; fi
  if [ "${ENABLE_SS:-false}" = true ]; then
    read -r -p "SS 角色 [${SS_ROLE:-落地}]: " x; [ -z "$x" ] || set_state SS_ROLE "$x"; source "$STATE_PATH"
    read -r -p "SS YAML 写入 dialer-proxy？[当前 ${SS_DIALER_PROXY_ENABLED:-false}] (Y/n/回车保持): " x
    case "$x" in Y|y) set_state SS_DIALER_PROXY_ENABLED true;; N|n) set_state SS_DIALER_PROXY_ENABLED false;; esac; source "$STATE_PATH"
    if [ "${SS_DIALER_PROXY_ENABLED:-false}" = true ]; then read -r -p "dialer-proxy [${SS_DIALER_PROXY:-中转}]: " x; [ -z "$x" ] || set_state SS_DIALER_PROXY "$x"; fi
  fi
  source "$STATE_PATH"
  set_state NODE_NAME "${NODE_REGION:-未分类}｜${NODE_ALIAS:-node}"
  source "$STATE_PATH"
  regen_uris || true
  regen_mihomo
  echo "已更新 Mihomo 导出信息与节点链接。"
}
set_state_many(){
  # 一次更新多个字段，避免切换 target 时反复复制整个状态文件。
  local t line k v
  local -A updates=()
  while [ "$#" -ge 2 ]; do
    k="$1"; v="$2"; shift 2
    [[ "$k" =~ ^[A-Z][A-Z0-9_]*$ ]] || return 1
    updates["$k"]="$v"
  done
  [ "$#" -eq 0 ] || return 1
  t="$(mktemp "${CONFIG_DIR}/.state.XXXXXX")" || return 1
  if [ -f "$STATE_PATH" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      k="${line%%=*}"
      if [[ "$k" =~ ^[A-Z][A-Z0-9_]*$ ]] && [ -n "${updates[$k]+x}" ]; then continue; fi
      printf '%s\n' "$line" >>"$t"
    done <"$STATE_PATH"
  fi
  for k in "${!updates[@]}"; do printf '%s=%q\n' "$k" "${updates[$k]}" >>"$t"; done
  chmod 600 "$t"
  mv -f "$t" "$STATE_PATH"
}
set_state(){ set_state_many "$1" "$2"; }
apply_candidate(){
  local f="$1"; mkdir -p "$BACKUP_DIR"; local b="${BACKUP_DIR}/config.$(date +%Y%m%d_%H%M%S).json"
  sing-box check -c "$f" || { echo "配置校验失败"; rm -f "$f"; return 1; }
  cp -a "$CONFIG_PATH" "$b"; install -m 600 "$f" "$CONFIG_PATH"; rm -f "$f"
  if ! service_restart; then cp -a "$b" "$CONFIG_PATH"; service_restart || true; echo "重启失败，已回滚"; return 1; fi
  echo "已应用；备份：$b"
}
reset_port(){
  local tag="$1" key="$2" old="$3" label="$4" new f
  read -r -p "$label 新端口 [当前 $old]: " new; new="${new:-$old}"
  [[ "$new" =~ ^[0-9]+$ ]] && [ "$new" -ge 1 ] && [ "$new" -le 65535 ] || { echo "端口无效"; return 1; }
  if [ "$new" != "$old" ] && panel_port_in_use "$new"; then echo "端口已占用"; return 1; fi
  f="$(mktemp)"; jq --arg tag "$tag" --argjson p "$new" '.inbounds |= map(if .tag==$tag then .listen_port=$p else . end)' "$CONFIG_PATH" >"$f"
  apply_candidate "$f" || return 1
  set_state "$key" "$new"; source "$STATE_PATH"; regen_uris; regen_mihomo
  if [ "$key" = PORT_SS ] && [ -f /root/install-singbox-relay.sh ] && [ "$new" != "$old" ]; then sed -i "s/\\\"server_port\\\":${old}/\\\"server_port\\\":${new}/g" /root/install-singbox-relay.sh 2>/dev/null || true; fi
}
edit_config(){
  mkdir -p "$BACKUP_DIR"; local b="${BACKUP_DIR}/config.edit.$(date +%Y%m%d_%H%M%S).json" ed
  cp -a "$CONFIG_PATH" "$b"; ed="${EDITOR:-}"; [ -n "$ed" ] || { command -v nano >/dev/null 2>&1 && ed=nano || ed=vi; }
  "$ed" "$CONFIG_PATH"
  if sing-box check -c "$CONFIG_PATH" && service_restart; then echo "编辑已应用；备份：$b"; else cp -a "$b" "$CONFIG_PATH"; service_restart || true; echo "校验/重启失败，已回滚"; fi
}
set_ss_mode(){
  [ "${ENABLE_SS:-false}" = true ] || { echo "未启用 SS"; return; }
  local c mode f
  echo "1) auto  2) prefer_ipv6  3) ipv6_only"; read -r -p "选择: " c
  case "$c" in 1) mode=auto;; 2) mode=prefer_ipv6;; 3) mode=ipv6_only;; *) return;; esac
  f="$(mktemp)"
  jq --arg mode "$mode" '
    .route=(.route//{})
    | .route.rules=[(.route.rules//[])[]? | select((((.inbound//[])|if type=="array" then index("ss-in") else .=="ss-in" end) and ((.action//"")=="resolve" or ((.action//"")=="reject" and (.ip_version//0)==4)))|not)]
    | if .dns then .dns.servers=[(.dns.servers//[])[]? | select(.tag!="ss-local-dns")] | if ((.dns.servers|length)==0 and ((.dns.rules//[])|length)==0) then del(.dns) else . end else . end
    | if $mode=="auto" then .
      else .dns=(.dns//{}) | .dns.servers=((.dns.servers//[])+[{type:"local",tag:"ss-local-dns",prefer_go:true}])
      | .route.rules += (if $mode=="ipv6_only" then [{inbound:["ss-in"],ip_version:4,action:"reject"}] else [] end)
      | .route.rules += [{inbound:["ss-in"],action:"resolve",server:"ss-local-dns",strategy:$mode}]
      end
  ' "$CONFIG_PATH" >"$f"
  apply_candidate "$f" || return 1; set_state SS_IP_MODE "$mode"; SS_IP_MODE="$mode"; echo "SS 出口模式：$mode"
}
valid_host(){ [[ "$1" =~ ^[a-zA-Z0-9.-]+$ ]] && [[ "$1" == *.* ]]; }

panel_port_in_use(){
  local p="$1" hex f _ local_addr
  printf -v hex '%04X' "$p"
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    while read -r _ local_addr _; do [ "${local_addr##*:}" = "$hex" ] && return 0; done <"$f"
  done
  return 1
}
panel_rand_port(){
  local low="${1:-22000}" high="${2:-62000}" p i span
  span=$((high-low+1))
  for ((i=0;i<64;i++)); do
    p=$(( ((RANDOM << 15) ^ RANDOM) % span + low ))
    if ! panel_port_in_use "$p"; then PANEL_RANDOM_PORT="$p"; printf '%s\n' "$p"; return 0; fi
  done
  return 1
}
panel_proc_count(){ local p n=0; for p in /proc/[0-9]*; do [ -d "$p" ] && n=$((n+1)); done; printf '%d' "$n"; }
panel_mem_kb(){ rp_mem_kb; }
panel_pid_headroom(){ rp_pid_headroom; }
panel_refresh_gfwlist(){
  [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] || return 0
  [ "${SINGBOX_REALITY_GFWLIST_CHECK:-1}" = 1 ] || return 0
  local tmp="${GFWLIST_PATH}.tmp.$$" url clean line d n=0 mtime now
  if [ -s "$GFWLIST_PATH" ]; then
    mtime="$(stat -c %Y "$GFWLIST_PATH" 2>/dev/null || true)"
    now="$(date +%s)"
    if [[ "$mtime" =~ ^[0-9]+$ ]] && [ "$now" -ge "$mtime" ] && [ $((now-mtime)) -lt 86400 ]; then return 0; fi
  fi
  for url in 'https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt' 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/gfw.txt'; do
    if curl -fsSL --retry 1 --connect-timeout 4 --max-time 10 "$url" -o "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
      clean="${tmp}.clean"; : >"$clean"; n=0
      while IFS= read -r line || [ -n "$line" ]; do d="${line%$'\r'}"; d="${d,,}"; d="${d#.}"; d="${d%.}"; [[ "$d" =~ ^[a-z0-9.-]+\.[a-z0-9-]+$ ]] || continue; printf '%s\n' "$d" >>"$clean"; n=$((n+1)); done <"$tmp"
      if [ "$n" -ge 100 ]; then install -m 600 "$clean" "$GFWLIST_PATH" 2>/dev/null || cp "$clean" "$GFWLIST_PATH"; rm -f "$tmp" "$clean"; return 0; fi
      rm -f "$clean"
    fi
  done
  rm -f "$tmp"; return 0
}

panel_current_asn(){ rp_vps_identity "${CONNECTION_HOST:-}"; }
panel_probe_summary(){
  local host="$1" status="${2:-NOT_TESTED}"
  printf '%s\n' "SNI=$host endpoint=${RP_IP:-未知} IPv${RP_FAMILY:-?} ASN=${RP_ASN:-未知} topology=${RP_TOPOLOGY:-unknown}"
  printf '%s\n' "compatibility=${RP_COMPAT:-FAIL} TLS13=${RP_TLS13:-NO} H2=${RP_H2:-NO} certificate=${RP_CERT:-NO} redirect_same_host=${RP_REDIRECT:-NO}"
  printf '%s\n' "client_path=UNMEASURED client_list_signal=${RP_CLIENT:-UNMEASURED} rule=${RP_RULE:-CLEAR} fallback_abuse=${RP_ABUSE:-NO_RULE_MATCH} short_sample=${RP_OK:-0}/${RP_TOTAL:-0} tls_ms=${RP_MS:-999999} local_selftest=$status"
  [ -z "${RP_REASON:-}" ] || printf '说明：%s\n' "$RP_REASON"
}
panel_show_record(){
  local -a fields=()
  IFS='|' read -r -a fields <<<"$1"
  rp_show_record "$1"
  printf '  拓扑=%s；样本仅为本次短时间观察，客户端公网路径与AnyTLS应用层未测。\n' "$(rp_topology "${fields[10]:-未知}" "${2:-未知}")"
}
reality_discover(){
  [ "${ENABLE_REALITY:-false}" = true ] || [ "${ENABLE_ANYTLS:-false}" = true ] || { echo "未启用 Reality。"; return 1; }
  panel_refresh_gfwlist || true
  local origin vps4 vasn prefix raw q source host apex age rank url malicious n=0
  local days="${SINGBOX_REALITY_URLSCAN_DAYS:-180}"
  local row best best_h best_asn best_ip best_family
  local -a best_fields=()
  local test_rc=0 selected_status=PASS x ep alt remaining i status tlsdays tasksource
  local -A seen=() sources=()
  origin="$(panel_current_asn)"; IFS='|' read -r vps4 vasn prefix <<<"$origin"
  vasn="${vasn:-未知}"; prefix="${prefix:-}"
  echo "VPS: $vps4 / ASN=$vasn / prefix=${prefix:-未知}；被动发现，不扫描网段。"
  echo "公共与动态候选在同一池比较；先看兼容和本机自测，再看拓扑、规则、短样本与延迟。没有抗封锁安全总分。"
  echo "客户端路径未实测；本机自测范围仅 local-vless-reality，不覆盖 AnyTLS 应用层。"
  : >"$DISCOVERY_CACHE"; chmod 600 "$DISCOVERY_CACHE"
  while IFS= read -r host; do
    seen["$host"]=1; sources["$host"]=public-core
    rp_probe_row "$host" "${REALITY_CLIENT_PROFILE:-cn}" "$GFWLIST_PATH" "$vasn" >>"$DISCOVERY_CACHE"
  done < <(rp_public_candidates "${REALITY_CLIENT_PROFILE:-cn}")
  local discovered
  discovered="$(mktemp "${CONFIG_DIR}/.reality-discover.XXXXXX")" || return 1
  rp_discover_candidates "$vasn" "$prefix" "$discovered"
  while IFS='|' read -r host source; do
    [ -z "${seen[$host]+x}" ] || continue; seen["$host"]=1; sources["$host"]="$source"
    rp_probe_row "$host" "${REALITY_CLIENT_PROFILE:-cn}" "$GFWLIST_PATH" "$vasn" >>"$DISCOVERY_CACHE"
  done <"$discovered"
  rm -f "$discovered"
  if rp_test_pool "$DISCOVERY_CACHE" "$vasn" "${SINGBOX_REALITY_COMPARE_LIMIT:-3}"; then test_rc=0; else test_rc=$?; fi
  while IFS= read -r row; do [ -z "$row" ] || panel_show_record "$row" "$vasn"; done <"$DISCOVERY_CACHE"
  best="$(rp_best_row "$DISCOVERY_CACHE" "$vasn" PASS || true)"
  if [ -z "$best" ] && [ "$test_rc" -eq 75 ]; then selected_status=DEFERRED; best="$(rp_best_row "$DISCOVERY_CACHE" "$vasn" DEFERRED || true)"; fi
  [ -n "$best" ] || { echo "没有候选通过本机兼容性自测；保留当前 SNI 和握手端点。"; return 1; }
  IFS='|' read -r -a best_fields <<<"$best"
  best_h="${best_fields[0]}"; best_asn="${best_fields[10]}"; best_ip="${best_fields[11]}"; best_family="${best_fields[12]}"
  echo "拓扑说明：same-asn=当前端点同ASN；cross-asn=本轮跨ASN兜底；unknown=无法核实。"
  echo; echo "建议候选（$selected_status，仅代表本机兼容性范围）："; panel_show_record "$best" "$vasn"
  remaining="$(mktemp "${CONFIG_DIR}/.reality-alternatives.XXXXXX")" || return 1
  grep -Fvx -- "$best" "$DISCOVERY_CACHE" >"$remaining" || true
  for i in 1 2; do
    alt="$(rp_best_row "$remaining" "$vasn" "$selected_status" || true)"; [ -n "$alt" ] || break
    echo "备选 $i："; panel_show_record "$alt" "$vasn"
    local remtmp="${remaining}.tmp"; grep -Fvx -- "$alt" "$remaining" >"$remtmp" || true; mv -f "$remtmp" "$remaining"
  done
  rm -f "$remaining"
  if [ "${1:-}" != --no-apply ]; then
    read -r -p "现在审计并切换到该候选？[y/N]: " x
    case "$x" in y|Y) change_reality "$best_h" "${sources[$best_h]:-public-core}" "$best_ip" "$best_family" "$best_asn";; esac
  fi
  return 0
}
reality_health(){
  [ "${ENABLE_REALITY:-false}" = true ] || [ "${ENABLE_ANYTLS:-false}" = true ] || { [ "${1:-}" = --scheduled ] || echo "未启用 Reality。"; return 0; }
  panel_refresh_gfwlist || true
  local mode="${1:-}" h="${REALITY_SNI:-}" pin="${REALITY_TARGET_IP:-}" now origin vps4 vasn prefix dns_ip dns_drift=NO
  local status=OK msg="当前端点兼容性检查通过；客户端路径未测" deep_rc="" deep_reason="" tmp
  [ -n "$h" ] || return 1
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; origin="$(panel_current_asn)"; IFS='|' read -r vps4 vasn prefix <<<"$origin"; vasn="${vasn:-未知}"
  rp_probe "$h" "${REALITY_CLIENT_PROFILE:-cn}" "$GFWLIST_PATH" "$vasn" "$pin"
  local tls="$RP_TLS13" h2="$RP_H2" cert="$RP_CERT" redir="$RP_REDIRECT" med="$RP_MS" tasn="$RP_ASN" actual_ip="$RP_IP" family="$RP_FAMILY"
  local rule="$RP_RULE" client="$RP_CLIENT" abuse="$RP_ABUSE" reason="$RP_REASON" ok="$RP_OK" total="$RP_TOTAL" compat="$RP_COMPAT" topology="$RP_TOPOLOGY"
  dns_ip="$(rp_resolve_ip "$h" || true)"
  if [ -n "$pin" ] && [ -n "$dns_ip" ] && ! rp_dns_contains "$h" "$pin"; then dns_drift=YES; fi
  if [ "$rule" = EXCLUDED ] && [ "$total" = 0 ]; then status=WARN; msg="客户端名单规则排除：端点兼容性未测试，不能据此判定封锁";
  elif [ "$compat" != PASS ]; then status=FAIL; msg="固定握手端点未通过兼容性检查";
  elif [ "$rule" != CLEAR ] || [ "$client" = LIST_FLAGGED ]; then status=WARN; msg="域名命中客户端画像规则；不等同于客户端路径实测";
  elif [ "$abuse" != NO_RULE_MATCH ]; then status=WARN; msg="发现回落转发滥用相关特征，请独立评估";
  elif [ -z "$pin" ]; then status=WARN; msg="旧配置按域名解析：尚未固定已验证端点，请人工重新审计";
  elif [ "$ok" -lt "$total" ]; then status=WARN; msg="固定端点短时采样有失败，建议复查稳定性";
  elif [ "$dns_drift" = YES ]; then status=WARN; msg="DNS 地址与固定握手端点不同；仅告警，不自动迁移";
  elif [ -n "${REALITY_SELECTED_ASN:-}" ] && [ "${REALITY_SELECTED_ASN:-未知}" != 未知 ] && [ "$tasn" != "$REALITY_SELECTED_ASN" ]; then status=WARN; msg="固定端点 ASN 与安装/切换记录不同"; fi
  if [ "$mode" = --deep ]; then
    if panel_reality_selftest "$h" "$actual_ip"; then deep_rc=PASS; else case $? in 75) deep_rc=DEFERRED; status=WARN; msg="本机回环自测延后，未获得新的验证";; *) deep_rc=FAIL; status=FAIL; msg="本机 VLESS+REALITY 兼容性自测失败";; esac; fi
    deep_reason="${PANEL_SELFTEST_REASON:-}"
  fi
  tmp="${HEALTH_PATH}.tmp.$$"
  jq -n --arg t "$now" --arg status "$status" --arg target "$h" --arg msg "$msg" \
    --arg tls "$tls" --arg h2 "$h2" --arg cert "$cert" --arg redir "$redir" --arg med "$med" \
    --arg ip "$actual_ip" --arg family "$family" --arg asn "$tasn" --arg dns "$dns_ip" --arg drift "$dns_drift" \
    --arg topology "$topology" --arg rule "$rule" --arg client "$client" --arg abuse "$abuse" --arg reason "$reason" \
    --arg ok "$ok" --arg total "$total" --arg compat "$compat" --arg vasn "$vasn" --arg source "${REALITY_SELECTED_SOURCE:-legacy}" \
    --arg deep "$deep_rc" --arg deep_reason "$deep_reason" \
    '{checked_at:$t,status:$status,target:$target,message:$msg,compatibility:$compat,tls13:$tls,h2:$h2,certificate:$cert,redirect_same_host:$redir,
      endpoint_ip:$ip,endpoint_family:$family,endpoint_asn:$asn,dns_endpoint:$dns,dns_drift:$drift,topology:$topology,vps_asn:$vasn,
      client_path:"UNMEASURED",client_list_signal:(if $client=="LIST_FLAGGED" then "FLAGGED" else "NO_RULE_MATCH" end),rule:$rule,fallback_abuse:$abuse,observation:$reason,successful_probes:($ok|tonumber),probe_samples:($total|tonumber),tls_ms:($med|tonumber),source:$source,
      stability_scope:"short-snapshot",selftest_scope:"local-vless-reality",anytls_application:"UNTESTED",local_selftest:(if $deep=="" then null else $deep end),local_selftest_reason:$deep_reason,
      automatically_switched:false}' >"$tmp" && install -m 600 "$tmp" "$HEALTH_PATH" || { rm -f "$tmp"; echo "无法保存 Reality 观察记录" >&2; return 1; }
  rm -f "$tmp"
  if [ "$mode" != --scheduled ] || [ "$status" != OK ]; then
    echo "Reality observation: $status — $msg"
    echo "SNI=$h endpoint=$actual_ip IPv$family ASN=$tasn/$vasn topology=$topology compatibility=$compat client_path=UNMEASURED client_list_signal=$client rule=$rule fallback_abuse=$abuse"
    echo "short_sample=$ok/$total tls_ms=$med DNS=$dns_ip dns_drift=$dns_drift local_selftest=${deep_rc:-NOT_RUN} selftest_scope=local-vless-reality anytls_application=UNTESTED"
    echo "只告警，不自动修改 SNI 或握手端点；客户端到 VPS 的公网路径未实测。"
  fi
  [ "$status" != FAIL ]
}
reality_health_status(){ [ -s "$HEALTH_PATH" ] && jq . "$HEALTH_PATH" || echo "暂无健康检查记录；运行：sb reality-health"; }

PANEL_SELFTEST_REASON=""
panel_reality_selftest(){
  local rc=0
  PANEL_SELFTEST_REASON=""
  if rp_selftest "$1" "${2:-}"; then rc=0; else rc=$?; fi
  PANEL_SELFTEST_REASON="${RP_TEST_REASON:-}"
  return "$rc"
}
change_reality(){
  if [ "${ENABLE_REALITY:-false}" != true ] && [ "${ENABLE_ANYTLS:-false}" != true ]; then echo "未启用 Reality。"; return 0; fi
  local new="${1:-}" source="${2:-manual}" pin="${3:-}" family="${4:-}" preset_asn="${5:-}" x origin vps4 vasn prefix candidate old_sni test_rc=0 self_status manual_override=false
  echo "当前 SNI: ${REALITY_SNI:-unknown}；固定握手端点: ${REALITY_TARGET_IP:-旧配置按域名解析}"
  [ -n "$new" ] || read -r -p "请输入新的 target 域名（留空取消）: " new
  [ -n "$new" ] || return 0
  new="${new//[[:space:]]/}"; new="${new,,}"; new="${new%.}"
  valid_host "$new" || { echo "域名格式无效"; return 1; }
  panel_refresh_gfwlist || true
  origin="$(panel_current_asn)"; IFS='|' read -r vps4 vasn prefix <<<"$origin"; vasn="${vasn:-未知}"
  rp_probe "$new" "${REALITY_CLIENT_PROFILE:-cn}" "$GFWLIST_PATH" "$vasn" "$pin"
  panel_probe_summary "$new"
  if [ "$RP_RULE" = EXCLUDED ] && [ "$RP_TOTAL" = 0 ]; then
    echo "该域名被客户端名单规则排除，尚未探测端点；名单不是客户端当前实测。"
    read -r -p "若仍要为该域名执行兼容性探测请输入 OVERRIDE: " x
    [ "$x" = OVERRIDE ] || return 0
    manual_override=true
    rp_probe "$new" global "" "$vasn" "$pin"
    RP_RULE=EXCLUDED; RP_CLIENT=LIST_FLAGGED; RP_ELIGIBLE=NO
    RP_REASON="手工覆盖名单规则；${RP_REASON:-}"
    panel_probe_summary "$new"
  fi
  [ "$RP_COMPAT" = PASS ] || { echo "固定端点兼容性未获确认，不修改。"; return 1; }
  if [ "$RP_ELIGIBLE" != YES ] && ! $manual_override; then
    echo "该候选未满足当前自动选择规则；这与客户端真实可达性、回落滥用观察分别显示。"
    read -r -p "如仍要手动使用请输入 OVERRIDE: " x
    [ "$x" = OVERRIDE ] || return 0
  fi
  pin="$RP_IP"; family="$RP_FAMILY"; preset_asn="$RP_ASN"
  local observed_rule="$RP_RULE" observed_client="$RP_CLIENT" observed_abuse="$RP_ABUSE" observed_ok="$RP_OK" observed_total="$RP_TOTAL" observed_ms="$RP_MS"
  echo "执行本机 VLESS+REALITY 自测（scope=local-vless-reality；不覆盖客户端公网路径或 AnyTLS 应用层）..."
  if panel_reality_selftest "$new" "$pin"; then test_rc=0; else test_rc=$?; fi
  case "$test_rc" in
    0) self_status=PASS; echo "本机兼容性自测：PASS" ;;
    75) self_status=DEFERRED; echo "本机兼容性自测：DEFERRED（${PANEL_SELFTEST_REASON:-资源不足}）" ;;
    *) self_status=FAIL; echo "本机兼容性自测：FAIL（${PANEL_SELFTEST_REASON:-未知原因}）"; read -r -p "如仍坚持应用请输入 FORCE: " x; [ "$x" = FORCE ] || return 0 ;;
  esac
  candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")" || return 1
  jq --arg h "$new" --arg ip "$pin" '.inbounds |= map(if ((.type=="vless" or .type=="anytls") and (.tls.reality.enabled==true)) then .tls.server_name=$h | .tls.reality.handshake.server=(if $ip!="" then $ip else $h end) else . end)' "$CONFIG_PATH" >"$candidate"
  old_sni="${REALITY_SNI:-}"
  apply_candidate "$candidate" || return 1
  set_state_many \
    REALITY_SNI "$new" REALITY_TARGET_IP "$pin" REALITY_TARGET_FAMILY "$family" \
    REALITY_SELECTED_SOURCE "$source" REALITY_SELECTED_ASN "$preset_asn" \
    REALITY_SELECTED_RULE "$observed_rule" REALITY_SELECTED_CLIENT_PATH UNMEASURED REALITY_SELECTED_CLIENT_LIST_SIGNAL "$observed_client" REALITY_SELECTED_FALLBACK_ABUSE "$observed_abuse" \
    REALITY_SELECTED_COMPAT PASS REALITY_SELECTED_SAMPLE_OK "$observed_ok" REALITY_SELECTED_SAMPLE_TOTAL "$observed_total" REALITY_SELECTED_TLS_MS "$observed_ms" \
    REALITY_SELECTED_SELFTEST "$self_status" REALITY_SELECTED_SELFTEST_SCOPE local-vless-reality REALITY_SELECTED_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  source "$STATE_PATH"
  regen_uris || true; regen_mihomo || true
  if [ -f /root/install-singbox-relay.sh ]; then sed -i "s|^INHERITED_SNI=.*$|INHERITED_SNI=\"${new}\"|" /root/install-singbox-relay.sh 2>/dev/null || true; fi
  echo "已同步应用 SNI=$new 与握手端点=$pin（IPv$family）；节点链接已重新生成。"
  [ "$old_sni" = "$new" ] || echo "SNI 已改变：请更新已导入客户端的 serverName；远端客户端不会自动同步。"
}
uninstall_all(){
  read -r -p "确认卸载 sing-box 与 /etc/sing-box？输入 YES: " x; [ "$x" = YES ] || return 0
  if command -v systemctl >/dev/null 2>&1; then systemctl disable --now sing-box sing-box-reality-health.timer 2>/dev/null || true; rm -f /etc/systemd/system/sing-box.service /etc/systemd/system/sing-box-reality-health.service /etc/systemd/system/sing-box-reality-health.timer; systemctl daemon-reload || true; else rc-service sing-box stop 2>/dev/null || true; rc-update del sing-box default 2>/dev/null || true; rm -f /etc/init.d/sing-box /etc/periodic/daily/sing-box-reality-health; fi
  rm -rf /etc/sing-box /usr/local/bin/sb /usr/bin/sb /root/node_names.txt
  echo "已卸载脚本配置。sing-box 二进制本身可能由官方安装器管理，可按其包管理方式卸载。"
}

if [ "${1:-}" = "doctor" ]; then doctor; exit $?; fi
if [ "${1:-}" = "update" ]; then safe_update; exit $?; fi
if [ "${1:-}" = "reality-health" ]; then reality_health "${2:-}"; exit $?; fi
if [ "${1:-}" = "reality-health-status" ]; then reality_health_status; exit $?; fi
if [ "${1:-}" = "reality-discover" ]; then reality_discover "${2:-}"; exit $?; fi

# 非交互快捷命令：sb mihomo [all|full|vless|ss|hy2|tuic|copy|setup]
if [ "${1:-}" = "mihomo" ]; then
  case "${2:-all}" in
    copy) osc52_copy "${3:-all}" ;;
    setup) edit_mihomo_meta ;;
    regen) regen_mihomo; show_mihomo all ;;
    all|full|vless|ss|hy2|hysteria2|tuic) show_mihomo "$2" ;;
    *) echo "用法: sb mihomo [all|full|vless|ss|hy2|tuic|copy [类型]|setup|regen]"; exit 2 ;;
  esac
  exit $?
fi

while true; do
  echo; echo "================ sing-box 管理 ================"
  echo "1) 查看节点链接"
  echo "2) 查看服务状态"
  echo "3) 查看最近日志"
  echo "4) 校验配置"
  echo "5) 安全重启"
  echo "6) 编辑配置（失败回滚）"
  echo "7) 查看当前 Reality SNI / 固定握手端点"
  echo "8) 审计并切换 Reality target"
  echo "9) 查看 IPv4/IPv6 出口"
  [ "${ENABLE_SS:-false}" = true ] && echo "10) 重置 SS 端口 / 11) 设置 SS 出口 IP 模式"
  [ "${ENABLE_HY2:-false}" = true ] && echo "12) 重置 Hysteria2 端口"
  [ "${ENABLE_TUIC:-false}" = true ] && echo "13) 重置 TUIC 端口"
  [ "${ENABLE_REALITY:-false}" = true ] && echo "14) 重置 VLESS Reality 端口"
  [ "${ENABLE_ANYTLS:-false}" = true ] && echo "15) 重置 AnyTLS Reality 端口"
  echo "16) 查看线路机安装脚本"
  echo "17) 安全更新 sing-box（失败自动恢复旧二进制）"
  echo "18) 卸载"
  echo "19) 查看当前 config.json"
  echo "20) 启动服务"
  echo "21) 停止服务"
  echo "22) 重新生成节点链接"
  echo "23) 查看 Mihomo YAML（可直接粘贴到 proxies: 下）"
  echo "24) OSC 52 一键复制 Mihomo YAML 到本机剪贴板"
  echo "25) 重新生成 Mihomo YAML"
  echo "26) 修改 Mihomo 节点命名 / SS dialer-proxy"
  echo "27) Doctor 全面自检"
  echo "28) Reality 端点观察 + 本机 VLESS+REALITY 自测"
  echo "29) 查看最近 Reality 健康记录"
  echo "30) 比较 Reality 候选（公共 + 被动同网发现）"
  echo "0) 退出"
  read -r -p "请选择: " c
  case "$c" in
    1) cat "$URI_PATH" 2>/dev/null || echo "链接文件不存在";;
    2) show_status;;
    3) show_logs;;
    4) sing-box check -c "$CONFIG_PATH" || true;;
    5) service_restart || true;;
    6) edit_config;;
    7) echo "SNI=${REALITY_SNI:-未启用} endpoint=${REALITY_TARGET_IP:-旧配置按域名解析} IPv${REALITY_TARGET_FAMILY:-?}";;
    8) change_reality || true;;
    9) echo -n "IPv4: "; curl -4 -fsS --max-time 7 https://api.ipify.org || echo "不可用"; echo; echo -n "IPv6: "; curl -6 -fsS --max-time 7 https://api64.ipify.org || echo "不可用"; echo;;
    10) [ "${ENABLE_SS:-false}" = true ] && reset_port ss-in PORT_SS "$PORT_SS" SS || echo "未启用 SS";;
    11) set_ss_mode;;
    12) [ "${ENABLE_HY2:-false}" = true ] && reset_port hy2-in PORT_HY2 "$PORT_HY2" Hysteria2 || echo "未启用 Hysteria2";;
    13) [ "${ENABLE_TUIC:-false}" = true ] && reset_port tuic-in PORT_TUIC "$PORT_TUIC" TUIC || echo "未启用 TUIC";;
    14) [ "${ENABLE_REALITY:-false}" = true ] && reset_port vless-reality-in PORT_REALITY "$PORT_REALITY" 'VLESS Reality' || echo "未启用 VLESS Reality";;
    15) [ "${ENABLE_ANYTLS:-false}" = true ] && reset_port anytls-reality-in PORT_ANYTLS "$PORT_ANYTLS" 'AnyTLS Reality' || echo "未启用 AnyTLS Reality";;
    16) if [ -f /root/install-singbox-relay.sh ]; then echo "/root/install-singbox-relay.sh"; echo "复制到线路机后执行：bash /root/install-singbox-relay.sh"; else echo "当前未生成（通常因为未启用 SS）。"; fi;;
    17) safe_update || true;;
    18) uninstall_all; exit 0;;
    19) cat "$CONFIG_PATH";;
    20) if command -v systemctl >/dev/null 2>&1; then systemctl start sing-box; else rc-service sing-box start; fi;;
    21) if command -v systemctl >/dev/null 2>&1; then systemctl stop sing-box; else rc-service sing-box stop; fi;;
    22) regen_uris && cat "$URI_PATH";;
    23) show_mihomo all;;
    24) echo "1) 全部片段  2) VLESS  3) SS  4) 完整 proxies: 区块"; read -r -p "选择 [默认 1]: " m; case "${m:-1}" in 2) osc52_copy vless;; 3) osc52_copy ss;; 4) osc52_copy full;; *) osc52_copy all;; esac;;
    25) regen_mihomo && show_mihomo all;;
    26) edit_mihomo_meta;;
    27) doctor || true;;
    28) reality_health --deep || true;;
    29) reality_health_status;;
    30) reality_discover || true;;
    0) exit 0;;
    *) echo "无效选项";;
  esac
done
SBEOF
  inject_reality_policy "$SB_PATH"
  chmod 755 "$SB_PATH"; ln -sf "$SB_PATH" /usr/bin/sb
}

change_reality_target_mode(){
  check_root; acquire_lock; detect_os; install_deps
  local executing_version="$SCRIPT_VERSION"
  command -v sing-box >/dev/null 2>&1 || die "未安装 sing-box。"
  # shellcheck source=/dev/null
  [ -f "$STATE_PATH" ] && source "$STATE_PATH" || die "找不到安装状态：$STATE_PATH"
  SCRIPT_VERSION="$executing_version"
  REALITY_CLIENT_PROFILE="${REALITY_CLIENT_PROFILE:-cn}"
  if [ "${ENABLE_REALITY:-false}" != true ] && [ "${ENABLE_ANYTLS:-false}" != true ]; then die "当前未启用 Reality。"; fi
  select_reality_sni
  local candidate backup
  candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"; TMP_FILES+=("$candidate")
  jq --arg ip "${REALITY_TARGET_IP:-$REALITY_SNI}" --arg h "$REALITY_SNI" '
    .inbounds |= map(
      if ((.type=="vless" or .type=="anytls") and (.tls.reality.enabled==true))
      then .tls.server_name=$h | .tls.reality.handshake.server=$ip
      else . end
    )
  ' "$CONFIG_PATH" >"$candidate"
  install_config_atomic "$candidate" || die "修改后的配置校验/原子写入失败，未应用。"
  backup="$LAST_CONFIG_BACKUP"
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl restart sing-box; then cp -a "$backup" "$CONFIG_PATH"; systemctl restart sing-box || true; die "服务重启失败，已恢复旧配置。"; fi
  else
    if ! rc-service sing-box restart; then cp -a "$backup" "$CONFIG_PATH"; rc-service sing-box restart || true; die "服务重启失败，已恢复旧配置。"; fi
  fi
  save_state
  # shellcheck source=/dev/null
  source "$STATE_PATH"
  generate_uris
  generate_mihomo_yaml || true
  generate_relay_installer
  install_sb_panel
  setup_reality_health_schedule
  ok "Reality target 已切换为 $REALITY_SNI / $REALITY_TARGET_IP；节点链接、面板与健康检查已更新；备份：$backup"
  warn "若 SNI 已变化，请同步已导入客户端的 serverName；远端客户端不会自动更新。"
  exit 0
}

setup_reality_health_schedule(){
  # 健康检查只观察当前 target，不自动切换 serverName，避免客户端配置失配。
  ($ENABLE_REALITY || $ENABLE_ANYTLS) || return 0
  [ "${REALITY_HEALTH_AUTO_ENABLE:-1}" = 1 ] || { info "Reality 周期健康检查已通过环境变量关闭。"; return 0; }
  local hours="${REALITY_HEALTH_INTERVAL_HOURS:-24}"
  [[ "$hours" =~ ^[0-9]+$ ]] || hours=24
  [ "$hours" -ge 1 ] || hours=24
  if command -v systemctl >/dev/null 2>&1; then
    cat >/etc/systemd/system/sing-box-reality-health.service <<EOF_HEALTH_SERVICE
[Unit]
Description=sing-box REALITY target health check
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/sb reality-health --scheduled
Nice=10
IOSchedulingClass=idle
EOF_HEALTH_SERVICE
    cat >/etc/systemd/system/sing-box-reality-health.timer <<EOF_HEALTH_TIMER
[Unit]
Description=Periodic sing-box REALITY target health check
[Timer]
OnBootSec=15min
OnUnitActiveSec=${hours}h
RandomizedDelaySec=30min
Persistent=true
[Install]
WantedBy=timers.target
EOF_HEALTH_TIMER
    systemctl daemon-reload
    systemctl enable --now sing-box-reality-health.timer >/dev/null 2>&1 || warn "Reality health timer 启用失败，可手动运行：sb reality-health"
    return 0
  fi
  # Alpine/OpenRC：优先使用系统已有的 periodic/daily + crond，不为了健康检查额外安装 cron 包。
  if [ -d /etc/periodic/daily ]; then
    cat >/etc/periodic/daily/sing-box-reality-health <<'EOF_HEALTH_CRON'
#!/bin/sh
/usr/local/bin/sb reality-health --scheduled >/dev/null 2>&1 || true
EOF_HEALTH_CRON
    chmod 755 /etc/periodic/daily/sing-box-reality-health
    if [ -x /etc/init.d/crond ]; then
      rc-update add crond default >/dev/null 2>&1 || true
      rc-service crond start >/dev/null 2>&1 || true
      info "Reality 健康检查：Alpine periodic/daily 已启用（约每日一次）。"
    else
      warn "已写入 /etc/periodic/daily/sing-box-reality-health，但未发现 crond OpenRC 服务；可手动执行 sb reality-health。"
    fi
  else
    warn "当前系统没有可安全复用的调度器；Reality 健康检查可手动执行：sb reality-health"
  fi
}

show_summary(){
  echo; echo "================================================"
  echo " sing-box 部署完成"
  echo "================================================"
  echo "脚本版本：$SCRIPT_VERSION"
  echo "sing-box：$(sing-box version 2>/dev/null | head -n1 || true)"
  echo "配置：$CONFIG_PATH"
  if $ENABLE_SS; then echo "SS：${PORT_SS} / ${SS_METHOD} / 出口=${SS_IP_MODE}"; fi
  if $ENABLE_HY2; then echo "Hysteria2：${PORT_HY2}"; fi
  if $ENABLE_TUIC; then echo "TUIC：${PORT_TUIC}"; fi
  if $ENABLE_HY2 || $ENABLE_TUIC; then echo "QUIC TLS：mode=${QUIC_TLS_MODE} / SNI=${QUIC_TLS_SERVER_NAME} / insecure=${QUIC_TLS_INSECURE}"; fi
  if $ENABLE_HY2; then echo "HY2：obfs=${HY2_OBFS} / bbr_profile=${HY2_BBR_PROFILE}"; fi
  if $ENABLE_REALITY; then echo "VLESS Reality：${PORT_REALITY} / target=${REALITY_SNI} / endpoint=${REALITY_TARGET_IP:-未知} / topology=$(rp_topology "${REALITY_SELECTED_ASN:-未知}" "${REALITY_VPS_ASN:-未知}") / source=${REALITY_SELECTED_SOURCE:-?} / client-profile=${REALITY_CLIENT_PROFILE:-cn}"; fi
  if $ENABLE_ANYTLS; then echo "AnyTLS Reality：${PORT_ANYTLS} / target=${REALITY_SNI} / endpoint=${REALITY_TARGET_IP:-未知} / topology=$(rp_topology "${REALITY_SELECTED_ASN:-未知}" "${REALITY_VPS_ASN:-未知}") / source=${REALITY_SELECTED_SOURCE:-?}"; fi
  echo
  echo "节点链接："
  cat "$URI_PATH"
  echo
  if $ENABLE_SS; then echo "线路机脚本：/root/install-singbox-relay.sh"; fi
  echo "Mihomo YAML（可直接粘贴到现有 proxies: 下）："
  cat "$MIHOMO_ALL_PATH" 2>/dev/null || true
  echo
  echo "Mihomo YAML 文件：$MIHOMO_ALL_PATH"
  echo "快捷导出：sb mihomo | sb mihomo vless | sb mihomo ss | sb mihomo full"
  echo "一键剪贴板：sb mihomo copy all（需本地终端允许 OSC 52）"
  echo 'Windows 本地复制：ssh root@VPS_IP "sb mihomo" | Set-Clipboard'
  echo "macOS 本地复制：ssh root@VPS_IP 'sb mihomo' | pbcopy"
  if $ENABLE_ANYTLS; then echo "提示：Mihomo 不支持 AnyTLS + Reality，因此 AnyTLS 不会出现在 Mihomo YAML 中。"; fi
  echo
  echo "防火墙提示（本脚本不擅自修改 UFW/nftables）："
  if $ENABLE_SS; then echo "  - SS: TCP+UDP ${PORT_SS}"; fi
  if $ENABLE_HY2; then echo "  - Hysteria2: UDP ${PORT_HY2}"; fi
  if $ENABLE_TUIC; then echo "  - TUIC: UDP ${PORT_TUIC}"; fi
  if $ENABLE_REALITY; then echo "  - VLESS Reality: TCP ${PORT_REALITY}"; fi
  if $ENABLE_ANYTLS; then echo "  - AnyTLS Reality: TCP ${PORT_ANYTLS}"; fi
  if $ENABLE_REALITY || $ENABLE_ANYTLS; then echo "Reality 健康检查：sb reality-health（周期任务只告警，不自动切换）"; fi
  echo "管理命令：sb"
  echo "================================================"
}

main(){
  if [ "${1:-}" = "--change-reality-target" ]; then change_reality_target_mode; fi
  check_root; acquire_lock; detect_os; detect_low_resource_mode
  [ "$OS" = alpine ] && cleanup_stale_singbox_packages
  info "系统：$OS (${OS_ID:-unknown})"
  install_deps
  preflight
  mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"; chmod 700 "$CONFIG_DIR" "$BACKUP_DIR"

  select_protocols
  prompt_node_name
  select_ss_method
  select_ss_ip_mode
  prompt_connection_host

  # 真实 Reality 自测与最新协议字段依赖 sing-box，因此先安装核心。
  install_singbox

  REALITY_SNI="$DEFAULT_REALITY_SNI"
  if $ENABLE_REALITY || $ENABLE_ANYTLS; then
    select_reality_client_profile
    select_reality_sni
  else
    REALITY_CLIENT_PROFILE="${SINGBOX_REALITY_CLIENT_PROFILE:-cn}"
  fi
  select_quic_tls

  configure_values
  generate_reality_keys
  generate_cert

  local candidate
  candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"; TMP_FILES+=("$candidate")
  build_config "$candidate"
  install_config_atomic "$candidate" || die "生成配置无法通过 sing-box check，未覆盖现有配置。"
  save_state
  if ! setup_service; then
    if [ -n "${LAST_CONFIG_BACKUP:-}" ] && [ -f "$LAST_CONFIG_BACKUP" ]; then
      warn "新服务启动失败，正在恢复安装前配置。"
      cp -a "$LAST_CONFIG_BACKUP" "$CONFIG_PATH"
      setup_service || true
    fi
    die "sing-box 服务未能使用新配置启动。"
  fi
  generate_uris
  generate_mihomo_yaml
  generate_relay_installer
  install_sb_panel
  setup_reality_health_schedule
  show_summary
}

main "$@"

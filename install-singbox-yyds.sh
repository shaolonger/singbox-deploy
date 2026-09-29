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
#   6. 高风险共享 CDN（Cloudflare/Fastly/CloudFront/Akamai 等）默认不参与自动推荐
#   7. 已知存在 Reality 兼容性争议的目标默认不参与自动推荐
#   8. 允许手动指定 target，但高风险目标会明确警告并要求确认
#   9. 配置原子写入，sing-box check 失败不覆盖工作配置
#  10. 自带 sb 管理命令，可重新审计/切换 Reality target
#  11. 自动生成 Mihomo/Clash YAML，支持 sb mihomo 一键输出与 OSC 52 剪贴板复制
#  12. 标准化节点命名：地区｜角色｜简称；SS 可选 dialer-proxy（默认“中转”）
#  13. 中国大陆 Reality 候选分核心/扩展池；动态同前缀/同 ASN 被动发现 + 评分
#  14. 周期 Reality target 健康检查，只告警不自动切换，避免客户端 serverName 失配
#
# 目标 sing-box：稳定版 1.14+（默认 stable；不自动追 alpha/testing）。
# ============================================================

SCRIPT_VERSION="2026.09.28-dynamic-reality-v5.2.0"
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
REALITY_HEALTH_PATH="${CONFIG_DIR}/reality-health.json"
REALITY_DISCOVERY_CACHE="${CONFIG_DIR}/reality-discovery.tsv"
REALITY_GFWLIST_CACHE="${CONFIG_DIR}/reality-gfw.txt"

# Reality 动态发现/健康检查。动态发现只读取公开被动数据，不主动扫描 ASN/IP 网段。
REALITY_DYNAMIC_DISCOVERY="${SINGBOX_REALITY_DYNAMIC_DISCOVERY:-auto}"   # auto|on|off
REALITY_DYNAMIC_MAX="${SINGBOX_REALITY_DYNAMIC_MAX:-12}"
REALITY_DYNAMIC_MIN_AGE_DAYS="${SINGBOX_REALITY_DYNAMIC_MIN_AGE_DAYS:-365}"
REALITY_URLSCAN_DAYS="${SINGBOX_REALITY_URLSCAN_DAYS:-180}"
REALITY_URLSCAN_API_KEY="${SINGBOX_URLSCAN_API_KEY:-}"
REALITY_HEALTH_INTERVAL_HOURS="${SINGBOX_REALITY_HEALTH_INTERVAL_HOURS:-24}"
REALITY_HEALTH_AUTO_ENABLE="${SINGBOX_REALITY_HEALTH_AUTO_ENABLE:-1}"
REALITY_GFWLIST_CHECK="${SINGBOX_REALITY_GFWLIST_CHECK:-1}"
REALITY_GFWLIST_READY=false

# 候选元数据用于评分。Bash 4+（本脚本强制 bash）支持关联数组。
declare -A REALITY_CANDIDATE_SOURCE=()
declare -A REALITY_CANDIDATE_AGE=()
declare -A REALITY_CANDIDATE_PASSIVE_IP=()
declare -A REALITY_CANDIDATE_PASSIVE_ASN=()
declare -A REALITY_CANDIDATE_REDIRECT=()
declare -A REALITY_CANDIDATE_RANK=()
REALITY_VPS_ASN="未知"
REALITY_VPS_PREFIX=""
REALITY_SELECTED_SCORE=""
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
LOW_RESOURCE_MEM_KB=0
LOW_RESOURCE_DISK_KB=0
SINGBOX_STABLE_FALLBACK_VERSION="1.14.2"

# Reality 真握手自测资源策略：auto 会在 PID/Tasks 或内存余量不足时自动降级为 DEFERRED，
# 不再为了“强行自测”把低配 VPS 的 shell / curl / sing-box 一起拖入 fork exhaustion。
REALITY_SELFTEST_MODE="${SINGBOX_REALITY_SELFTEST_MODE:-auto}"   # auto|on|off|force
# 真握手自测会短暂启动一个 Go 进程。默认阈值刻意保守：资源不足时宁可 DEFERRED，
# 也不要让低配/严格 TasksMax 的 VPS 因“额外自测”影响安装 shell 或正式服务。
REALITY_SELFTEST_MIN_PID_HEADROOM="${SINGBOX_REALITY_SELFTEST_MIN_PID_HEADROOM:-96}"
REALITY_SELFTEST_MIN_MEM_KB="${SINGBOX_REALITY_SELFTEST_MIN_MEM_KB:-131072}"
SELFTEST_DIR=""
SELFTEST_PRIVATE=""
SELFTEST_PUBLIC=""
SELFTEST_SID=""
SELFTEST_UUID=""
SELFTEST_PID=""
REALITY_SELFTEST_LAST_REASON=""

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
REALITY_CN_INAPPROPRIATE_REGEX='(^|\.)(google\.com|gstatic\.com|googleapis\.com|googleusercontent\.com|youtube\.com|ytimg\.com|wikipedia\.org|wikimedia\.org|facebook\.com|fbcdn\.net|instagram\.com|whatsapp\.com|twitter\.com|x\.com|t\.co|telegram\.org|t\.me|signal\.org|torproject\.org|reddit\.com|discord\.com|medium\.com)$'

# 中国大陆候选池：优先选择大陆网络通常可直接访问、且不是典型翻墙/受限站点的 HTTPS 域名。
# 注意：这仍只是“待审计输入”，不是永久白名单。网络可达性会随运营商/地区/时间变化，
# 最终仍需满足 TLS1.3 + H2 + 有效证书 + 不跨域跳转 + 低 CDN 滥用风险 + Reality 真实自测。
# 中国大陆“核心候选池”：优先放入网络行为自然、长期正常用途明显、且不是典型受限站点的域名。
# 这些仍不是永久白名单；运行时必须继续通过 TLS1.3/H2/证书/不跨域/共享 CDN/Reality 真握手审计。
# 排序只影响测试先后，不会绕过任何硬条件。
REALITY_CANDIDATES_CN_PRIMARY=(
  # 公共兜底核心池刻意保持很小；动态同前缀/同 ASN 候选会排在它们之前。
  # 这几个域名在此前多地区实测中更常满足 TLS1.3 + H2 + 证书 + 非跨域条件。
  "www.debian.org"
  "www.openssl.org"
  "www.postgresql.org"
  "www.alpinelinux.org"
)

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
  # 并在 known_target_risk() 中标记为 CAUTION，不会压过 LOW 风险候选。
  "developer.apple.com"
  "weather.apple.com"
  "gateway.icloud.com"
)

# 海外画像：在大陆画像基础上增加一些大陆可达性并非主要约束的候选。
# 仍然不默认加入 Google/大型下载域名，因为 fallback 滥用风险与“海外/大陆”无关。
REALITY_CANDIDATES_GLOBAL_PRIMARY=(
  "gateway.icloud.com"
  "www.debian.org"
  "www.freebsd.org"
  "www.kernel.org"
  "www.postgresql.org"
  "www.openssl.org"
  "www.openbsd.org"
  "www.netbsd.org"
  "www.videolan.org"
  "www.archlinux.org"
  "www.mozilla.org"
  "developer.mozilla.org"
)

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
REALITY_KNOWN_BAD_REGEX='(^|\.)cloudflare\.com$|(^|\.)workers\.dev$|(^|\.)pages\.dev$|(^|\.)cloudfront\.net$|(^|\.)fastly\.net$|(^|\.)fastlylb\.net$|(^|\.)akamaiedge\.net$|(^|\.)edgekey\.net$|(^|\.)edgesuite\.net$|(^|\.)azureedge\.net$|(^|\.)azurefd\.net$|(^|\.)vercel\.app$|(^|\.)netlify\.app$|(^|\.)github\.io$|(^|\.)microsoft\.com$|(^|\.)bing\.com$'

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
  local p f
  if [ -n "${SELFTEST_PID:-}" ]; then
    kill "$SELFTEST_PID" 2>/dev/null || true
    wait "$SELFTEST_PID" 2>/dev/null || true
    SELFTEST_PID=""
  fi
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
  local p pid arg joined killed=0
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
  local key val unit
  [ -r /proc/meminfo ] || { printf '0'; return 0; }
  while read -r key val unit; do
    if [ "$key" = "MemTotal:" ]; then printf '%s' "${val:-0}"; return 0; fi
  done </proc/meminfo
  printf '0'
}

detect_low_resource_mode(){
  local mem total free
  mem="$(mem_total_kb)"
  total="$(df -Pk / 2>/dev/null | awk 'NR==2{print $2}' || true)"
  free="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}' || true)"
  LOW_RESOURCE_MEM_KB="${mem:-0}"
  LOW_RESOURCE_DISK_KB="${free:-0}"
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
  case "$OS" in
    alpine)
      local -a pkgs=()
      command -v bash >/dev/null 2>&1 || pkgs+=(bash)
      command -v curl >/dev/null 2>&1 || pkgs+=(curl)
      command -v openssl >/dev/null 2>&1 || pkgs+=(openssl)
      command -v jq >/dev/null 2>&1 || pkgs+=(jq)
      command -v dig >/dev/null 2>&1 || pkgs+=(bind-tools)
      [ -s /etc/ssl/certs/ca-certificates.crt ] || pkgs+=(ca-certificates)
      command -v timeout >/dev/null 2>&1 || pkgs+=(coreutils)
      if [ "${#pkgs[@]}" -gt 0 ]; then
        info "Alpine 最小依赖：${pkgs[*]}"
        apk add --no-cache "${pkgs[@]}"
      else
        info "Alpine 必要依赖已满足；跳过 apk 安装。"
      fi
      ;;
    debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y curl ca-certificates openssl jq iproute2 coreutils dnsutils procps util-linux
      ;;
    redhat)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y curl ca-certificates openssl jq iproute coreutils bind-utils procps-ng util-linux
      else
        yum install -y curl ca-certificates openssl jq iproute coreutils bind-utils procps-ng util-linux
      fi
      ;;
    *) warn "未识别发行版；将尝试使用现有 curl/openssl/jq/timeout。" ;;
  esac
  local c
  for c in curl openssl jq timeout tar; do command -v "$c" >/dev/null 2>&1 || die "缺少依赖：$c"; done
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
    if ! port_in_use "$p"; then RANDOM_PORT="$p"; printf '%s\n' "$p"; return 0; fi
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

# ---------- Reality target 安全审计 ----------
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
  # Team Cymru origin DNS 返回 ASN | IP | BGP Prefix | CC | Registry | Allocated。
  # 输出：ASxxxxx|prefix。失败不影响主流程。
  local ip="$1" a b c d q raw ans n prefix
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  command -v dig >/dev/null 2>&1 || return 1
  IFS='.' read -r a b c d <<<"$ip"
  q="${d}.${c}.${b}.${a}.origin.asn.cymru.com"
  raw="$(dig +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"
  ans="$(first_nonempty_line <<<"$raw" || true)"
  [ -n "$ans" ] || { raw="$(dig @1.1.1.1 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(first_nonempty_line <<<"$raw" || true)"; }
  [ -n "$ans" ] || { raw="$(dig @9.9.9.9 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(first_nonempty_line <<<"$raw" || true)"; }
  ans="${ans//\"/}"
  IFS='|' read -r n _ prefix _ <<<"$ans"
  n="$(trim_ws "$n")"; prefix="$(trim_ws "$prefix")"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  [[ "$prefix" == */* ]] || prefix=""
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
  local tmp="${REALITY_GFWLIST_CACHE}.tmp.$$" url
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
  local host="${1,,}" d
  [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] || return 1
  [ "${REALITY_GFWLIST_CHECK:-1}" = 1 ] || return 1
  [ -s "$REALITY_GFWLIST_CACHE" ] || return 1
  while IFS= read -r d || [ -n "$d" ]; do
    [ -n "$d" ] || continue
    if [ "$host" = "$d" ] || [[ "$host" == *."$d" ]]; then return 0; fi
  done <"$REALITY_GFWLIST_CACHE"
  return 1
}

candidate_set_meta(){
  local host="$1" source="${2:-unknown}" age="${3:-0}" ip="${4:-}" pasn="${5:-}" redir="${6:-}" rank="${7:-0}"
  REALITY_CANDIDATE_SOURCE["$host"]="$source"
  REALITY_CANDIDATE_AGE["$host"]="$age"
  REALITY_CANDIDATE_PASSIVE_IP["$host"]="$ip"
  REALITY_CANDIDATE_PASSIVE_ASN["$host"]="$pasn"
  REALITY_CANDIDATE_REDIRECT["$host"]="$redir"
  REALITY_CANDIDATE_RANK["$host"]="$rank"
}

candidate_source(){ printf '%s' "${REALITY_CANDIDATE_SOURCE[$1]:-public}"; }

urlscan_fetch(){
  # $1=query；只读取公开历史扫描。API key 可选；无 key 时受匿名小配额限制。
  local q="$1" key="${REALITY_URLSCAN_API_KEY:-}" out size=50
  ${LOW_RESOURCE_MODE:-false} && size=20
  local -a args=(-fsS --connect-timeout 4 --max-time 12 --get 'https://urlscan.io/api/v1/search/' --data-urlencode "q=$q" --data-urlencode "size=$size" --data-urlencode "datasource=scans" --data-urlencode "collapse=page.domain.keyword")
  [ -n "$key" ] && args+=(-H "api-key: $key")
  out="$(curl "${args[@]}" 2>/dev/null || true)"
  [ -n "$out" ] && jq -e '.results and (.results|type=="array")' >/dev/null 2>&1 <<<"$out" || return 1
  printf '%s' "$out"
}

discover_reality_candidates(){
  # $3 为输出文件；元数据保留在当前 shell 的关联数组。不会主动扫描任何 IP/端口。
  local vps_asn="$1" vps_prefix="$2" outfile="$3" max="${REALITY_DYNAMIC_MAX:-12}" min_age="${REALITY_DYNAMIC_MIN_AGE_DAYS:-365}" days="${REALITY_URLSCAN_DAYS:-180}"
  local mode="${REALITY_DYNAMIC_DISCOVERY:-auto}" raw query source line host ip pasn age redir rank pageurl malicious krisk count=0
  local -A seen=()
  local -a queries=() sources=()
  : >"$outfile"
  case "$mode" in off|0|false) return 0;; auto|on|1|true) :;; *) mode=auto;; esac
  [[ "$max" =~ ^[0-9]+$ ]] || max=12; [ "$max" -gt 24 ] && max=24
  ${LOW_RESOURCE_MODE:-false} && [ "$max" -gt 4 ] && max=4
  [[ "$min_age" =~ ^[0-9]+$ ]] || min_age=365
  [[ "$days" =~ ^[0-9]+$ ]] || days=180
  if [ -n "$vps_prefix" ]; then
    local esc_prefix="${vps_prefix//\//\\/}"
    queries+=("page.ip:${esc_prefix} AND date:>now-${days}d")
    sources+=("dynamic-prefix")
  fi
  if [ "$vps_asn" != "未知" ] && [ -n "$vps_asn" ]; then
    queries+=("page.asn:${vps_asn} AND date:>now-${days}d")
    sources+=("dynamic-asn")
  fi
  [ "${#queries[@]}" -gt 0 ] || return 0
  info "被动发现 Reality 候选：仅查询公开历史数据，不扫描 ASN/IP 网段。"
  : >"$REALITY_DISCOVERY_CACHE" 2>/dev/null || true
  local qi
  for qi in "${!queries[@]}"; do
    [ "$count" -ge "$max" ] && break
    query="${queries[$qi]}"; source="${sources[$qi]}"
    raw="$(urlscan_fetch "$query" || true)"
    if [ -z "$raw" ]; then
      warn "urlscan 被动发现不可用/额度受限：${source}；自动降级到内置候选池。" >&2
      continue
    fi
    while IFS=$'\t' read -r host ip pasn age redir rank pageurl malicious; do
      [ "$count" -lt "$max" ] || break
      host="$(normalize_sni "$host")"
      validate_sni "$host" || continue
      [ -z "${seen[$host]+x}" ] || continue
      [[ "$pageurl" == https://* ]] || continue
      [ "$malicious" != "true" ] || continue
      [[ "$age" =~ ^[0-9]+$ ]] || age=0
      [ "$age" -ge "$min_age" ] || continue
      krisk="$(known_target_risk "$host")"
      [[ "$krisk" == HIGH\|* ]] && continue
      # urlscan 的 page.asn 是主页面 ASN；前缀查询结果必须仍与 VPS ASN 一致，避免历史漂移。
      if [ "$source" = dynamic-prefix ] && [ "$vps_asn" != 未知 ] && [ "$pasn" != "$vps_asn" ]; then continue; fi
      seen["$host"]=1
      candidate_set_meta "$host" "$source" "$age" "$ip" "$pasn" "$redir" "$rank"
      printf '%s\n' "$host" >>"$outfile"
      printf '%s|%s|%s|%s|%s|%s|%s\n' "$host" "$source" "$age" "$ip" "$pasn" "$redir" "$rank" >>"$REALITY_DISCOVERY_CACHE"
      count=$((count+1))
    done < <(jq -r '.results[]? | [(.page.domain//""),(.page.ip//""),(.page.asn//""),((.page.apexDomainAgeDays//.page.domainAgeDays//0)|tostring),(.page.redirected//"none"),((.page.umbrellaRank//0)|tostring),(.page.url//""),((.verdicts.malicious//false)|tostring)] | @tsv' <<<"$raw" 2>/dev/null)
  done
  return 0
}

candidate_score(){
  # 仅对已通过 TLS1.3/H2/证书/不跨域且非 HIGH 的候选评分；输出 0..100。
  # 评分强调网络拓扑而非知名度：LOW 25，同 ASN 30，动态同前缀 20，域名成熟度 10，延迟 10，排名信誉 5。
  local host="$1" risk="$2" tasn="$3" med="$4" vps_asn="$5" score=0 src age rank
  src="$(candidate_source "$host")"; age="${REALITY_CANDIDATE_AGE[$host]:-0}"; rank="${REALITY_CANDIDATE_RANK[$host]:-0}"
  case "$risk" in LOW) score=$((score+25));; CAUTION) score=$((score+5));; esac
  local same_asn=false
  [ "$vps_asn" != 未知 ] && [ "$tasn" = "$vps_asn" ] && { score=$((score+30)); same_asn=true; }
  case "$src" in
    dynamic-prefix) $same_asn && score=$((score+20)) || score=$((score+2));;
    dynamic-asn) $same_asn && score=$((score+10));;
    custom) score=$((score+8));;
    public-core) score=$((score+4));;
    *) :;;
  esac
  [[ "$age" =~ ^[0-9]+$ ]] || age=0
  if [ "$age" -ge 3650 ]; then score=$((score+10)); elif [ "$age" -ge 1825 ]; then score=$((score+8)); elif [ "$age" -ge 730 ]; then score=$((score+6)); elif [ "$age" -ge 365 ]; then score=$((score+4)); fi
  [[ "$med" =~ ^[0-9]+$ ]] || med=999999
  if [ "$med" -le 50 ]; then score=$((score+10)); elif [ "$med" -le 100 ]; then score=$((score+8)); elif [ "$med" -le 200 ]; then score=$((score+6)); elif [ "$med" -le 400 ]; then score=$((score+3)); fi
  [[ "$rank" =~ ^[0-9]+$ ]] || rank=0
  if [ "$rank" -gt 0 ] && [ "$rank" -le 100000 ]; then score=$((score+5)); elif [ "$rank" -le 500000 ] && [ "$rank" -gt 0 ]; then score=$((score+3)); fi
  [ "$score" -gt 100 ] && score=100
  printf '%d' "$score"
}

cdn_risk_from_text(){
  local txt
  txt="${1,,}"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cdn.cloudflare.net*) echo "HIGH|Cloudflare 共享 CDN" ;;
    *cloudfront.net*|*x-amz-cf-*|*cloudfront*) echo "HIGH|AWS CloudFront 共享 CDN" ;;
    *fastly.net*|*fastlylb.net*|*x-served-by*|*x-timer*) echo "HIGH|Fastly 共享 CDN" ;;
    *akamaiedge.net*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*akamaighost*|*x-akamai*) echo "HIGH|Akamai 共享 CDN" ;;
    *azureedge.net*|*azurefd.net*|*azurefrontdoor*|*x-azure-ref*|*trafficmanager.net*) echo "HIGH|Azure 边缘/CDN" ;;
    *b-cdn.net*|*bunnycdn*|*cdn77*|*stackpath*|*incapdns*|*imperva*|*vercel.app*|*netlify.app*) echo "HIGH|共享 CDN/边缘托管" ;;
    *) echo "LOW|未发现常见共享 CDN 特征" ;;
  esac
}

known_target_risk(){
  local host="$1"
  if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ] && [[ "$host" =~ $REALITY_CN_INAPPROPRIATE_REGEX ]]; then
    echo "HIGH|中国大陆画像下属于长期受限/高度不稳定 SNI，不适合作为默认 Reality 伪装目标"
    return 0
  fi
  if reality_host_in_gfwlist "$host"; then
    echo "HIGH|命中当前 GFWList 保守排除列表；中国大陆画像下不参与自动推荐"
    return 0
  fi
  case "$host" in
    dl.google.com|*.dl.google.com) echo "HIGH|大型下载域名，fallback 可被重复下载消耗 VPS 流量"; return 0 ;;
    www.gstatic.com|*.gstatic.com) echo "HIGH|大型静态资源域名，fallback 滥用价值较高"; return 0 ;;
    gateway.icloud.com)
      if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ]; then
        echo "CAUTION|中国大陆可达性存在波动，保留为扩展候选但降低自动推荐优先级"
        return 0
      fi
      ;;
  esac
  if [[ "$host" =~ $REALITY_KNOWN_BAD_REGEX ]]; then
    case "$host" in
      *microsoft.com|*bing.com) echo "HIGH|已知 Reality 兼容性争议/常见 Akamai 链路" ;;
      *) echo "HIGH|显式高风险目标" ;;
    esac
    return 0
  fi
  echo "LOW|未命中显式风险列表"
}

run_with_timeout(){
  # 为可能长时间半开的网络命令提供硬超时。timeout 已作为强制依赖检查。
  local sec="$1"; shift
  command -v timeout >/dev/null 2>&1 || return 124
  timeout "$sec" "$@"
}

probe_tls_http(){
  # 输出：tls13|h2|cert_ok|redirect_ok|median_ms|risk|reason|cname_summary|asn
  # v5.0.3：所有可能阻塞的外部网络探测都有明确超时；先做便宜的硬条件，失败立即短路。
  # 第一条 HTTPS 请求同时收集证书结果、重定向、首个 TLS 建连耗时和响应头，避免旧版额外 HEAD 请求。
  local host="$1" tlsout tlslower raw line headers="" cnames krisk crisk risk reason target_ip target_asn
  local tls13="NO" h2="NO" cert="NO" redirect="YES" med=999999
  local code="" redir="" t="" rh="" rest=""
  local -a times=() cname_arr=()

  krisk="$(known_target_risk "$host")"

  # openssl s_client 自身没有连接/握手超时，必须由 timeout 包裹，否则单个坏目标可永久卡住串行审计。
  tlsout="$(run_with_timeout 5 openssl s_client -connect "${host}:443" -servername "$host" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
  tlslower="${tlsout,,}"
  [[ "$tlsout" == *"TLSv1.3"* || "$tlsout" == *"TLS_AES_"* ]] && tls13="YES"
  [[ "$tlslower" == *"alpn protocol: h2"* || "$tlslower" == *"alpn: h2"* ]] && h2="YES"

  # 一次 GET 同时完成系统 CA 校验、重定向、首个耗时采样和 Header 收集。
  if raw="$(curl -sS -D - -o /dev/null --connect-timeout 3 --max-time 6 \
      -w $'\n__SBMETA__\t%{http_code}\t%{redirect_url}\t%{time_appconnect}\n' \
      "https://${host}/" 2>/dev/null)"; then
    cert="YES"
    while IFS= read -r line; do
      line="${line%$'\r'}"
      if [[ "$line" == __SBMETA__$'\t'* ]]; then
        IFS=$'\t' read -r _ code redir t <<<"$line"
      else
        headers+="$line"$'\n'
      fi
    done <<<"$raw"
    [[ "$t" =~ ^[0-9]+([.][0-9]+)?$ ]] && times+=("$t")
    if [[ -n "$redir" && "$redir" =~ ^https?:// ]]; then
      rest="${redir#*://}"
      rh="${rest%%/*}"
      rh="${rh%%:*}"
      rh="${rh,,}"
      [ "$rh" = "$host" ] || redirect="NO"
    fi
  fi

  # 任何硬条件已经失败时，不再做重复测速、深层 CNAME 和 ASN 查询；这能把坏目标控制在约 10 秒内返回。
  if [ "$tls13" != YES ] || [ "$h2" != YES ] || [ "$cert" != YES ] || [ "$redirect" != YES ]; then
    if [[ "$krisk" == HIGH\|* ]]; then risk="HIGH"; reason="${krisk#HIGH|}"
    elif [[ "$krisk" == CAUTION\|* ]]; then risk="CAUTION"; reason="${krisk#CAUTION|}"
    else risk="LOW"; reason="未进入 CDN 深审计（硬条件未全部通过）"; fi
    [ "${#times[@]}" -gt 0 ] && med="$(median_ms "${times[@]}")"
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "$tls13" "$h2" "$cert" "$redirect" "$med" "$risk" "$reason" "未深审计" "未知"
    return 0
  fi

  # 只有通过全部硬条件的候选才补 2 次快速样本，避免在注定 SKIP 的目标上浪费几十秒。
  local out i
  for i in 1 2; do
    out="$(curl -sS -o /dev/null --connect-timeout 2 --max-time 4 \
      -w '%{time_appconnect}' "https://${host}/" 2>/dev/null || true)"
    [[ "$out" =~ ^[0-9]+([.][0-9]+)?$ ]] && times+=("$out")
  done
  [ "${#times[@]}" -gt 0 ] && med="$(median_ms "${times[@]}")"

  # CNAME/CDN 深审计只对真正可能进入推荐池的目标执行。
  while IFS= read -r rh; do
    [ -n "$rh" ] && cname_arr+=("$rh")
  done < <(resolve_cnames "$host")
  if [ "${#cname_arr[@]}" -gt 0 ]; then
    local IFS=,
    cnames="${cname_arr[*]}"
  else
    cnames=""
  fi

  crisk="$(cdn_risk_from_text "${host} ${cnames} ${headers}")"
  if [[ "$krisk" == HIGH\|* ]]; then risk="HIGH"; reason="${krisk#HIGH|}"
  elif [[ "$crisk" == HIGH\|* ]]; then risk="HIGH"; reason="${crisk#HIGH|}"
  elif [[ "$krisk" == CAUTION\|* ]]; then risk="CAUTION"; reason="${krisk#CAUTION|}"
  else risk="LOW"; reason="未发现常见共享 CDN 特征"; fi

  # HIGH 已经不会进入推荐池，无需继续消耗 DNS/ASN 查询资源。
  target_asn="未知"
  if [ "$risk" != HIGH ]; then
    target_ip="$(lookup_ipv4 "$host" || true)"
    target_asn="$(asn_for_ipv4 "$target_ip" || true)"
    target_asn="${target_asn:-未知}"
  fi

  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$tls13" "$h2" "$cert" "$redirect" "$med" "$risk" "$reason" "${cnames:-无}" "$target_asn"
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

prepare_reality_selftest(){
  # 自测凭据只生成一次，所有候选复用，避免每个 target 都 fork 多次 sing-box/openssl。
  [ -n "${SELFTEST_PRIVATE:-}" ] && return 0
  local key value keyfile sidfile
  SELFTEST_DIR="/tmp/sb-reality-selftest.$$"
  mkdir -p "$SELFTEST_DIR" || return 1
  chmod 700 "$SELFTEST_DIR"
  TMP_FILES+=("$SELFTEST_DIR")
  keyfile="${SELFTEST_DIR}/keys"; sidfile="${SELFTEST_DIR}/sid"

  local keyerr="${SELFTEST_DIR}/keygen.err" line low resource_err=false rc
  if ! GODEBUG=netdns=go GOMAXPROCS=1 sing-box generate reality-keypair >"$keyfile" 2>"$keyerr"; then
    while IFS= read -r line; do
      low="${line,,}"
      [[ "$low" == *"resource temporarily unavailable"* || "$low" == *"failed to create new os thread"* ]] && { resource_err=true; break; }
    done <"$keyerr"
    if $resource_err; then
      REALITY_SELFTEST_LAST_REASON="生成临时 Reality 密钥时触发 PID/Tasks 资源限制"
      return 75
    fi
    REALITY_SELFTEST_LAST_REASON="无法生成临时 Reality 测试密钥"
    return 1
  fi
  while IFS=: read -r key value; do
    key="${key//[[:space:]]/}"
    value="${value#${value%%[![:space:]]*}}"
    case "$key" in
      PrivateKey) SELFTEST_PRIVATE="$value" ;;
      PublicKey)  SELFTEST_PUBLIC="$value" ;;
    esac
  done <"$keyfile"
  openssl rand -hex 8 >"$sidfile" 2>/dev/null || return 1
  IFS= read -r SELFTEST_SID <"$sidfile" || SELFTEST_SID=""
  if [ -r /proc/sys/kernel/random/uuid ]; then IFS= read -r SELFTEST_UUID </proc/sys/kernel/random/uuid || true; else SELFTEST_UUID="$(rand_uuid 2>/dev/null || true)"; fi
  [ -n "$SELFTEST_PRIVATE" ] && [ -n "$SELFTEST_PUBLIC" ] && [ -n "$SELFTEST_SID" ] && [ -n "$SELFTEST_UUID" ]
}

reality_selftest(){
  # v5.1：单进程 Reality 回环自测。
  # 同一个 sing-box 进程同时承载 VLESS+Reality server inbound 和 mixed client inbound，
  # mixed 流量通过本进程的 VLESS outbound 回到本进程 server，再由 direct 出站。
  # 相比旧版 server/client 两个 Go 进程，可显著降低 systemd TasksMax / cgroup pids 压力。
  # 返回码：0=PASS；1=真实失败；75=因本机资源不足而安全跳过（DEFERRED）。
  local host="$1" headroom mem sp lp conf log code pid
  REALITY_SELFTEST_LAST_REASON=""

  case "${REALITY_SELFTEST_MODE:-auto}" in
    off|0|false)
      REALITY_SELFTEST_LAST_REASON="用户配置关闭本机真握手自测"
      return 75
      ;;
    auto|on|1|true|force) : ;;
    *) REALITY_SELFTEST_MODE="auto" ;;
  esac

  headroom="$(pid_headroom_fast)"
  mem="$(mem_available_kb)"
  # 即使用户指定 on，也保留一个不可突破的硬安全底线；force 才会跳过资源保护。
  if [ "${REALITY_SELFTEST_MODE:-auto}" != force ]; then
    if [[ "$headroom" =~ ^[0-9]+$ ]] && [ "$headroom" -lt 24 ]; then
      REALITY_SELFTEST_LAST_REASON="PID/Tasks 余量仅 ${headroom}，低于单进程自测硬安全底线 24"
      return 75
    fi
    if [[ "$mem" =~ ^[0-9]+$ ]] && [ "$mem" -gt 0 ] && [ "$mem" -lt 65536 ]; then
      REALITY_SELFTEST_LAST_REASON="可用内存仅 $((mem/1024)) MiB，低于单进程自测硬安全底线 64 MiB"
      return 75
    fi
  fi
  if [ "${REALITY_SELFTEST_MODE:-auto}" = auto ]; then
    if [[ "$headroom" =~ ^[0-9]+$ ]] && [ "$headroom" -lt "${REALITY_SELFTEST_MIN_PID_HEADROOM:-96}" ]; then
      REALITY_SELFTEST_LAST_REASON="PID/Tasks 余量仅 ${headroom}，低于 auto 安全阈值 ${REALITY_SELFTEST_MIN_PID_HEADROOM:-96}"
      return 75
    fi
    if [[ "$mem" =~ ^[0-9]+$ ]] && [ "$mem" -gt 0 ] && [ "$mem" -lt "${REALITY_SELFTEST_MIN_MEM_KB:-131072}" ]; then
      REALITY_SELFTEST_LAST_REASON="可用内存仅 $((mem/1024)) MiB，低于 auto 自测安全阈值"
      return 75
    fi
  fi

  local prep_rc=0
  if prepare_reality_selftest; then prep_rc=0; else prep_rc=$?; fi
  if [ "$prep_rc" -eq 75 ]; then return 75; fi
  if [ "$prep_rc" -ne 0 ]; then
    [ -n "${REALITY_SELFTEST_LAST_REASON:-}" ] || REALITY_SELFTEST_LAST_REASON="无法生成临时 Reality 测试凭据"
    return 1
  fi
  rand_port 23000 43000 >/dev/null || { REALITY_SELFTEST_LAST_REASON="无法分配临时 server 端口"; return 1; }; sp="$RANDOM_PORT"
  rand_port 43001 62000 >/dev/null || { REALITY_SELFTEST_LAST_REASON="无法分配临时 SOCKS 端口"; return 1; }; lp="$RANDOM_PORT"
  [ "$sp" != "$lp" ] || lp=$((lp+1))
  conf="${SELFTEST_DIR}/selftest.json"
  log="${SELFTEST_DIR}/selftest.log"

  # host 已经过 validate_sni；其余测试凭据均为受控字符，可安全直接写入 JSON。
  cat >"$conf" <<EOF_SELFTEST
{
  "log":{"level":"error","timestamp":false},
  "inbounds":[
    {
      "type":"vless","tag":"rt-server","listen":"127.0.0.1","listen_port":${sp},
      "users":[{"uuid":"${SELFTEST_UUID}","flow":"xtls-rprx-vision"}],
      "tls":{"enabled":true,"server_name":"${host}","reality":{"enabled":true,"handshake":{"server":"${host}","server_port":443},"private_key":"${SELFTEST_PRIVATE}","short_id":["${SELFTEST_SID}"]}}
    },
    {"type":"mixed","tag":"rt-client","listen":"127.0.0.1","listen_port":${lp}}
  ],
  "outbounds":[
    {"type":"direct","tag":"rt-direct"},
    {
      "type":"vless","tag":"rt-proxy","server":"127.0.0.1","server_port":${sp},
      "uuid":"${SELFTEST_UUID}","flow":"xtls-rprx-vision",
      "tls":{"enabled":true,"server_name":"${host}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${SELFTEST_PUBLIC}","short_id":"${SELFTEST_SID}"}}
    }
  ],
  "route":{"rules":[
    {"inbound":["rt-client"],"action":"route","outbound":"rt-proxy"},
    {"inbound":["rt-server"],"action":"route","outbound":"rt-direct"}
  ],"final":"rt-direct"}
}
EOF_SELFTEST

  # 配置结构固定且只替换已验证的 host；直接 run 即可。避免每个候选额外启动一次 Go 进程做 check。
  # GODEBUG=netdns=go 避免 cgo resolver 额外线程；GOMAXPROCS=1 限制 Go 调度线程峰值。
  GODEBUG=netdns=go GOMAXPROCS=1 sing-box run -c "$conf" >"$log" 2>&1 &
  pid=$!
  SELFTEST_PID="$pid"
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    SELFTEST_PID=""
    local line low resource_err=false
    while IFS= read -r line; do low="${line,,}"; [[ "$low" == *"resource temporarily unavailable"* || "$low" == *"failed to create new os thread"* ]] && { resource_err=true; break; }; done <"$log"
    if $resource_err; then REALITY_SELFTEST_LAST_REASON="临时 sing-box 受 PID/Tasks 限制无法创建线程"; return 75; fi
    REALITY_SELFTEST_LAST_REASON="临时 sing-box 未能启动"
    return 1
  fi

  # 不再 fork /bin/sleep。让同一个 curl 进程在本地端口尚未就绪时重试 connection-refused。
  # 使用待测试 target 本身作为 HTTPS 探针，避免再依赖 Apple/Debian 等第三方测试 URL。
  local code_file="${SELFTEST_DIR}/http.code"
  : >"$code_file"
  curl -sS --retry 3 --retry-connrefused --retry-delay 0 --retry-max-time 8 \
    --proxy "socks5h://127.0.0.1:${lp}" --connect-timeout 2 --max-time 8 \
    -o /dev/null -w '%{http_code}' "https://${host}/" >"$code_file" 2>/dev/null || true
  IFS= read -r code <"$code_file" || code=""

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  SELFTEST_PID=""

  if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then
    REALITY_SELFTEST_LAST_REASON="真实回环握手与 HTTPS 代理成功"
    return 0
  fi

  # 进程可能在 kill -0 初检后才因线程/PID不足退出；失败时再次检查日志，
  # 资源型失败必须 DEFERRED，而不是把每个候选依次误判为 Reality FAIL。
  local fail_line fail_low fail_resource=false
  while IFS= read -r fail_line; do
    fail_low="${fail_line,,}"
    [[ "$fail_low" == *"resource temporarily unavailable"* || "$fail_low" == *"failed to create new os thread"* || "$fail_low" == *"newosproc"* ]] && { fail_resource=true; break; }
  done <"$log"
  if $fail_resource; then
    REALITY_SELFTEST_LAST_REASON="临时 sing-box 在启动/运行阶段触发 PID/Tasks 资源限制"
    return 75
  fi

  REALITY_SELFTEST_LAST_REASON="回环代理未取得有效 HTTP 响应（HTTP ${code:-000}）"
  return 1
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
  local key val unit
  [ -r /proc/meminfo ] || { printf '0'; return 0; }
  while read -r key val unit; do
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

audit_reality_one(){
  local host="$1" outfile="$2"
  local data tls h2 cert redir med risk reason cnames tasn self
  data="$(probe_tls_http "$host" || true)"
  IFS='|' read -r tls h2 cert redir med risk reason cnames tasn <<<"$data"
  [ -n "$tls" ] || { tls=NO; h2=NO; cert=NO; redir=NO; med=999999; risk=HIGH; reason="探测失败"; cnames=无; tasn=未知; }
  self="SKIP"
  if [ "$tls" = YES ] && [ "$h2" = YES ] && [ "$cert" = YES ] && [ "$redir" = YES ] && [ "$risk" != HIGH ]; then self="PENDING"; fi
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "$host" "$tls" "$h2" "$cert" "$redir" "$med" "$risk" "$self" "$reason" "$cnames" "$tasn" >"$outfile"
}

emit_audit_result(){
  local outfile="$1" tmp="$2" fallback_host="$3"
  local line host tls h2 cert redir med risk self reason cnames tasn
  if [ -s "$outfile" ]; then
    IFS= read -r line <"$outfile" || line=""
  else
    line="${fallback_host}|NO|NO|NO|NO|999999|HIGH|SKIP|探测进程异常退出|无|未知"
  fi
  IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn <<<"$line"
  [ -n "$host" ] || host="$fallback_host"
  local med_display="${med:-999999}"
  if [[ "$med_display" =~ ^[0-9]+$ ]] && [ "$med_display" -lt 999999 ]; then med_display="${med_display}ms"; else med_display="-"; fi
  print_target_row "$host" "${tls:-NO}" "${h2:-NO}" "${cert:-NO}" "${redir:-NO}" "$med_display" "${risk:-HIGH}" "${tasn:-未知}" "${self:-SKIP}"
  printf '%s\n' "$line" >>"$tmp"
}

audit_reality_candidates(){
  # 第一阶段做静态审计；AUTO 自适应并发。
  # v5.0.3：串行模式逐个实时打印；并发模式每批完成立即打印，不再“全部跑完后才显示”。
  # 每个外部网络命令自身都有超时，坏目标只会被 SKIP，不会拖死整个安装流程。
  local tmp="$1"; shift
  local work idx=0 max_jobs host outfile pid total="$#"
  local -a batch_pids=() batch_files=() batch_hosts=()
  declare -A seen=()

  max_jobs="$(resolve_reality_audit_jobs)"
  info "Reality 静态审计并发：${max_jobs}（${REALITY_AUDIT_JOBS:-auto}；低 PID/内存环境会自动降级）"
  [ "$max_jobs" -eq 1 ] && info "串行模式会逐个输出结果；单个异常目标有硬超时，不会无限等待。"
  work="$(mktemp -d /tmp/reality-static.XXXXXX)"; TMP_FILES+=("$work")

  while IFS='|' read -r host _; do [ -n "$host" ] && seen["$host"]=1; done <"$tmp"

  flush_batch(){
    local j
    for j in "${!batch_pids[@]}"; do wait "${batch_pids[$j]}" 2>/dev/null || true; done
    for j in "${!batch_files[@]}"; do emit_audit_result "${batch_files[$j]}" "$tmp" "${batch_hosts[$j]}"; done
    batch_pids=(); batch_files=(); batch_hosts=()
  }

  for host in "$@"; do
    host="$(normalize_sni "$host")"
    validate_sni "$host" || { warn "跳过无效候选域名：$host"; continue; }
    [ -n "${seen[$host]+x}" ] && continue
    seen["$host"]=1
    idx=$((idx+1))
    printf -v outfile '%s/%05d' "$work" "$idx"

    if [ "$max_jobs" -eq 1 ]; then
      info "[${idx}/${total}] 审计：${host}"
      audit_reality_one "$host" "$outfile" || true
      emit_audit_result "$outfile" "$tmp" "$host"
      continue
    fi

    ( audit_reality_one "$host" "$outfile" ) &
    pid=$!
    batch_pids+=("$pid"); batch_files+=("$outfile"); batch_hosts+=("$host")
    if [ "${#batch_pids[@]}" -ge "$max_jobs" ]; then
      info "等待当前审计批次完成（${#batch_pids[@]} 个目标）..."
      flush_batch
    fi
  done
  [ "${#batch_pids[@]}" -gt 0 ] && flush_batch
  unset -f flush_batch 2>/dev/null || true
}
next_reality_pending(){
  # 选择当前尚未真握手测试的最高评分 PENDING。真握手仍严格串行。
  local tmp="$1" vps_asn="$2"
  local host tls h2 cert redir med risk self reason cnames tasn score best_score=-1 best_med=999999999 best_host=""
  NEXT_PENDING_HOST=""
  while IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn; do
    [ -n "$host" ] || continue
    [ "$tls" = YES ] && [ "$h2" = YES ] && [ "$cert" = YES ] && [ "$redir" = YES ] || continue
    [ "$risk" != HIGH ] && [ "$self" = PENDING ] || continue
    score="$(candidate_score "$host" "$risk" "$tasn" "$med" "$vps_asn")"
    [[ "$med" =~ ^[0-9]+$ ]] || med=999999
    if [ "$score" -gt "$best_score" ] || { [ "$score" -eq "$best_score" ] && [ "$med" -lt "$best_med" ]; }; then
      best_score="$score"; best_med="$med"; best_host="$host"
    fi
  done <"$tmp"
  NEXT_PENDING_HOST="$best_host"
  [ -n "$best_host" ]
}

set_reality_self_status(){
  # 纯 Bash 原子重写，避免每次自测后再 fork awk。
  local tmp="$1" host="$2" status="$3" t line
  local h tls h2 cert redir med risk self reason cnames tasn
  t="${tmp}.rewrite.$$"
  : >"$t"
  while IFS= read -r line || [ -n "$line" ]; do
    IFS='|' read -r h tls h2 cert redir med risk self reason cnames tasn <<<"$line"
    if [ "$h" = "$host" ]; then self="$status"; line="${h}|${tls}|${h2}|${cert}|${redir}|${med}|${risk}|${self}|${reason}|${cnames}|${tasn}"; fi
    printf '%s\n' "$line" >>"$t"
  done <"$tmp"
  mv "$t" "$tmp"
}

run_reality_selftests(){
  # 严格串行；每次只运行一个受 GOMAXPROCS=1 限制的 sing-box 自测进程。
  # 若检测到本机 PID/内存资源不足，则把最佳静态候选标为 DEFERRED 并停止，避免 fork 风暴。
  local tmp="$1" vps_asn="$2" host rc headroom mem
  headroom="$(pid_headroom_fast)"; mem="$(mem_available_kb)"
  info "Reality 真握手自测：单进程模式（GOMAXPROCS=1；PID/Tasks 余量=${headroom}；可用内存约 $((mem/1024)) MiB）"

  while next_reality_pending "$tmp" "$vps_asn"; do
    host="$NEXT_PENDING_HOST"
    [ -n "$host" ] || break
    printf '  [Reality] %-28s ' "$host"
    if reality_selftest "$host"; then rc=0; else rc=$?; fi
    case "$rc" in
      0)
        echo 'PASS'
        set_reality_self_status "$tmp" "$host" PASS
        return 0
        ;;
      75)
        echo 'DEFERRED'
        set_reality_self_status "$tmp" "$host" DEFERRED
        warn "已安全跳过真实握手：${REALITY_SELFTEST_LAST_REASON:-资源不足}。将使用严格静态审计最佳候选，不再继续启动自测进程。"
        return 75
        ;;
      *)
        echo 'FAIL'
        [ -n "${REALITY_SELFTEST_LAST_REASON:-}" ] && info "自测说明：${REALITY_SELFTEST_LAST_REASON}"
        set_reality_self_status "$tmp" "$host" FAIL
        ;;
    esac
  done
  return 1
}

pick_reality_best(){
  # PASS 永远优先于 DEFERRED；同一验证状态内按 0..100 综合分排序。
  local tmp="$1" vps_asn="$2" wanted
  local host tls h2 cert redir med risk self reason cnames tasn score src
  local best best_med best_score best_status best_risk best_source best_asn same
  for wanted in PASS DEFERRED; do
    best=""; best_med=999999; best_score=-1; best_status=""; best_risk=""; best_source=""; best_asn="未知"; same=0
    while IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn; do
      [ "$tls" = YES ] && [ "$h2" = YES ] && [ "$cert" = YES ] && [ "$redir" = YES ] || continue
      [ "$risk" != HIGH ] && [ "$self" = "$wanted" ] || continue
      score="$(candidate_score "$host" "$risk" "$tasn" "$med" "$vps_asn")"
      src="$(candidate_source "$host")"
      [[ "$med" =~ ^[0-9]+$ ]] || med=999999
      if [ "$score" -gt "$best_score" ] || { [ "$score" -eq "$best_score" ] && [ "$med" -lt "$best_med" ]; }; then
        best="$host"; best_med="$med"; best_score="$score"; best_status="$self"; best_risk="$risk"; best_source="$src"; best_asn="$tasn"
        same=0; [ "$vps_asn" != 未知 ] && [ "$tasn" = "$vps_asn" ] && same=1
      fi
    done <"$tmp"
    if [ -n "$best" ]; then
      printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$best" "$best_med" "$same" "$best_risk" "$best_status" "$best_score" "$best_source" "$best_asn"
      return 0
    fi
  done
  return 1
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
  local forced="${SINGBOX_REALITY_SNI:-}" allow_risky="${SINGBOX_REALITY_ALLOW_RISKY:-0}"
  local host data tls h2 cert redir med risk reason cnames tasn self best="" best_med=999999 self_rc=0 best_status=""
  local tmp vps4 vps_asn="未知" vps_prefix="" best_same=-1 best_risk="LOW" best_score="" best_source=""
  local extra_raw="${SINGBOX_REALITY_EXTRA_SNI:-}"
  local -a primary_candidates=() base_extended=() extra_candidates=() dynamic_candidates=()
  refresh_reality_gfwlist || true
  if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ]; then
    primary_candidates=("${REALITY_CANDIDATES_CN_PRIMARY[@]}")
    base_extended=("${REALITY_CANDIDATES_CN_EXTENDED[@]}")
  else
    primary_candidates=("${REALITY_CANDIDATES_GLOBAL_PRIMARY[@]}")
    base_extended=("${REALITY_CANDIDATES_GLOBAL_EXTENDED[@]}")
  fi
  local c
  for c in "${primary_candidates[@]}"; do candidate_set_meta "$c" public-core 0 "" "" "" 0; done
  for c in "${base_extended[@]}"; do candidate_set_meta "$c" public-extended 0 "" "" "" 0; done

  # 自定义候选属于“优先候选”，第一轮就参与完整审计和评分。
  # 最适合用于加入你自己确认过的同 ASN/邻近网络正常 HTTPS 站点。
  # 例：SINGBOX_REALITY_EXTRA_SNI='a.example.com,b.example.com'
  if [ -n "$extra_raw" ]; then
    extra_raw="${extra_raw//,/ }"
    read -r -a extra_candidates <<<"$extra_raw"
    for c in "${extra_candidates[@]}"; do c="$(normalize_sni "$c")"; candidate_set_meta "$c" custom 0 "" "" "" 0; done
    primary_candidates+=("${extra_candidates[@]}")
  fi
  tmp="$(mktemp /tmp/reality-audit.XXXXXX)"; TMP_FILES+=("$tmp")
  vps4="$(get_public_ipv4 || true)"
  if [ -n "$vps4" ]; then
    local oinfo
    oinfo="$(origin_info_for_ipv4 "$vps4" || true)"
    if [ -n "$oinfo" ]; then vps_asn="${oinfo%%|*}"; vps_prefix="${oinfo#*|}"; fi
  fi
  vps_asn="${vps_asn:-未知}"
  REALITY_VPS_ASN="$vps_asn"; REALITY_VPS_PREFIX="$vps_prefix"

  if [ -n "$forced" ]; then
    host="$(normalize_sni "$forced")"; validate_sni "$host" || die "SINGBOX_REALITY_SNI 格式无效：$host"
    info "审计指定 Reality target：$host"
    data="$(probe_tls_http "$host")"
    IFS='|' read -r tls h2 cert redir med risk reason cnames tasn <<<"$data"
    self="FAIL"
    if reality_selftest "$host"; then self_rc=0; else self_rc=$?; fi
    case "$self_rc" in 0) self="PASS";; 75) self="DEFERRED";; *) self="FAIL";; esac
    echo "TLS1.3=$tls H2=$h2 Cert=$cert Redirect=$redir Median=${med}ms Risk=$risk ASN=${tasn}/${vps_asn} Reality=$self"
    echo "风险说明：$reason"
    if [ "$tls" != YES ] || [ "$h2" != YES ] || [ "$cert" != YES ] || [ "$redir" != YES ]; then
      [ "${SINGBOX_REALITY_ALLOW_INCOMPATIBLE:-0}" = 1 ] || die "指定 target 未满足 TLS1.3/H2/有效证书/不跨域跳转的完整静态条件。"
      warn "已通过 SINGBOX_REALITY_ALLOW_INCOMPATIBLE=1 强制放宽静态条件。"
    fi
    if [ "$risk" = HIGH ] && [ "$allow_risky" != 1 ]; then die "指定 target 被判定为高风险；如已充分了解风险，可设置 SINGBOX_REALITY_ALLOW_RISKY=1 强制使用。"; fi
    if [ "$self" = DEFERRED ]; then
      warn "真实 Reality 自测因本机资源限制安全跳过：${REALITY_SELFTEST_LAST_REASON:-未知原因}。静态条件已通过。"
    elif [ "$self" != PASS ]; then
      warn "真实 Reality 自测未通过。可能是 target 不兼容，也可能是当前网络环境异常。"
    fi
    REALITY_SNI="$host"; REALITY_SELECTED_SOURCE="forced"; REALITY_SELECTED_ASN="$tasn"; REALITY_SELECTED_SCORE="$(candidate_score "$host" "$risk" "$tasn" "$med" "$vps_asn")"; REALITY_SELECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; REALITY_SELECTED_AGE_DAYS=0; REALITY_SELECTED_UMBRELLA_RANK=0; return 0
  fi

  # 被动发现的同前缀/同 ASN 候选在第一轮加入；失败/限额时自动退回静态池。
  local dynamic_file
  dynamic_file="$(mktemp /tmp/reality-dynamic.XXXXXX)"; TMP_FILES+=("$dynamic_file")
  discover_reality_candidates "$vps_asn" "$vps_prefix" "$dynamic_file" || true
  while IFS= read -r c; do [ -n "$c" ] && dynamic_candidates+=("$c"); done <"$dynamic_file"
  [ "${#dynamic_candidates[@]}" -gt 0 ] && primary_candidates=("${dynamic_candidates[@]}" "${primary_candidates[@]}")

  info "开始 Reality target 安全审计；高风险共享 CDN 不进入自动推荐。"
  echo
  echo "VPS ASN：$vps_asn；BGP 前缀：${vps_prefix:-未知}（动态发现仅读取公开被动数据，不主动扫描）"
  echo "客户端画像：${REALITY_CLIENT_PROFILE:-cn}；第一轮核心/优先候选（${#primary_candidates[@]} 个）"
  if [ "${#dynamic_candidates[@]}" -gt 0 ]; then
    echo "动态发现：${#dynamic_candidates[@]} 个成熟 HTTPS 候选（同前缀优先，其次同 ASN）。"
  fi
  if [ "${#extra_candidates[@]}" -gt 0 ]; then
    echo "自定义优先候选：${#extra_candidates[@]} 个。"
  fi
  print_target_row "TARGET" "TLS13" "H2" "CERT" "RT-DIR" "MEDIAN" "RISK" "ASN" "REALITY"
  print_target_row "-------------------------" "------" "----" "------" "--------" "--------" "---------" "----------" "-------"

  audit_reality_candidates "$tmp" "${primary_candidates[@]}"
  run_reality_selftests "$tmp" "$vps_asn" || true

  local picked=""
  local -a extended_candidates=("${base_extended[@]}")
  picked="$(pick_reality_best "$tmp" "$vps_asn" || true)"

  # 主候选没有严格命中时，自动进入更大的扩展池，而不是立即要求手工输入。
  if [ -z "$picked" ]; then
    echo
    warn "核心/优先候选没有严格命中，自动启动第二轮扩展审计。"
    echo "第二轮：扩展候选池（内置 ${#base_extended[@]} 个）"

    print_target_row "TARGET" "TLS13" "H2" "CERT" "RT-DIR" "MEDIAN" "RISK" "ASN" "REALITY"
    print_target_row "-------------------------" "------" "----" "------" "--------" "--------" "---------" "----------" "-------"
    audit_reality_candidates "$tmp" "${extended_candidates[@]}"
    run_reality_selftests "$tmp" "$vps_asn" || true
    picked="$(pick_reality_best "$tmp" "$vps_asn" || true)"
  fi

  if [ -n "$picked" ]; then
    IFS='|' read -r best best_med best_same best_risk best_status best_score best_source REALITY_SELECTED_ASN <<<"$picked"
    REALITY_SELECTED_AGE_DAYS="${REALITY_CANDIDATE_AGE[$best]:-0}"
    REALITY_SELECTED_UMBRELLA_RANK="${REALITY_CANDIDATE_RANK[$best]:-0}"
  fi

  echo
  if [ -n "$best" ]; then
    local verify_text="真实 Reality 自测通过"
    [ "${best_status:-PASS}" = DEFERRED ] && verify_text="真实自测因资源限制已安全延后；严格静态审计通过"
    if [ "$best_same" -eq 1 ]; then
      ok "自动推荐：$best（评分=${best_score}/100；来源=${best_source}；风险=$best_risk；${verify_text}；同 ASN；TLS≈${best_med}ms）"
    else
      ok "自动推荐：$best（评分=${best_score}/100；来源=${best_source}；风险=$best_risk；${verify_text}；TLS≈${best_med}ms）"
    fi
  else
    warn "核心/优先候选 + 扩展候选均没有目标满足全部保守条件，将要求手动输入。"
  fi
  echo "说明：硬条件先过滤；PASS 永远优先于 DEFERRED。其后按 100 分模型排序：LOW 风险、同 ASN、被动同前缀/同 ASN 来源、域名年龄与 TLS 延迟。动态发现不主动扫描。"
  echo
  echo "1) 使用自动推荐：${best:-无}"
  echo "2) 手动输入 target 并立即审计"
  echo "3) 查看候选详细风险说明"
  local choice
  read -r -p "请选择 [默认 1]: " choice
  case "${choice:-1}" in
    1)
      [ -n "$best" ] || { choice=2; }
      ;;
    3)
      echo
      while IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn; do
        echo "- $host"
        echo "  风险：$risk / $reason"
        echo "  CNAME：$cnames"
        local dscore dsource
        dscore="$(candidate_score "$host" "$risk" "$tasn" "$med" "$vps_asn")"; dsource="$(candidate_source "$host")"
        echo "  ASN：$tasn（VPS=$vps_asn）"
        echo "  来源：$dsource / 评分：${dscore}/100"
        echo "  TLS1.3=$tls, H2=$h2, Cert=$cert, RedirectSameHost=$redir, Median=${med}ms, Reality=$self"
      done <"$tmp"
      echo
      read -r -p "输入要使用的 target（留空使用自动推荐）: " host
      if [ -z "$host" ] && [ -n "$best" ]; then REALITY_SNI="$best"; REALITY_SELECTED_SCORE="$best_score"; REALITY_SELECTED_SOURCE="$best_source"; REALITY_SELECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; return 0; fi
      choice=2
      ;;
  esac
  if [ "${choice:-1}" = 1 ] && [ -n "$best" ]; then REALITY_SNI="$best"; REALITY_SELECTED_SCORE="$best_score"; REALITY_SELECTED_SOURCE="$best_source"; REALITY_SELECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; return 0; fi

  while true; do
    [ -n "${host:-}" ] || read -r -p "请输入 Reality target 域名: " host
    host="$(normalize_sni "$host")"
    validate_sni "$host" || { warn "域名格式不正确。"; host=""; continue; }
    data="$(probe_tls_http "$host")"
    IFS='|' read -r tls h2 cert redir med risk reason cnames tasn <<<"$data"
    self="FAIL"
    if reality_selftest "$host"; then self_rc=0; else self_rc=$?; fi
    case "$self_rc" in 0) self="PASS";; 75) self="DEFERRED";; *) self="FAIL";; esac
    echo "审计结果：TLS1.3=$tls H2=$h2 Cert=$cert RedirectSameHost=$redir Median=${med}ms Risk=$risk ASN=${tasn}/${vps_asn} Reality=$self"
    echo "风险说明：$reason"
    echo "CNAME：$cnames"
    if [ "$tls" != YES ] || [ "$h2" != YES ] || [ "$cert" != YES ] || [ "$redir" != YES ]; then
      warn "未同时满足 TLS1.3 + H2 + 有效证书 + 不跨域跳转，不建议使用。"
      local compat_confirm
      read -r -p "如仍坚持使用请输入大写 FORCE；其他输入返回重选: " compat_confirm
      [ "$compat_confirm" = FORCE ] || { host=""; continue; }
    fi
    if [ "$risk" = HIGH ]; then
      warn "该 target 疑似大型共享 CDN/高风险目标。未认证 REALITY 流量可能被转发到它，存在被扫描后消耗 VPS 流量的风险。"
      local confirm
      read -r -p "如坚持使用，请输入大写 RISK；其他输入返回重选: " confirm
      [ "$confirm" = RISK ] || { host=""; continue; }
    fi
    if [ "$self" = DEFERRED ]; then
      warn "真实 Reality 自测因本机资源限制安全跳过：${REALITY_SELFTEST_LAST_REASON:-未知原因}。严格静态条件已通过。"
    elif [ "$self" != PASS ]; then
      warn "真实 Reality 自测未通过。"
      local confirm2
      read -r -p "仍然使用？输入大写 FORCE 继续，其他输入返回重选: " confirm2
      [ "$confirm2" = FORCE ] || { host=""; continue; }
    fi
    REALITY_SNI="$host"
    REALITY_SELECTED_SOURCE="manual"
    REALITY_SELECTED_ASN="$tasn"
    REALITY_SELECTED_SCORE="$(candidate_score "$host" "$risk" "$tasn" "$med" "$vps_asn")"
    REALITY_SELECTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    REALITY_SELECTED_AGE_DAYS=0
    REALITY_SELECTED_UMBRELLA_RANK=0
    return 0
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
    local v6="$(get_public_ipv6 || true)"
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
append_inbound(){
  local file="$1" obj="$2" tmp
  tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; TMP_FILES+=("$tmp")
  jq --argjson x "$obj" '.inbounds += [$x]' "$file" >"$tmp" && mv "$tmp" "$file"
}

build_config(){
  local out="$1" obj tmp loglevel="info"
  $LOW_RESOURCE_MODE && loglevel="warn"
  cat >"$out" <<JSON
{
  "log":{"level":"${loglevel}","timestamp":true},
  "ntp":{"enabled":true,"server":"time.apple.com","server_port":123,"interval":"30m"},
  "inbounds":[],
  "outbounds":[{"type":"direct","tag":"direct-out"}],
  "route":{"rules":[],"final":"direct-out"}
}
JSON

  if $ENABLE_SS; then
    obj="$(jq -cn --arg m "$SS_METHOD" --arg pw "$PSK_SS" --argjson p "$PORT_SS" '{type:"shadowsocks",tag:"ss-in",listen:"::",listen_port:$p,method:$m,password:$pw}')"
    append_inbound "$out" "$obj"
  fi
  if $ENABLE_HY2; then
    obj="$(jq -cn --arg pw "$PSK_HY2" --arg bbr "$HY2_BBR_PROFILE" --arg obfs "$HY2_OBFS" --arg opw "$HY2_OBFS_PASSWORD" --argjson p "$PORT_HY2" '
      {type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$p,users:[{name:"user",password:$pw}],bbr_profile:$bbr,tls:{enabled:true,alpn:["h3"],certificate_path:"/etc/sing-box/certs/fullchain.pem",key_path:"/etc/sing-box/certs/privkey.pem"}}
      | if $obfs!="none" then .obfs={type:$obfs,password:$opw} else . end')"
    append_inbound "$out" "$obj"
  fi
  if $ENABLE_TUIC; then
    obj="$(jq -cn --arg u "$UUID_TUIC" --arg pw "$PSK_TUIC" --argjson p "$PORT_TUIC" '{type:"tuic",tag:"tuic-in",listen:"::",listen_port:$p,users:[{name:"user",uuid:$u,password:$pw}],congestion_control:"bbr",zero_rtt_handshake:false,tls:{enabled:true,alpn:["h3"],certificate_path:"/etc/sing-box/certs/fullchain.pem",key_path:"/etc/sing-box/certs/privkey.pem"}}')"
    append_inbound "$out" "$obj"
  fi
  if $ENABLE_REALITY; then
    obj="$(jq -cn --arg h "$REALITY_SNI" --arg u "$UUID_REALITY" --arg pk "$REALITY_PRIVATE" --arg sid "$REALITY_SID" --argjson p "$PORT_REALITY" '{type:"vless",tag:"vless-reality-in",listen:"::",listen_port:$p,users:[{uuid:$u,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$h,reality:{enabled:true,handshake:{server:$h,server_port:443},private_key:$pk,short_id:[$sid]}}}')"
    append_inbound "$out" "$obj"
  fi
  if $ENABLE_ANYTLS; then
    obj="$(jq -cn --arg h "$REALITY_SNI" --arg user "$ANYTLS_USER" --arg pw "$ANYTLS_PSK" --arg pk "$REALITY_PRIVATE" --arg sid "$REALITY_SID" --argjson p "$PORT_ANYTLS" '{type:"anytls",tag:"anytls-reality-in",listen:"::",listen_port:$p,users:[{name:$user,password:$pw}],tls:{enabled:true,server_name:$h,reality:{enabled:true,handshake:{server:$h,server_port:443},private_key:$pk,short_id:[$sid]}}}')"
    append_inbound "$out" "$obj"
  fi

  # SS 独立出口策略：使用 resolve action 实现 DNS 策略，不改变其他协议。
  if $ENABLE_SS && [ "$SS_IP_MODE" != auto ]; then
    tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; TMP_FILES+=("$tmp")
    jq --arg mode "$SS_IP_MODE" '
      .dns={servers:[{type:"local",tag:"ss-local-dns",prefer_go:true}]}
      | .route.rules += (if $mode=="ipv6_only" then [{inbound:["ss-in"],ip_version:4,action:"reject"}] else [] end)
      | .route.rules += [{inbound:["ss-in"],action:"resolve",server:"ss-local-dns",strategy:$mode}]
    ' "$out" >"$tmp" && mv "$tmp" "$out"
  fi
}

LAST_CONFIG_BACKUP=""
install_config_atomic(){
  local candidate="$1" backup=""
  sing-box check -c "$candidate" || return 1
  mkdir -p "$CONFIG_DIR" "$BACKUP_DIR"; chmod 700 "$CONFIG_DIR" "$BACKUP_DIR"
  if [ -f "$CONFIG_PATH" ]; then backup="${BACKUP_DIR}/config.$(date +%Y%m%d_%H%M%S).json"; cp -a "$CONFIG_PATH" "$backup"; fi
  install -m 600 "$candidate" "$CONFIG_PATH"
  if ! sing-box check -c "$CONFIG_PATH"; then
    [ -n "$backup" ] && cp -a "$backup" "$CONFIG_PATH"
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
REALITY_SELECTED_SCORE=$(printf %q "${REALITY_SELECTED_SCORE:-}")
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
  local host uri_host suffix="" info64
  host="$(get_connection_host)" || die "无法获得公网连接地址，请设置 SINGBOX_CONNECTION_HOST 或重新安装时手动填写。"
  uri_host="$(format_uri_host "$host")"
  [ -n "${NODE_NAME:-}" ] && suffix="-$(url_encode "$NODE_NAME")"
  : >"$URI_PATH"
  if $ENABLE_SS; then
    if [ "$SS_METHOD" = "2022-blake3-aes-128-gcm" ]; then
      info64="${SS_METHOD}:${PSK_SS}"
      echo "ss://$(printf '%s' "$info64" | base64 | tr -d '\r\n')@${uri_host}:${PORT_SS}#ss${suffix}" >>"$URI_PATH"
    else
      info64="$(printf '%s' "${SS_METHOD}:${PSK_SS}" | base64 | tr -d '\r\n')"
      echo "ss://${info64}@${uri_host}:${PORT_SS}#ss${suffix}" >>"$URI_PATH"
    fi
  fi
  if $ENABLE_HY2; then
    local hyq="sni=${QUIC_TLS_SERVER_NAME}&alpn=h3&insecure=$([ "${QUIC_TLS_INSECURE:-true}" = true ] && echo 1 || echo 0)"
    if [ "${HY2_OBFS:-none}" != none ]; then hyq="${hyq}&obfs=${HY2_OBFS}&obfs-password=$(url_encode "$HY2_OBFS_PASSWORD")"; fi
    echo "hy2://$(url_encode "$PSK_HY2")@${uri_host}:${PORT_HY2}/?${hyq}#hy2${suffix}" >>"$URI_PATH"
  fi
  if $ENABLE_TUIC; then echo "tuic://${UUID_TUIC}:$(url_encode "$PSK_TUIC")@${uri_host}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=${QUIC_TLS_SERVER_NAME}&insecure=$([ "${QUIC_TLS_INSECURE:-true}" = true ] && echo 1 || echo 0)#tuic${suffix}" >>"$URI_PATH"; fi
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
  local host vname sname hname tname qhost qname qpw qdp
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
info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok(){ echo -e "\033[1;32m[ OK ]\033[0m $*"; }
die(){ echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "请使用 root 运行。"

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
  debian|ubuntu) export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y curl ca-certificates openssl jq coreutils dnsutils iproute2 ;;
  *) if command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates openssl jq coreutils bind-utils iproute; elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates openssl jq coreutils bind-utils iproute; fi ;;
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
RELAY_CN_BAD='(^|\.)(google\.com|gstatic\.com|googleapis\.com|googleusercontent\.com|youtube\.com|ytimg\.com|wikipedia\.org|wikimedia\.org|facebook\.com|fbcdn\.net|instagram\.com|whatsapp\.com|twitter\.com|x\.com|t\.co|telegram\.org|t\.me|signal\.org|torproject\.org|reddit\.com|discord\.com|medium\.com)$'
declare -A RELAY_SRC=() RELAY_AGE=() RELAY_RANK=()
relay_trim(){ local v="$1"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"; printf '%s' "$v"; }
relay_first_line(){ local x; while IFS= read -r x; do [ -n "$x" ] && { printf '%s' "$x"; return 0; }; done; return 1; }
relay_mem_kb(){ local k v _; while read -r k v _; do [ "$k" = MemAvailable: ] && { printf '%s' "${v:-0}"; return 0; }; done </proc/meminfo 2>/dev/null; printf '0'; }
relay_public_ipv4(){ curl -4 -fsS --connect-timeout 3 --max-time 7 https://api.ipify.org 2>/dev/null || true; }
relay_origin_info(){
  local ip="$1" a b c d q raw ans n pfx
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  command -v dig >/dev/null 2>&1 || return 1
  IFS='.' read -r a b c d <<<"$ip"; q="${d}.${c}.${b}.${a}.origin.asn.cymru.com"
  raw="$(dig +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(relay_first_line <<<"$raw" || true)"
  [ -n "$ans" ] || { raw="$(dig @1.1.1.1 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(relay_first_line <<<"$raw" || true)"; }
  ans="${ans//\"/}"; IFS='|' read -r n _ pfx _ <<<"$ans"; n="$(relay_trim "$n")"; pfx="$(relay_trim "$pfx")"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1; [[ "$pfx" == */* ]] || pfx=""; printf 'AS%s|%s' "$n" "$pfx"
}
relay_lookup4(){ local raw l; raw="$(dig +time=1 +tries=1 +short A "$1" 2>/dev/null || true)"; while IFS= read -r l; do [[ "$l" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$l"; return 0; }; done <<<"$raw"; return 1; }
relay_target_asn(){ local ip info; ip="$(relay_lookup4 "$1" || true)"; [ -n "$ip" ] || { printf '未知'; return 0; }; info="$(relay_origin_info "$ip" || true)"; [ -n "$info" ] && printf '%s' "${info%%|*}" || printf '未知'; }
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
relay_gfw_bad(){ local h="${1,,}" d; [ -n "$RELAY_GFW" ] && [ -s "$RELAY_GFW" ] || return 1; while IFS= read -r d || [ -n "$d" ]; do [ -n "$d" ] || continue; if [ "$h" = "$d" ] || [[ "$h" == *."$d" ]]; then return 0; fi; done <"$RELAY_GFW"; return 1; }
relay_cn_ok(){ local h="${1,,}"; [ "$RELAY_PROFILE" != cn ] && return 0; [[ "$h" =~ $RELAY_CN_BAD ]] && return 1; relay_gfw_bad "$h" && return 1; return 0; }
relay_seconds_to_ms(){
  local x="$1" w f
  [[ "$x" =~ ^[0-9]+([.][0-9]+)?$ ]] || return 1
  w="${x%%.*}"; if [[ "$x" == *.* ]]; then f="${x#*.}"; else f=""; fi; f="${f}000"
  printf '%d' $((10#$w*1000 + 10#${f:0:3}))
}
relay_probe_sni(){
  # 输出：ms|current_asn。只有全部硬条件通过才返回成功。
  local h="$1" raw line headers="" tls lower code redir t rest rh cn txt ms tasn
  relay_validate_sni "$h" || return 1; relay_cn_ok "$h" || return 1
  tls="$(timeout 5 openssl s_client -connect "$h:443" -servername "$h" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
  lower="${tls,,}"
  [[ "$tls" == *TLSv1.3* || "$tls" == *TLS_AES_* ]] || return 1
  [[ "$lower" == *"alpn protocol: h2"* || "$lower" == *"alpn: h2"* ]] || return 1
  raw="$(curl -sS -D - -o /dev/null --connect-timeout 3 --max-time 7 -w $'\\n__M__\\t%{http_code}\\t%{redirect_url}\\t%{time_appconnect}\\n' "https://$h/" 2>/dev/null || true)"
  code=""; redir=""; t=""
  while IFS= read -r line; do
    line="${line%$'\\r'}"
    if [[ "$line" == __M__$'\\t'* ]]; then IFS=$'\\t' read -r _ code redir t <<<"$line"; else headers+="$line"$'\\n'; fi
  done <<<"$raw"
  [[ "$code" =~ ^[1-5][0-9][0-9]$ ]] || return 1
  if [[ -n "$redir" && "$redir" =~ ^https?:// ]]; then rest="${redir#*://}"; rh="${rest%%/*}"; rh="${rh%%:*}"; rh="${rh,,}"; [ "$rh" = "${h,,}" ] || return 1; fi
  cn="$(dig +time=1 +tries=1 +short CNAME "$h" 2>/dev/null || true)"
  txt="${h} ${cn} ${headers}"; txt="${txt,,}"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cloudfront.net*|*x-amz-cf-*|*fastly*|*akamaiedge.net*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*azureedge.net*|*azurefd.net*|*trafficmanager.net*|*b-cdn.net*|*bunnycdn*|*cdn77*|*stackpath*|*imperva*|*vercel.app*|*netlify.app*) return 1;;
  esac
  ms="$(relay_seconds_to_ms "$t" 2>/dev/null || true)"; [[ "$ms" =~ ^[0-9]+$ ]] || return 1
  tasn="$(relay_target_asn "$h")"; printf '%s|%s' "$ms" "$tasn"
}
relay_urlscan(){
  local q="$1" size="$2" key="${SINGBOX_URLSCAN_API_KEY:-}" out
  local -a args=(-fsS --connect-timeout 4 --max-time 12 --get 'https://urlscan.io/api/v1/search/' --data-urlencode "q=$q" --data-urlencode "size=$size" --data-urlencode "datasource=scans" --data-urlencode "collapse=page.domain.keyword")
  [ -n "$key" ] && args+=(-H "api-key: $key")
  out="$(curl "${args[@]}" 2>/dev/null || true)"; [ -n "$out" ] && jq -e '.results and (.results|type=="array")' >/dev/null 2>&1 <<<"$out" || return 1; printf '%s' "$out"
}
relay_discover(){
  local asn="$1" pfx="$2" outfile="$3" max=10 mem raw q src host ip pasn age redir rank url malicious count=0 esc
  local -A seen=(); : >"$outfile"; mem="$(relay_mem_kb)"; [ "$mem" -lt 262144 ] && max=4
  local -a qs=() ss=()
  if [ -n "$pfx" ]; then esc="${pfx//\//\\/}"; qs+=("page.ip:${esc} AND date:>now-180d"); ss+=(dynamic-prefix); fi
  if [ "$asn" != 未知 ] && [ -n "$asn" ]; then qs+=("page.asn:${asn} AND date:>now-180d"); ss+=(dynamic-asn); fi
  [ "${#qs[@]}" -gt 0 ] || return 0
  local i tmp; tmp="$(mktemp)"
  for i in "${!qs[@]}"; do
    [ "$count" -ge "$max" ] && break; q="${qs[$i]}"; src="${ss[$i]}"; raw="$(relay_urlscan "$q" "$(( max < 6 ? 20 : 50 ))" || true)"; [ -n "$raw" ] || continue
    : >"$tmp"; jq -r '.results[]? | [(.page.domain//""),(.page.ip//""),(.page.asn//""),((.page.apexDomainAgeDays//.page.domainAgeDays//0)|tostring),(.page.redirected//"none"),((.page.umbrellaRank//0)|tostring),(.page.url//""),((.verdicts.malicious//false)|tostring)] | @tsv' <<<"$raw" >"$tmp" 2>/dev/null || true
    while IFS=$'\t' read -r host ip pasn age redir rank url malicious; do
      [ "$count" -lt "$max" ] || break; host="${host,,}"; host="${host%.}"
      relay_validate_sni "$host" || continue; relay_cn_ok "$host" || continue; [[ "$url" == https://* ]] || continue; [ "$malicious" != true ] || continue
      [[ "$age" =~ ^[0-9]+$ ]] || age=0; [ "$age" -ge 365 ] || continue; [ -z "${seen[$host]+x}" ] || continue
      [ "$src" != dynamic-prefix ] || [ "$asn" = 未知 ] || [ "$pasn" = "$asn" ] || continue
      seen["$host"]=1; RELAY_SRC["$host"]="$src"; RELAY_AGE["$host"]="$age"; RELAY_RANK["$host"]="$rank"; printf '%s\n' "$host" >>"$outfile"; count=$((count+1))
    done <"$tmp"
  done
  rm -f "$tmp"
}
relay_score(){
  local h="$1" ms="$2" tasn="$3" vasn="$4" src="${RELAY_SRC[$1]:-public}" age="${RELAY_AGE[$1]:-0}" rank="${RELAY_RANK[$1]:-0}" s=25 same=false
  [ "$vasn" != 未知 ] && [ "$tasn" = "$vasn" ] && { s=$((s+30)); same=true; }
  case "$src" in dynamic-prefix) $same && s=$((s+20)) || s=$((s+2));; dynamic-asn) $same && s=$((s+10));; public-core) s=$((s+4));; inherited) s=$((s+2));; esac
  [[ "$age" =~ ^[0-9]+$ ]] || age=0; if [ "$age" -ge 3650 ]; then s=$((s+10)); elif [ "$age" -ge 1825 ]; then s=$((s+8)); elif [ "$age" -ge 730 ]; then s=$((s+6)); elif [ "$age" -ge 365 ]; then s=$((s+4)); fi
  if [ "$ms" -le 50 ]; then s=$((s+10)); elif [ "$ms" -le 100 ]; then s=$((s+8)); elif [ "$ms" -le 200 ]; then s=$((s+6)); elif [ "$ms" -le 400 ]; then s=$((s+3)); fi
  [[ "$rank" =~ ^[0-9]+$ ]] || rank=0; if [ "$rank" -gt 0 ] && [ "$rank" -le 100000 ]; then s=$((s+5)); elif [ "$rank" -gt 0 ] && [ "$rank" -le 500000 ]; then s=$((s+3)); fi
  [ "$s" -gt 100 ] && s=100; printf '%d' "$s"
}
select_relay_sni(){
  relay_refresh_gfwlist || true
  local vip info vasn=未知 vpfx="" dynfile h data ms tasn score best="" best_score=-1 best_ms=999999 src
  vip="$(relay_public_ipv4 || true)"; info="$(relay_origin_info "$vip" || true)"; if [ -n "$info" ]; then vasn="${info%%|*}"; vpfx="${info#*|}"; fi
  info "线路机网络：ASN=${vasn}；BGP 前缀=${vpfx:-未知}。开始被动发现 + 实时审计 Reality target..."
  dynfile="$(mktemp)"; relay_discover "$vasn" "$vpfx" "$dynfile" || true
  local -a cands=(); while IFS= read -r h; do [ -n "$h" ] && cands+=("$h"); done <"$dynfile"; rm -f "$dynfile"
  RELAY_SRC["$INHERITED_SNI"]="inherited"
  for h in "www.debian.org" "www.openssl.org" "www.postgresql.org" "www.alpinelinux.org"; do RELAY_SRC["$h"]="public-core"; done
  cands+=("$INHERITED_SNI" "www.debian.org" "www.openssl.org" "www.postgresql.org" "www.alpinelinux.org")
  local -A seen=()
  printf '  %-28s %-8s %-10s %-7s %s\n' TARGET SOURCE ASN SCORE LATENCY
  for h in "${cands[@]}"; do
    h="${h,,}"; h="${h%.}"; relay_validate_sni "$h" || continue; [ -z "${seen[$h]+x}" ] || continue; seen["$h"]=1
    data="$(relay_probe_sni "$h" || true)"; [[ "$data" == *'|'* ]] || continue; ms="${data%%|*}"; tasn="${data#*|}"; score="$(relay_score "$h" "$ms" "$tasn" "$vasn")"; src="${RELAY_SRC[$h]:-public}"
    printf '  %-28s %-8s %-10s %3s/100 %5sms\n' "$h" "$src" "$tasn" "$score" "$ms"
    if [ "$score" -gt "$best_score" ] || { [ "$score" -eq "$best_score" ] && [ "$ms" -lt "$best_ms" ]; }; then best="$h"; best_score="$score"; best_ms="$ms"; fi
  done
  if [ -n "$best" ]; then
    read -r -p "Reality target [推荐 $best；回车采用]: " h; SNI="${h:-$best}"
  else
    warn "动态候选与公共兜底均未通过严格静态条件。"
    read -r -p "请手动输入 Reality target [默认 $INHERITED_SNI]: " h; SNI="${h:-$INHERITED_SNI}"
  fi
  SNI="${SNI,,}"; SNI="${SNI%.}"
  relay_validate_sni "$SNI" || die "Reality target 域名格式无效。"; relay_cn_ok "$SNI" || die "中国大陆画像下该 target 属于长期受限/高度不稳定 SNI。"
  # 用户如果改选，必须重新通过全部硬条件；不能用交互输入绕过审计。
  if [ "$SNI" != "$best" ] || [ -z "$best" ]; then
    data="$(relay_probe_sni "$SNI" || true)"; [[ "$data" == *'|'* ]] || die "手动 target 未通过 TLS1.3/H2/证书/不跨域/共享 CDN 审计。"
    ms="${data%%|*}"; tasn="${data#*|}"; score="$(relay_score "$SNI" "$ms" "$tasn" "$vasn")"
  else
    score="$best_score"
  fi
  ok "线路机 Reality target：$SNI（评分 ${score}/100）"
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
    if ! relay_port_in_use "$p"; then printf '%s\\n' "$p"; return 0; fi
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
        "handshake":{"server":"${SNI}","server_port":443},
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
    {"type":"direct","tag":"direct-out"}
  ],
  "route":{"rules":[{"inbound":["vless-reality-in"],"action":"route","outbound":"landing-ss"}],"final":"direct-out"}
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
PANEL_SELFTEST_PID=""
panel_cleanup(){
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
    echo "Reality target: ${REALITY_SNI:-unknown}"
    curl -fsS --connect-timeout 4 --max-time 8 -o /dev/null "https://${REALITY_SNI}/" && echo "[OK] target HTTPS 可达" || echo "[WARN] target HTTPS 当前不可达"
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
set_state(){
  local k="$1" v="$2" t
  t="$(mktemp)"
  if [ -f "$STATE_PATH" ]; then grep -v "^${k}=" "$STATE_PATH" >"$t" || true; fi
  printf '%s=%q\n' "$k" "$v" >>"$t"
  install -m 600 "$t" "$STATE_PATH"
  rm -f "$t"
}
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
risk_check(){
  local h="$1" txt cn="" hd=""
  if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ]; then
    case "$h" in
      *.google.com|google.com|*.gstatic.com|gstatic.com|*.googleapis.com|googleapis.com|*.googleusercontent.com|googleusercontent.com|*.youtube.com|youtube.com|*.ytimg.com|ytimg.com|*.wikipedia.org|wikipedia.org|*.wikimedia.org|wikimedia.org|*.facebook.com|facebook.com|*.instagram.com|instagram.com|*.whatsapp.com|whatsapp.com|*.twitter.com|twitter.com|x.com|*.x.com|t.co|*.t.co|telegram.org|*.telegram.org|t.me|*.t.me|signal.org|*.signal.org|torproject.org|*.torproject.org|reddit.com|*.reddit.com|discord.com|*.discord.com|medium.com|*.medium.com) return 1;;
    esac
  fi
  command -v dig >/dev/null 2>&1 && cn="$(dig +time=2 +tries=1 +short CNAME "$h" 2>/dev/null || true)" || true
  hd="$(curl -sSI --connect-timeout 4 --max-time 8 "https://$h/" 2>/dev/null || true)"
  hd="${hd//$'\r'/}"; txt="${h} ${cn} ${hd}"; txt="${txt,,}"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cloudfront.net*|*x-amz-cf-*|*fastly.net*|*fastlylb.net*|*x-served-by*|*akamaiedge.net*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*akamaighost*|*x-akamai*|*azureedge.net*|*azurefd.net*|*x-azure-ref*|*trafficmanager.net*|*b-cdn.net*|*bunnycdn*|*cdn77*|*incapdns*|*imperva*) return 1;;
  esac
  return 0
}
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
  local p i span=$((62000-22000+1))
  for ((i=0;i<64;i++)); do
    p=$(( ((RANDOM << 15) ^ RANDOM) % span + 22000 ))
    if ! panel_port_in_use "$p"; then PANEL_RANDOM_PORT="$p"; printf '%s\n' "$p"; return 0; fi
  done
  return 1
}
panel_proc_count(){ local p n=0; for p in /proc/[0-9]*; do [ -d "$p" ] && n=$((n+1)); done; printf '%d' "$n"; }
panel_mem_kb(){ local k v u; while read -r k v u; do [ "$k" = MemAvailable: ] && { printf '%s' "${v:-0}"; return; }; done </proc/meminfo; printf '0'; }
panel_pid_headroom(){
  local best=999999 head cgline cgrel cgbase cgmax cgcur parent
  if [ -r /proc/self/cgroup ]; then
    while IFS= read -r cgline; do
      if [[ "$cgline" == 0::* ]]; then cgrel="${cgline#0::}"; cgbase="/sys/fs/cgroup${cgrel}"; break; fi
    done </proc/self/cgroup
  fi
  cgbase="${cgbase:-/sys/fs/cgroup}"
  while [[ "$cgbase" == /sys/fs/cgroup* ]]; do
    if [ -r "$cgbase/pids.max" ] && [ -r "$cgbase/pids.current" ]; then
      read -r cgmax <"$cgbase/pids.max" || cgmax=max
      read -r cgcur <"$cgbase/pids.current" || cgcur=0
      if [[ "$cgmax" =~ ^[0-9]+$ && "$cgcur" =~ ^[0-9]+$ ]]; then head=$((cgmax-cgcur)); [ "$head" -lt "$best" ] && best="$head"; fi
    fi
    [ "$cgbase" = /sys/fs/cgroup ] && break
    parent="${cgbase%/*}"; [ "$parent" = "$cgbase" ] && break; cgbase="$parent"
  done
  [ "$best" -lt 0 ] && best=0
  printf '%d' "$best"
}
panel_trim(){ local v="$1"; v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"; printf '%s' "$v"; }
panel_first_line(){ local l; while IFS= read -r l; do [ -n "$l" ] && { printf '%s' "$l"; return 0; }; done; return 1; }
panel_origin_info(){
  local ip="$1" a b c d q raw ans n prefix
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  command -v dig >/dev/null 2>&1 || return 1
  IFS=. read -r a b c d <<<"$ip"; q="${d}.${c}.${b}.${a}.origin.asn.cymru.com"
  raw="$(dig +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(panel_first_line <<<"$raw" || true)"
  [ -n "$ans" ] || { raw="$(dig @1.1.1.1 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(panel_first_line <<<"$raw" || true)"; }
  ans="${ans//\"/}"; IFS='|' read -r n _ prefix _ <<<"$ans"; n="$(panel_trim "$n")"; prefix="$(panel_trim "$prefix")"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1; printf 'AS%s|%s' "$n" "$prefix"
}
panel_refresh_gfwlist(){
  [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] || return 0
  [ "${SINGBOX_REALITY_GFWLIST_CHECK:-1}" = 1 ] || return 0
  local tmp="${GFWLIST_PATH}.tmp.$$" url clean line d n=0
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
panel_gfw_bad(){
  local h="${1,,}" d; [ -s "$GFWLIST_PATH" ] || return 1
  while IFS= read -r d || [ -n "$d" ]; do [ -n "$d" ] || continue; if [ "$h" = "$d" ] || [[ "$h" == *."$d" ]]; then return 0; fi; done <"$GFWLIST_PATH"; return 1
}
panel_cn_bad(){
  [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] || return 1
  [ "${SINGBOX_REALITY_GFWLIST_CHECK:-1}" = 1 ] && panel_gfw_bad "$1" && return 0
  case "$1" in
    *.google.com|google.com|*.gstatic.com|gstatic.com|*.googleapis.com|googleapis.com|*.googleusercontent.com|googleusercontent.com|*.youtube.com|youtube.com|*.ytimg.com|ytimg.com|*.wikipedia.org|wikipedia.org|*.wikimedia.org|wikimedia.org|*.facebook.com|facebook.com|*.instagram.com|instagram.com|*.whatsapp.com|whatsapp.com|*.twitter.com|twitter.com|x.com|*.x.com|t.co|*.t.co|telegram.org|*.telegram.org|t.me|*.t.me|signal.org|*.signal.org|torproject.org|*.torproject.org|reddit.com|*.reddit.com|discord.com|*.discord.com|medium.com|*.medium.com) return 0;;
  esac
  return 1
}
panel_lookup_ipv4(){ local r l; command -v dig >/dev/null 2>&1 || return 1; r="$(dig +time=2 +tries=1 +short A "$1" 2>/dev/null || true)"; while IFS= read -r l; do [[ "$l" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$l"; return 0; }; done <<<"$r"; return 1; }
panel_target_probe(){
  # 设置 PANEL_TLS13/H2/CERT/REDIRECT/RISK/ASN/MED/REASON/CNAME。
  local h="$1" tls low raw line code redir t rest rh headers="" cname="" txt ip oi
  PANEL_TLS13=NO; PANEL_H2=NO; PANEL_CERT=NO; PANEL_REDIRECT=YES; PANEL_RISK=LOW; PANEL_ASN=未知; PANEL_MED=999999; PANEL_REASON=""; PANEL_CNAME=""
  if panel_cn_bad "$h"; then PANEL_RISK=HIGH; PANEL_REASON="中国大陆画像下长期受限/高度不稳定"; return 0; fi
  case "$h" in *.microsoft.com|microsoft.com|*.bing.com|bing.com|*.cloudflare.com|cloudflare.com|*.workers.dev|*.pages.dev|*.cloudfront.net|*.vercel.app|*.netlify.app) PANEL_RISK=HIGH; PANEL_REASON="显式高风险/共享边缘目标"; return 0;; esac
  tls="$(timeout 5 openssl s_client -connect "$h:443" -servername "$h" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"; low="${tls,,}"
  [[ "$tls" == *TLSv1.3* || "$tls" == *TLS_AES_* ]] && PANEL_TLS13=YES
  [[ "$low" == *"alpn protocol: h2"* || "$low" == *"alpn: h2"* ]] && PANEL_H2=YES
  if raw="$(curl -sS -D - -o /dev/null --connect-timeout 3 --max-time 7 -w $'\n__SBMETA__\t%{http_code}\t%{redirect_url}\t%{time_appconnect}\n' "https://$h/" 2>/dev/null)"; then
    PANEL_CERT=YES
    while IFS= read -r line; do line="${line%$'\r'}"; if [[ "$line" == __SBMETA__$'\t'* ]]; then IFS=$'\t' read -r _ code redir t <<<"$line"; else headers+="$line"$'\n'; fi; done <<<"$raw"
    if [[ "$t" =~ ^[0-9]+([.][0-9]+)?$ ]]; then PANEL_MED="$(awk -v x="$t" 'BEGIN{printf "%d", x*1000+0.5}')"; fi
    if [[ -n "$redir" && "$redir" =~ ^https?:// ]]; then rest="${redir#*://}"; rh="${rest%%/*}"; rh="${rh%%:*}"; rh="${rh,,}"; [ "$rh" = "$h" ] || PANEL_REDIRECT=NO; fi
  fi
  if [ "$PANEL_TLS13" != YES ] || [ "$PANEL_H2" != YES ] || [ "$PANEL_CERT" != YES ] || [ "$PANEL_REDIRECT" != YES ]; then PANEL_REASON="TLS/H2/证书/跳转硬条件未全部通过"; return 0; fi
  command -v dig >/dev/null 2>&1 && cname="$(dig +time=2 +tries=1 +short CNAME "$h" 2>/dev/null || true)" || true; PANEL_CNAME="${cname//$'\n'/,}"
  txt="${h} ${cname} ${headers}"; txt="${txt,,}"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cloudfront.net*|*x-amz-cf-*|*fastly.net*|*fastlylb.net*|*x-served-by*|*akamaiedge.net*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*akamaighost*|*x-akamai*|*azureedge.net*|*azurefd.net*|*x-azure-ref*|*trafficmanager.net*|*b-cdn.net*|*bunnycdn*|*cdn77*|*incapdns*|*imperva*|*vercel.app*|*netlify.app*) PANEL_RISK=HIGH; PANEL_REASON="共享 CDN/边缘网络特征";;
    *) [ "$h" = gateway.icloud.com ] && [ "${REALITY_CLIENT_PROFILE:-cn}" = cn ] && { PANEL_RISK=CAUTION; PANEL_REASON="大陆可达性存在波动"; } || PANEL_REASON="未发现常见高风险特征";;
  esac
  if [ "$PANEL_RISK" != HIGH ]; then ip="$(panel_lookup_ipv4 "$h" || true)"; oi="$(panel_origin_info "$ip" || true)"; [ -n "$oi" ] && PANEL_ASN="${oi%%|*}"; fi
}
panel_score(){
  local risk="$1" tasn="$2" med="$3" vpsasn="$4" source="${5:-public}" age="${6:-0}" rank="${7:-0}" score=0
  case "$risk" in LOW) score=$((score+25));; CAUTION) score=$((score+5));; esac
  local same_asn=false
  [ "$vpsasn" != 未知 ] && [ "$tasn" = "$vpsasn" ] && { score=$((score+30)); same_asn=true; }
  case "$source" in dynamic-prefix) $same_asn && score=$((score+20)) || score=$((score+2));; dynamic-asn) $same_asn && score=$((score+10));; custom) score=$((score+8));; public-core) score=$((score+4));; esac
  [[ "$age" =~ ^[0-9]+$ ]] || age=0; if [ "$age" -ge 3650 ]; then score=$((score+10)); elif [ "$age" -ge 1825 ]; then score=$((score+8)); elif [ "$age" -ge 730 ]; then score=$((score+6)); elif [ "$age" -ge 365 ]; then score=$((score+4)); fi
  [[ "$med" =~ ^[0-9]+$ ]] || med=999999; if [ "$med" -le 50 ]; then score=$((score+10)); elif [ "$med" -le 100 ]; then score=$((score+8)); elif [ "$med" -le 200 ]; then score=$((score+6)); elif [ "$med" -le 400 ]; then score=$((score+3)); fi
  [[ "$rank" =~ ^[0-9]+$ ]] || rank=0; if [ "$rank" -gt 0 ] && [ "$rank" -le 100000 ]; then score=$((score+5)); elif [ "$rank" -gt 0 ] && [ "$rank" -le 500000 ]; then score=$((score+3)); fi
  [ "$score" -gt 100 ] && score=100; printf '%d' "$score"
}
panel_urlscan(){
  local q="$1" out key="${SINGBOX_URLSCAN_API_KEY:-}" size=40 mem; mem="$(panel_mem_kb)"; [ "$mem" -gt 0 ] && [ "$mem" -lt 262144 ] && size=20
  local -a a=(-fsS --connect-timeout 4 --max-time 12 --get https://urlscan.io/api/v1/search/ --data-urlencode "q=$q" --data-urlencode "size=$size" --data-urlencode "datasource=scans" --data-urlencode "collapse=page.domain.keyword")
  [ -n "$key" ] && a+=(-H "api-key: $key"); out="$(curl "${a[@]}" 2>/dev/null || true)"; jq -e '.results|type=="array"' >/dev/null 2>&1 <<<"$out" || return 1; printf '%s' "$out"
}
reality_discover(){
  [ "${ENABLE_REALITY:-false}" = true ] || [ "${ENABLE_ANYTLS:-false}" = true ] || { echo "未启用 Reality。"; return 1; }
  panel_refresh_gfwlist || true
  local vps4 oi vasn=未知 prefix="" raw q source host ip pasn age redir rank url malicious score best="" bestscore=-1 bestsource="" bestasn="" bestage=0 bestrank=0 n=0 minage="${SINGBOX_REALITY_DYNAMIC_MIN_AGE_DAYS:-365}" days="${SINGBOX_REALITY_URLSCAN_DAYS:-180}"
  local -A seen=(); vps4="$(curl -4 -fsS --connect-timeout 3 --max-time 7 https://api.ipify.org 2>/dev/null || true)"; oi="$(panel_origin_info "$vps4" || true)"; [ -n "$oi" ] && { vasn="${oi%%|*}"; prefix="${oi#*|}"; }
  echo "VPS: ${vps4:-未知} / ASN=$vasn / prefix=${prefix:-未知}"; echo "被动发现，不扫描网段。"
  printf '%-34s %-14s %-7s %-8s %-10s\n' TARGET SOURCE SCORE RISK ASN
  : >"$DISCOVERY_CACHE"
  for source in dynamic-prefix dynamic-asn; do
    [ "$n" -ge 10 ] && break
    if [ "$source" = dynamic-prefix ]; then [ -n "$prefix" ] || continue; local ep="${prefix//\//\\/}"; q="page.ip:${ep} AND date:>now-${days}d"; else [ "$vasn" != 未知 ] || continue; q="page.asn:${vasn} AND date:>now-${days}d"; fi
    raw="$(panel_urlscan "$q" || true)"; [ -n "$raw" ] || { echo "[WARN] urlscan ${source} 查询不可用/额度受限"; continue; }
    while IFS=$'\t' read -r host ip pasn age redir rank url malicious; do
      [ "$n" -lt 10 ] || break; host="${host,,}"; host="${host%.}"; valid_host "$host" || continue; [ -z "${seen[$host]+x}" ] || continue; [[ "$url" == https://* ]] || continue; [ "$malicious" != true ] || continue; [[ "$age" =~ ^[0-9]+$ ]] || age=0; [ "$age" -ge "$minage" ] || continue; panel_cn_bad "$host" && continue
      seen[$host]=1; panel_target_probe "$host"
      [ "$PANEL_TLS13" = YES ] && [ "$PANEL_H2" = YES ] && [ "$PANEL_CERT" = YES ] && [ "$PANEL_REDIRECT" = YES ] && [ "$PANEL_RISK" != HIGH ] || continue
      score="$(panel_score "$PANEL_RISK" "$PANEL_ASN" "$PANEL_MED" "$vasn" "$source" "$age" "$rank")"; printf '%-34s %-14s %-7s %-8s %-10s\n' "$host" "$source" "$score" "$PANEL_RISK" "$PANEL_ASN"; printf '%s|%s|%s|%s|%s|%s\n' "$host" "$score" "$source" "$PANEL_ASN" "$age" "$PANEL_MED" >>"$DISCOVERY_CACHE"; n=$((n+1))
      if [ "$score" -gt "$bestscore" ]; then best="$host"; bestscore="$score"; bestsource="$source"; bestasn="$PANEL_ASN"; bestage="$age"; bestrank="$rank"; fi
    done < <(jq -r '.results[]? | [(.page.domain//""),(.page.ip//""),(.page.asn//""),((.page.apexDomainAgeDays//.page.domainAgeDays//0)|tostring),(.page.redirected//"none"),((.page.umbrellaRank//0)|tostring),(.page.url//""),((.verdicts.malicious//false)|tostring)] | @tsv' <<<"$raw" 2>/dev/null)
  done
  chmod 600 "$DISCOVERY_CACHE" 2>/dev/null || true
  [ -n "$best" ] || { echo "未发现满足严格条件的动态候选；继续使用当前 target。"; return 1; }
  echo; echo "推荐：$best（score=$bestscore/100, source=$bestsource, ASN=$bestasn）"
  if [ "${1:-}" != --no-apply ]; then local x; read -r -p "现在审计并切换到该候选？[y/N]: " x; case "$x" in y|Y) change_reality "$best" "$bestsource" "$bestscore" "$bestasn" "$bestage" "$bestrank";; esac; fi
}
reality_health(){
  [ "${ENABLE_REALITY:-false}" = true ] || [ "${ENABLE_ANYTLS:-false}" = true ] || { [ "${1:-}" = --scheduled ] || echo "未启用 Reality。"; return 0; }
  panel_refresh_gfwlist || true
  local mode="${1:-}" h="${REALITY_SNI:-}" now vps4 oi vasn=未知 prefix="" score status=OK msg="健康" source="${REALITY_SELECTED_SOURCE:-public}" base="${REALITY_SELECTED_SCORE:-0}" deep_rc=""
  [ -n "$h" ] || return 1; now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; vps4="$(curl -4 -fsS --connect-timeout 3 --max-time 7 https://api.ipify.org 2>/dev/null || true)"; oi="$(panel_origin_info "$vps4" || true)"; [ -n "$oi" ] && { vasn="${oi%%|*}"; prefix="${oi#*|}"; }
  panel_target_probe "$h"; score="$(panel_score "$PANEL_RISK" "$PANEL_ASN" "$PANEL_MED" "$vasn" "$source" "${REALITY_SELECTED_AGE_DAYS:-0}" "${REALITY_SELECTED_UMBRELLA_RANK:-0}")"
  if [ "$PANEL_TLS13" != YES ] || [ "$PANEL_H2" != YES ] || [ "$PANEL_CERT" != YES ] || [ "$PANEL_REDIRECT" != YES ] || [ "$PANEL_RISK" = HIGH ]; then status=FAIL; msg="Reality target 静态硬条件已退化";
  elif [ "$PANEL_RISK" = CAUTION ]; then status=WARN; msg="target 进入 CAUTION";
  elif [[ "$base" =~ ^[0-9]+$ ]] && [ "$base" -gt 0 ] && [ "$score" -lt $((base-20)) ]; then status=WARN; msg="评分较安装基线下降超过 20 分";
  elif [ -n "${REALITY_SELECTED_ASN:-}" ] && [ "${REALITY_SELECTED_ASN:-未知}" != 未知 ] && [ "$PANEL_ASN" != "${REALITY_SELECTED_ASN}" ]; then status=WARN; msg="target ASN 与安装/切换基线不一致";
  elif [[ "$source" == dynamic-* ]] && [ "$vasn" != 未知 ] && [ "$PANEL_ASN" != "$vasn" ]; then status=WARN; msg="动态 target 已漂移出 VPS ASN"; fi
  if [ "$mode" = --deep ]; then if panel_reality_selftest "$h"; then deep_rc=PASS; else case $? in 75) deep_rc=DEFERRED;; *) deep_rc=FAIL; status=FAIL; msg="真实 Reality 自测失败";; esac; fi; fi
  local tmp="${HEALTH_PATH}.tmp.$$"; jq -n --arg t "$now" --arg status "$status" --arg target "$h" --arg msg "$msg" --arg tls "$PANEL_TLS13" --arg h2 "$PANEL_H2" --arg cert "$PANEL_CERT" --arg redir "$PANEL_REDIRECT" --arg risk "$PANEL_RISK" --arg tasn "$PANEL_ASN" --arg vasn "$vasn" --arg prefix "$prefix" --arg source "$source" --arg deep "$deep_rc" --argjson score "$score" '{checked_at:$t,status:$status,target:$target,message:$msg,tls13:$tls,h2:$h2,certificate:$cert,redirect_same_host:$redir,risk:$risk,target_asn:$tasn,vps_asn:$vasn,vps_prefix:$prefix,source:$source,score:$score,reality_selftest:(if $deep=="" then null else $deep end)}' >"$tmp" && install -m 600 "$tmp" "$HEALTH_PATH"; rm -f "$tmp"
  if [ "$mode" != --scheduled ]; then echo "Reality health: $status — $msg"; echo "target=$h TLS13=$PANEL_TLS13 H2=$PANEL_H2 CERT=$PANEL_CERT Redirect=$PANEL_REDIRECT Risk=$PANEL_RISK ASN=$PANEL_ASN/$vasn Score=$score/100${deep_rc:+ Selftest=$deep_rc}"; fi
  [ "$status" != FAIL ]
}
reality_health_status(){ [ -s "$HEALTH_PATH" ] && jq . "$HEALTH_PATH" || echo "暂无健康检查记录；运行：sb reality-health"; }

PANEL_SELFTEST_REASON=""
panel_reality_selftest(){
  # 返回：0 PASS；1 FAIL；75 因资源不足安全跳过。
  local h="$1" d sp lp keys key value priv="" pub="" sid uuid pid code head mem
  PANEL_SELFTEST_REASON=""
  head="$(panel_pid_headroom)"; mem="$(panel_mem_kb)"
  if [ "$head" -lt "${SINGBOX_REALITY_SELFTEST_MIN_PID_HEADROOM:-96}" ] || { [ "$mem" -gt 0 ] && [ "$mem" -lt "${SINGBOX_REALITY_SELFTEST_MIN_MEM_KB:-131072}" ]; }; then
    PANEL_SELFTEST_REASON="当前资源不足（PID/Tasks余量=${head}，MemAvailable约$((mem/1024))MiB）；为避免 fork exhaustion 已安全延后"
    return 75
  fi
  d="/tmp/sb-panel-reality.$$"; rm -rf "$d"; mkdir -p "$d" || return 1; chmod 700 "$d"
  panel_rand_port >/dev/null || { rm -rf "$d"; return 1; }; sp="$PANEL_RANDOM_PORT"
  panel_rand_port >/dev/null || { rm -rf "$d"; return 1; }; lp="$PANEL_RANDOM_PORT"
  if ! GODEBUG=netdns=go GOMAXPROCS=1 sing-box generate reality-keypair >"$d/keys" 2>"$d/keygen.err"; then
    local eline elow eres=false
    while IFS= read -r eline; do elow="${eline,,}"; [[ "$elow" == *"resource temporarily unavailable"* || "$elow" == *"failed to create new os thread"* ]] && { eres=true; break; }; done <"$d/keygen.err"
    if $eres; then PANEL_SELFTEST_REASON="生成临时 Reality 密钥时触发 PID/Tasks 限制"; rm -rf "$d"; return 75; fi
    rm -rf "$d"; return 1
  fi
  while IFS=: read -r key value; do key="${key//[[:space:]]/}"; value="${value#${value%%[![:space:]]*}}"; case "$key" in PrivateKey) priv="$value";; PublicKey) pub="$value";; esac; done <"$d/keys"
  openssl rand -hex 8 >"$d/sid" 2>/dev/null || { rm -rf "$d"; return 1; }; IFS= read -r sid <"$d/sid" || sid=""
  if [ -r /proc/sys/kernel/random/uuid ]; then IFS= read -r uuid </proc/sys/kernel/random/uuid || uuid=""; else uuid=""; fi
  [ -n "$priv" ] && [ -n "$pub" ] && [ -n "$sid" ] && [ -n "$uuid" ] || { rm -rf "$d"; return 1; }
  cat >"$d/test.json" <<JSON
{"log":{"level":"error"},"inbounds":[{"type":"vless","tag":"rs","listen":"127.0.0.1","listen_port":${sp},"users":[{"uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${h}","reality":{"enabled":true,"handshake":{"server":"${h}","server_port":443},"private_key":"${priv}","short_id":["${sid}"]}}},{"type":"mixed","tag":"rc","listen":"127.0.0.1","listen_port":${lp}}],"outbounds":[{"type":"direct","tag":"rd"},{"type":"vless","tag":"rp","server":"127.0.0.1","server_port":${sp},"uuid":"${uuid}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${h}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${pub}","short_id":"${sid}"}}}],"route":{"rules":[{"inbound":["rc"],"action":"route","outbound":"rp"},{"inbound":["rs"],"action":"route","outbound":"rd"}],"final":"rd"}}
JSON
  GODEBUG=netdns=go GOMAXPROCS=1 sing-box run -c "$d/test.json" >"$d/test.log" 2>&1 & pid=$!
  PANEL_SELFTEST_PID="$pid"
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    PANEL_SELFTEST_PID=""
    local line low resource_err=false
    while IFS= read -r line; do low="${line,,}"; [[ "$low" == *"resource temporarily unavailable"* || "$low" == *"failed to create new os thread"* ]] && { resource_err=true; break; }; done <"$d/test.log"
    if $resource_err; then PANEL_SELFTEST_REASON="sing-box 受到 PID/Tasks 限制"; rm -rf "$d"; return 75; fi
    rm -rf "$d"; return 1
  fi
  : >"$d/http.code"
  curl -sS --retry 3 --retry-connrefused --retry-delay 0 --retry-max-time 8 --proxy "socks5h://127.0.0.1:${lp}" --connect-timeout 2 --max-time 8 -o /dev/null -w '%{http_code}' "https://${h}/" >"$d/http.code" 2>/dev/null || true
  IFS= read -r code <"$d/http.code" || code=""
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; PANEL_SELFTEST_PID=""
  if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then rm -rf "$d"; return 0; fi
  local pline plow pres=false
  while IFS= read -r pline; do plow="${pline,,}"; [[ "$plow" == *"resource temporarily unavailable"* || "$plow" == *"failed to create new os thread"* || "$plow" == *"newosproc"* ]] && { pres=true; break; }; done <"$d/test.log"
  if $pres; then PANEL_SELFTEST_REASON="临时 sing-box 在启动/运行阶段触发 PID/Tasks 资源限制"; rm -rf "$d"; return 75; fi
  rm -rf "$d"; return 1
}
change_reality(){
  if [ "${ENABLE_REALITY:-false}" != true ] && [ "${ENABLE_ANYTLS:-false}" != true ]; then echo "未启用 Reality。"; return; fi
  local new="${1:-}" source="${2:-manual}" preset_score="${3:-}" preset_asn="${4:-}" preset_age="${5:-0}" preset_rank="${6:-0}" tls candidate backup x
  echo "当前 target: ${REALITY_SNI:-unknown}"
  [ -n "$new" ] || read -r -p "请输入新的 target 域名（留空取消）: " new
  [ -n "$new" ] || return 0
  new="${new//[[:space:]]/}"; new="${new,,}"; new="${new%.}"
  valid_host "$new" || { echo "域名格式无效"; return 1; }
  panel_refresh_gfwlist || true
  if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ] && [ "$new" = "gateway.icloud.com" ]; then
    echo "提示：gateway.icloud.com 在中国大陆画像中属于 CAUTION，仅建议作为扩展/备用 target，不应优先于 LOW 候选。"
  fi
  command -v timeout >/dev/null 2>&1 || { echo "缺少 timeout 命令，无法安全执行 Reality 探测。"; return 1; }
  tls="$(timeout 5 openssl s_client -connect "$new:443" -servername "$new" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
  local tls_lower="${tls,,}"
  [[ "$tls" == *TLSv1.3* || "$tls" == *TLS_AES_* ]] || { echo "未通过 TLS 1.3 检查，不修改。"; return 1; }
  [[ "$tls_lower" == *"alpn protocol: h2"* || "$tls_lower" == *"alpn: h2"* ]] || { echo "未协商 h2，不修改。"; return 1; }
  curl -sS -o /dev/null --connect-timeout 4 --max-time 10 "https://$new/" || { echo "证书/HTTPS 检查失败，不修改。"; return 1; }
  if ! risk_check "$new"; then
    echo "警告：该域名命中当前客户端画像的不推荐规则，或检测到共享 CDN/边缘网络特征；不建议作为 Reality target。"
    read -r -p "如仍坚持使用请输入 RISK: " x
    [ "$x" = RISK ] || return 0
  fi
  echo "正在执行真实 Reality 回环握手自测（单 sing-box 进程 / GOMAXPROCS=1）..."
  local test_rc=0
  if panel_reality_selftest "$new"; then test_rc=0; else test_rc=$?; fi
  if [ "$test_rc" -eq 0 ]; then
    echo "Reality 自测：PASS"
  elif [ "$test_rc" -eq 75 ]; then
    echo "Reality 自测：DEFERRED（${PANEL_SELFTEST_REASON:-本机资源不足}）；静态检查通过，可继续切换。"
  else
    echo "Reality 自测：FAIL（目标不兼容或当前网络异常）"
    read -r -p "如仍坚持使用请输入 FORCE: " x
    [ "$x" = FORCE ] || return 0
  fi
  # 为手工切换也记录可比较的评分/ASN基线；动态发现传入的预设值优先。
  if [ -z "$preset_score" ] || [ -z "$preset_asn" ]; then
    panel_target_probe "$new"
    local hv4 hoi hvasn=未知
    hv4="$(curl -4 -fsS --connect-timeout 3 --max-time 7 https://api.ipify.org 2>/dev/null || true)"; hoi="$(panel_origin_info "$hv4" || true)"; [ -n "$hoi" ] && hvasn="${hoi%%|*}"
    [ -n "$preset_asn" ] || preset_asn="$PANEL_ASN"
    [ -n "$preset_score" ] || preset_score="$(panel_score "$PANEL_RISK" "$PANEL_ASN" "$PANEL_MED" "$hvasn" "$source" 0 0)"
  fi
  candidate="$(mktemp)"
  jq --arg h "$new" '.inbounds |= map(if ((.type=="vless" or .type=="anytls") and (.tls.reality.enabled==true)) then .tls.server_name=$h | .tls.reality.handshake.server=$h else . end)' "$CONFIG_PATH" >"$candidate"
  old_sni="${REALITY_SNI:-}"
  # apply_candidate 会先 sing-box check，重启失败则自动回滚工作配置。
  apply_candidate "$candidate" || return 1
  REALITY_SNI="$new"
  set_state REALITY_SNI "$new"
  set_state REALITY_SELECTED_SOURCE "$source"
  [ -n "$preset_score" ] && set_state REALITY_SELECTED_SCORE "$preset_score" || set_state REALITY_SELECTED_SCORE ""
  [ -n "$preset_asn" ] && set_state REALITY_SELECTED_ASN "$preset_asn" || set_state REALITY_SELECTED_ASN ""
  set_state REALITY_SELECTED_AT "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set_state REALITY_SELECTED_AGE_DAYS "${preset_age:-0}"
  set_state REALITY_SELECTED_UMBRELLA_RANK "${preset_rank:-0}"
  source "$STATE_PATH"
  regen_uris || true
  regen_mihomo || true
  if [ -f /root/install-singbox-relay.sh ]; then
    sed -i "s|^INHERITED_SNI=.*$|INHERITED_SNI=\"${new}\"|" /root/install-singbox-relay.sh 2>/dev/null || true
  fi
  echo "已切换为 $new；节点链接已重新生成。"
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
  echo "7) 查看当前 Reality target"
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
  echo "28) Reality target 健康检查"
  echo "29) 查看最近 Reality 健康记录"
  echo "30) 被动发现同前缀/同 ASN Reality 候选"
  echo "0) 退出"
  read -r -p "请选择: " c
  case "$c" in
    1) cat "$URI_PATH" 2>/dev/null || echo "链接文件不存在";;
    2) show_status;;
    3) show_logs;;
    4) sing-box check -c "$CONFIG_PATH" || true;;
    5) service_restart || true;;
    6) edit_config;;
    7) echo "${REALITY_SNI:-未启用}";;
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
  chmod 755 "$SB_PATH"; ln -sf "$SB_PATH" /usr/bin/sb
}

change_reality_target_mode(){
  check_root; detect_os; install_deps
  command -v sing-box >/dev/null 2>&1 || die "未安装 sing-box。"
  [ -f "$STATE_PATH" ] && source "$STATE_PATH" || die "找不到安装状态：$STATE_PATH"
  REALITY_CLIENT_PROFILE="${REALITY_CLIENT_PROFILE:-cn}"
  if [ "${ENABLE_REALITY:-false}" != true ] && [ "${ENABLE_ANYTLS:-false}" != true ]; then die "当前未启用 Reality。"; fi
  select_reality_sni
  local candidate backup
  candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"; TMP_FILES+=("$candidate")
  jq --arg h "$REALITY_SNI" '
    .inbounds |= map(
      if ((.type=="vless" or .type=="anytls") and (.tls.reality.enabled==true))
      then .tls.server_name=$h | .tls.reality.handshake.server=$h
      else . end
    )
  ' "$CONFIG_PATH" >"$candidate"
  sing-box check -c "$candidate" || die "修改后的配置校验失败，未应用。"
  mkdir -p "$BACKUP_DIR"; backup="${BACKUP_DIR}/config.reality.$(date +%Y%m%d_%H%M%S).json"; cp -a "$CONFIG_PATH" "$backup"
  install -m 600 "$candidate" "$CONFIG_PATH"
  if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl restart sing-box; then cp -a "$backup" "$CONFIG_PATH"; systemctl restart sing-box || true; die "服务重启失败，已恢复旧配置。"; fi
  else
    if ! rc-service sing-box restart; then cp -a "$backup" "$CONFIG_PATH"; rc-service sing-box restart || true; die "服务重启失败，已恢复旧配置。"; fi
  fi
  save_state
  source "$STATE_PATH"
  generate_uris
  generate_mihomo_yaml || true
  if [ -f /root/install-singbox-relay.sh ]; then
    sed -i "s|^INHERITED_SNI=.*$|INHERITED_SNI=\"${REALITY_SNI}\"|" /root/install-singbox-relay.sh 2>/dev/null || true
  fi
  ok "Reality target 已切换为 $REALITY_SNI；节点链接与 Mihomo YAML 已重建；备份：$backup"
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
  if $ENABLE_REALITY; then echo "VLESS Reality：${PORT_REALITY} / target=${REALITY_SNI} / score=${REALITY_SELECTED_SCORE:-?} / source=${REALITY_SELECTED_SOURCE:-?} / client-profile=${REALITY_CLIENT_PROFILE:-cn}"; fi
  if $ENABLE_ANYTLS; then echo "AnyTLS Reality：${PORT_ANYTLS} / target=${REALITY_SNI} / score=${REALITY_SELECTED_SCORE:-?} / source=${REALITY_SELECTED_SOURCE:-?}"; fi
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

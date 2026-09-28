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
#   5. 使用本机临时 sing-box server/client 做真实 Reality 握手自测
#   6. 高风险共享 CDN（Cloudflare/Fastly/CloudFront/Akamai 等）默认不参与自动推荐
#   7. 已知存在 Reality 兼容性争议的目标默认不参与自动推荐
#   8. 允许手动指定 target，但高风险目标会明确警告并要求确认
#   9. 配置原子写入，sing-box check 失败不覆盖工作配置
#  10. 自带 sb 管理命令，可重新审计/切换 Reality target
#  11. 自动生成 Mihomo/Clash YAML，支持 sb mihomo 一键输出与 OSC 52 剪贴板复制
#  12. 标准化节点命名：地区｜角色｜简称；SS 可选 dialer-proxy（默认“中转”）
#  13. 中国大陆 Reality 候选分核心/扩展池；LOW > CAUTION，同风险下同 ASN 强优先
#
# 目标 sing-box：稳定版 1.14+（默认 stable；不自动追 alpha/testing）。
# ============================================================

SCRIPT_VERSION="2026.09.27-ultimate-v5.0.3"
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
LOCK_FILE="/run/lock/sing-box-deploy.lock"
MIN_SINGBOX_VERSION="1.14.0"
REALITY_AUDIT_JOBS="${SINGBOX_REALITY_AUDIT_JOBS:-auto}"
BACKUP_KEEP="${SINGBOX_BACKUP_KEEP:-10}"

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
  # 开源/基础设施类：大陆访问行为自然，且通常不是大型公共下载/CDN入口。
  "www.debian.org"
  "www.freebsd.org"
  "www.kernel.org"
  "www.openssl.org"
  "www.postgresql.org"
  "www.openbsd.org"
  "www.netbsd.org"

  # Apple 大众正常业务：大陆存在大量正常 TLS 流量；若实际落到共享 CDN，运行时仍会自动 SKIP。
  "www.apple.com"
  "support.apple.com"
  "appleid.apple.com"
  "captive.apple.com"

  # 其它技术站点。
  "www.archlinux.org"
  "www.alpinelinux.org"
)

# 扩展候选池：核心池无严格命中时再测试。
REALITY_CANDIDATES_CN_EXTENDED=(
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
REALITY_KNOWN_BAD_REGEX='(^|\.)cloudflare\.com$|(^|\.)workers\.dev$|(^|\.)pages\.dev$|(^|\.)microsoft\.com$|(^|\.)bing\.com$'

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
  for p in "${TMP_PIDS[@]:-}"; do
    [ -n "${p:-}" ] && kill "$p" 2>/dev/null || true
    [ -n "${p:-}" ] && wait "$p" 2>/dev/null || true
  done
  for f in "${TMP_FILES[@]:-}"; do
    [ -n "${f:-}" ] && rm -rf "$f" 2>/dev/null || true
  done
}
trap cleanup EXIT
trap 'err "第 ${LINENO} 行执行失败：${BASH_COMMAND}"' ERR

check_root(){ [ "$(id -u)" -eq 0 ] || die "请使用 root 运行此脚本。"; }


version_ge(){
  # version_ge current required
  local a b
  a="$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)"
  [ "$a" = "$2" ]
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
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  local keep="${BACKUP_KEEP:-10}"
  [[ "$keep" =~ ^[0-9]+$ ]] || keep=10
  find "$BACKUP_DIR" -maxdepth 1 -type f -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr | awk -v k="$keep" 'NR>k{sub(/^[^ ]+ /,"");print}' \
    | while IFS= read -r f; do rm -f -- "$f"; done
}

preflight(){
  local arch free_kb year
  arch="$(uname -m 2>/dev/null || true)"
  case "$arch" in x86_64|amd64|aarch64|arm64|armv7l|armv6l|i386|i686) :;; *) warn "较少见的 CPU 架构：$arch；请确认官方 sing-box 提供对应构建。";; esac
  free_kb="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}')"
  [ -z "$free_kb" ] || [ "$free_kb" -ge 102400 ] || die "根分区剩余空间不足 100 MiB。"
  year="$(date +%Y 2>/dev/null || echo 0)"
  [ "$year" -ge 2024 ] || die "系统时间明显异常；TLS/Reality 依赖正确时间，请先同步系统时钟。"
  command -v systemctl >/dev/null 2>&1 || command -v rc-service >/dev/null 2>&1 || warn "未检测到 systemd/OpenRC，服务管理可能不可用。"
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
      apk update
      apk add --no-cache bash curl ca-certificates openssl jq iproute2 coreutils bind-tools procps util-linux
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
    *) warn "未识别发行版；将尝试使用现有 curl/openssl/jq/ip/dig/timeout。" ;;
  esac
  local c
  for c in curl openssl jq timeout; do command -v "$c" >/dev/null 2>&1 || die "缺少依赖：$c"; done
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
  info "通过官方安装脚本安装 sing-box..."
  local tmp
  tmp="$(mktemp /tmp/sing-box-install.XXXXXX)"; TMP_FILES+=("$tmp")
  curl -fsSL --retry 3 --connect-timeout 8 https://sing-box.app/install.sh -o "$tmp" || die "下载 sing-box 官方安装脚本失败。"
  bash "$tmp"
  command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"
  local installed_ver
  installed_ver="$(singbox_version_number || true)"
  [ -n "$installed_ver" ] || die "无法识别 sing-box 版本。"
  version_ge "$installed_ver" "$MIN_SINGBOX_VERSION" || die "sing-box $installed_ver 过旧；本脚本要求 >= $MIN_SINGBOX_VERSION。"
  ok "$(sing-box version 2>/dev/null | head -n1)（stable 策略；脚本不自动追 alpha/testing）"
}

# ---------- 通用工具 ----------
rand_port(){
  local low="${1:-10000}" high="${2:-60000}" p i
  for i in $(seq 1 80); do
    if command -v shuf >/dev/null 2>&1; then p="$(shuf -i "${low}-${high}" -n1)"; else p=$((RANDOM % (high-low+1) + low)); fi
    if ! port_in_use "$p"; then echo "$p"; return 0; fi
  done
  return 1
}

port_in_use(){
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "(^|[:.])${p}$"
  else
    return 1
  fi
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
rand_pass(){ openssl rand -base64 24 | tr -d '\r\n'; }
url_encode(){
  local s="$1"
  s="${s//'%'/'%25'}"; s="${s//':'/'%3A'}"; s="${s//'+'/'%2B'}"; s="${s//'/'/'%2F'}"; s="${s//'='/'%3D'}"; s="${s//' '/'%20'}"
  printf '%s' "$s"
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
    x="$(curl -4 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
    [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$x"; return 0; }
  done
  return 1
}
get_public_ipv6(){
  local u x
  for u in https://api64.ipify.org https://ipv6.icanhazip.com https://ifconfig.co/ip; do
    x="$(curl -6 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
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

asn_for_ipv4(){
  # 使用 Team Cymru 的 DNS ASN 查询；失败时仅返回空，不影响安装。
  # 只保留 dig 子进程，避免 head/tr/awk 连锁 fork。
  local ip="$1" a b c d ans raw n q
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  command -v dig >/dev/null 2>&1 || return 1
  IFS='.' read -r a b c d <<<"$ip"
  q="${d}.${c}.${b}.${a}.origin.asn.cymru.com"
  raw="$(dig +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"
  ans="$(first_nonempty_line <<<"$raw" || true)"
  [ -n "$ans" ] || { raw="$(dig @1.1.1.1 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(first_nonempty_line <<<"$raw" || true)"; }
  [ -n "$ans" ] || { raw="$(dig @9.9.9.9 +time=2 +tries=1 +short TXT "$q" 2>/dev/null || true)"; ans="$(first_nonempty_line <<<"$raw" || true)"; }
  ans="${ans//\"/}"
  n="${ans%%|*}"
  n="${n//[[:space:]]/}"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  printf 'AS%s' "$n"
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
  timeout --foreground --signal=TERM --kill-after=2 "${sec}s" "$@"
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
reality_selftest(){
  # 用当前 sing-box 二进制在本机回环地址建立临时 VLESS+Reality server/client。
  # 成功说明“当前 sing-box 版本 + 当前 target”至少能完成真实 Reality 握手并代理 HTTPS。
  local host="$1" d server_port socks_port keys priv pub sid uuid sconf cconf slog clog spid cpid http
  d="$(mktemp -d /tmp/sb-reality-test.XXXXXX)"; TMP_FILES+=("$d")
  server_port="$(rand_port 21000 45000)" || return 1
  socks_port="$(rand_port 45001 62000)" || return 1
  keys="$(sing-box generate reality-keypair 2>/dev/null || true)"
  priv="$(awk '/PrivateKey/{print $NF;exit}' <<<"$keys")"
  pub="$(awk '/PublicKey/{print $NF;exit}' <<<"$keys")"
  sid="$(sing-box generate rand 8 --hex 2>/dev/null || openssl rand -hex 8)"
  uuid="$(rand_uuid)"
  [ -n "$priv" ] && [ -n "$pub" ] && [ -n "$sid" ] || return 1
  sconf="$d/server.json"; cconf="$d/client.json"; slog="$d/server.log"; clog="$d/client.log"

  jq -n --arg h "$host" --arg u "$uuid" --arg pk "$priv" --arg sid "$sid" --argjson p "$server_port" '{
    log:{level:"error"},
    inbounds:[{type:"vless",tag:"test-in",listen:"127.0.0.1",listen_port:$p,users:[{uuid:$u,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$h,reality:{enabled:true,handshake:{server:$h,server_port:443},private_key:$pk,short_id:[$sid]}}}],
    outbounds:[{type:"direct",tag:"direct"}],route:{final:"direct"}
  }' >"$sconf"

  jq -n --arg h "$host" --arg u "$uuid" --arg pub "$pub" --arg sid "$sid" --argjson sp "$server_port" --argjson lp "$socks_port" '{
    log:{level:"error"},
    inbounds:[{type:"mixed",tag:"mixed",listen:"127.0.0.1",listen_port:$lp}],
    outbounds:[{type:"vless",tag:"proxy",server:"127.0.0.1",server_port:$sp,uuid:$u,flow:"xtls-rprx-vision",tls:{enabled:true,server_name:$h,utls:{enabled:true,fingerprint:"chrome"},reality:{enabled:true,public_key:$pub,short_id:$sid}}}],
    route:{final:"proxy"}
  }' >"$cconf"

  sing-box check -c "$sconf" >/dev/null 2>&1 || return 1
  sing-box check -c "$cconf" >/dev/null 2>&1 || return 1

  sing-box run -c "$sconf" >"$slog" 2>&1 & spid=$!; TMP_PIDS+=("$spid")
  sleep 0.5
  kill -0 "$spid" 2>/dev/null || return 1
  sing-box run -c "$cconf" >"$clog" 2>&1 & cpid=$!; TMP_PIDS+=("$cpid")
  sleep 0.8
  kill -0 "$cpid" 2>/dev/null || return 1

  http="$(curl -sS --proxy "socks5h://127.0.0.1:${socks_port}" --connect-timeout 4 --max-time 10 -o /dev/null -w '%{http_code}' https://www.apple.com/ 2>/dev/null || true)"
  if [[ ! "$http" =~ ^[23][0-9][0-9]$ ]]; then
    http="$(curl -sS --proxy "socks5h://127.0.0.1:${socks_port}" --connect-timeout 4 --max-time 10 -o /dev/null -w '%{http_code}' https://www.debian.org/ 2>/dev/null || true)"
  fi
  kill "$cpid" "$spid" 2>/dev/null || true
  wait "$cpid" "$spid" 2>/dev/null || true
  TMP_PIDS=()
  [[ "$http" =~ ^[23][0-9][0-9]$ ]]
}

print_target_row(){
  printf '%-25s %-6s %-4s %-6s %-8s %-8s %-9s %-10s %s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}

proc_count_fast(){
  local p n=0
  for p in /proc/[0-9]*; do [ -d "$p" ] && n=$((n+1)); done
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
  # auto 模式综合 CPU、可用内存、RLIMIT_NPROC 与 cgroup pids 余量。
  # Reality 单个静态探测本身会短时启动 openssl/curl/dig，因此宁可保守，不追求“核数=并发数”。
  local req="${REALITY_AUDIT_JOBS:-auto}" cpu mem jobs=1 procs nproc_limit cgmax cgcur headroom
  if [[ "$req" =~ ^[1-9][0-9]*$ ]]; then
    jobs="$req"
    [ "$jobs" -le 8 ] || jobs=8
  else
    cpu="$(cpu_count_fast)"
    mem="$(mem_available_kb)"
    jobs=1
    if [ "$cpu" -ge 2 ] && [ "$mem" -ge 393216 ]; then jobs=2; fi
    if [ "$cpu" -ge 4 ] && [ "$mem" -ge 786432 ]; then jobs=3; fi
    if [ "$cpu" -ge 8 ] && [ "$mem" -ge 1572864 ]; then jobs=4; fi
  fi

  procs="$(proc_count_fast)"
  nproc_limit="$(ulimit -u 2>/dev/null || true)"
  if [[ "$nproc_limit" =~ ^[0-9]+$ ]]; then
    headroom=$((nproc_limit - procs))
    [ "$headroom" -lt 96 ] && jobs=1
    [ "$headroom" -ge 96 ] && [ "$headroom" -lt 160 ] && [ "$jobs" -gt 2 ] && jobs=2
  fi

  # Debian 12/systemd 常见 cgroup v2。SSH shell 往往位于 user.slice/.../session-*.scope，
  # TasksMax/pids.max 可能只限制当前会话，因此必须读取 /proc/self/cgroup 定位真实 cgroup，而不是只看根节点。
  local cgline cgrel cgbase="/sys/fs/cgroup"
  if [ -r /proc/self/cgroup ]; then
    while IFS= read -r cgline; do
      if [[ "$cgline" == 0::* ]]; then
        cgrel="${cgline#0::}"
        [ "$cgrel" = "/" ] || cgbase="/sys/fs/cgroup${cgrel}"
        break
      fi
    done </proc/self/cgroup
  fi
  if [ -r "${cgbase}/pids.max" ] && [ -r "${cgbase}/pids.current" ]; then
    read -r cgmax <"${cgbase}/pids.max" || cgmax=max
    read -r cgcur <"${cgbase}/pids.current" || cgcur=0
    if [[ "$cgmax" =~ ^[0-9]+$ && "$cgcur" =~ ^[0-9]+$ ]]; then
      headroom=$((cgmax - cgcur))
      [ "$headroom" -lt 64 ] && jobs=1
      [ "$headroom" -ge 64 ] && [ "$headroom" -lt 128 ] && [ "$jobs" -gt 2 ] && jobs=2
      [ "$headroom" -ge 128 ] && [ "$headroom" -lt 224 ] && [ "$jobs" -gt 3 ] && jobs=3
    fi
  fi

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
  print_target_row "$host" "${tls:-NO}" "${h2:-NO}" "${cert:-NO}" "${redir:-NO}" "${med:-999999}ms" "${risk:-HIGH}" "${tasn:-未知}" "${self:-SKIP}"
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
rank_reality_pending(){
  # 输出按最终推荐顺序排列的 PENDING host：
  # LOW > CAUTION；同风险下同 ASN > 跨 ASN；最后比较 TLS 中位延迟。
  # 这里故意使用 Bash 解析字段，而不是多行 awk printf，避免脚本经 curl/bash 传递或生成时
  # 转义换行导致 awk "Unexpected end of string"。
  local tmp="$1" vps_asn="$2"
  local host tls h2 cert redir med risk self reason cnames tasn
  local risk_rank same_asn med_num

  while IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn; do
    [ -n "$host" ] || continue
    [ "$tls" = "YES" ] || continue
    [ "$h2" = "YES" ] || continue
    [ "$cert" = "YES" ] || continue
    [ "$redir" = "YES" ] || continue
    [ "$risk" != "HIGH" ] || continue
    [ "$self" = "PENDING" ] || continue

    case "$risk" in
      LOW) risk_rank=0 ;;
      CAUTION) risk_rank=1 ;;
      *) risk_rank=2 ;;
    esac

    if [ "$vps_asn" != "未知" ] && [ "$tasn" = "$vps_asn" ]; then
      same_asn=0
    else
      same_asn=1
    fi

    if [[ "$med" =~ ^[0-9]+$ ]]; then
      med_num="$med"
    else
      med_num=999999
    fi

    printf '%d|%d|%09d|%s\n' "$risk_rank" "$same_asn" "$med_num" "$host"
  done <"$tmp" | LC_ALL=C sort -t'|' -k1,1n -k2,2n -k3,3n -k4,4 | cut -d'|' -f4-
}

set_reality_self_status(){
  local tmp="$1" host="$2" status="$3" t
  t="$(mktemp /tmp/reality-status.XXXXXX)"; TMP_FILES+=("$t")
  awk -F'|' -v OFS='|' -v h="$host" -v s="$status" '$1==h{$8=s} {print}' "$tmp" >"$t"
  mv "$t" "$tmp"
}

run_reality_selftests(){
  # 按排序逐个真握手；找到第一个 PASS 就停止。通常只需 1~2 次，显著快于对所有静态候选逐个启动临时 sing-box。
  local tmp="$1" vps_asn="$2" host
  while IFS= read -r host; do
    [ -n "$host" ] || continue
    printf '  [Reality] %-28s ' "$host"
    if reality_selftest "$host"; then
      echo 'PASS'; set_reality_self_status "$tmp" "$host" PASS; return 0
    else
      echo 'FAIL'; set_reality_self_status "$tmp" "$host" FAIL
    fi
  done < <(rank_reality_pending "$tmp" "$vps_asn")
  return 1
}

pick_reality_best(){
  # 仅从“全部保守条件 + 真实 Reality 自测 PASS”的目标中选推荐项。
  # 排序：LOW 风险 > CAUTION；同风险下同 ASN 强优先；最后比较 TLS 中位延迟。
  # HIGH 永不进入自动推荐。输出 host|median_ms|same_asn|risk；无严格命中时返回 1。
  local tmp="$1" vps_asn="$2"
  local host tls h2 cert redir med risk self reason cnames tasn
  local best="" best_med=999999 best_same=-1 best_risk_rank=-1 same risk_rank

  while IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn; do
    [ "$tls" = YES ] && [ "$h2" = YES ] && [ "$cert" = YES ] && [ "$redir" = YES ] || continue
    [ "$risk" != HIGH ] && [ "$self" = PASS ] || continue

    case "$risk" in
      LOW) risk_rank=2 ;;
      CAUTION) risk_rank=1 ;;
      *) risk_rank=0 ;;
    esac
    same=0
    [ "$vps_asn" != 未知 ] && [ "$tasn" = "$vps_asn" ] && same=1

    if [ "$risk_rank" -gt "$best_risk_rank" ]       || { [ "$risk_rank" -eq "$best_risk_rank" ] && [ "$same" -gt "$best_same" ]; }       || { [ "$risk_rank" -eq "$best_risk_rank" ] && [ "$same" -eq "$best_same" ] && [ "$med" -lt "$best_med" ]; }; then
      best="$host"; best_med="$med"; best_same="$same"; best_risk_rank="$risk_rank"
    fi
  done <"$tmp"

  [ -n "$best" ] || return 1
  if [ "$best_risk_rank" -ge 2 ]; then risk="LOW"; else risk="CAUTION"; fi
  printf '%s|%s|%s|%s\n' "$best" "$best_med" "$best_same" "$risk"
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
  local host data tls h2 cert redir med risk reason cnames tasn self best="" best_med=999999
  local tmp vps4 vps_asn="未知" best_same=-1 best_risk="LOW"
  local extra_raw="${SINGBOX_REALITY_EXTRA_SNI:-}"
  local -a primary_candidates=() base_extended=() extra_candidates=()
  if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ]; then
    primary_candidates=("${REALITY_CANDIDATES_CN_PRIMARY[@]}")
    base_extended=("${REALITY_CANDIDATES_CN_EXTENDED[@]}")
  else
    primary_candidates=("${REALITY_CANDIDATES_GLOBAL_PRIMARY[@]}")
    base_extended=("${REALITY_CANDIDATES_GLOBAL_EXTENDED[@]}")
  fi
  # 自定义候选属于“优先候选”，第一轮就参与完整审计和同 ASN 排序。
  # 最适合用于加入你自己确认过的同 ASN/邻近网络正常 HTTPS 站点。
  # 例：SINGBOX_REALITY_EXTRA_SNI='a.example.com,b.example.com'
  if [ -n "$extra_raw" ]; then
    extra_raw="${extra_raw//,/ }"
    read -r -a extra_candidates <<<"$extra_raw"
    primary_candidates+=("${extra_candidates[@]}")
  fi
  tmp="$(mktemp /tmp/reality-audit.XXXXXX)"; TMP_FILES+=("$tmp")
  vps4="$(get_public_ipv4 || true)"
  [ -n "$vps4" ] && vps_asn="$(asn_for_ipv4 "$vps4" || true)"
  vps_asn="${vps_asn:-未知}"

  if [ -n "$forced" ]; then
    host="$(normalize_sni "$forced")"; validate_sni "$host" || die "SINGBOX_REALITY_SNI 格式无效：$host"
    info "审计指定 Reality target：$host"
    data="$(probe_tls_http "$host")"
    IFS='|' read -r tls h2 cert redir med risk reason cnames tasn <<<"$data"
    self="FAIL"; reality_selftest "$host" && self="PASS" || true
    echo "TLS1.3=$tls H2=$h2 Cert=$cert Redirect=$redir Median=${med}ms Risk=$risk ASN=${tasn}/${vps_asn} Reality=$self"
    echo "风险说明：$reason"
    if [ "$tls" != YES ] || [ "$h2" != YES ] || [ "$cert" != YES ] || [ "$redir" != YES ]; then
      [ "${SINGBOX_REALITY_ALLOW_INCOMPATIBLE:-0}" = 1 ] || die "指定 target 未满足 TLS1.3/H2/有效证书/不跨域跳转的完整静态条件。"
      warn "已通过 SINGBOX_REALITY_ALLOW_INCOMPATIBLE=1 强制放宽静态条件。"
    fi
    if [ "$risk" = HIGH ] && [ "$allow_risky" != 1 ]; then die "指定 target 被判定为高风险；如已充分了解风险，可设置 SINGBOX_REALITY_ALLOW_RISKY=1 强制使用。"; fi
    if [ "$self" != PASS ]; then warn "真实 Reality 自测未通过。可能是 target 不兼容，也可能是当前 sing-box 自测客户端兼容性问题。"; fi
    REALITY_SNI="$host"; return 0
  fi

  info "开始 Reality target 安全审计；高风险共享 CDN 不进入自动推荐。"
  echo
  echo "VPS ASN：$vps_asn（通过全部硬条件后，同 ASN 作为强优先项；查询失败不影响安装）"
  echo "客户端画像：${REALITY_CLIENT_PROFILE:-cn}；第一轮核心/优先候选（${#primary_candidates[@]} 个）"
  if [ "${#extra_candidates[@]}" -gt 0 ]; then
    echo "其中自定义优先候选：${#extra_candidates[@]} 个（会参与 LOW/CAUTION、同 ASN、延迟综合排序）"
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
    IFS='|' read -r best best_med best_same best_risk <<<"$picked"
  fi

  echo
  if [ -n "$best" ]; then
    if [ "$best_same" -eq 1 ]; then
      ok "自动推荐：$best（风险=$best_risk；真实 Reality 自测通过；同 ASN 强优先；TLS 建连中位数约 ${best_med} ms）"
    else
      ok "自动推荐：$best（风险=$best_risk；真实 Reality 自测通过；TLS 建连中位数约 ${best_med} ms）"
    fi
  else
    warn "核心/优先候选 + 扩展候选均没有目标满足全部保守条件，将要求手动输入。"
  fi
  echo "说明：自动推荐先满足大陆画像/TLS1.3/H2/证书/不跨域/非共享 CDN/Reality 真握手；LOW 优先于 CAUTION，同风险下同 ASN 强优先，最后才比较延迟。"
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
        echo "  ASN：$tasn（VPS=$vps_asn）"
        echo "  TLS1.3=$tls, H2=$h2, Cert=$cert, RedirectSameHost=$redir, Median=${med}ms, Reality=$self"
      done <"$tmp"
      echo
      read -r -p "输入要使用的 target（留空使用自动推荐）: " host
      if [ -z "$host" ] && [ -n "$best" ]; then REALITY_SNI="$best"; return 0; fi
      choice=2
      ;;
  esac
  if [ "${choice:-1}" = 1 ] && [ -n "$best" ]; then REALITY_SNI="$best"; return 0; fi

  while true; do
    [ -n "${host:-}" ] || read -r -p "请输入 Reality target 域名: " host
    host="$(normalize_sni "$host")"
    validate_sni "$host" || { warn "域名格式不正确。"; host=""; continue; }
    data="$(probe_tls_http "$host")"
    IFS='|' read -r tls h2 cert redir med risk reason cnames tasn <<<"$data"
    self="FAIL"; reality_selftest "$host" && self="PASS" || true
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
    if [ "$self" != PASS ]; then
      warn "真实 Reality 自测未通过。"
      local confirm2
      read -r -p "仍然使用？输入大写 FORCE 继续，其他输入返回重选: " confirm2
      [ "$confirm2" = FORCE ] || { host=""; continue; }
    fi
    REALITY_SNI="$host"; return 0
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
  host_default="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo node)"

  echo
  info "=== Mihomo / Clash 节点命名 ==="
  [ -n "$region" ] || read -r -p "节点地区（如 香港/荷兰；留空=未分类）: " region
  region="${region:-未分类}"

  # 兼容旧环境变量 SINGBOX_NODE_NAME：若新 alias 未设置，则把旧值当作简称。
  if [ -z "$alias" ] && [ -n "${SINGBOX_NODE_NAME:-}" ]; then alias="$SINGBOX_NODE_NAME"; fi
  [ -n "$alias" ] || read -r -p "节点简称 [默认 ${host_default}]: " alias
  alias="${alias:-$host_default}"

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
  CONNECTION_HOST="$(normalize_host "$(printf '%s' "$x" | tr -d '[:space:]')")"
}

configure_values(){
  if $ENABLE_SS; then
    PORT_SS="$(prompt_port SS "${SINGBOX_PORT_SS:-}")"
    if [ "$SS_METHOD" = "2022-blake3-aes-128-gcm" ]; then
      # SS2022 AES-128 要求 16-byte PSK，使用标准 base64 表示。
      PSK_SS="$(openssl rand -base64 16 | tr -d '\r\n')"
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
  local out
  out="$(sing-box generate reality-keypair 2>&1)" || die "生成 Reality 密钥失败：$out"
  REALITY_PRIVATE="$(awk '/PrivateKey/{print $NF;exit}' <<<"$out")"
  REALITY_PUBLIC="$(awk '/PublicKey/{print $NF;exit}' <<<"$out")"
  REALITY_SID="$(sing-box generate rand 8 --hex 2>/dev/null || openssl rand -hex 8)"
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
  local out="$1" obj tmp
  cat >"$out" <<'JSON'
{
  "log":{"level":"info","timestamp":true},
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
  alpine) apk update; apk add --no-cache bash curl ca-certificates openssl jq coreutils bind-tools iproute2 ;;
  debian|ubuntu) export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y curl ca-certificates openssl jq coreutils dnsutils iproute2 ;;
  *) if command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates openssl jq coreutils bind-utils iproute; elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates openssl jq coreutils bind-utils iproute; fi ;;
esac

if ! command -v sing-box >/dev/null 2>&1; then
  t="$(mktemp)"; curl -fsSL --retry 3 https://sing-box.app/install.sh -o "$t"; bash "$t"; rm -f "$t"
fi
command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"
command -v timeout >/dev/null 2>&1 || die "缺少 coreutils timeout，无法进行有界 Reality 探测。"

# 线路机必须基于“线路机自身网络”重新选择 Reality target，不能盲目继承落地机结果。
probe_sni(){
  local h="$1" o tls h2 cn hd txt t
  tls="$(timeout --foreground --signal=TERM --kill-after=2 5s openssl s_client -connect "$h:443" -servername "$h" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
  grep -Eq 'TLSv1\.3|TLS_AES_' <<<"$tls" || return 1
  grep -Eqi 'ALPN protocol: h2|ALPN: h2' <<<"$tls" || return 1
  o="$(curl -sS -o /dev/null --connect-timeout 4 --max-time 10 -w '%{redirect_url}|%{time_appconnect}' "https://$h/" 2>/dev/null || true)"
  [ -n "$o" ] || return 1
  if [[ "${o%%|*}" =~ ^https?:// ]]; then
    local rh; rh="$(sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#' <<<"${o%%|*}" | tr '[:upper:]' '[:lower:]')"
    [ "$rh" = "$h" ] || return 1
  fi
  cn="$(dig +time=2 +tries=1 +short CNAME "$h" 2>/dev/null | tr '\n' ' ' || true)"
  hd="$(curl -sSI --connect-timeout 4 --max-time 8 "https://$h/" 2>/dev/null | tr -d '\r' || true)"
  txt="$(printf '%s %s %s' "$h" "$cn" "$hd" | tr '[:upper:]' '[:lower:]')"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cloudfront.net*|*x-amz-cf-*|*fastly*|*akamaiedge.net*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*azureedge.net*|*azurefd.net*|*trafficmanager.net*|*b-cdn.net*|*bunnycdn*|*cdn77*|*imperva*) return 1;;
  esac
  t="${o##*|}"; awk -v x="$t" 'BEGIN{exit !(x>0)}' || return 1
  awk -v x="$t" 'BEGIN{printf "%.0f",x*1000}'
}

select_relay_sni(){
  local -a cands=("__SNI__" "www.debian.org" "www.freebsd.org" "www.kernel.org" "www.openssl.org" "www.postgresql.org" "www.openbsd.org" "www.netbsd.org" "www.apple.com" "support.apple.com" "appleid.apple.com" "www.archlinux.org")
  local h ms best="" best_ms=999999
  info "在线路机本机重新审计 Reality target..."
  for h in "${cands[@]}"; do
    ms="$(probe_sni "$h" || true)"
    if [[ "$ms" =~ ^[0-9]+$ ]]; then
      printf '  %-28s %6sms\n' "$h" "$ms"
      if [ "$ms" -lt "$best_ms" ]; then best="$h"; best_ms="$ms"; fi
    fi
  done
  [ -n "$best" ] || best="__SNI__"
  read -r -p "Reality target [默认 $best；回车采用]: " h
  SNI="${h:-$best}"
  [[ "$SNI" =~ ^[A-Za-z0-9.-]+$ ]] && [[ "$SNI" == *.* ]] || die "Reality target 域名格式无效。"
  ok "线路机 Reality target：$SNI"
}
select_relay_sni

rand_port(){
  local p
  while true; do
    if command -v shuf >/dev/null 2>&1; then p="$(shuf -i 20000-65000 -n1)"; else p=$((RANDOM%45001+20000)); fi
    if ! command -v ss >/dev/null 2>&1 || ! ss -H -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}$"; then echo "$p"; return; fi
  done
}
UUID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
[ -n "$UUID" ] || UUID="$(sing-box generate uuid 2>/dev/null)"
KEYS="$(sing-box generate reality-keypair)"
PRIV="$(awk '/PrivateKey/{print $NF;exit}' <<<"$KEYS")"
PUB="$(awk '/PublicKey/{print $NF;exit}' <<<"$KEYS")"
SID="$(sing-box generate rand 8 --hex 2>/dev/null || openssl rand -hex 8)"
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
CONFIG_DIR="/etc/sing-box"; CONFIG_PATH="$CONFIG_DIR/config.json"; STATE_PATH="$CONFIG_DIR/install-state.env"; URI_PATH="$CONFIG_DIR/uris.txt"; MIHOMO_DIR="$CONFIG_DIR/mihomo"; BACKUP_DIR="$CONFIG_DIR/backups"
[ "$(id -u)" -eq 0 ] || { echo "需要 root"; exit 1; }
[ -f "$STATE_PATH" ] && source "$STATE_PATH" || true
service_restart(){ sing-box check -c "$CONFIG_PATH" && { if command -v systemctl >/dev/null 2>&1; then systemctl restart sing-box; else rc-service sing-box restart; fi; }; }
show_status(){ if command -v systemctl >/dev/null 2>&1; then systemctl status sing-box --no-pager; else rc-service sing-box status; fi; }
show_logs(){ if command -v journalctl >/dev/null 2>&1; then journalctl -u sing-box -n 100 --no-pager; else tail -n 100 /var/log/messages 2>/dev/null || true; fi; }
doctor(){
  local fail=0 h
  echo "===== sing-box Doctor ====="
  echo "版本: $(sing-box version 2>/dev/null | head -n1 || echo 未安装)"
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
  fi
  return "$fail"
}

safe_update(){
  local oldbin realbin b tmp
  oldbin="$(command -v sing-box)"; realbin="$(readlink -f "$oldbin" 2>/dev/null || echo "$oldbin")"
  mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
  b="$BACKUP_DIR/sing-box.$(date +%Y%m%d_%H%M%S)"; cp -a "$realbin" "$b"
  tmp="$(mktemp /tmp/sing-box-update.XXXXXX)"
  if ! curl -fsSL --retry 3 --connect-timeout 8 https://sing-box.app/install.sh -o "$tmp" || ! bash "$tmp"; then
    rm -f "$tmp"; echo "更新器执行失败，旧二进制未删除：$b"; return 1
  fi
  rm -f "$tmp"
  if ! sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1 || ! service_restart; then
    echo "新版本与当前配置/服务不兼容，正在恢复旧二进制。"
    install -m 755 "$b" "$realbin"
    service_restart || true
    return 1
  fi
  echo "更新成功：$(sing-box version 2>/dev/null | head -n1)"
  find "$BACKUP_DIR" -maxdepth 1 -type f -name 'sing-box.*' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk 'NR>3{sub(/^[^ ]+ /,"");print}' | while IFS= read -r f; do rm -f -- "$f"; done
}
urlenc(){ local s="$1"; s="${s//'%'/'%25'}"; s="${s//':'/'%3A'}"; s="${s//'+'/'%2B'}"; s="${s//'/'/'%2F'}"; s="${s//'='/'%3D'}"; s="${s//' '/'%20'}"; printf '%s' "$s"; }
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
  if [ "$new" != "$old" ] && command -v ss >/dev/null 2>&1 && ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${new}$"; then echo "端口已占用"; return 1; fi
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
  command -v dig >/dev/null 2>&1 && cn="$(dig +time=2 +tries=1 +short CNAME "$h" 2>/dev/null | tr '\n' ' ')" || true
  hd="$(curl -sSI --connect-timeout 4 --max-time 8 "https://$h/" 2>/dev/null | tr -d '\r' || true)"
  txt="$(printf '%s %s %s' "$h" "$cn" "$hd" | tr '[:upper:]' '[:lower:]')"
  case "$txt" in
    *cloudflare*|*cf-ray*|*cloudfront.net*|*x-amz-cf-*|*fastly.net*|*fastlylb.net*|*x-served-by*|*akamaiedge.net*|*edgekey.net*|*edgesuite.net*|*akamai.net*|*akamaighost*|*x-akamai*|*azureedge.net*|*azurefd.net*|*x-azure-ref*|*trafficmanager.net*|*b-cdn.net*|*bunnycdn*|*cdn77*|*incapdns*|*imperva*) return 1;;
  esac
  return 0
}
panel_rand_port(){
  local p i
  for i in $(seq 1 50); do
    p="$(shuf -i 22000-62000 -n1 2>/dev/null || echo $((RANDOM%40001+22000)))"
    if ! command -v ss >/dev/null 2>&1 || ! ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${p}$"; then echo "$p"; return 0; fi
  done
  return 1
}
panel_reality_selftest(){
  local h="$1" d sp lp keys priv pub sid uuid spid cpid code
  d="$(mktemp -d /tmp/sb-panel-reality.XXXXXX)" || return 1
  sp="$(panel_rand_port)" || { rm -rf "$d"; return 1; }; lp="$(panel_rand_port)" || { rm -rf "$d"; return 1; }
  keys="$(sing-box generate reality-keypair 2>/dev/null || true)"
  priv="$(awk '/PrivateKey/{print $NF;exit}' <<<"$keys")"; pub="$(awk '/PublicKey/{print $NF;exit}' <<<"$keys")"
  sid="$(sing-box generate rand 8 --hex 2>/dev/null || openssl rand -hex 8)"
  uuid="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || true)"
  [ -n "$priv" ] && [ -n "$pub" ] && [ -n "$sid" ] && [ -n "$uuid" ] || { rm -rf "$d"; return 1; }
  jq -n --arg h "$h" --arg u "$uuid" --arg pk "$priv" --arg sid "$sid" --argjson p "$sp" '{log:{level:"error"},inbounds:[{type:"vless",tag:"i",listen:"127.0.0.1",listen_port:$p,users:[{uuid:$u,flow:"xtls-rprx-vision"}],tls:{enabled:true,server_name:$h,reality:{enabled:true,handshake:{server:$h,server_port:443},private_key:$pk,short_id:[$sid]}}}],outbounds:[{type:"direct",tag:"d"}],route:{final:"d"}}' >"$d/s.json"
  jq -n --arg h "$h" --arg u "$uuid" --arg pub "$pub" --arg sid "$sid" --argjson sp "$sp" --argjson lp "$lp" '{log:{level:"error"},inbounds:[{type:"mixed",tag:"m",listen:"127.0.0.1",listen_port:$lp}],outbounds:[{type:"vless",tag:"p",server:"127.0.0.1",server_port:$sp,uuid:$u,flow:"xtls-rprx-vision",tls:{enabled:true,server_name:$h,utls:{enabled:true,fingerprint:"chrome"},reality:{enabled:true,public_key:$pub,short_id:$sid}}}],route:{final:"p"}}' >"$d/c.json"
  sing-box check -c "$d/s.json" >/dev/null 2>&1 && sing-box check -c "$d/c.json" >/dev/null 2>&1 || { rm -rf "$d"; return 1; }
  sing-box run -c "$d/s.json" >"$d/s.log" 2>&1 & spid=$!; sleep 0.5
  kill -0 "$spid" 2>/dev/null || { wait "$spid" 2>/dev/null || true; rm -rf "$d"; return 1; }
  sing-box run -c "$d/c.json" >"$d/c.log" 2>&1 & cpid=$!; sleep 0.8
  if ! kill -0 "$cpid" 2>/dev/null; then kill "$spid" 2>/dev/null || true; wait "$spid" "$cpid" 2>/dev/null || true; rm -rf "$d"; return 1; fi
  code="$(curl -sS --proxy "socks5h://127.0.0.1:${lp}" --connect-timeout 4 --max-time 10 -o /dev/null -w '%{http_code}' https://www.apple.com/ 2>/dev/null || true)"
  if [[ ! "$code" =~ ^[23][0-9][0-9]$ ]]; then code="$(curl -sS --proxy "socks5h://127.0.0.1:${lp}" --connect-timeout 4 --max-time 10 -o /dev/null -w '%{http_code}' https://www.debian.org/ 2>/dev/null || true)"; fi
  kill "$cpid" "$spid" 2>/dev/null || true; wait "$cpid" "$spid" 2>/dev/null || true; rm -rf "$d"
  [[ "$code" =~ ^[23][0-9][0-9]$ ]]
}
change_reality(){
  if [ "${ENABLE_REALITY:-false}" != true ] && [ "${ENABLE_ANYTLS:-false}" != true ]; then echo "未启用 Reality。"; return; fi
  local new tls candidate backup x
  echo "当前 target: ${REALITY_SNI:-unknown}"
  read -r -p "请输入新的 target 域名（留空取消）: " new
  [ -n "$new" ] || return 0
  new="$(printf '%s' "$new" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
  valid_host "$new" || { echo "域名格式无效"; return 1; }
  if [ "${REALITY_CLIENT_PROFILE:-cn}" = "cn" ] && [ "$new" = "gateway.icloud.com" ]; then
    echo "提示：gateway.icloud.com 在中国大陆画像中属于 CAUTION，仅建议作为扩展/备用 target，不应优先于 LOW 候选。"
  fi
  command -v timeout >/dev/null 2>&1 || { echo "缺少 timeout 命令，无法安全执行 Reality 探测。"; return 1; }
  tls="$(timeout --foreground --signal=TERM --kill-after=2 5s openssl s_client -connect "$new:443" -servername "$new" -tls1_3 -alpn h2 </dev/null 2>&1 || true)"
  grep -Eq 'TLSv1\.3|TLS_AES_' <<<"$tls" || { echo "未通过 TLS 1.3 检查，不修改。"; return 1; }
  grep -Eqi 'ALPN protocol: h2|ALPN: h2' <<<"$tls" || { echo "未协商 h2，不修改。"; return 1; }
  curl -sS -o /dev/null --connect-timeout 4 --max-time 10 "https://$new/" || { echo "证书/HTTPS 检查失败，不修改。"; return 1; }
  if ! risk_check "$new"; then
    echo "警告：该域名命中当前客户端画像的不推荐规则，或检测到共享 CDN/边缘网络特征；不建议作为 Reality target。"
    read -r -p "如仍坚持使用请输入 RISK: " x
    [ "$x" = RISK ] || return 0
  fi
  echo "正在执行真实 Reality 回环握手自测..."
  if panel_reality_selftest "$new"; then
    echo "Reality 自测：PASS"
  else
    echo "Reality 自测：FAIL（目标不兼容或当前环境无法完成自测）"
    read -r -p "如仍坚持使用请输入 FORCE: " x
    [ "$x" = FORCE ] || return 0
  fi
  candidate="$(mktemp)"
  jq --arg h "$new" '.inbounds |= map(if ((.type=="vless" or .type=="anytls") and (.tls.reality.enabled==true)) then .tls.server_name=$h | .tls.reality.handshake.server=$h else . end)' "$CONFIG_PATH" >"$candidate"
  old_sni="${REALITY_SNI:-}"
  # apply_candidate 会先 sing-box check，重启失败则自动回滚工作配置。
  apply_candidate "$candidate" || return 1
  REALITY_SNI="$new"
  set_state REALITY_SNI "$new"
  source "$STATE_PATH"
  regen_uris || true
  regen_mihomo || true
  if [ -f /root/install-singbox-relay.sh ] && [ -n "$old_sni" ]; then
    old_re="${old_sni//./\\.}"
    sed -i "s|${old_re}|${new}|g" /root/install-singbox-relay.sh 2>/dev/null || true
  fi
  echo "已切换为 $new；节点链接已重新生成。"
}
uninstall_all(){
  read -r -p "确认卸载 sing-box 与 /etc/sing-box？输入 YES: " x; [ "$x" = YES ] || return 0
  if command -v systemctl >/dev/null 2>&1; then systemctl disable --now sing-box 2>/dev/null || true; rm -f /etc/systemd/system/sing-box.service; systemctl daemon-reload || true; else rc-service sing-box stop 2>/dev/null || true; rc-update del sing-box default 2>/dev/null || true; rm -f /etc/init.d/sing-box; fi
  rm -rf /etc/sing-box /usr/local/bin/sb /usr/bin/sb /root/node_names.txt
  echo "已卸载脚本配置。sing-box 二进制本身可能由官方安装器管理，可按其包管理方式卸载。"
}

if [ "${1:-}" = "doctor" ]; then doctor; exit $?; fi
if [ "${1:-}" = "update" ]; then safe_update; exit $?; fi

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
  echo "0) 退出"
  read -r -p "请选择: " c
  case "$c" in
    1) cat "$URI_PATH" 2>/dev/null || echo "链接文件不存在";;
    2) show_status;;
    3) show_logs;;
    4) sing-box check -c "$CONFIG_PATH";;
    5) service_restart;;
    6) edit_config;;
    7) echo "${REALITY_SNI:-未启用}";;
    8) change_reality;;
    9) echo -n "IPv4: "; curl -4 -fsS --max-time 7 https://api.ipify.org || echo "不可用"; echo; echo -n "IPv6: "; curl -6 -fsS --max-time 7 https://api64.ipify.org || echo "不可用"; echo;;
    10) [ "${ENABLE_SS:-false}" = true ] && reset_port ss-in PORT_SS "$PORT_SS" SS || echo "未启用 SS";;
    11) set_ss_mode;;
    12) [ "${ENABLE_HY2:-false}" = true ] && reset_port hy2-in PORT_HY2 "$PORT_HY2" Hysteria2 || echo "未启用 Hysteria2";;
    13) [ "${ENABLE_TUIC:-false}" = true ] && reset_port tuic-in PORT_TUIC "$PORT_TUIC" TUIC || echo "未启用 TUIC";;
    14) [ "${ENABLE_REALITY:-false}" = true ] && reset_port vless-reality-in PORT_REALITY "$PORT_REALITY" 'VLESS Reality' || echo "未启用 VLESS Reality";;
    15) [ "${ENABLE_ANYTLS:-false}" = true ] && reset_port anytls-reality-in PORT_ANYTLS "$PORT_ANYTLS" 'AnyTLS Reality' || echo "未启用 AnyTLS Reality";;
    16) if [ -f /root/install-singbox-relay.sh ]; then echo "/root/install-singbox-relay.sh"; echo "复制到线路机后执行：bash /root/install-singbox-relay.sh"; else echo "当前未生成（通常因为未启用 SS）。"; fi;;
    17) safe_update;;
    18) uninstall_all; exit 0;;
    19) cat "$CONFIG_PATH";;
    20) if command -v systemctl >/dev/null 2>&1; then systemctl start sing-box; else rc-service sing-box start; fi;;
    21) if command -v systemctl >/dev/null 2>&1; then systemctl stop sing-box; else rc-service sing-box stop; fi;;
    22) regen_uris && cat "$URI_PATH";;
    23) show_mihomo all;;
    24) echo "1) 全部片段  2) VLESS  3) SS  4) 完整 proxies: 区块"; read -r -p "选择 [默认 1]: " m; case "${m:-1}" in 2) osc52_copy vless;; 3) osc52_copy ss;; 4) osc52_copy full;; *) osc52_copy all;; esac;;
    25) regen_mihomo && show_mihomo all;;
    26) edit_mihomo_meta;;
    27) doctor;;
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
  sed -i -E "s|^REALITY_SNI=.*$|REALITY_SNI=$(printf %q "$REALITY_SNI")|" "$STATE_PATH"
  source "$STATE_PATH"
  generate_uris
  generate_mihomo_yaml || true
  ok "Reality target 已切换为 $REALITY_SNI；节点链接与 Mihomo YAML 已重建；备份：$backup"
  exit 0
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
  if $ENABLE_REALITY; then echo "VLESS Reality：${PORT_REALITY} / target=${REALITY_SNI} / client-profile=${REALITY_CLIENT_PROFILE:-cn}"; fi
  if $ENABLE_ANYTLS; then echo "AnyTLS Reality：${PORT_ANYTLS} / target=${REALITY_SNI}"; fi
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
  echo "管理命令：sb"
  echo "================================================"
}

main(){
  if [ "${1:-}" = "--change-reality-target" ]; then change_reality_target_mode; fi
  check_root; acquire_lock; detect_os
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
  show_summary
}

main "$@"

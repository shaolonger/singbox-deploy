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
#
# 目标 sing-box：1.13+；兼容当前 1.14+ 配置格式。
# ============================================================

SCRIPT_VERSION="2026.09.20-reality-safe-mihomo-v4"
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

# 默认值只用于兜底展示；真正安装 Reality 时仍会执行完整审计。
# 不再把 dl.google.com 设为默认：它虽有不错的 REALITY 握手特征，但本身是大型下载域名，
# 从“防 fallback 偷流量”角度并不理想。
DEFAULT_REALITY_SNI="www.google.com"

# 自动候选池故意混入多个不同运营方；运行时会按 TLS/H2、跨域跳转、共享 CDN、
# 真实 Reality 自测、ASN 接近性和握手中位数继续筛选。
# 高价值下载/静态域名可保留为诊断项，但会被 known_target_risk 排除出自动推荐。
REALITY_CANDIDATES=(
  "gateway.icloud.com"
  "www.google.com"
  "www.mozilla.org"
  "www.gnu.org"
  "www.debian.org"
  "www.freebsd.org"
  "www.kernel.org"
  "dl.google.com"
  "www.gstatic.com"
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
      apk add --no-cache bash curl ca-certificates openssl jq iproute2 coreutils bind-tools procps
      ;;
    debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y curl ca-certificates openssl jq iproute2 coreutils dnsutils procps
      ;;
    redhat)
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y curl ca-certificates openssl jq iproute coreutils bind-utils procps-ng
      else
        yum install -y curl ca-certificates openssl jq iproute coreutils bind-utils procps-ng
      fi
      ;;
    *) warn "未识别发行版；将尝试使用现有 curl/openssl/jq/ip/dig。" ;;
  esac
  local c
  for c in curl openssl jq; do command -v "$c" >/dev/null 2>&1 || die "缺少依赖：$c"; done
}

install_singbox(){
  if command -v sing-box >/dev/null 2>&1; then
    info "检测到：$(sing-box version 2>/dev/null | head -n1 || true)"
    local ans="${SINGBOX_REINSTALL:-}"
    if [ -z "$ans" ]; then read -r -p "是否更新/重新安装 sing-box？(y/N): " ans; fi
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then return 0; fi
  fi
  info "通过官方安装脚本安装 sing-box..."
  local tmp
  tmp="$(mktemp /tmp/sing-box-install.XXXXXX)"; TMP_FILES+=("$tmp")
  curl -fsSL --retry 3 --connect-timeout 8 https://sing-box.app/install.sh -o "$tmp" || die "下载 sing-box 官方安装脚本失败。"
  bash "$tmp"
  command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"
  ok "$(sing-box version 2>/dev/null | head -n1)"
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

normalize_sni(){ printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | sed 's/\.$//'; }
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

median_ms(){
  # 输入若干秒（小数），输出毫秒整数中位数
  printf '%s\n' "$@" | awk 'NF&&$1+0>0{printf "%.0f\n",$1*1000}' | sort -n | awk '{a[NR]=$1} END{if(NR==0){print 999999}else if(NR%2){print a[(NR+1)/2]}else{printf "%.0f\n",(a[NR/2]+a[NR/2+1])/2}}'
}

# ---------- Reality target 安全审计 ----------
resolve_cnames(){
  local host="$1"
  command -v dig >/dev/null 2>&1 || return 0
  # 跟随最多 5 层 CNAME，仅用于风险识别。
  local cur="$host" nxt i
  for i in 1 2 3 4 5; do
    nxt="$(dig +time=2 +tries=1 +short CNAME "$cur" 2>/dev/null | head -n1 | sed 's/\.$//' | tr '[:upper:]' '[:lower:]')"
    [ -n "$nxt" ] || break
    echo "$nxt"
    [ "$nxt" = "$cur" ] && break
    cur="$nxt"
  done
}

lookup_ipv4(){
  local h="$1" x
  command -v dig >/dev/null 2>&1 || return 1
  x="$(dig +time=2 +tries=1 +short A "$h" 2>/dev/null | awk '/^[0-9]+(\.[0-9]+){3}$/{print;exit}')"
  [ -n "$x" ] || return 1
  printf '%s' "$x"
}

asn_for_ipv4(){
  # 使用 Team Cymru 的 DNS ASN 查询；失败时仅返回空，不影响安装。
  local ip="$1" a b c d ans n
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  command -v dig >/dev/null 2>&1 || return 1
  IFS='.' read -r a b c d <<<"$ip"
  ans="$(dig +time=2 +tries=1 +short TXT "${d}.${c}.${b}.${a}.origin.asn.cymru.com" 2>/dev/null | head -n1 | tr -d '"' || true)"
  n="$(awk -F'|' '{gsub(/[[:space:]]/,"",$1); print $1}' <<<"$ans")"
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  printf 'AS%s' "$n"
}

cdn_risk_from_text(){
  local txt
  txt="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
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
  case "$host" in
    dl.google.com|*.dl.google.com) echo "HIGH|大型下载域名，fallback 可被重复下载消耗 VPS 流量"; return 0 ;;
    www.gstatic.com|*.gstatic.com) echo "HIGH|大型静态资源域名，fallback 滥用价值较高"; return 0 ;;
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

probe_tls_http(){
  # 输出：tls13|h2|cert_ok|redirect_ok|median_ms|risk|reason|cname_summary
  local host="$1" tlsout headers cnames krisk crisk risk reason target_ip target_asn
  local tls13="NO" h2="NO" cert="NO" redirect="YES" med=999999
  local -a times=()

  # 证书 + TLS1.3 + ALPN h2
  tlsout="$(printf '\n' | openssl s_client -connect "${host}:443" -servername "$host" -tls1_3 -alpn h2 2>&1 || true)"
  grep -Eq 'TLSv1\.3|TLS_AES_' <<<"$tlsout" && tls13="YES"
  grep -Eqi 'ALPN protocol: h2|ALPN: h2' <<<"$tlsout" && h2="YES"

  # curl 不使用 -k：握手成功即意味着系统 CA 验证通过。
  local out code redir t i
  for i in 1 2 3; do
    if out="$(curl -sS -o /dev/null --connect-timeout 4 --max-time 10 \
      -w '%{http_code}\t%{redirect_url}\t%{time_appconnect}' "https://${host}/" 2>/dev/null)"; then
      cert="YES"
      code="$(cut -f1 <<<"$out")"
      redir="$(cut -f2 <<<"$out")"
      t="$(cut -f3 <<<"$out")"
      awk -v x="$t" 'BEGIN{exit !(x>0)}' && times+=("$t") || true
      if [ -n "$redir" ]; then
        # 相对跳转仍属于同一主机；只有绝对 URL 跳到别的 hostname 才降级。
        if [[ "$redir" =~ ^https?:// ]]; then
          local rh
          rh="$(sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#' <<<"$redir" | tr '[:upper:]' '[:lower:]')"
          [ "$rh" = "$host" ] || redirect="NO"
        fi
      fi
    fi
  done
  if [ "${#times[@]}" -gt 0 ]; then med="$(median_ms "${times[@]}")"; fi

  headers="$(curl -sSI --connect-timeout 4 --max-time 8 "https://${host}/" 2>/dev/null | tr -d '\r' || true)"
  cnames="$(resolve_cnames "$host" | paste -sd ',' - || true)"
  krisk="$(known_target_risk "$host")"
  crisk="$(cdn_risk_from_text "${host} ${cnames} ${headers}")"
  if [[ "$krisk" == HIGH\|* ]]; then risk="HIGH"; reason="${krisk#HIGH|}"
  elif [[ "$crisk" == HIGH\|* ]]; then risk="HIGH"; reason="${crisk#HIGH|}"
  else risk="LOW"; reason="未发现常见共享 CDN 特征"; fi
  target_ip="$(lookup_ipv4 "$host" || true)"
  target_asn="$(asn_for_ipv4 "$target_ip" || true)"

  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$tls13" "$h2" "$cert" "$redirect" "$med" "$risk" "$reason" "${cnames:-无}" "${target_asn:-未知}"
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

  http="$(curl -sS --proxy "socks5h://127.0.0.1:${socks_port}" --connect-timeout 4 --max-time 10 -o /dev/null -w '%{http_code}' https://www.gstatic.com/generate_204 2>/dev/null || true)"
  kill "$cpid" "$spid" 2>/dev/null || true
  wait "$cpid" "$spid" 2>/dev/null || true
  TMP_PIDS=()
  [[ "$http" =~ ^(200|204)$ ]]
}

print_target_row(){
  printf '%-25s %-6s %-4s %-6s %-8s %-8s %-9s %-10s %s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}

select_reality_sni(){
  local forced="${SINGBOX_REALITY_SNI:-}" allow_risky="${SINGBOX_REALITY_ALLOW_RISKY:-0}"
  local host data tls h2 cert redir med risk reason cnames tasn self best="" best_med=999999
  local tmp any_self_pass=0 vps4 vps_asn="未知" best_same=-1 same
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
    [ "$tls" = YES ] && [ "$cert" = YES ] || die "指定 target 的 TLS 基础检查失败。"
    if [ "$risk" = HIGH ] && [ "$allow_risky" != 1 ]; then die "指定 target 被判定为高风险；如已充分了解风险，可设置 SINGBOX_REALITY_ALLOW_RISKY=1 强制使用。"; fi
    if [ "$self" != PASS ]; then warn "真实 Reality 自测未通过。可能是 target 不兼容，也可能是当前 sing-box 自测客户端兼容性问题。"; fi
    REALITY_SNI="$host"; return 0
  fi

  info "开始 Reality target 安全审计；高风险共享 CDN 不进入自动推荐。"
  echo
  echo "VPS ASN：$vps_asn（同 ASN 仅作为加分项；查询失败不影响安装）"
  print_target_row "TARGET" "TLS13" "H2" "CERT" "RT-DIR" "MEDIAN" "RISK" "ASN" "REALITY"
  print_target_row "-------------------------" "------" "----" "------" "--------" "--------" "---------" "----------" "-------"

  for host in "${REALITY_CANDIDATES[@]}"; do
    host="$(normalize_sni "$host")"
    data="$(probe_tls_http "$host")"
    IFS='|' read -r tls h2 cert redir med risk reason cnames tasn <<<"$data"
    self="SKIP"
    if [ "$tls" = YES ] && [ "$cert" = YES ] && [ "$risk" != HIGH ]; then
      if reality_selftest "$host"; then self="PASS"; any_self_pass=1; else self="FAIL"; fi
    fi
    print_target_row "$host" "$tls" "$h2" "$cert" "$redir" "${med}ms" "$risk" "$tasn" "$self"
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$host" "$tls" "$h2" "$cert" "$redir" "$med" "$risk" "$self" "$reason" "$cnames" "$tasn" >>"$tmp"
  done

  # 如果至少一个候选通过真实 Reality 自测，则只在 PASS 中选择；否则退化到静态 TLS 筛选。
  while IFS='|' read -r host tls h2 cert redir med risk self reason cnames tasn; do
    [ "$tls" = YES ] && [ "$h2" = YES ] && [ "$cert" = YES ] && [ "$risk" != HIGH ] || continue
    [ "$redir" = YES ] || continue
    if [ "$any_self_pass" -eq 1 ] && [ "$self" != PASS ]; then continue; fi
    same=0; [ "$vps_asn" != 未知 ] && [ "$tasn" = "$vps_asn" ] && same=1
    if [ "$same" -gt "$best_same" ] || { [ "$same" -eq "$best_same" ] && [ "$med" -lt "$best_med" ]; }; then
      best="$host"; best_med="$med"; best_same="$same"
    fi
  done <"$tmp"

  echo
  if [ -n "$best" ]; then
    if [ "$best_same" -eq 1 ]; then ok "自动推荐：$best（同 ASN；TLS 建连中位数约 ${best_med} ms）"; else ok "自动推荐：$best（TLS 建连中位数约 ${best_med} ms）"; fi
  else
    warn "没有候选目标满足全部保守条件，将要求手动输入。"
  fi
  echo "说明：自动推荐首先排除共享 CDN/已知风险，再比较兼容性和稳定性；不是单纯追求最低延迟。"
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
    if [ "$tls" != YES ] || [ "$cert" != YES ]; then warn "TLS 基础条件不满足，不建议使用。"; host=""; continue; fi
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
  $ENABLE_REALITY && info "VLESS YAML 名称：${NODE_REGION}｜${VLESS_ROLE}｜${NODE_ALIAS}"
  $ENABLE_SS && info "SS YAML 名称：${NODE_REGION}｜${SS_ROLE}｜${NODE_ALIAS}"
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
  openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
    -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
    -subj "/CN=www.bing.com" >/dev/null 2>&1
  chmod 600 "$CERT_DIR/privkey.pem" "$CERT_DIR/fullchain.pem"
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
    obj="$(jq -cn --arg pw "$PSK_HY2" --argjson p "$PORT_HY2" '{type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$p,users:[{name:"user",password:$pw}],tls:{enabled:true,alpn:["h3"],certificate_path:"/etc/sing-box/certs/fullchain.pem",key_path:"/etc/sing-box/certs/privkey.pem"}}')"
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
  mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
  if [ -f "$CONFIG_PATH" ]; then backup="${CONFIG_PATH}.bak.$(date +%Y%m%d_%H%M%S)"; cp -a "$CONFIG_PATH" "$backup"; fi
  install -m 600 "$candidate" "$CONFIG_PATH"
  if ! sing-box check -c "$CONFIG_PATH"; then
    [ -n "$backup" ] && cp -a "$backup" "$CONFIG_PATH"
    return 1
  fi
  LAST_CONFIG_BACKUP="$backup"
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
  $ENABLE_HY2 && echo "hy2://$(url_encode "$PSK_HY2")@${uri_host}:${PORT_HY2}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${suffix}" >>"$URI_PATH"
  $ENABLE_TUIC && echo "tuic://${UUID_TUIC}:$(url_encode "$PSK_TUIC")@${uri_host}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=www.bing.com&insecure=1#tuic${suffix}" >>"$URI_PATH"
  $ENABLE_REALITY && echo "vless://${UUID_REALITY}@${uri_host}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}#reality${suffix}" >>"$URI_PATH"
  $ENABLE_ANYTLS && echo "anytls://$(url_encode "$ANYTLS_PSK")@${uri_host}:${PORT_ANYTLS}/?security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUBLIC}&sid=${REALITY_SID}#anytls${suffix}" >>"$URI_PATH"
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
    udp: false
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
    sni: "www.bing.com"
    skip-cert-verify: true
    alpn:
      - h3
EOF_YAML
  fi

  if $ENABLE_TUIC; then
    cat >"$MIHOMO_TUIC_PATH" <<EOF_YAML
  - name: $(yaml_quote "$tname")
    type: tuic
    server: ${qhost}
    port: ${PORT_TUIC}
    uuid: $(yaml_quote "$UUID_TUIC")
    password: $(yaml_quote "$PSK_TUIC")
    sni: "www.bing.com"
    skip-cert-verify: true
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
  alpine) apk update; apk add --no-cache bash curl ca-certificates openssl jq coreutils ;;
  debian|ubuntu) export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y curl ca-certificates openssl jq coreutils ;;
  *) if command -v dnf >/dev/null 2>&1; then dnf install -y curl ca-certificates openssl jq coreutils; elif command -v yum >/dev/null 2>&1; then yum install -y curl ca-certificates openssl jq coreutils; fi ;;
esac

if ! command -v sing-box >/dev/null 2>&1; then
  t="$(mktemp)"; curl -fsSL --retry 3 https://sing-box.app/install.sh -o "$t"; bash "$t"; rm -f "$t"
fi
command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"

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
      "server_name":"__SNI__",
      "reality":{
        "enabled":true,
        "handshake":{"server":"__SNI__","server_port":443},
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
URI="vless://${UUID}@${UH}:${P}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=__SNI__&fp=chrome&pbk=${PUB}&sid=${SID}#relay"
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
    servername: "__SNI__"
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
  # 把当前安装器复制一份，供 sb 的 Reality 审计/修改功能复用。
  install -m 700 "$0" "${CONFIG_DIR}/installer-safe.sh" 2>/dev/null || true
  cat >"$SB_PATH" <<'SBEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
CONFIG_DIR="/etc/sing-box"; CONFIG_PATH="$CONFIG_DIR/config.json"; STATE_PATH="$CONFIG_DIR/install-state.env"; URI_PATH="$CONFIG_DIR/uris.txt"; MIHOMO_DIR="$CONFIG_DIR/mihomo"
[ "$(id -u)" -eq 0 ] || { echo "需要 root"; exit 1; }
[ -f "$STATE_PATH" ] && source "$STATE_PATH" || true
service_restart(){ sing-box check -c "$CONFIG_PATH" && { if command -v systemctl >/dev/null 2>&1; then systemctl restart sing-box; else rc-service sing-box restart; fi; }; }
show_status(){ if command -v systemctl >/dev/null 2>&1; then systemctl status sing-box --no-pager; else rc-service sing-box status; fi; }
show_logs(){ if command -v journalctl >/dev/null 2>&1; then journalctl -u sing-box -n 100 --no-pager; else tail -n 100 /var/log/messages 2>/dev/null || true; fi; }
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
  [ "${ENABLE_HY2:-false}" = true ] && echo "hy2://$(urlenc "$PSK_HY2")@${uh}:${PORT_HY2}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${suf}" >>"$URI_PATH"
  [ "${ENABLE_TUIC:-false}" = true ] && echo "tuic://${UUID_TUIC}:$(urlenc "$PSK_TUIC")@${uh}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=www.bing.com&insecure=1#tuic${suf}" >>"$URI_PATH"
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
    udp: false
YAML
    if [ "${SS_DIALER_PROXY_ENABLED:-false}" = true ]; then printf '    dialer-proxy: %s\n' "$(panel_yaml_quote "${SS_DIALER_PROXY:-中转}")" >>"$MIHOMO_DIR/ss.yaml"; fi
  fi
  if [ "${ENABLE_HY2:-false}" = true ]; then cat >"$MIHOMO_DIR/hysteria2.yaml" <<YAML
  - name: $(panel_yaml_quote "$hname")
    type: hysteria2
    server: ${qh}
    port: ${PORT_HY2}
    password: $(panel_yaml_quote "$PSK_HY2")
    sni: "www.bing.com"
    skip-cert-verify: true
    alpn:
      - h3
YAML
  fi
  if [ "${ENABLE_TUIC:-false}" = true ]; then cat >"$MIHOMO_DIR/tuic.yaml" <<YAML
  - name: $(panel_yaml_quote "$tname")
    type: tuic
    server: ${qh}
    port: ${PORT_TUIC}
    uuid: $(panel_yaml_quote "$UUID_TUIC")
    password: $(panel_yaml_quote "$PSK_TUIC")
    sni: "www.bing.com"
    skip-cert-verify: true
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
  local f="$1" b="${CONFIG_PATH}.bak.$(date +%Y%m%d_%H%M%S)"
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
  local b="${CONFIG_PATH}.bak.edit.$(date +%Y%m%d_%H%M%S)" ed
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
  code="$(curl -sS --proxy "socks5h://127.0.0.1:${lp}" --connect-timeout 4 --max-time 10 -o /dev/null -w '%{http_code}' https://www.gstatic.com/generate_204 2>/dev/null || true)"
  kill "$cpid" "$spid" 2>/dev/null || true; wait "$cpid" "$spid" 2>/dev/null || true; rm -rf "$d"
  [[ "$code" =~ ^(200|204)$ ]]
}
change_reality(){
  if [ "${ENABLE_REALITY:-false}" != true ] && [ "${ENABLE_ANYTLS:-false}" != true ]; then echo "未启用 Reality。"; return; fi
  local new tls candidate backup x
  echo "当前 target: ${REALITY_SNI:-unknown}"
  read -r -p "请输入新的 target 域名（留空取消）: " new
  [ -n "$new" ] || return 0
  new="$(printf '%s' "$new" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | sed 's/\.$//')"
  valid_host "$new" || { echo "域名格式无效"; return 1; }
  tls="$(printf '\n' | openssl s_client -connect "$new:443" -servername "$new" -tls1_3 -alpn h2 2>&1 || true)"
  grep -Eq 'TLSv1\.3|TLS_AES_' <<<"$tls" || { echo "未通过 TLS 1.3 检查，不修改。"; return 1; }
  grep -Eqi 'ALPN protocol: h2|ALPN: h2' <<<"$tls" || { echo "未协商 h2，不修改。"; return 1; }
  curl -sS -o /dev/null --connect-timeout 4 --max-time 10 "https://$new/" || { echo "证书/HTTPS 检查失败，不修改。"; return 1; }
  if ! risk_check "$new"; then
    echo "警告：检测到共享 CDN/边缘网络特征，存在 REALITY fallback 被滥用消耗流量的风险。"
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
  echo "17) 更新 sing-box"
  echo "18) 卸载"
  echo "19) 查看当前 config.json"
  echo "20) 启动服务"
  echo "21) 停止服务"
  echo "22) 重新生成节点链接"
  echo "23) 查看 Mihomo YAML（可直接粘贴到 proxies: 下）"
  echo "24) OSC 52 一键复制 Mihomo YAML 到本机剪贴板"
  echo "25) 重新生成 Mihomo YAML"
  echo "26) 修改 Mihomo 节点命名 / SS dialer-proxy"
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
    17) t="$(mktemp)"; curl -fsSL https://sing-box.app/install.sh -o "$t" && bash "$t" && rm -f "$t" && service_restart;;
    18) uninstall_all; exit 0;;
    19) cat "$CONFIG_PATH";;
    20) if command -v systemctl >/dev/null 2>&1; then systemctl start sing-box; else rc-service sing-box start; fi;;
    21) if command -v systemctl >/dev/null 2>&1; then systemctl stop sing-box; else rc-service sing-box stop; fi;;
    22) regen_uris && cat "$URI_PATH";;
    23) show_mihomo all;;
    24) echo "1) 全部片段  2) VLESS  3) SS  4) 完整 proxies: 区块"; read -r -p "选择 [默认 1]: " m; case "${m:-1}" in 2) osc52_copy vless;; 3) osc52_copy ss;; 4) osc52_copy full;; *) osc52_copy all;; esac;;
    25) regen_mihomo && show_mihomo all;;
    26) edit_mihomo_meta;;
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
  backup="${CONFIG_PATH}.bak.reality.$(date +%Y%m%d_%H%M%S)"; cp -a "$CONFIG_PATH" "$backup"
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
  $ENABLE_SS && echo "SS：${PORT_SS} / ${SS_METHOD} / 出口=${SS_IP_MODE}"
  $ENABLE_HY2 && echo "Hysteria2：${PORT_HY2}"
  $ENABLE_TUIC && echo "TUIC：${PORT_TUIC}"
  $ENABLE_REALITY && echo "VLESS Reality：${PORT_REALITY} / target=${REALITY_SNI}"
  $ENABLE_ANYTLS && echo "AnyTLS Reality：${PORT_ANYTLS} / target=${REALITY_SNI}"
  echo
  echo "节点链接："
  cat "$URI_PATH"
  echo
  $ENABLE_SS && echo "线路机脚本：/root/install-singbox-relay.sh"
  echo "Mihomo YAML（可直接粘贴到现有 proxies: 下）："
  cat "$MIHOMO_ALL_PATH" 2>/dev/null || true
  echo
  echo "Mihomo YAML 文件：$MIHOMO_ALL_PATH"
  echo "快捷导出：sb mihomo | sb mihomo vless | sb mihomo ss | sb mihomo full"
  echo "一键剪贴板：sb mihomo copy all（需本地终端允许 OSC 52）"
  echo 'Windows 本地复制：ssh root@VPS_IP "sb mihomo" | Set-Clipboard'
  echo "macOS 本地复制：ssh root@VPS_IP 'sb mihomo' | pbcopy"
  $ENABLE_ANYTLS && echo "提示：Mihomo 不支持 AnyTLS + Reality，因此 AnyTLS 不会出现在 Mihomo YAML 中。"
  echo "管理命令：sb"
  echo "================================================"
}

main(){
  if [ "${1:-}" = "--change-reality-target" ]; then change_reality_target_mode; fi
  check_root; detect_os
  info "系统：$OS (${OS_ID:-unknown})"
  install_deps
  mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"

  select_protocols
  prompt_node_name
  select_ss_method
  select_ss_ip_mode
  prompt_connection_host

  # Reality 真实自测依赖 sing-box，因此先安装核心，再选 target。
  install_singbox

  REALITY_SNI="$DEFAULT_REALITY_SNI"
  if $ENABLE_REALITY || $ENABLE_ANYTLS; then select_reality_sni; fi

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

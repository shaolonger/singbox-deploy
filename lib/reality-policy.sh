#!/usr/bin/env bash
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

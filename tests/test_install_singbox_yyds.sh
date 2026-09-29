#!/usr/bin/env bash
# Run on Linux with Bash 4+, jq, curl, OpenSSL and the script's normal dependencies.
# ShellCheck cannot track definitions loaded from the installer or extracted heredocs.
# shellcheck disable=SC1090,SC2034,SC2120
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/install-singbox-yyds.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The installer also supports `bash -c "$(curl ...)"`, so its entry point stays
# unconditional. Source every definition except the final main invocation.
source <(sed '$d' "$script")
trap 'rm -rf "$tmp"' EXIT

fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
extract_function(){
  awk -v name="$1" '$0 == name "(){" {inside=1} inside {print} inside && $0 == "}" {exit}' "$script"
}

# Every protocol combination must produce exactly the selected inbounds. The
# SS-specific DNS rules must never leak into other protocol configurations.
SS_METHOD=2022-blake3-aes-128-gcm PSK_SS=test-ss PORT_SS=21001
PSK_HY2=test-hy2 PORT_HY2=21002 HY2_BBR_PROFILE=standard HY2_OBFS=salamander HY2_OBFS_PASSWORD=test-obfs
UUID_TUIC=00000000-0000-4000-8000-000000000003 PSK_TUIC=test-tuic PORT_TUIC=21003
REALITY_SNI=example.org REALITY_PRIVATE=test-private REALITY_SID=1234567890abcdef
UUID_REALITY=00000000-0000-4000-8000-000000000004 PORT_REALITY=21004
ANYTLS_USER=user-test ANYTLS_PSK=test-anytls PORT_ANYTLS=21005
LOW_RESOURCE_MODE=false
for ((mask=1; mask<32; mask++)); do
  ((mask & 1)) && ENABLE_SS=true || ENABLE_SS=false
  ((mask & 2)) && ENABLE_HY2=true || ENABLE_HY2=false
  ((mask & 4)) && ENABLE_TUIC=true || ENABLE_TUIC=false
  ((mask & 8)) && ENABLE_REALITY=true || ENABLE_REALITY=false
  ((mask & 16)) && ENABLE_ANYTLS=true || ENABLE_ANYTLS=false
  for SS_IP_MODE in auto prefer_ipv6 ipv6_only; do
    build_config "$tmp/config.json"
    jq -e --argjson ss "$ENABLE_SS" --argjson hy2 "$ENABLE_HY2" \
      --argjson tuic "$ENABLE_TUIC" --argjson reality "$ENABLE_REALITY" \
      --argjson anytls "$ENABLE_ANYTLS" --arg mode "$SS_IP_MODE" '
      (.inbounds | map(.tag)) as $tags
      | (($tags | index("ss-in") != null) == $ss)
        and (($tags | index("hy2-in") != null) == $hy2)
        and (($tags | index("tuic-in") != null) == $tuic)
        and (($tags | index("vless-reality-in") != null) == $reality)
        and (($tags | index("anytls-reality-in") != null) == $anytls)
        and ((.dns.servers | any(.tag == "ss-local-dns")) == ($ss and $mode != "auto"))
        and ((.route.rules | any(.action == "resolve")) == ($ss and $mode != "auto"))
        and ((.route.rules | any(.action == "reject")) == ($ss and $mode == "ipv6_only"))
    ' "$tmp/config.json" >/dev/null || fail "config mask=$mask mode=$SS_IP_MODE"
  done
done

# An exact line for any parent domain must match, but a similar-looking suffix
# or child of the requested name must not.
printf 'example.org\nother.net\n' >"$tmp/gfw.txt"
REALITY_CLIENT_PROFILE=cn REALITY_GFWLIST_CHECK=1 REALITY_GFWLIST_CACHE="$tmp/gfw.txt"
reality_host_in_gfwlist www.example.org || fail 'parent domain did not match'
if reality_host_in_gfwlist notexample.org; then fail 'substring matched'; fi
if reality_host_in_gfwlist example.org.evil; then fail 'unrelated parent matched'; fi
eval "$(extract_function relay_gfw_bad)"
eval "$(extract_function panel_gfw_bad)"
RELAY_GFW="$tmp/gfw.txt" GFWLIST_PATH="$tmp/gfw.txt"
relay_gfw_bad www.example.org || fail 'relay parent domain did not match'
panel_gfw_bad www.example.org || fail 'panel parent domain did not match'
if relay_gfw_bad notexample.org || panel_gfw_bad notexample.org; then fail 'embedded domain substring matched'; fi

# An explicitly high-risk public candidate must not make external network calls.
known_target_risk(){ printf 'HIGH|test exclusion'; }
probe_tls_http(){ fail 'network probe called for excluded target'; }
audit_reality_one bad.example.org "$tmp/audit.row"
grep -Fq '|N/A|N/A|N/A|N/A|999999|HIGH|SKIP|test exclusion|' "$tmp/audit.row" || fail 'high-risk audit row'

# Mock only the process and HTTP boundary; execute the real installer and panel
# self-test functions, including their temporary config generation and cleanup.
pid_headroom_fast(){ printf '%s' "${MOCK_HEADROOM:-999}"; }
mem_available_kb(){ printf '999999'; }
prepare_reality_selftest(){
  SELFTEST_DIR="$tmp/installer-selftest"; mkdir -p "$SELFTEST_DIR"
  SELFTEST_PRIVATE=test-private SELFTEST_PUBLIC=test-public
  SELFTEST_SID=1234567890abcdef SELFTEST_UUID=00000000-0000-4000-8000-000000000004
}
rand_port(){
  if [ "$1" -eq 23000 ]; then RANDOM_PORT=25000; else RANDOM_PORT=45000; fi
  printf '%s\n' "$RANDOM_PORT"
}
sing-box(){
  case "$1" in
    generate) printf 'PrivateKey: test-private\nPublicKey: test-public\n' ;;
    run) [ "${MOCK_SB_ERROR:-0}" != 1 ] || printf 'ERROR mock startup failure\n' >&2; sleep 10 ;;
    *) return 1 ;;
  esac
}
curl(){
  if [ "${MOCK_REQUIRE_IPV4:-0}" = 1 ]; then
    local arg ipv4=false
    for arg in "$@"; do [ "$arg" != -4 ] || ipv4=true; done
    $ipv4 || fail 'Reality self-test did not force IPv4 on an IPv4-only VPS'
  fi
  printf '%s' "${MOCK_CURL_CODE:-200}"
  [ -z "${MOCK_CURL_ERRORS:-}" ] || printf '%s\n' "$MOCK_CURL_ERRORS" >&2
  return "${MOCK_CURL_RC:-0}"
}
REALITY_SELFTEST_MODE=auto MOCK_HEADROOM=999 MOCK_CURL_RC=0 MOCK_REQUIRE_IPV4=1
MOCK_CURL_CODE=200 MOCK_CURL_ERRORS=$'curl: (7) initial refusal\ncurl: (7) retried refusal' MOCK_SB_ERROR=0
reality_selftest example.org || fail "installer lost successful retry: $REALITY_SELFTEST_LAST_REASON"
MOCK_CURL_CODE=503 MOCK_CURL_ERRORS=""
reality_selftest example.org || fail 'installer rejected valid HTTP 503 response'
MOCK_CURL_CODE=200 MOCK_CURL_RC=7 MOCK_CURL_ERRORS='curl: (7) final failure' MOCK_SB_ERROR=1
if reality_selftest example.org; then fail 'installer ignored curl final error'; fi
[[ "$REALITY_SELFTEST_LAST_REASON" == *'curl rc=7'* && "$REALITY_SELFTEST_LAST_REASON" == *'mock startup failure'* ]] || fail 'installer diagnostics'
MOCK_HEADROOM=1
if reality_selftest example.org; then fail 'installer ignored low-resource guard'; else [ "$?" -eq 75 ] || fail 'installer did not defer'; fi

eval "$(extract_function panel_reality_selftest)"
panel_pid_headroom(){ printf '%s' "${MOCK_HEADROOM:-999}"; }
panel_mem_kb(){ printf '999999'; }
panel_rand_port(){
  if [ "$1" -eq 23000 ]; then PANEL_RANDOM_PORT=25001; else PANEL_RANDOM_PORT=45001; fi
  printf '%s\n' "$PANEL_RANDOM_PORT"
}
MOCK_HEADROOM=999 MOCK_CURL_RC=0 MOCK_CURL_CODE=200
MOCK_CURL_ERRORS='curl: (7) initial refusal' MOCK_SB_ERROR=0
panel_reality_selftest example.org || fail "panel lost successful retry: $PANEL_SELFTEST_REASON"
MOCK_CURL_RC=7 MOCK_SB_ERROR=1 MOCK_CURL_ERRORS='curl: (7) final failure'
if panel_reality_selftest example.org; then fail 'panel ignored curl final error'; fi
[[ "$PANEL_SELFTEST_REASON" == *'curl rc=7'* && "$PANEL_SELFTEST_REASON" == *'mock startup failure'* ]] || fail 'panel diagnostics'

# Empty redirect_url must keep the following TLS timing field in all three
# implementations. This is the common response for a target without a redirect.
known_target_risk(){ printf 'LOW|test'; }
eval "$(extract_function probe_tls_http)"
run_with_timeout(){ printf 'TLSv1.3\nALPN protocol: h2\n'; }
timeout(){ printf 'TLSv1.3\nALPN protocol: h2\n'; }
resolve_cnames(){ :; }
lookup_ipv4(){ :; }
asn_for_ipv4(){ printf '未知'; }
panel_cn_bad(){ return 1; }
panel_lookup_ipv4(){ return 1; }
panel_origin_info(){ return 1; }
curl(){
  case "$*" in
    *__SBMETA__*) printf 'HTTP/2 200\r\nserver: example\r\n\r\n\n__SBMETA__|200||0.125\n' ;;
    *__M__*) printf 'HTTP/2 200\r\nserver: example\r\n\r\n\n__M__|200||0.125\n' ;;
    *) printf '0.125' ;;
  esac
}
probe="$(probe_tls_http example.org)"
[[ "$probe" == 'YES|YES|YES|YES|125|'* ]] || fail "installer metadata fields shifted: $probe"
eval "$(extract_function panel_target_probe)"
panel_target_probe example.org
[[ "$PANEL_MED" == 125 && "$PANEL_CERT" == YES ]] || fail 'panel metadata fields shifted'

relay_script="$tmp/relay.sh"
awk '/^  cat >.*RELAYEOF/{inside=1;next} /^RELAYEOF$/{inside=0} inside {print}' "$script" >"$relay_script"
bash -n "$relay_script" || fail 'generated relay syntax'
relay_function(){ awk -v name="$1" '$0 == name "(){" {inside=1} inside {print} inside && $0 == "}" {exit}' "$relay_script"; }
eval "$(relay_function relay_seconds_to_ms)"
eval "$(relay_function relay_probe_sni)"
eval "$(relay_function rand_port)"
relay_validate_sni(){ return 0; }
relay_cn_ok(){ return 0; }
relay_target_asn(){ printf 'AS0'; }
relay_port_in_use(){ return 1; }
dig(){ :; }
relay_probe_sni example.org >"$tmp/relay-probe" || fail 'relay rejected valid metadata'
[[ "$(cat "$tmp/relay-probe")" == '125|AS0' ]] || fail 'relay metadata fields shifted'
curl(){ return 7; }
if relay_probe_sni example.org >"$tmp/relay-probe"; then fail 'relay accepted failed curl transfer'; fi
port="$(rand_port)"
[[ "$port" =~ ^[0-9]+$ ]] || fail "relay port has invalid escaping: $port"

# Bulk state update keeps unrelated settings and safely writes empty values.
eval "$(extract_function set_state_many)"
CONFIG_DIR="$tmp/state"; STATE_PATH="$CONFIG_DIR/install-state.env"
mkdir -p "$CONFIG_DIR"
printf 'UNCHANGED=old\nREALITY_SNI=old.example\n' >"$STATE_PATH"
set_state_many REALITY_SNI new.example REALITY_SELECTED_SCORE ''
( source "$STATE_PATH"; [[ "$UNCHANGED" == old && "$REALITY_SNI" == new.example && "$REALITY_SELECTED_SCORE" == '' ]] ) || fail 'bulk state update'
[[ "$(grep -c '^REALITY_SNI=' "$STATE_PATH")" == 1 ]] || fail 'duplicate state key'

# Fully provisioned Debian installs should not run an expensive apt update.
OS=debian
apt-get(){ fail 'apt called although required dependencies are installed'; }
install_deps

# Atomic config switch restores the old file if post-install validation fails.
CONFIG_DIR="$tmp/atomic"; CONFIG_PATH="$CONFIG_DIR/config.json"; BACKUP_DIR="$CONFIG_DIR/backups"
mkdir -p "$BACKUP_DIR"
printf 'old\n' >"$CONFIG_PATH"
candidate="$CONFIG_DIR/.candidate.first"
printf 'new\n' >"$candidate"
sing-box(){ [[ "$3" != "$CONFIG_PATH" ]]; }
if install_config_atomic "$candidate"; then fail 'accepted failed post-install validation'; fi
[[ "$(cat "$CONFIG_PATH")" == old ]] || fail 'atomic rollback did not restore config'
candidate="$CONFIG_DIR/.candidate.second"
printf 'new\n' >"$candidate"
sing-box(){ return 0; }
install_config_atomic "$candidate"
[[ "$(cat "$CONFIG_PATH")" == new && ! -e "$candidate" ]] || fail 'atomic switch did not move candidate'

printf 'PASS: 93 config combinations, domain matching, high-risk skip, self-tests, metadata, relay, state, dependencies, atomic rollback\n'

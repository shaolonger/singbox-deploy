#!/usr/bin/env bash
# Behavioral regression tests for the shared REALITY policy. Network and Go
# process boundaries are mocked; policy decisions and generated JSON are real.
# shellcheck disable=SC1090,SC2034,SC2218
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/install-singbox-yyds.sh"
tmp="$(mktemp -d)"
policy_test_dir="$tmp"
trap 'rm -rf "$tmp"' EXIT
source <(sed '$d' "$script")
source "$root/lib/reality-policy.sh"
trap 'rm -rf "$tmp"' EXIT

fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
row(){
  # host, ASN, elapsed ms, endpoint, status
  printf '%s|YES|YES|YES|YES|%s|CLEAR|%s|test|none|%s|%s|4|UNMEASURED|NO_RULE_MATCH|3|3|PASS\n' \
    "$1" "$3" "${5:-PENDING}" "$2" "$4"
}
rp_pid_headroom(){ printf '999999'; }
rp_mem_kb(){ printf '999999'; }
for reserved in 127.0.0.1 10.0.0.1 198.18.1.1 192.0.2.44 ::1 2001:db8::44; do
  if rp_public_ip "$reserved"; then fail "reserved target admitted: $reserved"; fi
done
rp_public_ip 1.1.1.1 && rp_public_ip 2606:4700:4700::1111 || fail 'public target rejected'
# Remaining isolated fixtures use documentation IPs instead of real services.
rp_public_ip(){ return 0; }

# A slower, verified same-ASN target must beat a fast cross-ASN fallback.
{
  row fast.example AS64501 18 192.0.2.10 PASS
  row near.example AS64500 420 192.0.2.20 PASS
  row unknown.example 未知 1 192.0.2.30 PASS
} >"$tmp/ranking"
best="$(rp_best_row "$tmp/ranking" AS64500 PASS)"
[[ "$best" == near.example\|* ]] || fail "same-ASN target lost to a fast fallback: $best"
rp_topology AS64501 AS64500 >"$tmp/topology"
[[ "$(cat "$tmp/topology")" == cross-asn ]] || fail 'cross-ASN fallback was not identified'

# A bounded comparison must continue after the first PASS and leave candidates
# beyond its budget untested instead of inventing a successful verification.
{
  row one.example AS64500 20 192.0.2.1
  row two.example AS64500 30 192.0.2.2
  row three.example AS64501 10 192.0.2.3
  row four.example AS64501 40 192.0.2.4
} >"$tmp/pool"
rp_selftest(){ printf '%s\n' "$1" >>"$tmp/tested"; RP_TEST_REASON='mock pass'; return 0; }
rp_test_pool "$tmp/pool" AS64500 3
[[ "$(wc -l <"$tmp/tested")" -eq 3 ]] || fail 'comparison stopped at first PASS or exceeded its limit'
[[ "$(awk -F'|' '$8=="PASS" {n++} END{print n+0}' "$tmp/pool")" -eq 3 ]] || fail 'PASS records do not match actual test count'
[[ "$(awk -F'|' '$8=="PENDING" {n++} END{print n+0}' "$tmp/pool")" -eq 1 ]] || fail 'untested candidate lost PENDING status'

# Resource deferral is not successful verification, and it stops further Go
# process attempts so constrained VPSes remain usable.
row defer.example AS64500 10 192.0.2.5 >"$tmp/deferred"
row after.example AS64500 20 192.0.2.6 >>"$tmp/deferred"
: >"$tmp/tested"
rp_selftest(){ printf '%s\n' "$1" >>"$tmp/tested"; RP_TEST_REASON='mock resource limit'; return 75; }
rc=0
rp_test_pool "$tmp/deferred" AS64500 3 || rc=$?
[[ "$rc" -eq 75 ]] || fail "resource deferral returned $rc"
[[ "$(wc -l <"$tmp/tested")" -eq 1 ]] || fail 'resource deferral continued testing'
[[ "$(awk -F'|' '$8=="PASS" {n++} END{print n+0}' "$tmp/deferred")" -eq 0 ]] || fail 'resource deferral became PASS'
[[ "$(awk -F'|' '$8=="DEFERRED" {n++} END{print n+0}' "$tmp/deferred")" -eq 1 ]] || fail 'resource deferral was not recorded'

# Unpinned probes may fall back to one IPv6 endpoint when IPv4 fails, while
# pinned health checks never silently migrate to another endpoint.
(
  source "$root/lib/reality-policy.sh"
  rp_dns_ips(){ printf '%s\n' 1.1.1.1 8.8.8.8 2606:4700:4700::1111; }
  rp_probe_endpoint(){ printf '%s\n' "$5" >>"$policy_test_dir/families"; RP_IP="$5"; RP_CLIENT=UNMEASURED; if [[ "$5" == *:* ]]; then RP_COMPAT=PASS; else RP_COMPAT=FAIL; fi; }
  rp_probe cover.example global '' 未知
  [[ "$RP_IP" == 2606:4700:4700::1111 && "$(wc -l <"$policy_test_dir/families")" -eq 2 ]] || fail 'family fallback was unbounded or did not reach IPv6'
  : >"$policy_test_dir/families"
  rp_probe cover.example global '' 未知 1.1.1.1
  [[ "$RP_IP" == 1.1.1.1 && "$(wc -l <"$policy_test_dir/families")" -eq 1 ]] || fail 'pinned probe migrated endpoints'
)
(
  source "$root/lib/reality-policy.sh"
  rp_dns_ips(){ printf '%s\n' 1.1.1.1 8.8.8.8 2606:4700:4700::1111; }
  rp_dns_contains cover.example 8.8.8.8 || fail 'multi-address DNS incorrectly reported drift'
  rp_dns_contains cover.example 2606:4700:4700:0:0:0:0:1111 || fail 'equivalent IPv6 spelling incorrectly reported drift'
)

# Main installer applies the same ordering and persists the measured pin.
(
  refresh_reality_gfwlist(){ :; }
  rp_vps_identity(){ printf '192.0.2.100|AS64500|192.0.2.0/24'; }
  discover_reality_candidates(){ : >"$3"; }
  resolve_reality_audit_jobs(){ printf 1; }
  rp_public_candidates(){ printf '%s\n' fast.example near.example backup.example fourth.example; }
  rp_probe_row(){
    case "$1" in
      near.example) row "$1" AS64500 420 192.0.2.20 ;;
      *) row "$1" AS64501 18 192.0.2.10 ;;
    esac
  }
  rp_selftest(){ printf '%s\n' "$1" >>"$policy_test_dir/main-tested"; return 0; }
  CONNECTION_HOST=192.0.2.100 REALITY_CLIENT_PROFILE=cn REALITY_DISCOVERY_CACHE="$policy_test_dir/discovery"
  REALITY_CANDIDATES_CN_EXTENDED=()
  select_reality_sni <<<"" >"$policy_test_dir/main-selection"
  [[ "$REALITY_SNI" == near.example && "$REALITY_TARGET_IP" == 192.0.2.20 ]] || fail 'main selection did not preserve same-ASN audited endpoint'
  [[ "$(wc -l <"$policy_test_dir/main-tested")" -eq 3 ]] || fail 'main selection did not compare three candidates'
  grep -q '已通过的备选' "$policy_test_dir/main-selection" || fail 'main selection omitted verified alternatives'
  cleanup
)
# Historical discovery no longer rejects otherwise eligible hosts solely for
# missing age/rank metadata, and malformed optional fields cannot shift columns.
(
  source "$root/lib/reality-policy.sh"
  rp_mem_kb(){ printf 999999; }
  curl(){ printf '%s' '{"results":[{"page":{"domain":"fresh.example","url":"https://fresh.example/","status":200,"tlsValidDays":30}},{"page":{"domain":"bad.example","url":"https://bad.example/","status":200,"tlsValidDays":30},"verdicts":{"malicious":true}}]}'; }
  rp_discover_candidates AS64500 '' "$policy_test_dir/discovered"
  grep -Fxq 'fresh.example|dynamic-asn' "$policy_test_dir/discovered" || fail 'missing age/rank wrongly excluded discovered host'
  if grep -q bad.example "$policy_test_dir/discovered"; then fail 'malicious source entered candidate pool'; fi
)
# Configured ingress identity must not silently become a different egress IP.
(
  source "$root/lib/reality-policy.sh"
  rp_origin_info(){ printf 'AS64500|192.0.2.0/24'; }
  rp_resolve_ip(){ return 1; }
  curl(){ fail 'configured identity unexpectedly fell back to egress'; }
  [[ "$(rp_vps_identity 192.0.2.100)" == '192.0.2.100|AS64500|192.0.2.0/24' ]] || fail 'configured ingress identity changed'
  [[ "$(rp_vps_identity missing.example)" == '未知|未知|' ]] || fail 'unresolved ingress silently used egress identity'
)

# Exercise the actual shared local self-test too. Only its external boundaries
# are fake: generated config, curl exit handling and scope declarations are real.
(
  source "$root/lib/reality-policy.sh"
  rp_pid_headroom(){ printf '%s' "${MOCK_TEST_HEADROOM:-999999}"; }
  rp_mem_kb(){ printf '999999'; }
  rp_free_port(){ if [ "$1" -eq 23000 ]; then RP_PORT=25001; else RP_PORT=45001; fi; }
  sing-box(){
    case "$1" in
      generate) printf 'PrivateKey: test-private\nPublicKey: test-public\n' ;;
      run) sleep 10 ;;
      *) return 1 ;;
    esac
  }
  jq(){ command jq "$@" | tee "$policy_test_dir/local-selftest-config.json"; }
  curl(){
    printf '%s\n' "$@" >"$policy_test_dir/local-selftest-curl"
    printf '200'
    printf 'curl: (7) initial listener refusal\n' >&2
    return "${MOCK_LOCAL_CURL_RC:-0}"
  }
  SINGBOX_REALITY_SELFTEST_MODE=auto
  rp_selftest cover.example 192.0.2.44 || fail "valid no-newline curl response failed: $RP_TEST_REASON"
  [[ "$RP_TEST_SCOPE" == local-vless-reality ]] || fail 'shared self-test did not declare its local VLESS scope'
  command jq -e '.inbounds[] | select(.tag=="rs") | .tls.server_name=="cover.example" and .tls.reality.handshake.server=="192.0.2.44"' "$policy_test_dir/local-selftest-config.json" >/dev/null || fail 'self-test handshake endpoint drifted from its SNI'
  grep -Fxq 'cover.example:443:192.0.2.44' "$policy_test_dir/local-selftest-curl" || fail 'self-test HTTPS did not use its selected endpoint'
  MOCK_LOCAL_CURL_RC=35
  if rp_selftest cover.example 192.0.2.44; then fail 'shared self-test ignored failed curl transfer'; fi
  MOCK_LOCAL_CURL_RC=0 MOCK_TEST_HEADROOM=1
  local_rc=0
  rp_selftest cover.example 192.0.2.44 || local_rc=$?
  [[ "$local_rc" -eq 75 ]] || fail 'shared self-test did not defer under resource pressure'
)

# Each static observation must use one pinned endpoint despite a proxy in the
# environment and DNS advertising a different address. The curl stub honors its
# write-out format, rather than returning a hand-crafted policy record.
dig(){
  local arg
  for arg in "$@"; do
    case "$arg" in
      TXT) printf '"64500 | 192.0.2.0/24 | ZZ | test | 2020-01-01"\n'; return 0 ;;
      A) printf '192.0.2.99\n'; return 0 ;;
      AAAA) printf '2001:db8::99\n'; return 0 ;;
      CNAME) return 0 ;;
    esac
  done
}
timeout(){ printf '%s\n' "$@" >>"$tmp/openssl-args"; printf 'TLSv1.3\nALPN protocol: h2\n'; }
curl(){
  local arg previous='' format='' header_dest='' out_dest='' headers=$'HTTP/2 200\r\nserver: test\r\n\r\n'
  [ "${MOCK_SHARED_EDGE:-0}" != 1 ] || headers+=$'cf-ray: test\r\n'
  printf '%s\n' "$@" >>"$tmp/curl-args"
  for arg in "$@"; do
    case "$previous" in
      -w|--write-out) format="$arg" ;;
      -D|--dump-header) header_dest="$arg" ;;
      -o|--output) out_dest="$arg" ;;
    esac
    previous="$arg"
  done
  if [[ "$*" == *stat.ripe.net* ]]; then
    printf '{"data":{"asns":[64500],"prefix":"192.0.2.0/24"}}'
    return 0
  fi
  if [ "$header_dest" = '-' ]; then printf '%s' "$headers"; elif [ -n "$header_dest" ]; then printf '%s' "$headers" >"$header_dest"; fi
  if [ -n "$out_dest" ] && [ "$out_dest" != /dev/null ]; then : >"$out_dest"; fi
  format="${format//\%\{http_code\}/200}"
  format="${format//\%\{redirect_url\}/}"
  format="${format//\%\{time_appconnect\}/0.125}"
  format="${format//\%\{time_connect\}/0.050}"
  format="${format//\%\{time_namelookup\}/0.000}"
  format="${format//\%\{remote_ip\}/${MOCK_REMOTE_IP:-192.0.2.44}}"
  format="${format//\%\{ssl_verify_result\}/0}"
  printf '%b' "$format"
  return "${MOCK_CURL_RC:-0}"
}
export HTTPS_PROXY='http://must-not-be-used.invalid:8080'
export ALL_PROXY="$HTTPS_PROXY"
: >"$tmp/gfw-empty"
MOCK_REMOTE_IP=192.0.2.44
rp_probe cover.example cn "$tmp/gfw-empty" AS64500 "$MOCK_REMOTE_IP"
[[ "$RP_IP" == 192.0.2.44 && "$RP_FAMILY" == 4 ]] || fail 'probe did not retain pinned IPv4 endpoint'
[[ "$RP_COMPAT" == PASS && "$RP_CLIENT" == UNMEASURED ]] || fail 'probe confused local compatibility with client-path evidence'
grep -Fxq -- '--noproxy' "$tmp/curl-args" && grep -Fxq '*' "$tmp/curl-args" || fail 'static curl did not bypass environment proxies'
grep -Fxq 'cover.example:443:192.0.2.44' "$tmp/curl-args" || fail 'curl did not pin hostname to the selected IPv4'
grep -Fxq '192.0.2.44:443' "$tmp/openssl-args" || fail 'OpenSSL used a different IPv4 endpoint'
: >"$tmp/curl-args"; : >"$tmp/openssl-args"
MOCK_REMOTE_IP=2001:db8::44
rp_probe cover.example cn "$tmp/gfw-empty" AS64500 "$MOCK_REMOTE_IP"
[[ "$RP_IP" == 2001:db8::44 && "$RP_FAMILY" == 6 ]] || fail 'probe did not retain pinned IPv6 endpoint'
grep -Fxq 'cover.example:443:[2001:db8::44]' "$tmp/curl-args" || fail 'curl IPv6 --resolve syntax is invalid'
grep -Fxq '[2001:db8::44]:443' "$tmp/openssl-args" || fail 'OpenSSL IPv6 endpoint syntax is invalid'
MOCK_CURL_RC=35
rp_probe cover.example cn "$tmp/gfw-empty" AS64500 "$MOCK_REMOTE_IP"
[[ "$RP_COMPAT" == FAIL && "$RP_ELIGIBLE" == NO ]] || fail 'failed curl transfer became compatible'
MOCK_CURL_RC=0
MOCK_REMOTE_IP=192.0.2.99
rp_probe cover.example cn "$tmp/gfw-empty" AS64500 192.0.2.44
[[ "$RP_COMPAT" == FAIL && "$RP_ELIGIBLE" == NO ]] || fail 'probe accepted a remote endpoint different from its TLS-tested pin'
MOCK_REMOTE_IP=192.0.2.44 MOCK_SHARED_EDGE=1
rp_probe cover.example cn "$tmp/gfw-empty" AS64500 "$MOCK_REMOTE_IP"
[[ "$RP_COMPAT" == PASS && "$RP_ABUSE" == SHARED_EDGE && "$RP_ELIGIBLE" == NO ]] || fail 'shared-edge abuse classification became a protocol failure'
MOCK_SHARED_EDGE=0
printf 'cover.example\n' >"$tmp/gfw-flagged"
rp_probe cover.example cn "$tmp/gfw-flagged" AS64500 "$MOCK_REMOTE_IP"
[[ "$RP_CLIENT" == LIST_FLAGGED && "$RP_COMPAT" == UNTESTED && "$RP_ELIGIBLE" == NO ]] || fail 'list evidence was represented as measured protocol/client failure'

# The hostname remains the certificate/SNI name while the handshake endpoint
# uses the exact IP that was selected and probed.
ENABLE_SS=false ENABLE_HY2=false ENABLE_TUIC=false ENABLE_REALITY=true ENABLE_ANYTLS=true
LOW_RESOURCE_MODE=false
REALITY_SNI=cover.example REALITY_TARGET_IP=192.0.2.44 REALITY_TARGET_FAMILY=4
REALITY_PRIVATE=test-private REALITY_SID=1234567890abcdef
UUID_REALITY=00000000-0000-4000-8000-000000000004 PORT_REALITY=21004
ANYTLS_USER=test ANYTLS_PSK=test-anytls PORT_ANYTLS=21005
build_config "$tmp/pinned-config.json"
jq -e --arg name "$REALITY_SNI" --arg ip "$REALITY_TARGET_IP" '
  [.inbounds[] | select(.type=="vless" or .type=="anytls")]
  | length==2 and all(.[]; .tls.server_name==$name and .tls.reality.handshake.server==$ip)
' "$tmp/pinned-config.json" >/dev/null || fail 'production SNI and handshake IP were not separated'

# Run the actual generated panel health function with observations mocked at its
# boundary. Neither a scheduled warning nor a deep check may migrate settings.
panel_source="${POLICY_TEST_PANEL_SOURCE:-$script}"
extract_panel_function(){ awk -v name="$1" '$0 == name "(){" {inside=1} inside {print} inside && $0 == "}" {exit}' "$panel_source"; }
eval "$(extract_panel_function reality_health)"
eval "$(extract_panel_function panel_reality_selftest)"
panel_current_asn(){ printf '192.0.2.100|AS64500|192.0.2.0/24'; }
panel_refresh_gfwlist(){ :; }
service_restart(){ fail 'health check restarted service'; }
change_reality(){ fail 'health check changed SNI'; }
apply_candidate(){ fail 'health check changed configuration'; }
set_state_many(){ fail 'health check changed persisted state'; }
rp_probe(){
  printf '%s|%s\n' "$1" "${5:-}" >"$policy_test_dir/health-probe"
  RP_TLS13=YES RP_H2=YES RP_CERT=YES RP_REDIRECT=YES RP_MS=125 RP_ASN=AS64500
  RP_IP="${5:-192.0.2.44}" RP_FAMILY=4 RP_RULE=CLEAR RP_CLIENT=UNMEASURED
  RP_ABUSE=NO_RULE_MATCH RP_REASON='mock endpoint observation' RP_OK=3 RP_TOTAL=3
  RP_COMPAT=PASS RP_TOPOLOGY=same-asn RP_ELIGIBLE=YES
}
rp_resolve_ip(){ printf '%s' "${MOCK_DNS_IP:-192.0.2.44}"; }
rp_dns_contains(){ [ "${MOCK_DNS_IP:-192.0.2.44}" = "$2" ]; }
rp_selftest(){
  printf '%s|%s\n' "$1" "$2" >>"$policy_test_dir/health-selftest"
  RP_TEST_REASON='mock local VLESS+REALITY only'
  return "${MOCK_HEALTH_SELFTEST_RC:-0}"
}
ENABLE_REALITY=true ENABLE_ANYTLS=true REALITY_CLIENT_PROFILE=cn
REALITY_SNI=cover.example REALITY_TARGET_IP=192.0.2.44 REALITY_SELECTED_ASN=AS64500
HEALTH_PATH="$tmp/health.json" GFWLIST_PATH="$tmp/gfw-empty"
reality_health --scheduled >"$tmp/health-output"
[[ ! -s "$tmp/health-output" && ! -e "$tmp/health-selftest" ]] || fail 'scheduled check was noisy or ran a deep self-test'
[[ "$(cat "$tmp/health-probe")" == 'cover.example|192.0.2.44' ]] || fail 'health did not probe the production pin'
jq -e '.status=="OK" and .client_path=="UNMEASURED" and .selftest_scope=="local-vless-reality" and .anytls_application=="UNTESTED" and .local_selftest==null and .automatically_switched==false' "$HEALTH_PATH" >/dev/null || fail 'scheduled health scope is misleading'
MOCK_DNS_IP=192.0.2.77
reality_health --scheduled >"$tmp/health-output"
jq -e '.status=="WARN" and .dns_drift=="YES" and .endpoint_ip=="192.0.2.44" and .automatically_switched==false' "$HEALTH_PATH" >/dev/null || fail 'DNS drift silently migrated or was not reported'
[[ "$REALITY_SNI" == cover.example && "$REALITY_TARGET_IP" == 192.0.2.44 ]] || fail 'health mutated active target'
MOCK_DNS_IP=192.0.2.44
reality_health --deep >"$tmp/health-output"
[[ "$(cat "$tmp/health-selftest")" == 'cover.example|192.0.2.44' ]] || fail 'deep health did not test the production pin'
jq -e '.local_selftest=="PASS" and .client_path=="UNMEASURED" and .anytls_application=="UNTESTED"' "$HEALTH_PATH" >/dev/null || fail 'local PASS was promoted to a client/AnyTLS verification'
MOCK_HEALTH_SELFTEST_RC=75
reality_health --deep >"$tmp/health-output"
jq -e '.status=="WARN" and .local_selftest=="DEFERRED" and .local_selftest!="PASS" and .automatically_switched==false' "$HEALTH_PATH" >/dev/null || fail 'deep health resource deferral was misreported'

REALITY_TARGET_IP=''
reality_health --scheduled >"$tmp/health-output"
jq -e '.status=="WARN" and .automatically_switched==false' "$HEALTH_PATH" >/dev/null || fail 'legacy unpinned state was not reported'
[[ -z "$REALITY_TARGET_IP" ]] || fail 'legacy health silently migrated target'

# A real panel switch updates both protocols and persists the pin; existing
# imported clients are explicitly told to synchronize the changed serverName.
(
  eval "$(extract_panel_function change_reality)"
  eval "$(extract_panel_function set_state_many)"
  valid_host(){ rp_valid_host "$1"; }
  panel_probe_summary(){ :; }
  panel_reality_selftest(){ PANEL_SELFTEST_REASON='mock local check'; return 0; }
  apply_candidate(){ cp "$1" "$CONFIG_PATH"; rm -f "$1"; }
  regen_uris(){ :; }; regen_mihomo(){ :; }
  CONFIG_DIR="$policy_test_dir/switch"; mkdir -p "$CONFIG_DIR"; CONFIG_PATH="$CONFIG_DIR/config.json"; STATE_PATH="$CONFIG_DIR/install-state.env"
  cp "$policy_test_dir/pinned-config.json" "$CONFIG_PATH"
  printf 'ENABLE_REALITY=true\nENABLE_ANYTLS=true\n' >"$STATE_PATH"
  REALITY_SNI=old.example REALITY_TARGET_IP=192.0.2.44
  change_reality new.example manual 192.0.2.55 4 AS64500 >"$policy_test_dir/switch-output"
  jq -e '[.inbounds[] | select(.type=="vless" or .type=="anytls")] | all(.[]; .tls.server_name=="new.example" and .tls.reality.handshake.server=="192.0.2.55")' "$CONFIG_PATH" >/dev/null || fail 'panel switch did not update both REALITY protocols'
  source "$STATE_PATH"
  [[ "$REALITY_TARGET_IP" == 192.0.2.55 && "$REALITY_SELECTED_SELFTEST" == PASS ]] || fail 'panel switch did not save endpoint and verification'
  grep -q '客户端.*serverName' "$policy_test_dir/switch-output" || fail 'panel switch omitted client synchronization notice'
)

# The lightweight upgrade path preserves the executing release identifier,
# refreshes generated tools and atomically updates the existing REALITY config.
(
  check_root(){ :; }; acquire_lock(){ :; }; detect_os(){ :; }; install_deps(){ :; }
  CONFIG_DIR="$policy_test_dir/upgrade"; mkdir -p "$CONFIG_DIR"; CONFIG_PATH="$CONFIG_DIR/config.json"; STATE_PATH="$CONFIG_DIR/install-state.env"; BACKUP_DIR="$CONFIG_DIR/backups"
  cp "$policy_test_dir/pinned-config.json" "$CONFIG_PATH"
  printf 'SCRIPT_VERSION=old-release\nENABLE_REALITY=true\nENABLE_ANYTLS=true\n' >"$STATE_PATH"
  SCRIPT_VERSION=new-release
  select_reality_sni(){ REALITY_SNI=new.example; REALITY_TARGET_IP=192.0.2.66; }
  sing-box(){ return 0; }; systemctl(){ return 0; }
  save_state(){ printf 'SCRIPT_VERSION=%q\n' "$SCRIPT_VERSION" >"$STATE_PATH"; }
  generate_uris(){ :; }; generate_mihomo_yaml(){ :; }
  generate_relay_installer(){ printf 'relay\n' >>"$policy_test_dir/upgraded-tools"; }
  install_sb_panel(){ printf 'panel\n' >>"$policy_test_dir/upgraded-tools"; }
  setup_reality_health_schedule(){ printf 'health\n' >>"$policy_test_dir/upgraded-tools"; }
  change_reality_target_mode
) >"$tmp/upgrade-output"
grep -Fxq 'SCRIPT_VERSION=new-release' "$policy_test_dir/upgrade/install-state.env" || fail 'old state overwrote executing release version'
[[ "$(wc -l <"$policy_test_dir/upgraded-tools")" -eq 3 ]] || fail 'upgrade did not refresh relay, panel and health schedule'
jq -e '[.inbounds[] | select(.type=="vless" or .type=="anytls")] | all(.[]; .tls.server_name=="new.example" and .tls.reality.handshake.server=="192.0.2.66")' "$policy_test_dir/upgrade/config.json" >/dev/null || fail 'upgrade did not preserve pinned REALITY configuration'

printf 'PASS: topology priority, bounded comparisons, resource deferral, pinned probes/config, health scope and no auto-switch\n'

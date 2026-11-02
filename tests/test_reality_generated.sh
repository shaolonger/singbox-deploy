#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2034
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/install-singbox-yyds.sh"
tmp="$(mktemp -d)"
source <(sed '$d' "$script")
trap 'rp_cleanup_selftest; rm -rf "$tmp"' EXIT
fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }
extract(){ awk -v name="$2" '$0 == name "(){" {inside=1} inside {print} inside && $0 == "}" {exit}' "$1"; }
for kind in relay panel; do
  if [ "$kind" = relay ]; then marker=RELAYEOF; else marker=SBEOF; fi
  awk -v marker="$marker" '$0 ~ "^  cat >.*" marker {inside=1;next} $0==marker {inside=0} inside {print}' "$script" >"$tmp/$kind.sh"
  inject_reality_policy "$tmp/$kind.sh"
  bash -n "$tmp/$kind.sh"
done
rp_vps_identity(){ printf '192.0.2.100|AS64500|192.0.2.0/24'; }
rp_pid_headroom(){ printf 999999; }
rp_mem_kb(){ printf 999999; }
rp_public_candidates(){
  printf '%s\n' fast.example near.example backup.example fourth.example
  if [ "$fixture" != fallback ]; then printf '%s\n' www.apple.com www.microsoft.com www.amazon.com www.oracle.com; fi
}
rp_probe_row(){
  local asn=AS64501 ip=192.0.2.10 ms=18
  case "$1" in
    near.example) asn=AS64500; ip=192.0.2.20; ms=420 ;;
    www.apple.com) asn=AS64500; ip=192.0.2.30; ms=80 ;;
    www.microsoft.com) ip=192.0.2.40; ms=20 ;;
    www.amazon.com) ip=192.0.2.50; ms=50 ;;
    www.oracle.com) ip=192.0.2.60; ms=100 ;;
  esac
  printf '%s|YES|YES|YES|YES|%s|CLEAR|PENDING|test||%s|%s|4|UNMEASURED|NO_RULE_MATCH|3|3|PASS\n' "$1" "$ms" "$asn" "$ip"
}
rp_selftest(){
  printf '%s\n' "$1" >>"$tmp/tested"
  if [ "$fixture" = vendor_failure ] && rp_vendor_name "$1" >/dev/null; then RP_TEST_REASON='mock vendor failure'; return 1; fi
  return 0
}
SINGBOX_REALITY_COMPARE_LIMIT=3
for fixture in fallback vendor vendor_failure; do
  expected_host=near.example expected_ip=192.0.2.20 expected_tests=3
  if [ "$fixture" = vendor ]; then expected_host=www.microsoft.com; expected_ip=192.0.2.40; fi
  if [ "$fixture" = vendor_failure ]; then expected_tests=6; fi
  : >"$tmp/tested"
(
  eval "$(extract "$tmp/relay.sh" relay_record_source)"
  eval "$(extract "$tmp/relay.sh" select_relay_sni)"
  relay_refresh_gfwlist(){ :; }
  relay_discover(){ : >"$3"; }
  relay_validate_sni(){ rp_valid_host "$1"; }
  declare -A RELAY_SRC=()
  RELAY_PROFILE=cn RELAY_GFW='' INHERITED_SNI=''
  select_relay_sni <<<"" >"$tmp/relay-output"
  [[ "$SNI" == "$expected_host" && "$TARGET_IP" == "$expected_ip" ]] || fail "relay selected wrong audited endpoint for $fixture"
  [[ "$(wc -l <"$tmp/tested")" -eq "$expected_tests" ]] || fail "relay ignored staged comparison cap for $fixture"
  grep -q '备选' "$tmp/relay-output" || fail 'relay omitted alternatives'
)
: >"$tmp/tested"
(
  eval "$(extract "$tmp/panel.sh" panel_show_record)"
  eval "$(extract "$tmp/panel.sh" reality_discover)"
  panel_refresh_gfwlist(){ :; }
  panel_current_asn(){ rp_vps_identity; }
  rp_discover_candidates(){ : >"$3"; }
  change_reality(){ fail 'no-apply discovery changed active target'; }
  CONFIG_DIR="$tmp" DISCOVERY_CACHE="$tmp/panel-rows" GFWLIST_PATH="$tmp/gfw"
  ENABLE_REALITY=true ENABLE_ANYTLS=true REALITY_CLIENT_PROFILE=cn
  reality_discover --no-apply >"$tmp/panel-output"
  [[ "$(wc -l <"$tmp/tested")" -eq "$expected_tests" ]] || fail "panel ignored staged comparison cap for $fixture"
  grep -q '建议候选' "$tmp/panel-output" || fail 'panel did not recommend a tested candidate'
  best="$(rp_best_row "$DISCOVERY_CACHE" AS64500 PASS)"
  [[ "$best" == "$expected_host"\|* ]] || fail "panel ordering differs from relay/main for $fixture"
)
done
printf 'PASS: generated relay and panel share vendor latency preference, old-policy fallback, endpoint pinning and staged limits\n'

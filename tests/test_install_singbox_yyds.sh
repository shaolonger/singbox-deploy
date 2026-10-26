#!/usr/bin/env bash
# Run on Linux with Bash 4+, jq, curl, OpenSSL and the script's normal dependencies.
# ShellCheck cannot track definitions loaded from the installer or extracted heredocs.
# shellcheck disable=SC1090,SC2034,SC2120
set -Eeuo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="$root/install-singbox-yyds.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# The installer runs from a downloaded file, so its entry point stays
# unconditional. Source every definition except the final main invocation.
source <(sed '$d' "$script")
trap 'rm -rf "$tmp"' EXIT
[[ "$SCRIPT_VERSION" == "${SINGBOX_DEPLOY_VERSION:-latest}" ]] || { printf 'FAIL: dynamic script version\n' >&2; exit 1; }

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
rp_list_flagged www.example.org "$tmp/gfw.txt" || fail 'shared domain matcher failed'
if rp_list_flagged notexample.org "$tmp/gfw.txt"; then fail 'shared domain substring matched'; fi

# Both standalone generated scripts receive identical canonical policy functions.
for kind in relay panel; do
  if [ "$kind" = relay ]; then start=RELAYEOF; else start=SBEOF; fi
  awk -v marker="$start" '$0 ~ "^  cat >.*" marker {inside=1;next} $0 == marker {inside=0} inside {print}' "$script" >"$tmp/$kind.sh"
  inject_reality_policy "$tmp/$kind.sh"
  bash -n "$tmp/$kind.sh" || fail "generated $kind syntax"
  grep -Fq 'rp_probe ()' "$tmp/$kind.sh" || fail "generated $kind lacks shared probe"
  grep -Fq 'rp_test_pool ()' "$tmp/$kind.sh" || fail "generated $kind lacks bounded comparison"
  if grep -Fq '# __REALITY_POLICY__' "$tmp/$kind.sh"; then fail "generated $kind still has injection placeholder"; fi
done

# Bulk state update keeps unrelated settings and safely writes empty values.
eval "$(extract_function set_state_many)"
CONFIG_DIR="$tmp/state"; STATE_PATH="$CONFIG_DIR/install-state.env"
mkdir -p "$CONFIG_DIR"
printf 'UNCHANGED=old\nREALITY_SNI=old.example\n' >"$STATE_PATH"
set_state_many REALITY_SNI new.example REALITY_TARGET_IP ''
( source "$STATE_PATH"; [[ "$UNCHANGED" == old && "$REALITY_SNI" == new.example && "$REALITY_TARGET_IP" == '' ]] ) || fail 'bulk state update'
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

printf 'PASS: 93 config combinations, shared generated policy, domain matching, state, dependencies, atomic rollback\n'

#!/usr/bin/env bash
# shellcheck disable=SC2016
set -Eeuo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail(){ printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# The bootstrap must remain standalone and runnable by Alpine's POSIX sh.
for file in install-latest.sh install-singbox-yyds.sh; do
  sed -n '/^# BEGIN ALPINE_STORAGE_PREFLIGHT$/,/^# END ALPINE_STORAGE_PREFLIGHT$/p' "$root/$file" >"$tmp/$file.storage"
done
cmp "$tmp/install-latest.sh.storage" "$tmp/install-singbox-yyds.sh.storage" || fail 'storage guards differ'
sed '/^ensure_bootstrap_dependencies$/,$d' "$root/install-latest.sh" >"$tmp/bootstrap.sh"
printf 'source <(sed '\''$d'\'' "$STORAGE_TEST_ROOT/install-singbox-yyds.sh")\n' >"$tmp/main.sh"

cat >"$tmp/mocks.sh" <<'EOF'
# Only dependency discovery is mocked; apk is logged, never run.
command(){
  case "$*" in
    '-v bash'|'-v dig') [ -f "$STORAGE_TEST_LOG" ] ;;
    *) return 0 ;;
  esac
}
apk(){ printf '%s\n' "$*" >>"$STORAGE_TEST_LOG"; }
df(){
  storage_test_total=1048576 storage_test_free=524288 storage_test_inodes=10000
  case "$STORAGE_TEST_CASE:$2" in
    root-full:/|usr-full:/usr) storage_test_free=1024 ;;
    etc-full:/etc|db-full:/lib/apk/db|tmp-full:/tmp) storage_test_free=4096 ;;
    no-inodes:/usr) storage_test_inodes=0 ;;
    unknown-inodes:*) storage_test_inodes=- ;;
    zero-inode-total:*) storage_test_inodes=0 ;;
    bad-df:/usr) return 1 ;;
  esac
  if [ "$1" = -Pi ]; then
    storage_test_free="$storage_test_inodes"
    if [ "$STORAGE_TEST_CASE" = zero-inode-total ]; then storage_test_total=0; fi
  fi
  printf 'Filesystem Blocks Used Available Capacity Mounted\n'
  printf 'testfs %s 0 %s 1%% %s\n' "$storage_test_total" "$storage_test_free" "$2"
}
EOF
cat "$tmp/mocks.sh" >>"$tmp/bootstrap.sh"
printf 'ensure_bootstrap_dependencies\n' >>"$tmp/bootstrap.sh"
cat "$tmp/mocks.sh" >>"$tmp/main.sh"
printf 'OS=alpine\ninstall_deps\n' >>"$tmp/main.sh"
export STORAGE_TEST_ROOT="$root" STORAGE_TEST_LOG="$tmp/apk.log"
# Check the standard Alpine temporary directory regardless of the test host.
export TMPDIR=/tmp
for mode in bootstrap main; do
  if [ "$mode" = bootstrap ]; then runner='sh'; else runner='bash'; fi
  for fixture in root-full usr-full etc-full db-full tmp-full no-inodes bad-df healthy unknown-inodes zero-inode-total; do
    if [ "$fixture" = db-full ] && [ ! -d /lib/apk/db ]; then continue; fi
    rm -f "$STORAGE_TEST_LOG"
    if STORAGE_TEST_CASE="$fixture" "$runner" "$tmp/$mode.sh" >"$tmp/output" 2>&1; then
      case "$fixture" in healthy|unknown-inodes|zero-inode-total) ;; *) fail "$mode accepted $fixture" ;; esac
      [ -s "$STORAGE_TEST_LOG" ] || fail "$mode skipped healthy apk install"
    else
      case "$fixture" in healthy|unknown-inodes|zero-inode-total) cat "$tmp/output" >&2; fail "$mode rejected $fixture" ;; esac
      [ ! -e "$STORAGE_TEST_LOG" ] || fail "$mode ran apk before rejecting $fixture"
      grep -Eq '空间预检失败|无法检查' "$tmp/output" || fail "$mode failed without a storage diagnostic"
    fi
  done
done
printf 'PASS: Alpine bootstrap/main reject full filesystems and exhausted inodes before apk; healthy installs proceed\n'

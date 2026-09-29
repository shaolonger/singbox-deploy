#!/bin/sh
set -eu

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' 0
mkdir "$tmp/bin"

cat >"$tmp/bin/curl" <<'EOF'
#!/bin/sh
case "$*" in
  *releases/latest*)
    printf 'https://github.com/shaolonger/singbox-deploy/releases/tag/%s' "${BOOTSTRAP_TEST_TAG:-v9.8.7}"
    ;;
  *install-singbox-yyds.sh*)
    outfile=''
    previous=''
    for arg do
      if [ "$previous" = '-o' ]; then outfile="$arg"; break; fi
      previous="$arg"
    done
    [ -n "$outfile" ] || exit 1
    printf '%s\n' "$*" >"$BOOTSTRAP_TEST_URL_LOG"
    printf '#!/usr/bin/env bash\nexit 0\n' >"$outfile"
    ;;
  *) exit 1 ;;
esac
EOF
cat >"$tmp/bin/bash" <<'EOF'
#!/bin/sh
if [ "$1" = '-n' ]; then
  /bin/bash -n "$2"
else
  printf '%s\n' "$SINGBOX_DEPLOY_VERSION" >"$BOOTSTRAP_TEST_VERSION_LOG"
fi
EOF
chmod +x "$tmp/bin/curl" "$tmp/bin/bash"
export BOOTSTRAP_TEST_URL_LOG="$tmp/url" BOOTSTRAP_TEST_VERSION_LOG="$tmp/version"
PATH="$tmp/bin:$PATH" sh "$root/install-latest.sh" >"$tmp/output"
[ "$(cat "$tmp/version")" = 'v9.8.7' ] || { echo 'FAIL: resolved version not passed to installer' >&2; exit 1; }
grep -Fq '/v9.8.7/install-singbox-yyds.sh' "$tmp/url" || { echo 'FAIL: installer was not fetched from latest tag' >&2; exit 1; }

rm -f "$tmp/version"
PATH="$tmp/bin:$PATH" sh "$root/install-latest.sh" --check >"$tmp/output"
[ ! -e "$tmp/version" ] || { echo 'FAIL: check mode executed installer' >&2; exit 1; }
if BOOTSTRAP_TEST_TAG=latest PATH="$tmp/bin:$PATH" sh "$root/install-latest.sh" --check >"$tmp/output" 2>&1; then
  echo 'FAIL: accepted an invalid release tag' >&2
  exit 1
fi
printf 'PASS: latest release resolution, version handoff, check mode, invalid tag\n'

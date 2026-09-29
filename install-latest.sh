#!/bin/sh
# Small POSIX bootstrap: resolve the newest published release, then run its
# interactive Bash installer from a file so stdin remains attached to the user.
set -eu

die() {
  printf '[ERR] %s\n' "$*" >&2
  exit 1
}

[ "$(id -u)" -eq 0 ] || die '请使用 root 运行。'
check_only=0
[ "${1:-}" != '--check' ] || check_only=1

install_packages() {
  if command -v apk >/dev/null 2>&1; then
    apk add --no-cache "$@"
  elif command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$@"
  else
    die '未找到支持的包管理器；请先安装 curl、Bash 和 CA 证书。'
  fi
}

set --
command -v curl >/dev/null 2>&1 || set -- "$@" curl
command -v bash >/dev/null 2>&1 || set -- "$@" bash
if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ]; then
  set -- "$@" ca-certificates
fi
[ "$#" -eq 0 ] || install_packages "$@"

repo='shaolonger/singbox-deploy'
release_url="$(curl -fsSL --retry 2 --connect-timeout 8 --max-time 30 -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")" ||
  die '无法查询 GitHub 最新正式 Release。'
case "$release_url" in
  "https://github.com/$repo/releases/tag/"*) tag=${release_url##*/} ;;
  *) die "最新 Release 地址无效：$release_url" ;;
esac
case "$tag" in
  v[0-9]*) ;;
  *) die "最新 Release 标签无效：$tag" ;;
esac
case "$tag" in
  *[!a-zA-Z0-9._-]*) die "最新 Release 标签包含非法字符：$tag" ;;
esac

installer="$(mktemp "${TMPDIR:-/tmp}/singbox-deploy.XXXXXX")" || die '无法创建临时文件。'
trap 'rm -f "$installer"' 0
trap 'exit 130' 1 2 3 15
curl -fsSL --retry 2 --connect-timeout 8 --max-time 90 \
  "https://raw.githubusercontent.com/$repo/$tag/install-singbox-yyds.sh" -o "$installer" ||
  die "下载 $tag 安装脚本失败。"
[ -s "$installer" ] || die '下载的安装脚本为空。'
bash -n "$installer" || die '下载的安装脚本语法检查失败。'

printf '[INFO] 使用最新正式版本：%s\n' "$tag"
if [ "$check_only" -eq 1 ]; then
  printf '[INFO] 下载与语法检查通过。\n'
  exit 0
fi
SINGBOX_DEPLOY_VERSION="$tag" bash "$installer"

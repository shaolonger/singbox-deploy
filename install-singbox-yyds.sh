#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# ============================================================
# Sing-box 多协议一键部署脚本（IPv6 Enhanced）
# 支持：
#   - Shadowsocks (SS / SS2022)
#   - Hysteria2
#   - TUIC
#   - VLESS Reality
#   - AnyTLS Reality
#   - SS 出口模式：auto / prefer_ipv6 / ipv6_only
#   - sb 管理面板：端口管理、SS 出口模式切换、网络检测、
#     配置校验、日志、更新、线路机脚本生成、卸载
#   - IPv6 URI 自动加 []、配置原子更新、失败自动回滚
#
# 目标 sing-box：优先面向 1.13+，并使用 1.12+ 新式 domain_resolver。
# ============================================================

SCRIPT_VERSION="2026.09.16-ipv6-enhanced-v1"
CONFIG_DIR="/etc/sing-box"
CONFIG_PATH="${CONFIG_DIR}/config.json"
CACHE_FILE="${CONFIG_DIR}/.config_cache"
PROTOCOL_FILE="${CONFIG_DIR}/.protocols"
SB_PATH="/usr/local/bin/sb"
NODE_NAME_FILE="/root/node_names.txt"
DEFAULT_REALITY_SNI="addons.mozilla.org"

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; }

cleanup_files=()
cleanup() {
    local f
    for f in "${cleanup_files[@]:-}"; do
        [ -n "$f" ] && rm -f "$f" 2>/dev/null || true
    done
}
trap cleanup EXIT

die() {
    err "$*"
    exit 1
}

check_root() {
    [ "$(id -u)" -eq 0 ] || die "此脚本需要 root 权限。"
}

detect_os() {
    local os_id="" os_like=""
    if [ -r /etc/os-release ]; then
        os_id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print tolower($2); exit}' /etc/os-release)"
        os_like="$(awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2); print tolower($2); exit}' /etc/os-release)"
    fi

    if grep -qi alpine <<<"$os_id $os_like"; then
        OS="alpine"
    elif grep -Eqi 'debian|ubuntu' <<<"$os_id $os_like"; then
        OS="debian"
    elif grep -Eqi 'centos|rhel|fedora|rocky|almalinux' <<<"$os_id $os_like"; then
        OS="redhat"
    else
        OS="unknown"
    fi
    OS_ID="$os_id"
}

install_deps() {
    info "安装/检查系统依赖..."
    case "$OS" in
        alpine)
            apk update
            apk add --no-cache bash curl ca-certificates openssl jq iproute2 coreutils
            ;;
        debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -y
            apt-get install -y curl ca-certificates openssl jq iproute2 coreutils
            ;;
        redhat)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y curl ca-certificates openssl jq iproute coreutils
            else
                yum install -y curl ca-certificates openssl jq iproute coreutils
            fi
            ;;
        *)
            warn "未识别系统，尝试继续；请确保 curl/openssl/jq/ip 命令已安装。"
            ;;
    esac

    local cmd
    for cmd in curl openssl jq; do
        command -v "$cmd" >/dev/null 2>&1 || die "缺少依赖：$cmd"
    done
}

rand_port() {
    if command -v shuf >/dev/null 2>&1; then
        shuf -i 10000-60000 -n 1
    else
        echo $((RANDOM % 50001 + 10000))
    fi
}

rand_relay_port() {
    if command -v shuf >/dev/null 2>&1; then
        shuf -i 20000-65000 -n 1
    else
        echo $((RANDOM % 45001 + 20000))
    fi
}

rand_pass() {
    openssl rand -base64 16 | tr -d '\r\n'
}

rand_uuid() {
    if [ -r /proc/sys/kernel/random/uuid ]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr '[:upper:]' '[:lower:]'
    else
        local h
        h="$(openssl rand -hex 16)"
        printf '%s-%s-%s-%s-%s\n' \
            "${h:0:8}" "${h:8:4}" "${h:12:4}" "${h:16:4}" "${h:20:12}"
    fi
}

validate_port() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

port_in_use() {
    local p="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -H -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "(^|[\]:.])${p}$"
    else
        return 1
    fi
}

prompt_port() {
    local label="$1" env_value="${2:-}" default_random="${3:-normal}"
    local p=""
    if [ -n "$env_value" ]; then
        p="$env_value"
    else
        while true; do
            if [ "$default_random" = "relay" ]; then
                read -r -p "请输入 ${label} 端口(留空随机 20000-65000): " p
                p="${p:-$(rand_relay_port)}"
            else
                read -r -p "请输入 ${label} 端口(留空随机 10000-60000): " p
                p="${p:-$(rand_port)}"
            fi
            validate_port "$p" || { warn "端口必须为 1-65535"; continue; }
            if port_in_use "$p"; then
                warn "端口 $p 当前已被占用，请换一个。"
                continue
            fi
            break
        done
    fi
    validate_port "$p" || die "无效端口：$p"
    printf '%s' "$p"
}

url_encode() {
    # URI userinfo / password 的保守编码
    local s="$1"
    s="${s//'%'/'%25'}"
    s="${s//':'/'%3A'}"
    s="${s//'+'/'%2B'}"
    s="${s//'/'/'%2F'}"
    s="${s//'='/'%3D'}"
    s="${s//' '/'%20'}"
    printf '%s' "$s"
}

format_uri_host() {
    local host="${1:-}"
    if [[ "$host" == \[*\] ]]; then
        printf '%s' "$host"
    elif [[ "$host" == *:* ]]; then
        printf '[%s]' "$host"
    else
        printf '%s' "$host"
    fi
}

normalize_host_for_json() {
    local host="${1:-}"
    host="${host#[}"
    host="${host%]}"
    printf '%s' "$host"
}

get_public_ipv4() {
    local u ip
    for u in \
        "https://api.ipify.org" \
        "https://ipv4.icanhazip.com" \
        "https://ifconfig.me/ip"; do
        ip="$(curl -4 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            printf '%s' "$ip"
            return 0
        fi
    done
    return 1
}

get_public_ipv6() {
    local u ip
    for u in \
        "https://api64.ipify.org" \
        "https://ipv6.icanhazip.com" \
        "https://ifconfig.co/ip"; do
        ip="$(curl -6 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
        if [[ "$ip" == *:* ]]; then
            printf '%s' "$ip"
            return 0
        fi
    done
    return 1
}

test_ipv6_connectivity() {
    local v6=""
    v6="$(get_public_ipv6 || true)"
    if [ -n "$v6" ]; then
        IPV6_TEST_IP="$v6"
        return 0
    fi
    return 1
}

test_ipv4_connectivity() {
    local v4=""
    v4="$(get_public_ipv4 || true)"
    if [ -n "$v4" ]; then
        IPV4_TEST_IP="$v4"
        return 0
    fi
    return 1
}

normalize_sni() {
    printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' | sed 's/\.$//'
}

validate_sni() {
    local sni="$1" label
    [ -n "$sni" ] || return 1
    [ "${#sni}" -le 253 ] || return 1
    [[ "$sni" =~ ^[a-z0-9.-]+$ ]] || return 1
    [[ "$sni" != .* && "$sni" != *..* ]] || return 1
    IFS='.' read -r -a _labels <<<"$sni"
    for label in "${_labels[@]}"; do
        [ -n "$label" ] || return 1
        [ "${#label}" -le 63 ] || return 1
        [[ "$label" =~ ^[a-z0-9-]+$ ]] || return 1
        [[ "$label" != -* && "$label" != *- ]] || return 1
    done
}

probe_sni() {
    local sni="$1" stats
    stats="$(curl -fsS -o /dev/null \
        --connect-timeout 3 --max-time 8 \
        -w '%{time_appconnect} %{time_total}' "https://${sni}/" 2>/dev/null || true)"
    [ -n "$stats" ] || return 1
    awk -v x="${stats%% *}" 'BEGIN{exit !(x>0)}' || return 1
    printf '%s %s\n' "$stats" "$sni"
}

select_reality_sni() {
    local candidates=(
        "addons.mozilla.org"
        "www.cloudflare.com"
        "www.microsoft.com"
        "www.apple.com"
        "gateway.icloud.com"
        "www.bing.com"
    )
    local tmp best="" c n choice
    tmp="$(mktemp /tmp/singbox-sni.XXXXXX)"
    cleanup_files+=("$tmp")

    info "探测 Reality SNI..."
    for c in "${candidates[@]}"; do
        n="$(normalize_sni "$c")"
        validate_sni "$n" || continue
        probe_sni "$n" >>"$tmp" 2>/dev/null || true
    done
    if [ -s "$tmp" ]; then
        best="$(sort -k1,1n -k2,2n "$tmp" | awk 'NR==1{print $3}')"
    fi
    best="${best:-$DEFAULT_REALITY_SNI}"

    echo "请选择 Reality SNI："
    echo "1) 自动探测结果：$best（推荐）"
    echo "2) 默认值：$DEFAULT_REALITY_SNI"
    echo "3) 手动输入"
    read -r -p "请选择 [默认 1]: " choice
    case "${choice:-1}" in
        1) REALITY_SNI="$best" ;;
        2) REALITY_SNI="$DEFAULT_REALITY_SNI" ;;
        3)
            while true; do
                read -r -p "请输入 SNI: " REALITY_SNI
                REALITY_SNI="$(normalize_sni "$REALITY_SNI")"
                validate_sni "$REALITY_SNI" && break
                warn "SNI 格式不正确。"
            done
            ;;
        *) REALITY_SNI="$best" ;;
    esac
    info "Reality SNI：$REALITY_SNI"
}

select_protocols() {
    echo ""
    info "=== 选择要部署的协议 ==="
    echo "1) Shadowsocks (SS)"
    echo "2) Hysteria2 (HY2)"
    echo "3) TUIC"
    echo "4) VLESS Reality"
    echo "5) AnyTLS Reality"
    echo ""
    local input="${SINGBOX_PROTOCOLS:-}"
    if [ -z "$input" ]; then
        read -r -p "请输入协议编号(多个用空格分隔，如 1 4): " input
    else
        info "使用环境变量 SINGBOX_PROTOCOLS=$input"
    fi

    ENABLE_SS=false
    ENABLE_HY2=false
    ENABLE_TUIC=false
    ENABLE_REALITY=false
    ENABLE_ANYTLS=false

    local n
    for n in $input; do
        case "$n" in
            1) ENABLE_SS=true ;;
            2) ENABLE_HY2=true ;;
            3) ENABLE_TUIC=true ;;
            4) ENABLE_REALITY=true ;;
            5) ENABLE_ANYTLS=true ;;
            *) warn "忽略无效协议编号：$n" ;;
        esac
    done

    if ! $ENABLE_SS && ! $ENABLE_HY2 && ! $ENABLE_TUIC && ! $ENABLE_REALITY && ! $ENABLE_ANYTLS; then
        die "未选择任何协议。"
    fi
}

select_ss_method() {
    SS_METHOD="2022-blake3-aes-128-gcm"
    $ENABLE_SS || return 0

    echo ""
    info "=== Shadowsocks 加密方式 ==="
    echo "1) 2022-blake3-aes-128-gcm（推荐）"
    echo "2) aes-128-gcm"
    local choice="${SINGBOX_SS_METHOD:-}"
    if [ -z "$choice" ]; then
        read -r -p "请选择 [默认 1]: " choice
    fi
    case "${choice:-1}" in
        1|2022-blake3-aes-128-gcm) SS_METHOD="2022-blake3-aes-128-gcm" ;;
        2|aes-128-gcm) SS_METHOD="aes-128-gcm" ;;
        *) warn "无效选择，使用 SS2022"; SS_METHOD="2022-blake3-aes-128-gcm" ;;
    esac
}

normalize_ss_ip_mode() {
    case "${1:-}" in
        auto|default|1|"") echo "auto" ;;
        prefer_ipv6|prefer-v6|2) echo "prefer_ipv6" ;;
        ipv6_only|v6-only|3) echo "ipv6_only" ;;
        *) return 1 ;;
    esac
}

select_ss_ip_mode() {
    SS_IP_MODE="auto"
    $ENABLE_SS || return 0

    local raw="${SINGBOX_SS_IP_MODE:-}"
    if [ -z "$raw" ]; then
        echo ""
        info "=== Shadowsocks 最终出口 IP 模式 ==="
        echo "1) 系统默认 / 双栈（兼容原脚本）"
        echo "2) IPv6 优先（推荐用于 AI IPv6 落地；不可用时可回退 IPv4）"
        echo "3) 仅 IPv6（严格模式；IPv4 目标直接拒绝）"
        read -r -p "请选择 [默认 1]: " raw
    else
        info "使用环境变量 SINGBOX_SS_IP_MODE=$raw"
    fi

    SS_IP_MODE="$(normalize_ss_ip_mode "${raw:-1}")" || {
        warn "无效 SS IP 模式，使用 auto。"
        SS_IP_MODE="auto"
    }

    if [ "$SS_IP_MODE" != "auto" ]; then
        info "检测 VPS IPv6 出口..."
        if test_ipv6_connectivity; then
            ok "IPv6 出口正常：$IPV6_TEST_IP"
        else
            if [ "$SS_IP_MODE" = "ipv6_only" ]; then
                warn "当前 VPS 未检测到可用 IPv6 出口；严格 IPv6 模式可能导致 SS 无法访问互联网。"
                local c
                read -r -p "仍然继续配置 ipv6_only？(y/N): " c
                [[ "$c" =~ ^[Yy]$ ]] || die "已取消，请先修复 VPS IPv6。"
            else
                warn "当前未检测到 IPv6 出口；prefer_ipv6 会在可用时优先 IPv6。"
            fi
        fi
    fi
    info "SS 出口模式：$SS_IP_MODE"
}

prompt_node_name() {
    local user_name=""
    read -r -p "请输入节点名称(留空不加后缀): " user_name
    if [ -n "$user_name" ]; then
        NODE_SUFFIX="-${user_name}"
        printf '%s\n' "$NODE_SUFFIX" >"$NODE_NAME_FILE"
    else
        NODE_SUFFIX=""
        rm -f "$NODE_NAME_FILE" 2>/dev/null || true
    fi
}

prompt_connection_host() {
    echo ""
    read -r -p "请输入节点连接 IP 或 DDNS 域名(留空自动检测；IPv6 可直接填写): " CUSTOM_IP
    CUSTOM_IP="$(printf '%s' "${CUSTOM_IP:-}" | tr -d '[:space:]')"
    CUSTOM_IP="$(normalize_host_for_json "$CUSTOM_IP")"
}

configure_protocol_values() {
    info "配置协议端口和凭据..."

    if $ENABLE_SS; then
        PORT_SS="$(prompt_port "SS" "${SINGBOX_PORT_SS:-}")"
        PSK_SS="$(rand_pass)"
    fi
    if $ENABLE_HY2; then
        PORT_HY2="$(prompt_port "HY2" "${SINGBOX_PORT_HY2:-}")"
        PSK_HY2="$(rand_pass)"
    fi
    if $ENABLE_TUIC; then
        PORT_TUIC="$(prompt_port "TUIC" "${SINGBOX_PORT_TUIC:-}")"
        UUID_TUIC="$(rand_uuid)"
        PSK_TUIC="$(rand_pass)"
    fi
    if $ENABLE_REALITY; then
        PORT_REALITY="$(prompt_port "VLESS Reality" "${SINGBOX_PORT_REALITY:-}")"
        UUID_REALITY="$(rand_uuid)"
    fi
    if $ENABLE_ANYTLS; then
        PORT_ANYTLS="$(prompt_port "AnyTLS Reality" "${SINGBOX_PORT_ANYTLS:-}")"
        ANYTLS_USER="$(openssl rand -hex 4)"
        ANYTLS_PSK="$(rand_pass)"
    fi
}

ensure_singbox_service_path() {
    local bin
    bin="$(command -v sing-box 2>/dev/null || true)"
    [ -n "$bin" ] || return 1
    if [ "$bin" != "/usr/bin/sing-box" ]; then
        ln -sf "$bin" /usr/bin/sing-box
    fi
}

install_singbox() {
    if command -v sing-box >/dev/null 2>&1; then
        info "已安装：$(sing-box version 2>/dev/null | head -n1 || true)"
        local reinstall
        read -r -p "是否重新安装/更新 sing-box？(y/N): " reinstall
        if [[ ! "$reinstall" =~ ^[Yy]$ ]]; then
            ensure_singbox_service_path
            return 0
        fi
    fi

    info "安装 sing-box..."
    case "$OS" in
        alpine)
            # 优先官方脚本，失败再尝试 edge community
            local tmp
            tmp="$(mktemp /tmp/singbox-install.XXXXXX)"
            cleanup_files+=("$tmp")
            if curl -fsSL https://sing-box.app/install.sh -o "$tmp" && bash "$tmp"; then
                :
            else
                warn "官方安装脚本失败，尝试 Alpine edge/community..."
                apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community sing-box
            fi
            ;;
        debian|redhat|unknown)
            local tmp
            tmp="$(mktemp /tmp/singbox-install.XXXXXX)"
            cleanup_files+=("$tmp")
            curl -fsSL https://sing-box.app/install.sh -o "$tmp"
            bash "$tmp"
            ;;
    esac

    command -v sing-box >/dev/null 2>&1 || die "sing-box 安装失败。"
    ensure_singbox_service_path
    ok "sing-box：$(sing-box version 2>/dev/null | head -n1)"
}

generate_reality_keys() {
    REALITY_PK=""
    REALITY_PUB=""
    REALITY_SID=""
    if ! $ENABLE_REALITY && ! $ENABLE_ANYTLS; then
        return 0
    fi

    local keys
    keys="$(sing-box generate reality-keypair 2>&1)" || die "Reality 密钥生成失败：$keys"
    REALITY_PK="$(awk '/PrivateKey/{print $NF; exit}' <<<"$keys" | tr -d '\r')"
    REALITY_PUB="$(awk '/PublicKey/{print $NF; exit}' <<<"$keys" | tr -d '\r')"
    REALITY_SID="$(sing-box generate rand 8 --hex 2>/dev/null || true)"

    [ -n "$REALITY_PK" ] && [ -n "$REALITY_PUB" ] && [ -n "$REALITY_SID" ] \
        || die "Reality 密钥生成结果异常。"

    printf '%s' "$REALITY_PUB" >"${CONFIG_DIR}/.reality_pub"
    printf '%s' "$REALITY_SID" >"${CONFIG_DIR}/.reality_sid"
}

generate_cert() {
    if ! $ENABLE_HY2 && ! $ENABLE_TUIC; then
        return 0
    fi
    mkdir -p "${CONFIG_DIR}/certs"
    if [ ! -s "${CONFIG_DIR}/certs/fullchain.pem" ] || [ ! -s "${CONFIG_DIR}/certs/privkey.pem" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "${CONFIG_DIR}/certs/privkey.pem" \
            -out "${CONFIG_DIR}/certs/fullchain.pem" \
            -days 3650 \
            -subj "/CN=www.bing.com"
    fi
    chmod 600 "${CONFIG_DIR}/certs/privkey.pem"
}

append_json_array() {
    # append_json_array <file> <jq-path> <json>
    local file="$1" path="$2" json="$3" tmp
    tmp="$(mktemp "${CONFIG_DIR}/.json.XXXXXX")"
    cleanup_files+=("$tmp")
    jq --argjson x "$json" "${path} += [\$x]" "$file" >"$tmp"
    mv "$tmp" "$file"
}

build_config_file() {
    local out="$1"
    cat >"$out" <<'JSON'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "inbounds": [],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    }
  ],
  "route": {
    "rules": [],
    "final": "direct-out"
  }
}
JSON

    local obj tmp

    if $ENABLE_SS; then
        obj="$(jq -cn \
            --arg method "$SS_METHOD" \
            --arg password "$PSK_SS" \
            --argjson port "$PORT_SS" \
            '{type:"shadowsocks",listen:"::",listen_port:$port,method:$method,password:$password,tag:"ss-in"}')"
        tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; cleanup_files+=("$tmp")
        jq --argjson x "$obj" '.inbounds += [$x]' "$out" >"$tmp" && mv "$tmp" "$out"
    fi

    if $ENABLE_HY2; then
        obj="$(jq -cn \
            --arg password "$PSK_HY2" \
            --argjson port "$PORT_HY2" \
            '{type:"hysteria2",tag:"hy2-in",listen:"::",listen_port:$port,
              users:[{password:$password}],
              tls:{enabled:true,alpn:["h3"],certificate_path:"/etc/sing-box/certs/fullchain.pem",key_path:"/etc/sing-box/certs/privkey.pem"}}')"
        tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; cleanup_files+=("$tmp")
        jq --argjson x "$obj" '.inbounds += [$x]' "$out" >"$tmp" && mv "$tmp" "$out"
    fi

    if $ENABLE_TUIC; then
        obj="$(jq -cn \
            --arg uuid "$UUID_TUIC" --arg password "$PSK_TUIC" \
            --argjson port "$PORT_TUIC" \
            '{type:"tuic",tag:"tuic-in",listen:"::",listen_port:$port,
              users:[{uuid:$uuid,password:$password}],congestion_control:"bbr",
              tls:{enabled:true,alpn:["h3"],certificate_path:"/etc/sing-box/certs/fullchain.pem",key_path:"/etc/sing-box/certs/privkey.pem"}}')"
        tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; cleanup_files+=("$tmp")
        jq --argjson x "$obj" '.inbounds += [$x]' "$out" >"$tmp" && mv "$tmp" "$out"
    fi

    if $ENABLE_REALITY; then
        obj="$(jq -cn \
            --arg uuid "$UUID_REALITY" \
            --arg sni "$REALITY_SNI" \
            --arg pk "$REALITY_PK" \
            --arg sid "$REALITY_SID" \
            --argjson port "$PORT_REALITY" \
            '{type:"vless",tag:"vless-in",listen:"::",listen_port:$port,
              users:[{uuid:$uuid,flow:"xtls-rprx-vision"}],
              tls:{enabled:true,server_name:$sni,reality:{enabled:true,
              handshake:{server:$sni,server_port:443},private_key:$pk,short_id:[$sid]}}}')"
        tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; cleanup_files+=("$tmp")
        jq --argjson x "$obj" '.inbounds += [$x]' "$out" >"$tmp" && mv "$tmp" "$out"
    fi

    if $ENABLE_ANYTLS; then
        obj="$(jq -cn \
            --arg user "$ANYTLS_USER" \
            --arg password "$ANYTLS_PSK" \
            --arg sni "$REALITY_SNI" \
            --arg pk "$REALITY_PK" \
            --arg sid "$REALITY_SID" \
            --argjson port "$PORT_ANYTLS" \
            '{type:"anytls",tag:"anytls-in",listen:"::",listen_port:$port,
              users:[{name:$user,password:$password}],padding_scheme:[],
              tls:{enabled:true,server_name:$sni,reality:{enabled:true,
              handshake:{server:$sni,server_port:443},private_key:$pk,short_id:[$sid]}}}')"
        tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; cleanup_files+=("$tmp")
        jq --argjson x "$obj" '.inbounds += [$x]' "$out" >"$tmp" && mv "$tmp" "$out"
    fi

    if $ENABLE_SS && [ "$SS_IP_MODE" != "auto" ]; then
        tmp="$(mktemp "${CONFIG_DIR}/.cfg.XXXXXX")"; cleanup_files+=("$tmp")
        # sing-box 1.13/1.14 current-compatible approach:
        # use non-final route "resolve" action to resolve SS request domains with the
        # desired address-family strategy, then let route.final send them to direct-out.
        # This avoids the DNS-rule-action strategy carried inside domain_resolver,
        # which is deprecated in sing-box 1.14 and scheduled for removal in 1.16.
        jq --arg strategy "$SS_IP_MODE" '
          .dns = {
            servers: [
              {
                type: "local",
                tag: "ss-local-dns",
                prefer_go: true
              }
            ]
          }
          | .outbounds = [ .outbounds[] | select(.tag != "ss-direct-v6") ]
          | .route.rules = [
              .route.rules[]
              | select((.outbound // "") != "ss-direct-v6")
            ]
          | .route.rules += (
              if $strategy == "ipv6_only" then
                [{
                  inbound: ["ss-in"],
                  ip_version: 4,
                  action: "reject"
                }]
              else [] end
            )
          | .route.rules += [{
              inbound: ["ss-in"],
              action: "resolve",
              server: "ss-local-dns",
              strategy: $strategy
            }]
          | .route.final = "direct-out"
        ' "$out" >"$tmp" && mv "$tmp" "$out"
    fi

    jq empty "$out"
}

validate_config() {
    local file="${1:-$CONFIG_PATH}"
    jq empty "$file" >/dev/null 2>&1 || {
        err "JSON 语法校验失败：$file"
        jq empty "$file" 2>&1 || true
        return 1
    }
    if command -v sing-box >/dev/null 2>&1; then
        sing-box check -c "$file"
    fi
}

install_config_atomic() {
    local candidate="$1" backup=""
    validate_config "$candidate" || return 1

    if [ -f "$CONFIG_PATH" ]; then
        backup="${CONFIG_PATH}.bak.$(date +%Y%m%d_%H%M%S)"
        cp -a "$CONFIG_PATH" "$backup"
        info "旧配置已备份：$backup"
    fi

    mv "$candidate" "$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"
    ok "配置校验通过并已写入。"
}

shell_quote() {
    printf '%q' "$1"
}

save_state() {
    mkdir -p "$CONFIG_DIR"
    {
        printf 'ENABLE_SS=%q\n' "$ENABLE_SS"
        printf 'ENABLE_HY2=%q\n' "$ENABLE_HY2"
        printf 'ENABLE_TUIC=%q\n' "$ENABLE_TUIC"
        printf 'ENABLE_REALITY=%q\n' "$ENABLE_REALITY"
        printf 'ENABLE_ANYTLS=%q\n' "$ENABLE_ANYTLS"
        printf 'SS_IP_MODE=%q\n' "${SS_IP_MODE:-auto}"
        printf 'CUSTOM_IP=%q\n' "${CUSTOM_IP:-}"
        printf 'REALITY_SNI=%q\n' "${REALITY_SNI:-$DEFAULT_REALITY_SNI}"
        $ENABLE_SS && {
            printf 'SS_PORT=%q\n' "$PORT_SS"
            printf 'SS_PSK=%q\n' "$PSK_SS"
            printf 'SS_METHOD=%q\n' "$SS_METHOD"
        }
        $ENABLE_HY2 && {
            printf 'HY2_PORT=%q\n' "$PORT_HY2"
            printf 'HY2_PSK=%q\n' "$PSK_HY2"
        }
        $ENABLE_TUIC && {
            printf 'TUIC_PORT=%q\n' "$PORT_TUIC"
            printf 'TUIC_UUID=%q\n' "$UUID_TUIC"
            printf 'TUIC_PSK=%q\n' "$PSK_TUIC"
        }
        $ENABLE_REALITY && {
            printf 'REALITY_PORT=%q\n' "$PORT_REALITY"
            printf 'REALITY_UUID=%q\n' "$UUID_REALITY"
            printf 'REALITY_PK=%q\n' "$REALITY_PK"
            printf 'REALITY_PUB=%q\n' "$REALITY_PUB"
            printf 'REALITY_SID=%q\n' "$REALITY_SID"
        }
        $ENABLE_ANYTLS && {
            printf 'ANYTLS_PORT=%q\n' "$PORT_ANYTLS"
            printf 'ANYTLS_USER=%q\n' "$ANYTLS_USER"
            printf 'ANYTLS_PSK=%q\n' "$ANYTLS_PSK"
        }
    } >"$CACHE_FILE"
    chmod 600 "$CACHE_FILE"

    {
        printf 'ENABLE_SS=%q\n' "$ENABLE_SS"
        printf 'ENABLE_HY2=%q\n' "$ENABLE_HY2"
        printf 'ENABLE_TUIC=%q\n' "$ENABLE_TUIC"
        printf 'ENABLE_REALITY=%q\n' "$ENABLE_REALITY"
        printf 'ENABLE_ANYTLS=%q\n' "$ENABLE_ANYTLS"
    } >"$PROTOCOL_FILE"
    chmod 600 "$PROTOCOL_FILE"
}

setup_service() {
    info "配置 sing-box 系统服务..."
    if [ "$OS" = "alpine" ]; then
        SERVICE_PATH="/etc/init.d/sing-box"
        cat >"$SERVICE_PATH" <<'OPENRC'
#!/sbin/openrc-run
name="sing-box"
description="Sing-box Proxy Server"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/sing-box.log"
error_log="/var/log/sing-box.err"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"
depend() {
    need net
    after firewall
}
start_pre() {
    checkpath --directory --mode 0755 /var/log
    checkpath --directory --mode 0755 /run
}
OPENRC
        chmod 755 "$SERVICE_PATH"
        rc-update add sing-box default >/dev/null 2>&1 || true
        rc-service sing-box restart
        sleep 1
        rc-service sing-box status >/dev/null 2>&1 || die "sing-box 服务启动失败。"
    else
        SERVICE_PATH="/etc/systemd/system/sing-box.service"
        cat >"$SERVICE_PATH" <<'SYSTEMD'
[Unit]
Description=Sing-box Proxy Server
Documentation=https://sing-box.sagernet.org
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SYSTEMD
        systemctl daemon-reload
        systemctl enable sing-box >/dev/null 2>&1
        if ! systemctl restart sing-box; then
            journalctl -u sing-box -n 50 --no-pager || true
            die "sing-box 服务启动失败。"
        fi
        sleep 1
        systemctl is-active --quiet sing-box || {
            journalctl -u sing-box -n 50 --no-pager || true
            die "sing-box 服务状态异常。"
        }
    fi
    ok "sing-box 服务已启动。"
}

choose_generic_public_host() {
    if [ -n "${CUSTOM_IP:-}" ]; then
        printf '%s' "$CUSTOM_IP"
        return
    fi
    get_public_ipv4 || get_public_ipv6 || printf '%s' "YOUR_SERVER_IP"
}

choose_ss_public_host() {
    if [ -n "${CUSTOM_IP:-}" ]; then
        printf '%s' "$CUSTOM_IP"
        return
    fi
    if [ "${SS_IP_MODE:-auto}" != "auto" ]; then
        get_public_ipv6 || get_public_ipv4 || printf '%s' "YOUR_SERVER_IP"
    else
        get_public_ipv4 || get_public_ipv6 || printf '%s' "YOUR_SERVER_IP"
    fi
}

generate_uris_install() {
    local generic_host ss_host gh sh ss_userinfo ss_encoded ss_b64 enc
    generic_host="$(choose_generic_public_host)"
    ss_host="$(choose_ss_public_host)"
    gh="$(format_uri_host "$generic_host")"
    sh="$(format_uri_host "$ss_host")"

    URI_FILE="${CONFIG_DIR}/uris.txt"
    : >"$URI_FILE"

    if $ENABLE_SS; then
        ss_userinfo="${SS_METHOD}:${PSK_SS}"
        ss_encoded="$(url_encode "$ss_userinfo")"
        ss_b64="$(printf '%s' "$ss_userinfo" | base64 | tr -d '\r\n')"
        {
            echo "=== Shadowsocks (SS) ==="
            echo "# SS出口模式: ${SS_IP_MODE}"
            echo "ss://${ss_encoded}@${sh}:${PORT_SS}#ss${NODE_SUFFIX}"
            echo "ss://${ss_b64}@${sh}:${PORT_SS}#ss${NODE_SUFFIX}"
            echo
        } >>"$URI_FILE"
    fi

    if $ENABLE_HY2; then
        enc="$(url_encode "$PSK_HY2")"
        {
            echo "=== Hysteria2 (HY2) ==="
            echo "hy2://${enc}@${gh}:${PORT_HY2}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${NODE_SUFFIX}"
            echo
        } >>"$URI_FILE"
    fi

    if $ENABLE_TUIC; then
        enc="$(url_encode "$PSK_TUIC")"
        {
            echo "=== TUIC ==="
            echo "tuic://${UUID_TUIC}:${enc}@${gh}:${PORT_TUIC}/?congestion_control=bbr&alpn=h3&sni=www.bing.com&insecure=1#tuic${NODE_SUFFIX}"
            echo
        } >>"$URI_FILE"
    fi

    if $ENABLE_REALITY; then
        {
            echo "=== VLESS Reality ==="
            echo "vless://${UUID_REALITY}@${gh}:${PORT_REALITY}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality${NODE_SUFFIX}"
            echo
        } >>"$URI_FILE"
    fi

    if $ENABLE_ANYTLS; then
        enc="$(url_encode "$ANYTLS_PSK")"
        {
            echo "=== AnyTLS Reality ==="
            echo "anytls://${enc}@${gh}:${PORT_ANYTLS}/?security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#anytls${NODE_SUFFIX}"
            echo
        } >>"$URI_FILE"
    fi
    chmod 600 "$URI_FILE"
}

install_sb_panel() {
    cat >"$SB_PATH" <<'SB_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

CONFIG_DIR="/etc/sing-box"
CONFIG_PATH="${CONFIG_DIR}/config.json"
CACHE_FILE="${CONFIG_DIR}/.config_cache"
PROTOCOL_FILE="${CONFIG_DIR}/.protocols"
SERVICE_NAME="sing-box"
NODE_NAME_FILE="/root/node_names.txt"
DEFAULT_REALITY_SNI="addons.mozilla.org"

info() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
ok()   { echo -e "\033[1;32m[ OK ]\033[0m $*"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
err()  { echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; }

detect_os() {
    local a="" b=""
    if [ -r /etc/os-release ]; then
        a="$(awk -F= '$1=="ID"{gsub(/"/,"",$2); print tolower($2); exit}' /etc/os-release)"
        b="$(awk -F= '$1=="ID_LIKE"{gsub(/"/,"",$2); print tolower($2); exit}' /etc/os-release)"
    fi
    if grep -qi alpine <<<"$a $b"; then OS="alpine";
    elif grep -Eqi 'debian|ubuntu' <<<"$a $b"; then OS="debian";
    elif grep -Eqi 'centos|rhel|fedora|rocky|almalinux' <<<"$a $b"; then OS="redhat";
    else OS="unknown"; fi
}
detect_os

service_start() {
    if [ "$OS" = "alpine" ]; then rc-service "$SERVICE_NAME" start;
    else systemctl start "$SERVICE_NAME"; fi
}
service_stop() {
    if [ "$OS" = "alpine" ]; then rc-service "$SERVICE_NAME" stop;
    else systemctl stop "$SERVICE_NAME"; fi
}
service_status() {
    if [ "$OS" = "alpine" ]; then rc-service "$SERVICE_NAME" status;
    else systemctl status "$SERVICE_NAME" --no-pager; fi
}
service_restart_raw() {
    if [ "$OS" = "alpine" ]; then rc-service "$SERVICE_NAME" restart;
    else systemctl restart "$SERVICE_NAME"; fi
}
service_restart_safe() {
    if ! sing-box check -c "$CONFIG_PATH"; then
        err "配置校验失败，拒绝重启。"
        return 1
    fi
    service_restart_raw
}

show_logs() {
    if [ "$OS" = "alpine" ]; then
        tail -n 100 /var/log/sing-box.err /var/log/sing-box.log 2>/dev/null || true
    else
        journalctl -u sing-box -n 100 --no-pager
    fi
}

rand_port() {
    if command -v shuf >/dev/null 2>&1; then shuf -i 10000-60000 -n1;
    else echo $((RANDOM % 50001 + 10000)); fi
}
rand_pass() { openssl rand -base64 16 | tr -d '\r\n'; }

validate_port() {
    [[ "${1:-}" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
url_encode() {
    local s="$1"
    s="${s//'%'/'%25'}"; s="${s//':'/'%3A'}"; s="${s//'+'/'%2B'}"
    s="${s//'/'/'%2F'}"; s="${s//'='/'%3D'}"; s="${s//' '/'%20'}"
    printf '%s' "$s"
}
format_uri_host() {
    local h="${1:-}"
    if [[ "$h" == \[*\] ]]; then printf '%s' "$h";
    elif [[ "$h" == *:* ]]; then printf '[%s]' "$h";
    else printf '%s' "$h"; fi
}
normalize_host_for_json() {
    local h="${1:-}"; h="${h#[}"; h="${h%]}"; printf '%s' "$h"
}
get_public_ipv4() {
    local u x
    for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.me/ip; do
        x="$(curl -4 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
        [[ "$x" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { printf '%s' "$x"; return 0; }
    done
    return 1
}
get_public_ipv6() {
    local u x
    for u in https://api64.ipify.org https://ipv6.icanhazip.com https://ifconfig.co/ip; do
        x="$(curl -6 -fsS --connect-timeout 3 --max-time 7 "$u" 2>/dev/null | tr -d '[:space:]' || true)"
        [[ "$x" == *:* ]] && { printf '%s' "$x"; return 0; }
    done
    return 1
}

load_state() {
    ENABLE_SS=false; ENABLE_HY2=false; ENABLE_TUIC=false
    ENABLE_REALITY=false; ENABLE_ANYTLS=false
    SS_IP_MODE="auto"; CUSTOM_IP=""; REALITY_SNI="$DEFAULT_REALITY_SNI"

    [ -f "$PROTOCOL_FILE" ] && . "$PROTOCOL_FILE"
    [ -f "$CACHE_FILE" ] && . "$CACHE_FILE"

    [ -f "$CONFIG_PATH" ] || return 1

    # 以真实 config.json 为准补齐
    jq -e '.inbounds[]? | select(.type=="shadowsocks")' "$CONFIG_PATH" >/dev/null 2>&1 && ENABLE_SS=true || true
    jq -e '.inbounds[]? | select(.type=="hysteria2")' "$CONFIG_PATH" >/dev/null 2>&1 && ENABLE_HY2=true || true
    jq -e '.inbounds[]? | select(.type=="tuic")' "$CONFIG_PATH" >/dev/null 2>&1 && ENABLE_TUIC=true || true
    jq -e '.inbounds[]? | select(.type=="vless")' "$CONFIG_PATH" >/dev/null 2>&1 && ENABLE_REALITY=true || true
    jq -e '.inbounds[]? | select(.type=="anytls")' "$CONFIG_PATH" >/dev/null 2>&1 && ENABLE_ANYTLS=true || true

    if $ENABLE_SS; then
        SS_PORT="$(jq -r '.inbounds[]|select(.type=="shadowsocks")|.listen_port' "$CONFIG_PATH" | head -n1)"
        SS_PSK="$(jq -r '.inbounds[]|select(.type=="shadowsocks")|.password' "$CONFIG_PATH" | head -n1)"
        SS_METHOD="$(jq -r '.inbounds[]|select(.type=="shadowsocks")|.method' "$CONFIG_PATH" | head -n1)"
        if jq -e '.route.rules[]? | select(.action=="resolve" and .server=="ss-local-dns" and .strategy=="ipv6_only" and ((.inbound // []) | index("ss-in")))' "$CONFIG_PATH" >/dev/null 2>&1; then
            SS_IP_MODE="ipv6_only"
        elif jq -e '.route.rules[]? | select(.action=="resolve" and .server=="ss-local-dns" and .strategy=="prefer_ipv6" and ((.inbound // []) | index("ss-in")))' "$CONFIG_PATH" >/dev/null 2>&1; then
            SS_IP_MODE="prefer_ipv6"
        # Backward compatibility with the earlier direct-v6/domain_resolver layout.
        elif jq -e '.outbounds[]? | select(.tag=="ss-direct-v6") | .domain_resolver.strategy=="ipv6_only"' "$CONFIG_PATH" >/dev/null 2>&1; then
            SS_IP_MODE="ipv6_only"
        elif jq -e '.outbounds[]? | select(.tag=="ss-direct-v6") | .domain_resolver.strategy=="prefer_ipv6"' "$CONFIG_PATH" >/dev/null 2>&1; then
            SS_IP_MODE="prefer_ipv6"
        else
            SS_IP_MODE="auto"
        fi
    fi
    if $ENABLE_HY2; then
        HY2_PORT="$(jq -r '.inbounds[]|select(.type=="hysteria2")|.listen_port' "$CONFIG_PATH" | head -n1)"
        HY2_PSK="$(jq -r '.inbounds[]|select(.type=="hysteria2")|.users[0].password' "$CONFIG_PATH" | head -n1)"
    fi
    if $ENABLE_TUIC; then
        TUIC_PORT="$(jq -r '.inbounds[]|select(.type=="tuic")|.listen_port' "$CONFIG_PATH" | head -n1)"
        TUIC_UUID="$(jq -r '.inbounds[]|select(.type=="tuic")|.users[0].uuid' "$CONFIG_PATH" | head -n1)"
        TUIC_PSK="$(jq -r '.inbounds[]|select(.type=="tuic")|.users[0].password' "$CONFIG_PATH" | head -n1)"
    fi
    if $ENABLE_REALITY; then
        REALITY_PORT="$(jq -r '.inbounds[]|select(.type=="vless")|.listen_port' "$CONFIG_PATH" | head -n1)"
        REALITY_UUID="$(jq -r '.inbounds[]|select(.type=="vless")|.users[0].uuid' "$CONFIG_PATH" | head -n1)"
        REALITY_SID="$(jq -r '.inbounds[]|select(.type=="vless")|.tls.reality.short_id[0]' "$CONFIG_PATH" | head -n1)"
        REALITY_PUB="$(cat /etc/sing-box/.reality_pub 2>/dev/null || true)"
        REALITY_SNI="$(jq -r '.inbounds[]|select(.type=="vless")|.tls.server_name // "addons.mozilla.org"' "$CONFIG_PATH" | head -n1)"
    elif $ENABLE_ANYTLS; then
        REALITY_SID="$(jq -r '.inbounds[]|select(.type=="anytls")|.tls.reality.short_id[0]' "$CONFIG_PATH" | head -n1)"
        REALITY_PUB="$(cat /etc/sing-box/.reality_pub 2>/dev/null || true)"
        REALITY_SNI="$(jq -r '.inbounds[]|select(.type=="anytls")|.tls.server_name // "addons.mozilla.org"' "$CONFIG_PATH" | head -n1)"
    fi
    if $ENABLE_ANYTLS; then
        ANYTLS_PORT="$(jq -r '.inbounds[]|select(.type=="anytls")|.listen_port' "$CONFIG_PATH" | head -n1)"
        ANYTLS_USER="$(jq -r '.inbounds[]|select(.type=="anytls")|.users[0].name' "$CONFIG_PATH" | head -n1)"
        ANYTLS_PSK="$(jq -r '.inbounds[]|select(.type=="anytls")|.users[0].password' "$CONFIG_PATH" | head -n1)"
    fi
}

set_cache_key() {
    local key="$1" value="$2" tmp
    touch "$CACHE_FILE"; chmod 600 "$CACHE_FILE"
    tmp="$(mktemp "${CONFIG_DIR}/.cache.XXXXXX")"
    grep -v "^${key}=" "$CACHE_FILE" >"$tmp" || true
    printf '%s=%q\n' "$key" "$value" >>"$tmp"
    mv "$tmp" "$CACHE_FILE"
    chmod 600 "$CACHE_FILE"
}

save_protocol_flags() {
    {
        printf 'ENABLE_SS=%q\n' "$ENABLE_SS"
        printf 'ENABLE_HY2=%q\n' "$ENABLE_HY2"
        printf 'ENABLE_TUIC=%q\n' "$ENABLE_TUIC"
        printf 'ENABLE_REALITY=%q\n' "$ENABLE_REALITY"
        printf 'ENABLE_ANYTLS=%q\n' "$ENABLE_ANYTLS"
    } >"$PROTOCOL_FILE"
    chmod 600 "$PROTOCOL_FILE"
}

validate_config() {
    jq empty "$CONFIG_PATH" >/dev/null 2>&1 || { jq empty "$CONFIG_PATH" 2>&1 || true; return 1; }
    sing-box check -c "$CONFIG_PATH"
}

apply_candidate() {
    local candidate="$1" backup
    jq empty "$candidate" >/dev/null
    sing-box check -c "$candidate"

    backup="${CONFIG_PATH}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -a "$CONFIG_PATH" "$backup"
    mv "$candidate" "$CONFIG_PATH"
    chmod 600 "$CONFIG_PATH"

    if service_restart_raw; then
        sleep 1
        if [ "$OS" = "alpine" ]; then
            rc-service sing-box status >/dev/null 2>&1 && { ok "配置已应用。备份：$backup"; return 0; }
        else
            systemctl is-active --quiet sing-box && { ok "配置已应用。备份：$backup"; return 0; }
        fi
    fi

    err "新配置启动失败，自动恢复旧配置。"
    cp -a "$backup" "$CONFIG_PATH"
    service_restart_raw || true
    return 1
}

choose_generic_host() {
    if [ -n "${CUSTOM_IP:-}" ]; then printf '%s' "$CUSTOM_IP";
    else get_public_ipv4 || get_public_ipv6 || printf 'YOUR_SERVER_IP'; fi
}
choose_ss_host() {
    if [ -n "${CUSTOM_IP:-}" ]; then printf '%s' "$CUSTOM_IP";
    elif [ "${SS_IP_MODE:-auto}" != "auto" ]; then get_public_ipv6 || get_public_ipv4 || printf 'YOUR_SERVER_IP';
    else get_public_ipv4 || get_public_ipv6 || printf 'YOUR_SERVER_IP'; fi
}

generate_uris() {
    load_state || return 1
    local generic ss_host gh sh suffix enc info64
    generic="$(choose_generic_host)"
    ss_host="$(choose_ss_host)"
    gh="$(format_uri_host "$generic")"
    sh="$(format_uri_host "$ss_host")"
    suffix="$(cat "$NODE_NAME_FILE" 2>/dev/null || true)"
    local f="${CONFIG_DIR}/uris.txt"
    : >"$f"

    if $ENABLE_SS; then
        info64="${SS_METHOD}:${SS_PSK}"
        {
            echo "=== Shadowsocks (SS) ==="
            echo "# SS出口模式: ${SS_IP_MODE}"
            echo "ss://$(url_encode "$info64")@${sh}:${SS_PORT}#ss${suffix}"
            echo "ss://$(printf '%s' "$info64" | base64 | tr -d '\r\n')@${sh}:${SS_PORT}#ss${suffix}"
            echo
        } >>"$f"
    fi
    if $ENABLE_HY2; then
        {
            echo "=== Hysteria2 (HY2) ==="
            echo "hy2://$(url_encode "$HY2_PSK")@${gh}:${HY2_PORT}/?sni=www.bing.com&alpn=h3&insecure=1#hy2${suffix}"
            echo
        } >>"$f"
    fi
    if $ENABLE_TUIC; then
        {
            echo "=== TUIC ==="
            echo "tuic://${TUIC_UUID}:$(url_encode "$TUIC_PSK")@${gh}:${TUIC_PORT}/?congestion_control=bbr&alpn=h3&sni=www.bing.com&insecure=1#tuic${suffix}"
            echo
        } >>"$f"
    fi
    if $ENABLE_REALITY; then
        {
            echo "=== VLESS Reality ==="
            echo "vless://${REALITY_UUID}@${gh}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#reality${suffix}"
            echo
        } >>"$f"
    fi
    if $ENABLE_ANYTLS; then
        {
            echo "=== AnyTLS Reality ==="
            echo "anytls://$(url_encode "$ANYTLS_PSK")@${gh}:${ANYTLS_PORT}/?security=reality&sni=${REALITY_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${REALITY_SID}#anytls${suffix}"
            echo
        } >>"$f"
    fi
    chmod 600 "$f"
    cat "$f"
}

action_edit_config() {
    [ -f "$CONFIG_PATH" ] || { err "配置不存在"; return 1; }
    local backup="${CONFIG_PATH}.bak.edit.$(date +%Y%m%d_%H%M%S)"
    cp -a "$CONFIG_PATH" "$backup"

    if command -v nano >/dev/null 2>&1; then
        "${EDITOR:-nano}" "$CONFIG_PATH"
    else
        "${EDITOR:-vi}" "$CONFIG_PATH"
    fi

    if sing-box check -c "$CONFIG_PATH"; then
        if service_restart_raw; then
            ok "配置已校验并重启。备份：$backup"
        else
            err "服务重启失败，恢复旧配置。"
            cp -a "$backup" "$CONFIG_PATH"
            service_restart_raw || true
        fi
    else
        err "配置校验失败，恢复编辑前配置。"
        cp -a "$backup" "$CONFIG_PATH"
    fi
}

reset_port_by_type() {
    local type="$1" old="$2" label="$3"
    local p candidate
    read -r -p "新的 ${label} 端口(回车保持 ${old}): " p
    p="${p:-$old}"
    validate_port "$p" || { err "无效端口"; return 1; }

    candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"
    jq --arg type "$type" --argjson port "$p" \
       '.inbounds |= map(if .type==$type then .listen_port=$port else . end)' \
       "$CONFIG_PATH" >"$candidate"

    apply_candidate "$candidate"
}

action_set_ss_mode() {
    load_state || return 1
    $ENABLE_SS || { err "SS 未启用"; return 1; }

    echo "当前 SS 出口模式：$SS_IP_MODE"
    echo "1) 系统默认 / 双栈"
    echo "2) IPv6 优先（可回退 IPv4）"
    echo "3) 仅 IPv6（严格）"
    local c mode candidate
    read -r -p "请选择: " c
    case "$c" in
        1) mode="auto" ;;
        2) mode="prefer_ipv6" ;;
        3) mode="ipv6_only" ;;
        *) warn "无效选择"; return 0 ;;
    esac

    if [ "$mode" != "auto" ]; then
        local v6
        v6="$(get_public_ipv6 || true)"
        if [ -n "$v6" ]; then ok "IPv6 出口正常：$v6";
        else
            warn "未检测到可用 IPv6。"
            [ "$mode" = "ipv6_only" ] && {
                read -r -p "仍继续严格 IPv6？(y/N): " c
                [[ "$c" =~ ^[Yy]$ ]] || return 0
            }
        fi
    fi

    candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"
    jq --arg mode "$mode" '
      # 清理本脚本管理的 SS IPv6 专用对象，并兼容清理旧 direct-v6 布局。
      .outbounds = [ .outbounds[]? | select(.tag != "ss-direct-v6") ]
      | .route = (.route // {})
      | .route.rules = [
          (.route.rules // [])[]?
          | select(
              (.outbound // "") != "ss-direct-v6"
              and ((
                (.action // "") == "reject"
                and (.ip_version // 0) == 4
                and ((.inbound // []) | if type=="array" then index("ss-in") else .=="ss-in" end)
              ) | not)
              and ((
                (.action // "") == "resolve"
                and (.server // "") == "ss-local-dns"
                and ((.inbound // []) | if type=="array" then index("ss-in") else .=="ss-in" end)
              ) | not)
            )
        ]
      | if .dns then
          .dns.servers = [(.dns.servers // [])[]? | select(.tag != "ss-local-dns")]
          | if (.dns.servers|length)==0 and ((.dns.rules // [])|length)==0
            then del(.dns) else . end
        else . end
      | if $mode == "auto" then
          .route.final = "direct-out"
        else
          .dns = (.dns // {})
          | .dns.servers = ((.dns.servers // []) + [{
              type:"local", tag:"ss-local-dns", prefer_go:true
            }])
          | .route.rules += (
              if $mode=="ipv6_only" then [{
                inbound:["ss-in"], ip_version:4, action:"reject"
              }] else [] end
            )
          | .route.rules += [{
              inbound:["ss-in"],
              action:"resolve",
              server:"ss-local-dns",
              strategy:$mode
            }]
          | .route.final = "direct-out"
        end
    ' "$CONFIG_PATH" >"$candidate"

    if apply_candidate "$candidate"; then
        set_cache_key SS_IP_MODE "$mode"
        SS_IP_MODE="$mode"
        ok "SS 出口模式已切换为：$mode"
    fi
}

action_network_test() {
    echo "===== 本机网络出口 ====="
    local v4 v6
    v4="$(get_public_ipv4 || true)"
    v6="$(get_public_ipv6 || true)"
    echo "IPv4: ${v4:-不可用}"
    echo "IPv6: ${v6:-不可用}"
    echo
    echo "===== IPv6 地址 ====="
    ip -6 addr show scope global 2>/dev/null || true
    echo
    echo "===== IPv6 路由 ====="
    ip -6 route 2>/dev/null || true
    echo
    load_state || true
    echo "SS 出口模式: ${SS_IP_MODE:-unknown}"
}

action_validate() {
    if validate_config; then ok "配置校验通过。"; else err "配置校验失败。"; fi
}

action_update() {
    local tmp
    tmp="$(mktemp /tmp/singbox-update.XXXXXX)"
    curl -fsSL https://sing-box.app/install.sh -o "$tmp"
    bash "$tmp"
    rm -f "$tmp"

    info "当前版本：$(sing-box version 2>/dev/null | head -n1 || true)"
    if validate_config; then
        service_restart_raw
        ok "更新完成并已重启。"
    else
        err "新版本无法接受当前配置，未主动重启；请检查配置。"
        return 1
    fi
}

action_add_ss_if_missing() {
    load_state || return 1
    $ENABLE_SS && return 0

    local p method password mode candidate c
    read -r -p "未启用 SS，是否现在添加？(y/N): " c
    [[ "$c" =~ ^[Yy]$ ]] || return 1

    p="$(rand_port)"
    read -r -p "SS 端口(默认 $p): " c
    p="${c:-$p}"
    validate_port "$p" || { err "端口无效"; return 1; }
    method="2022-blake3-aes-128-gcm"
    password="$(rand_pass)"
    mode="auto"

    candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"
    jq --argjson port "$p" --arg method "$method" --arg pass "$password" '
      .inbounds += [{
        type:"shadowsocks",listen:"::",listen_port:$port,
        method:$method,password:$pass,tag:"ss-in"
      }]
    ' "$CONFIG_PATH" >"$candidate"

    apply_candidate "$candidate" || return 1
    ENABLE_SS=true
    SS_PORT="$p"; SS_METHOD="$method"; SS_PSK="$password"; SS_IP_MODE="$mode"
    set_cache_key ENABLE_SS true
    set_cache_key SS_PORT "$p"
    set_cache_key SS_METHOD "$method"
    set_cache_key SS_PSK "$password"
    set_cache_key SS_IP_MODE "$mode"
    save_protocol_flags
    ok "SS 已添加。"
}

action_generate_relay() {
    load_state || return 1
    action_add_ss_if_missing || return 1
    load_state

    local landing_host
    if [ -n "${CUSTOM_IP:-}" ]; then
        landing_host="$CUSTOM_IP"
    elif [ "${SS_IP_MODE:-auto}" != "auto" ]; then
        landing_host="$(get_public_ipv6 || get_public_ipv4 || true)"
    else
        landing_host="$(get_public_ipv4 || get_public_ipv6 || true)"
    fi
    [ -n "$landing_host" ] || { err "无法获取落地机连接地址，请先在缓存 CUSTOM_IP 中指定。"; return 1; }

    local out="/root/install-singbox-relay.sh"
    cat >"$out" <<'RELAY'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

info(){ echo -e "\033[1;34m[INFO]\033[0m $*"; }
err(){ echo -e "\033[1;31m[ERR ]\033[0m $*" >&2; }
[ "$(id -u)" -eq 0 ] || { err "必须 root 运行"; exit 1; }

os_id="$(awk -F= '$1=="ID"{gsub(/"/,"",$2);print tolower($2);exit}' /etc/os-release 2>/dev/null || true)"
case "$os_id" in
  alpine) apk update; apk add --no-cache bash curl jq openssl ca-certificates coreutils ;;
  debian|ubuntu) apt-get update -y; apt-get install -y curl jq openssl ca-certificates coreutils ;;
  *) command -v dnf >/dev/null && dnf install -y curl jq openssl ca-certificates coreutils || true ;;
esac

tmp="$(mktemp /tmp/singbox-install.XXXXXX)"
curl -fsSL https://sing-box.app/install.sh -o "$tmp"
bash "$tmp"
rm -f "$tmp"
SB_BIN="$(command -v sing-box)"
[ "$SB_BIN" = "/usr/bin/sing-box" ] || ln -sf "$SB_BIN" /usr/bin/sing-box

UUID="$(cat /proc/sys/kernel/random/uuid)"
KEYS="$(sing-box generate reality-keypair)"
PK="$(awk '/PrivateKey/{print $NF;exit}' <<<"$KEYS")"
REALITY_PUB="$(awk '/PublicKey/{print $NF;exit}' <<<"$KEYS")"
SID="$(sing-box generate rand 8 --hex)"
read -r -p "线路机监听端口(留空随机 20000-65000): " P
if [ -z "$P" ]; then
    if command -v shuf >/dev/null 2>&1; then P="$(shuf -i 20000-65000 -n1)"; else P=20443; fi
fi

mkdir -p /etc/sing-box
cat >/etc/sing-box/config.json <<JSON
{
  "log":{"level":"info","timestamp":true},
  "dns":{"servers":[{"type":"local","tag":"local","prefer_go":true}]},
  "inbounds":[{
    "type":"vless",
    "listen":"::",
    "listen_port":${P},
    "users":[{"uuid":"${UUID}","flow":"xtls-rprx-vision"}],
    "tls":{
      "enabled":true,
      "server_name":"__SNI__",
      "reality":{
        "enabled":true,
        "handshake":{"server":"__SNI__","server_port":443},
        "private_key":"${PK}",
        "short_id":["${SID}"]
      }
    },
    "tag":"vless-in"
  }],
  "outbounds":[
    {
      "type":"shadowsocks",
      "server":"__LANDING_HOST__",
      "server_port":__LANDING_PORT__,
      "method":"__LANDING_METHOD__",
      "password":"__LANDING_PASS__",
      "domain_resolver":"local",
      "tag":"relay-out"
    },
    {"type":"direct","tag":"direct-out"}
  ],
  "route":{
    "rules":[{
      "inbound":["vless-in"],
      "action":"route",
      "outbound":"relay-out"
    }],
    "final":"direct-out"
  }
}
JSON

sing-box check -c /etc/sing-box/config.json
chmod 600 /etc/sing-box/config.json

if [ -f /etc/alpine-release ]; then
cat >/etc/init.d/sing-box <<'RC'
#!/sbin/openrc-run
name="sing-box"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=yes
pidfile="/run/sing-box.pid"
supervisor=supervise-daemon
supervise_daemon_args="--respawn-max 0 --respawn-delay 5"
depend(){ need net; }
RC
chmod +x /etc/init.d/sing-box
rc-update add sing-box default
rc-service sing-box restart
else
cat >/etc/systemd/system/sing-box.service <<'UNIT'
[Unit]
Description=Sing-box Relay
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable sing-box >/dev/null
systemctl restart sing-box
fi

get4(){ curl -4 -fsS --max-time 7 https://api.ipify.org 2>/dev/null || true; }
get6(){ curl -6 -fsS --max-time 7 https://api64.ipify.org 2>/dev/null || true; }
PUB_IP="$(get4)"; [ -n "$PUB_IP" ] || PUB_IP="$(get6)"
if [[ "$PUB_IP" == *:* ]]; then URI_HOST="[${PUB_IP}]"; else URI_HOST="$PUB_IP"; fi
URI="vless://${UUID}@${URI_HOST}:${P}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=__SNI__&fp=chrome&pbk=${REALITY_PUB}&sid=${SID}#relay"
echo "$URI" >/etc/sing-box/relay_uri.txt
echo
info "中转节点链接："
cat /etc/sing-box/relay_uri.txt
RELAY

    # 注意：替换顺序与分隔符，避免 IPv6 冒号问题
    sed -i \
        -e "s|__LANDING_HOST__|$(printf '%s' "$landing_host" | sed 's/[&|]/\\&/g')|g" \
        -e "s|__LANDING_PORT__|${SS_PORT}|g" \
        -e "s|__LANDING_METHOD__|$(printf '%s' "$SS_METHOD" | sed 's/[&|]/\\&/g')|g" \
        -e "s|__LANDING_PASS__|$(printf '%s' "$SS_PSK" | sed 's/[&|]/\\&/g')|g" \
        -e "s|__SNI__|$(printf '%s' "$REALITY_SNI" | sed 's/[&|]/\\&/g')|g" \
        "$out"


    chmod 700 "$out"
    ok "线路机安装脚本已生成：$out"
    echo "复制到线路机后执行：bash $out"
}

action_uninstall() {
    local c
    read -r -p "确认卸载 sing-box 及本脚本配置？(y/N): " c
    [[ "$c" =~ ^[Yy]$ ]] || return 0

    service_stop || true
    if [ "$OS" = "alpine" ]; then
        rc-update del sing-box default 2>/dev/null || true
        rm -f /etc/init.d/sing-box
        apk del sing-box >/dev/null 2>&1 || true
    else
        systemctl disable sing-box >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/sing-box.service
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    rm -rf /etc/sing-box /var/log/sing-box* /usr/local/bin/sb /usr/bin/sb /root/node_names.txt
    ok "卸载完成。"
}

show_menu() {
    load_state 2>/dev/null || true
    declare -gA MENU_MAP=()
    local n=1

    echo
    echo "================================================"
    echo " Sing-box 管理面板"
    echo "================================================"

    echo "$n) 查看协议链接"; MENU_MAP[$n]="uri"; n=$((n+1))
    echo "$n) 查看配置文件"; MENU_MAP[$n]="config"; n=$((n+1))
    echo "$n) 编辑配置文件（失败自动回滚）"; MENU_MAP[$n]="edit"; n=$((n+1))
    echo "$n) 校验配置"; MENU_MAP[$n]="validate"; n=$((n+1))
    echo "$n) 网络 / IPv4 / IPv6 检测"; MENU_MAP[$n]="net"; n=$((n+1))

    if ${ENABLE_SS:-false}; then
        echo "$n) 重置 SS 端口"; MENU_MAP[$n]="reset_ss"; n=$((n+1))
        echo "$n) 设置 SS 出口 IP 模式 [${SS_IP_MODE:-auto}]"; MENU_MAP[$n]="ss_mode"; n=$((n+1))
    fi
    if ${ENABLE_HY2:-false}; then
        echo "$n) 重置 HY2 端口"; MENU_MAP[$n]="reset_hy2"; n=$((n+1))
    fi
    if ${ENABLE_TUIC:-false}; then
        echo "$n) 重置 TUIC 端口"; MENU_MAP[$n]="reset_tuic"; n=$((n+1))
    fi
    if ${ENABLE_REALITY:-false}; then
        echo "$n) 重置 VLESS Reality 端口"; MENU_MAP[$n]="reset_vless"; n=$((n+1))
    fi
    if ${ENABLE_ANYTLS:-false}; then
        echo "$n) 重置 AnyTLS Reality 端口"; MENU_MAP[$n]="reset_anytls"; n=$((n+1))
    fi

    echo "$n) 启动服务"; MENU_MAP[$n]="start"; n=$((n+1))
    echo "$n) 停止服务"; MENU_MAP[$n]="stop"; n=$((n+1))
    echo "$n) 安全重启服务（先校验）"; MENU_MAP[$n]="restart"; n=$((n+1))
    echo "$n) 查看服务状态"; MENU_MAP[$n]="status"; n=$((n+1))
    echo "$n) 查看最近日志"; MENU_MAP[$n]="logs"; n=$((n+1))
    echo "$n) 更新 sing-box"; MENU_MAP[$n]="update"; n=$((n+1))
    echo "$n) 生成线路机 VLESS Reality → 本机 SS 脚本"; MENU_MAP[$n]="relay"; n=$((n+1))
    echo "$n) 卸载 sing-box"; MENU_MAP[$n]="uninstall"; n=$((n+1))
    echo "0) 退出"
    echo "================================================"
}

while true; do
    show_menu
    read -r -p "请输入选项: " opt
    [ "$opt" = "0" ] && exit 0
    action="${MENU_MAP[$opt]:-}"
    case "$action" in
        uri) generate_uris ;;
        config) echo "$CONFIG_PATH"; cat "$CONFIG_PATH" ;;
        edit) action_edit_config ;;
        validate) action_validate ;;
        net) action_network_test ;;
        reset_ss) load_state; reset_port_by_type shadowsocks "$SS_PORT" "SS" ;;
        ss_mode) action_set_ss_mode ;;
        reset_hy2) load_state; reset_port_by_type hysteria2 "$HY2_PORT" "HY2" ;;
        reset_tuic) load_state; reset_port_by_type tuic "$TUIC_PORT" "TUIC" ;;
        reset_vless) load_state; reset_port_by_type vless "$REALITY_PORT" "VLESS Reality" ;;
        reset_anytls) load_state; reset_port_by_type anytls "$ANYTLS_PORT" "AnyTLS Reality" ;;
        start) service_start && ok "已启动" ;;
        stop) service_stop && ok "已停止" ;;
        restart) service_restart_safe && ok "已重启" ;;
        status) service_status ;;
        logs) show_logs ;;
        update) action_update ;;
        relay) action_generate_relay ;;
        uninstall) action_uninstall; exit 0 ;;
        *) warn "无效选项：$opt" ;;
    esac
    echo
done
SB_SCRIPT

    chmod 755 "$SB_PATH"
    ln -sf "$SB_PATH" /usr/bin/sb
    ok "管理面板已创建：输入 sb 即可打开。"
}

show_summary() {
    echo
    echo "================================================"
    echo " Sing-box 部署完成"
    echo "================================================"
    echo "脚本版本：$SCRIPT_VERSION"
    echo "sing-box：$(sing-box version 2>/dev/null | head -n1 || true)"
    echo "配置文件：$CONFIG_PATH"
    $ENABLE_SS && echo "SS：端口 $PORT_SS | $SS_METHOD | 出口模式 $SS_IP_MODE"
    $ENABLE_HY2 && echo "HY2：端口 $PORT_HY2"
    $ENABLE_TUIC && echo "TUIC：端口 $PORT_TUIC"
    $ENABLE_REALITY && echo "VLESS Reality：端口 $PORT_REALITY | SNI $REALITY_SNI"
    $ENABLE_ANYTLS && echo "AnyTLS Reality：端口 $PORT_ANYTLS | SNI $REALITY_SNI"
    echo
    echo "协议链接："
    cat "${CONFIG_DIR}/uris.txt"
    echo "管理命令：sb"
    echo "================================================"
}

main() {
    check_root
    detect_os
    info "系统：$OS (${OS_ID:-unknown})"
    install_deps

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    prompt_node_name
    select_protocols
    select_ss_method
    select_ss_ip_mode
    prompt_connection_host

    REALITY_SNI="$DEFAULT_REALITY_SNI"
    if $ENABLE_REALITY || $ENABLE_ANYTLS; then
        select_reality_sni
    fi

    configure_protocol_values
    install_singbox
    generate_reality_keys
    generate_cert

    local candidate
    candidate="$(mktemp "${CONFIG_DIR}/.candidate.XXXXXX")"
    cleanup_files+=("$candidate")
    build_config_file "$candidate"

    # 核心原则：配置校验失败绝不继续，也绝不覆盖工作配置。
    install_config_atomic "$candidate" || die "生成配置无效，已停止安装。"

    save_state
    setup_service
    generate_uris_install
    install_sb_panel
    show_summary
}

main "$@"

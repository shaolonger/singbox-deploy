# singbox-deploy-shaolonger 深度安全审计报告 (V2)

## 概述

在修复了基础的“远程代码执行”、“临时文件竞态”以及“权限管理”等问题后，我们对 `singbox-deploy-shaolonger` 脚本项目进行了更加**深入的白盒代码安全审查**。本次审查主要关注**用户输入交互处理**、**代码注入点**以及**应用运行时的特权隔离**。

尽管该脚本主要在用户自己的机器上由管理员主动运行，但在自动化运维（如通过云提供商的 metadata 注入、Ansible/Terraform 自动化参数喂入）或多用户操作环境中，以下隐藏的安全漏洞依然可能被转化为**本地提权 (Local Privilege Escalation)** 或**任意命令执行 (Command Injection)**。

本报告列出了本次深度检查发现的高级安全隐患，并提供修复建议供后续重构参考。

---

## 1. 交互式提示符引发的命令注入 (Command Injection via Sourcing)

**严重程度**：高

**漏洞描述**：
在诸多脚本文件（如 `install-singbox-yyds*.sh` 等）中，脚本会通过 `read -r` 获取用户输入（如 `CUSTOM_IP` 或 `REALITY_SNI`），并直接以纯文本拼接的方式写入到 `.config_cache` 缓存文件中：
```bash
read -r CUSTOM_IP
CUSTOM_IP="$(echo "$CUSTOM_IP" | tr -d '[:space:]')"
echo "CUSTOM_IP=$CUSTOM_IP" >> /etc/sing-box/.config_cache.tmp
```
随后，在脚本的后续流程以及生成的 `sb` 管理脚本中，会直接通过 `source` (`.`) 命令加载该缓存：
```bash
if [ -f "$CACHE_FILE" ]; then
    . "$CACHE_FILE"
fi
```
**攻击利用场景**：如果恶意用户或自动化平台在提示输入 `CUSTOM_IP` 时输入：
`1.1.1.1";rm -rf /;#`
那么缓存文件中的内容将变为：
`CUSTOM_IP=1.1.1.1";rm -rf /;#`
当 `sb` 工具或脚本重新加载此文件时，Bash 将在 `root` 权限下立刻执行 `rm -rf /`，造成灾难性后果。

**修复建议**：
在将变量写入会被 `source` 加载的环境变量文件时，必须进行严谨的引用转义，或者直接杜绝使用 `source` 加载不受信的数据：
1. **严格包裹**：使用 `printf` 与单引号：`printf "CUSTOM_IP='%s'\n" "${CUSTOM_IP//\'/}" >> "$CACHE_FILE"`。
2. **输入白名单清洗**：针对 IP，仅允许 `0-9` 与 `.`；针对 SNI，仅允许字母、数字及横杠：
   `CUSTOM_IP="$(echo "$CUSTOM_IP" | tr -cd '0-9.')"`

---

## 2. sed 表达式注入攻击 (Sed Expression Injection)

**严重程度**：高

**漏洞描述**：
在生成 JSON 配置文件时，由于 bash 缺乏现成的 JSON 解析器（如 jq 并非所有系统预装），脚本大量依赖 `sed` 进行字符串替换。例如：
```bash
read -p "请输入 SS 端口(留空则随机): " USER_PORT_SS
PORT_SS="${USER_PORT_SS:-$(rand_port)}"
# ...
sed -i "s|PORT_SS_PLACEHOLDER|$PORT_SS|g" "$TEMP_INBOUNDS"
```
由于没有对 `$PORT_SS`（及其他参数）的值进行任何过滤，如果攻击者故意在端口处输入带有分隔符 `|` 以及 sed 控制符的内容（如：`1234|w /etc/cron.d/malicious_cron|`），则可以直接跳出 `sed` 的 `s` 命令沙盒，将文件内容写入系统任意高权限目录（如定时任务），实现提权。

**修复建议**：
1. **替换为 `jq` 构建**：由于前面已经通过 `apk/apt/yum` 安装了 `jq`，最安全的做法是使用 `jq` 直接通过键值赋值更新 JSON，例如：
   `jq --arg p "$PORT_SS" '.inbounds[0].listen_port = ($p | tonumber)' config.json > tmp.json`
2. 若必须使用 `sed`，需要对用于分隔符的字符（如 `|`、`/`、`&`）进行过滤或前置转义处理。

---

## 3. Sing-box 服务以 Root 特权运行 (Violation of Least Privilege)

**严重程度**：中

**漏洞描述**：
生成的 Systemd 服务文件固定包含了：
```ini
[Service]
Type=simple
User=root
```
`sing-box` 作为一个复杂的网络协议代理服务端，负责解析并处理大量的外部不受信流量。尽管 Go 语言本身具有内存安全特性，但如果 sing-box 存在逻辑漏洞或者被发现新的反序列化等相关漏洞，攻击者一旦攻破 `sing-box` 进程，便直接获取了操作系统的 `root` 权限，没有任何降权隔离。

**修复建议**：
代理软件应当作为普通用户运行，这在大型服务器架构中是常识。
1. **创建专用账户**：在安装阶段执行 `useradd -M -s /sbin/nologin sing-box`。
2. **提权绑定网络**：修改 systemd 服务为：
   ```ini
   User=sing-box
   AmbientCapabilities=CAP_NET_BIND_SERVICE
   ```
3. **文件权限划归**：确保 `/etc/sing-box` 和 `/var/log/sing-box.log` 属于 `sing-box:sing-box`。

---

## 4. 参数输入缺乏合法性边界校验 (Lack of Input Validation)

**严重程度**：低

**漏洞描述**：
目前脚本仅通过 `tr -d '[:space:]'` 去除了输入中的空格，并未对具体参数值的合理性做任何兜底验证。例如：
1. **端口号校验**：用户完全可以输入非数字（如 `abc`），或者超出 `65535` 的超大数值，导致后续服务拉起时直接崩溃无法启动。
2. **UUID 校验**：在使用外部输入的 UUID 替代随机生成 UUID 时，并未做正则表达式校验（如 `^[0-9a-f]{8}-...`），会导致 sing-box 启动报错。

**修复建议**：
引入规范化的输入检测函数：
```bash
function validate_port() {
    if ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 1 ] || [ "$1" -gt 65535 ]; then
        echo "无效端口: $1" ; exit 1
    fi
}
```
在每次 `read` 后强制执行该类校验。

---

## 总结

虽然之前的加固已经拦截了脚本**执行环境本身**的大部分通用威胁（如 `/tmp` 劫持、配置泄露等），但在处理**非可信输入**和**进程隔离**方面依然存在传统的 Shell 脚本通病（注入与超权）。

对于一个健壮的自动化运维脚本：
- **永远不要直接拼接用户的输入到 `sed` 语句中。**
- **永远不要将用户输入原文写入会被 `. (source)` 加载的文件中。**
- **始终遵循权限最小化（Non-Root 运行）原则。**

建议在项目的后续更新版本中逐步落实上述深层隐患的修复工作。

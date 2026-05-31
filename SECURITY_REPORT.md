# singbox-deploy-shaolonger 安全审计报告

## 概述

对 `singbox-deploy-shaolonger` 项目下的多份安装脚本（如 `install-singbox.sh`, `install-singbox-all.sh`, `install-singbox-yyds*.sh` 等）进行了代码安全审计。总体来看，这些脚本能够方便快捷地完成 `sing-box` 的部署工作，但在设计与实现上存在若干较为普遍的系统安全隐患，可能导致服务器遭受权限提升、信息泄露或恶意代码执行等攻击。

本报告列出了发现的主要安全隐患，并提供了相应的修复建议。

---

## 1. 任意代码执行风险 (直接运行远程脚本)

**严重程度**：高

**漏洞描述**：
在大部分脚本中，使用了如下的命令来安装或更新 sing-box：
```bash
bash <(curl -fsSL https://sing-box.app/install.sh)
```
这种做法会直接以 `root` 权限执行从互联网下载的未经完整性校验的脚本。如果官方域名被劫持、DNS 污染或发生中间人攻击 (MITM)（虽然在 HTTPS 环境下较难，但仍有可能），攻击者可以向服务器注入任意恶意代码，直接获取服务器的最高控制权。

**修复建议**：
不推荐使用直接执行远程脚本的方式。更安全的做法是：
1. **优先使用预编译二进制文件**：直接下载官方 GitHub Releases 中的对应架构压缩包。
2. **强制校验**：在下载后校验文件的 SHA256 哈希值或 GPG 签名，确认文件未被篡改后再赋予执行权限并移入 `/usr/local/bin/` 目录中。

---

## 2. 不安全的临时文件创建 (Race Condition / Symlink Attack)

**严重程度**：中 - 高

**漏洞描述**：
在如 `install-singbox-all.sh` 等脚本中，存在将内容直接写入硬编码或部分可预测的 `/tmp/` 目录的现象。例如：
```bash
RELAY_SCRIPT_PATH="/tmp/relay-install.sh"
local TEMP_INBOUNDS="/tmp/singbox_inbounds_$.json"
```
其中 `$$` (PID) 是相对容易预测的。
如果系统存在其他恶意本地用户，可以利用竞争条件（Race Condition），提前在此路径创建指向关键系统文件（如 `/etc/shadow` 或 `/root/.ssh/authorized_keys`）的符号链接（Symlink）。当脚本以 `root` 身份运行时，会顺着软连接将内容覆盖到这些系统核心文件中，造成严重的破坏或权限获取。

**修复建议**：
在 Bash 中处理临时文件时，应始终使用 `mktemp` 命令安全地生成随机路径：
```bash
RELAY_SCRIPT_PATH=$(mktemp /tmp/relay-install.XXXXXX.sh)
local TEMP_INBOUNDS=$(mktemp /tmp/singbox_inbounds_XXXXXX.json)
```

---

## 3. 敏感配置文件的权限过大

**严重程度**：中

**漏洞描述**：
脚本在生成包含 Shadowsocks 密钥（`$PSK`）的配置文件 `/etc/sing-box/config.json` 时，没有主动收缩文件权限。
默认情况下，通过 `cat > config.json` 生成的文件，其权限通常为 `644` (即 `-rw-r--r--`)。这意味着系统上的所有用户（即使是权限极低的 `www-data` 或 `nobody` 等）都可以直接读取配置文件的内容并获取代理密码。

**修复建议**：
在生成配置文件之后，必须立即限制该文件及所在目录的访问权限，仅允许 `root` 访问：
```bash
chmod 700 /etc/sing-box
chmod 600 /etc/sing-box/config.json
```

---

## 4. Systemd 服务以 root 权限运行

**严重程度**：中

**漏洞描述**：
脚本创建的 Systemd 配置文件中包含 `User=root`：
```ini
[Service]
Type=simple
User=root
```
这意味着 `sing-box` 主进程以操作系统的最高权限运行。如果 `sing-box` 自身存在未知的缓冲区溢出或远程代码执行漏洞，攻击者一旦突破进程便直接获得机器的 `root` 权限。

**修复建议**：
最佳实践应遵循“权限最小化”原则。可以创建一个专门的非特权用户（例如 `sing-box`），将配置文件所有者交给该用户，并使用 `User=sing-box` 运行服务。如果需要监听 1024 以下的特权端口（如 443 端口），可以通过配置 Systemd 的 `AmbientCapabilities=CAP_NET_BIND_SERVICE` 来授权该能力，而不需要完整的 `root` 权限。

---

## 5. 日志与控制台明文输出密码

**严重程度**：低

**漏洞描述**：
脚本在部署完成后，在标准输出 (stdout) 中直接打印了刚刚生成的明文密码 `$PSK` 以及包含密码的完整 `ss://` URI 链接。
如果该脚本是通过某些自动化运维平台（如 Ansible、Jenkins 或云服务商的初始化脚本）执行，部署日志会被长期存档在这些平台上。任何能接触到日志的人都会获得代理服务器的控制权。

**修复建议**：
对于纯交互式的手动部署，输出密码勉强可以接受；但在设计为通用安装脚本时，建议：
1. 不要在终端回显明文密码，或者提供参数选项以决定是否在终端显示。
2. 告知用户密码保存在 `/etc/sing-box/config.json` 中，需要时可登录机器查看。

---

## 6. 不严谨的随机数生成机制 (仅针对少部分老旧系统环境)

**严重程度**：低

**漏洞描述**：
在生成端口回退时使用了 `$RANDOM % 50001`：
```bash
PORT=$(shuf -i 10000-60000 -n 1 2>/dev/null || echo $((RANDOM % 50001 + 10000)))
```
在密码生成备选方案中，使用了 `/dev/urandom`：
```bash
PSK=$(head -c "$KEY_BYTES" /dev/urandom | base64 | tr -d '\n\r')
```
对于密码生成，`openssl rand` 是最可靠的首选；对于端口生成，`$RANDOM` 虽然并不是加密安全的，但对于随机指定端口目的已经足够。该问题不属于严重的漏洞，仅作为代码规范上的瑕疵提出。

**修复建议**：
当前脚本中密码生成首选了 `sing-box generate rand` 以及 `openssl rand`，逻辑已经比较健全。回退机制中的问题基本不会在现代 Linux 系统上被触发。

---

## 总结与建议
项目脚本非常全面地考虑了多系统兼容性和多协议扩展，但在 `系统权限管理` 和 `临时文件操作安全` 方面有待进一步加强。
建议开发者：
1. 对所有的 `/tmp/` 路径硬编码进行排查，替换为 `mktemp`。
2. 为 `/etc/sing-box/config.json` 补加 `chmod 600`。
3. 谨慎评估是否需要继续使用 `bash <(curl ...)`，并考虑加入 SHA256 校验。

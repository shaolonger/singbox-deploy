# Sing-box 多协议一键部署脚本

一个面向 VPS 的 Sing-box 一键部署与管理脚本，支持 **Shadowsocks / SS2022、Hysteria2、TUIC、VLESS Reality、AnyTLS Reality** 自由组合部署，并支持从落地机生成 **VLESS Reality 线路机 → Shadowsocks 落地机** 的中转方案。

当前脚本同时加强了 Shadowsocks 的 IPv6 落地能力：可在安装时或后续通过 `sb` 管理面板选择 **系统默认 / IPv6 优先 / 仅 IPv6**，适合 AI、流媒体以及对出口 IP 有明确要求的场景。

---

## ✨ 主要特性

### 🎯 多协议一键部署

- ✅ **协议自由组合**：Shadowsocks、Hysteria2、TUIC、VLESS Reality、AnyTLS Reality 可按需选择
- ✅ **SS2022 默认推荐**：Shadowsocks 默认使用 `2022-blake3-aes-128-gcm`
- ✅ **Reality SNI 自动探测**：自动测试候选 SNI，也支持手动指定
- ✅ **自动生成凭据**：自动生成 UUID、密码、Reality 密钥、Short ID 等
- ✅ **自动生成节点链接**：部署完成后输出对应协议分享链接
- ✅ **IPv6 URI 兼容**：IPv6 地址在分享链接中自动转换为 `[IPv6]:端口` 格式
- ✅ **多系统支持**：支持 Debian / Ubuntu、Alpine、CentOS / RHEL / Fedora 等常见 Linux 系统
- ✅ **开机自启**：自动配置 systemd / OpenRC，并支持服务异常后的自动拉起

### 🌐 Shadowsocks IPv6 出口模式

安装 Shadowsocks 时可直接选择最终互联网出口策略：

```text
1) 系统默认 / 双栈
2) IPv6 优先
3) 仅 IPv6
```

#### 1. 系统默认 / 双栈 `auto`

保持普通 Sing-box 行为，由系统、DNS 与目标网站共同决定使用 IPv4 或 IPv6。

适合普通 VPS、没有明确 IPv6 出口需求的节点。

#### 2. IPv6 优先 `prefer_ipv6`

对于通过 `ss-in` 进入的域名请求优先解析并使用 IPv6；当目标没有可用 IPv6 时仍可回退 IPv4。

推荐用于：

- AI IPv6 落地
- 希望大部分网站使用 IPv6、但仍需兼容 IPv4-only 依赖的场景
- ChatGPT / Claude / Gemini 等包含大量第三方 CDN、登录和静态资源的服务

#### 3. 仅 IPv6 `ipv6_only`

通过 `ss-in` 的域名仅解析 IPv6，同时拒绝直接传入的 IPv4 目标。

适合严格要求 **SS 不允许 IPv4 出口** 的场景。若目标或其依赖只支持 IPv4，该连接会失败。

> IPv6 模式只作用于 Shadowsocks 入站 `ss-in`。同一台 VPS 上的 VLESS Reality、HY2、TUIC、AnyTLS 不会因此被强制改为 IPv6。

---

## 🔗 线路机 → 落地机中转

脚本支持从落地机直接生成 VLESS Reality 线路机部署脚本，用于以下架构：

```text
客户端 / Clash Verge Rev
        │
        │ VLESS + Reality
        ▼
      线路机
        │
        │ Shadowsocks / SS2022
        ▼
      落地机
        │
        ├─ IPv4
        └─ IPv6 / IPv6 优先
        ▼
      目标网站
```

线路机本身使用 IPv4 入口并不会阻止最终使用 IPv6 出口。关键是：

1. 线路机必须能够通过 IPv6 访问落地机（如果 SS 落地地址使用 IPv6）；
2. 落地机自身必须具有正常 IPv6 地址和默认路由；
3. Shadowsocks 出口模式选择 `prefer_ipv6` 或 `ipv6_only`。

---

## 🛠 `sb` 管理面板

安装完成后直接执行：

```bash
sb
```

管理面板会根据已安装协议动态显示相关选项，主要功能包括：

- 查看协议链接
- 查看 Sing-box 配置文件
- 编辑配置文件（失败自动回滚）
- 校验配置
- IPv4 / IPv6 网络检测
- 重置各协议端口
- 随时切换 SS 出口 IP 模式
- 启动 / 停止 Sing-box
- 安全重启（先执行配置校验）
- 查看服务状态
- 查看最近日志
- 更新 Sing-box
- 生成“VLESS Reality 线路机 → 本机 SS”部署脚本
- 卸载 Sing-box

### 修改 SS 出口模式

以后不需要手动编辑 `/etc/sing-box/config.json`：

```bash
sb
```

选择：

```text
设置 SS 出口 IP 模式
```

即可在以下模式间切换：

```text
auto
prefer_ipv6
ipv6_only
```

脚本会先生成候选配置并执行 `sing-box check`，通过后才替换正式配置和重启服务；如果新配置导致服务启动失败，会尽量恢复之前的工作配置。

---

## ✅ 一键部署命令

使用 root 用户执行：

```sh
u="https://github.com/shaolonger/singbox-deploy/releases/latest/download/install-latest.sh?ts=$(date +%s)"; (curl -fsSL "$u" -o /root/install-singbox-latest.sh 2>/dev/null || wget -qO /root/install-singbox-latest.sh "$u") && sh /root/install-singbox-latest.sh
```

这条命令兼容系统预装的 curl 或 wget（Alpine 默认提供 wget）。两者都没有的极简镜像，需要先用系统包管理器安装其中一个下载工具及 CA 证书，例如 Debian/Ubuntu 执行 `apt-get update && apt-get install -y curl ca-certificates`。下载器就绪后，POSIX `sh` 启动器会补齐 Bash 等依赖、查询最新正式 Release，并从文件运行交互式安装脚本。每次发布 Release 会自动附带启动器；命令不固定版本号，也不会触发 `bash -c` 的参数长度限制。

安装流程会依次完成：

1. 检测系统并安装依赖
2. 输入可选节点名称
3. 选择需要部署的协议
4. 如果选择 SS，选择加密方式与 SS 出口 IP 模式
5. 输入节点连接 IP / DDNS（支持 IPv4、IPv6、域名）
6. Reality / AnyTLS 场景自动探测或手动指定 SNI
7. 配置协议端口与凭据
8. 安装 / 更新 Sing-box
9. 生成配置并执行真实 `sing-box check`
10. 校验成功后写入配置、启动服务并安装 `sb` 管理面板

### Alpine 提示 `No space left on device`

如果错误发生在 `apk add` 解压 `/usr/lib`、`/usr/bin` 或写入包数据库时，表示对应文件系统的可用空间或 inode 已耗尽。标称 1G 硬盘不等于根目录仍有 1G 可用；`/usr` 可能单独挂载，容器和 tmpfs 也可能有更小的容量限制。先检查：

```sh
df -h / /usr /tmp /lib/apk/db
df -i / /usr /tmp /lib/apk/db
du -xhd1 / 2>/dev/null
du -xhd1 /var /root /usr 2>/dev/null
mount
```

按检查结果清理不需要的下载包、日志或备份，或者扩容实际写入的文件系统/容器配额。不要直接删除 `/usr/lib` 或 `/lib/apk/db`。脚本已经使用 `apk add --no-cache`，重复加该参数不能解决解压后文件没有空间的问题；`bind-tools` 还会安装 `bind-libs`、Kerberos 等依赖，不能只按包名数量估算占用。

当前版本在 Alpine 安装依赖前检查 `/`、`/usr`、已有的 `/usr/local` 各自所在文件系统至少有 **128 MiB 可用空间**，并检查 `/etc`、APK 数据库及临时目录至少有 8 MiB 可用空间和可用 inode。依赖安装后再次检查二进制写入目录至少有 90 MiB 可用空间。这些是保守的最低门槛，实际需求取决于系统已有依赖和 sing-box 版本，并不保证满足所有配额限制。

如果之前已经安装到一半，释放空间后先修复已登记的软件包，再重跑安装命令：

```sh
apk fix --no-cache
```

`apk fix` 用于修复/重新安装包；如果包数据库本身无法读取，需要先恢复数据库或修复系统。参见 [Alpine APK 修复说明](https://github.com/alpinelinux/apk-tools/blob/master/doc/apk-fix.8.scd)。上面的 `releases/latest` 命令从最新正式 Release 获取安装器，直接修改分支不会改变已发布版本。

---

### Reality target 的选择与验证范围

安装器、线路机脚本和 `sb` 面板共用一套探测和选择规则。输出分别展示协议兼容性、实际目标 IP/地址族/ASN、与 VPS 的拓扑关系、客户端测量状态、回落滥用提示及短时采样成功率，不再把这些信息合成“安全分”。

- **协议兼容性**：从 VPS 对选定 IP 检查 TLS 1.3、H2、证书名称及重定向行为。静态探测显式绕过代理环境变量，最多尝试每种地址族一个端点，并以成功的实际 IP 完成全部采样；选择后，服务端握手地址固定为已验证的 IP，SNI 仍使用域名。
- **大厂优先**：合格的大厂域名优先于其他候选；大厂内部按本轮多次 TLS 建连耗时的中位数从低到高选择。同延迟时再比较 ASN、规则提示和短时成功率。这里的耗时是 **VPS 到已固定目标 IP** 的 curl `time_appconnect`，包含连接建立和 TLS 握手，不是客户端 ping 或客户端到 VPS 的延迟。
- **原策略兜底**：本轮大厂验证没有通过时，再按同 ASN、已知跨 ASN、ASN 未知的顺序，结合规则提示、短时成功率和建连耗时选择其他候选。同 ASN 和短延迟都是部署参考，不能据此推断封锁概率。
- **客户端可达性**：`UNMEASURED` 表示没有来自实际客户端接入网的测量。GFWList 命中只是名单信号；未命中名单不能解释为大陆客户端已经通过验证。
- **回落滥用**：共享 CDN/边缘服务提示与客户端封锁信号分别展示。未命中当前特征规则只表示没有识别出该类特征，不等于已证明安全。
- **稳定性**：短时成功率只是本次安装期间的小样本；长期变化由健康检查另行报告。健康检查只告警，不会自动更换 SNI 或目标 IP。

大厂候选采用精确主机名清单：Apple 的 `gateway.icloud.com`、`www.apple.com`；Microsoft 的 `www.microsoft.com`、`www.bing.com`；以及 `www.amazon.com`、`www.oracle.com`、`www.nvidia.com`、`www.samsung.com`、`www.ibm.com`、`www.google.com`。相似名称或未列出的子域名不会自动获得品牌优先级。这些仍是待验证输入：Google 在中国大陆画像下继续按名单排除；任何域名命中兼容性、名单或共享边缘服务排除条件，都不会因品牌获得豁免。没有有效建连耗时的大厂候选也不享受延迟优先。

自动选择分“大厂优先”和“原策略兜底”两个阶段，每阶段串行验证默认最多 3 个候选、上限 5 个，低资源时每阶段降为 1 个。大厂阶段有 PASS 时不启动兜底；该阶段已测候选全部失败时，兜底仍保留独立预算（每批候选默认合计最多 6 次，上限合计 10 次），避免大厂失败耗尽所有验证机会。安装器首批没有可推荐候选时，还会审计有界扩展池，扩展批次另行计数。资源不足导致 DEFERRED 时立即停止后续验证，不把延后当作 PASS，也不会为兜底继续启动临时进程。未测试候选保留 PENDING；推荐仅代表本轮已测范围。手动指定目标的入口保持可用。

健康 JSON 使用 `compatibility`、`endpoint_ip`、`topology`、`client_path`、`client_list_signal`、`fallback_abuse` 和采样计数等独立字段替代旧的 `score/risk`；依赖旧字段的外部脚本需要调整。

本机自测的范围是临时 VLESS + REALITY 回环链路，不经过客户端到 VPS 的公网路径。AnyTLS 共用 REALITY 目标，但该项自测不覆盖 AnyTLS 应用层；应使用实际客户端进行端到端验证。

解析到私网、Fake-IP 或明显测试保留地址时，自动选择会拒绝采用，避免把本机代理的合成地址写入生产握手配置。

SNI 和目标 IP 分开保存。切换时会同步更新服务端配置及重新生成客户端链接，但已经导入的客户端需要手动同步 `serverName`。目标地址发生 DNS/ASN 漂移时，先查看健康告警并重新审计；不会悄悄改动现有连接配置。

可通过 `SINGBOX_REALITY_COMPARE_LIMIT=1..5` 限制每阶段回环比较数，`SINGBOX_REALITY_PROBE_SAMPLES=1..3` 控制每个端点的短时采样数。动态发现仅从公开历史数据取得候选，年龄和流行度不再转换为安全加分；各入口的公共候选、发现过滤、端点探测、排序及回环验证均来自同一策略。

已有节点可只重新审计 Reality 并更新管理面板，不必重新选择其他协议。先下载最新启动器再传入切换参数：

```sh
u="https://github.com/shaolonger/singbox-deploy/releases/latest/download/install-latest.sh?ts=$(date +%s)"; (curl -fsSL "$u" -o /root/install-singbox-latest.sh 2>/dev/null || wget -qO /root/install-singbox-latest.sh "$u") && sh /root/install-singbox-latest.sh --change-reality-target
```

既有安装缺少固定端点记录时，健康检查会提示 `legacy` 配置需要重新审计；它不会静默升级或迁移目标。当前实际入口通过配置的连接地址确定，未配置时才使用公网出口推断；NAT/多出口用户应核对两者是否一致。

维护共享策略时编辑 `lib/reality-policy.sh`，再运行 `python3 scripts/sync-reality-policy.py` 同步到独立安装脚本。发布后的安装器及生成的面板、中继脚本都自带这段代码，运行时无需额外下载库文件。

---

## 🤖 AI IPv6 落地推荐设置

如果这台 VPS 主要作为 ChatGPT、Claude、Gemini 等 AI 服务的 IPv6 落地机，安装 SS 时推荐选择：

```text
2) IPv6 优先
```

对应模式：

```text
prefer_ipv6
```

相比 `ipv6_only`，它可以在目标没有 IPv6 时自动回退 IPv4，对实际网页、OAuth、验证码、CDN、图片与文件资源兼容性更好。

### Clash / Mihomo 示例

```yaml
- name: "美国｜落地｜v6｜example"
  type: ss
  server: 2600:xxxx:xxxx::1234
  port: 19175
  cipher: 2022-blake3-aes-128-gcm
  password: "YOUR_PASSWORD"
  udp: true
  ip-version: ipv6
  dialer-proxy: "美国-中转"
```

注意：

- `server` 使用 IPv6 只代表 **客户端/线路机 → SS 落地机** 这一跳使用 IPv6；
- 最终 **落地机 → 目标网站** 是否使用 IPv6，由落地机的网络环境和 SS 出口模式共同决定；
- 线路机本身通过 IPv4 接入完全可以与后续 IPv6 落地、IPv6 出口共存。

---

## 🔎 如何验证真实 IPv6 出口

### 1. 先检查 VPS 自身 IPv6

在落地 VPS 上执行：

```bash
curl -4 https://api64.ipify.org ; echo
curl -6 https://api64.ipify.org ; echo
ip -6 addr show scope global
ip -6 route
```

如果 `curl -6` 能返回 VPS 的公网 IPv6，且存在 IPv6 默认路由，说明 VPS 自身具备 IPv6 出口能力。

### 2. 验证客户端经过 SS 后的出口

将一个 IP 查询域名临时分流到对应 SS 落地节点，然后在客户端执行：

```bash
curl https://api64.ipify.org
```

若返回落地 VPS 的 IPv6 地址，说明完整代理链路已经能够使用 IPv6 出口。

### 3. 验证 AI 网站真实连接

最可靠的方法是在落地 VPS 抓包：

```bash
tcpdump -ni eth0 'ip6 and (tcp port 443 or udp port 443)'
```

随后从客户端重新打开 ChatGPT / Claude / Gemini 并产生新请求。

如果看到类似：

```text
IP6 2600:xxxx:xxxx::1234.xxxxx > 2606:xxxx:xxxx::xxxx.443
```

说明落地 VPS 正在真实使用 IPv6 连接目标或其 CDN。

若使用 `prefer_ipv6`，少量 IPv4 fallback 是正常行为；若要求绝对禁止 IPv4，请选择 `ipv6_only`。

---

## ⚙️ 无人值守 / 环境变量

脚本保留交互式安装，同时支持部分环境变量预设，方便自动化部署。

例如：先执行上面的命令下载启动器，之后可带环境变量重新运行；启动器每次都会查询最新正式 Release。

```bash
SINGBOX_PROTOCOLS="1 4" \
SINGBOX_SS_METHOD="2022-blake3-aes-128-gcm" \
SINGBOX_SS_IP_MODE="prefer_ipv6" \
sh /root/install-singbox-latest.sh
```

常用变量：

| 变量 | 作用 | 示例 |
| --- | --- | --- |
| `SINGBOX_PROTOCOLS` | 预选协议编号 | `"1 4"` |
| `SINGBOX_SS_METHOD` | SS 加密方式 | `2022-blake3-aes-128-gcm` |
| `SINGBOX_SS_IP_MODE` | SS 出口模式 | `auto` / `prefer_ipv6` / `ipv6_only` |
| `SINGBOX_PORT_SS` | SS 端口 | `19175` |
| `SINGBOX_PORT_HY2` | Hysteria2 端口 | `8443` |
| `SINGBOX_PORT_TUIC` | TUIC 端口 | `10443` |
| `SINGBOX_PORT_REALITY` | VLESS Reality 端口 | `443` |
| `SINGBOX_PORT_ANYTLS` | AnyTLS Reality 端口 | `24443` |

> 环境变量仅用于减少部分交互步骤；脚本仍会执行配置生成、安全校验和服务部署流程。

---

## 🧪 配置检查与故障排查

### 检查 Sing-box 配置

```bash
sing-box check -c /etc/sing-box/config.json
```

没有报错且退出码为 `0` 才表示配置通过校验：

```bash
echo $?
```

### 查看状态

```bash
systemctl status sing-box --no-pager
```

Alpine / OpenRC 环境也可直接通过 `sb` 管理。

### 查看日志

```bash
journalctl -u sing-box -n 100 --no-pager
```

或直接：

```bash
sb
```

选择“查看最近日志”。

### 检查监听端口

```bash
ss -lntup | grep sing-box
```

### 节点突然 timeout

如果 Clash / Mihomo 中节点突然 timeout，而服务状态显示：

```text
activating (auto-restart)
Result: exit-code
```

优先执行：

```bash
sing-box check -c /etc/sing-box/config.json
```

不要反复重启服务。先根据具体配置错误修复后再启动。

---

## 🔐 配置安全与回滚

新版脚本对配置修改进行了额外保护：

- 配置目录和敏感配置使用收紧权限
- 生成候选配置后先执行 JSON 校验
- 使用本机 Sing-box 执行 `sing-box check`
- 校验失败时不覆盖工作配置
- 修改前备份旧配置
- `sb` 编辑和模式切换采用安全应用流程
- 服务启动失败时尽量回滚到之前配置
- 不在分享 URI 中错误拼接裸 IPv6 地址

配置文件默认位置：

```text
/etc/sing-box/config.json
```

状态缓存：

```text
/etc/sing-box/.config_cache
```

管理命令：

```text
sb
```

---

## 🔄 从旧版本升级

如果已经使用旧版脚本部署过 Sing-box，可以重新执行最新一键安装脚本进行更新，或在现有 `sb` 面板中使用对应更新功能。

建议升级前先备份：

```bash
cp -a /etc/sing-box /etc/sing-box.backup.$(date +%Y%m%d_%H%M%S)
```

对于旧节点，如果希望启用 SS IPv6 出口，不需要手工维护 `config.json`，升级新版管理脚本后直接使用：

```bash
sb
```

选择“设置 SS 出口 IP 模式”。

---

## ⚠️ 使用说明

- 请确保云厂商安全组、防火墙和本机防火墙已放行实际使用的协议端口。
- 使用 IPv6 落地前，请确认上游线路机能访问落地 VPS 的 IPv6 地址。
- `prefer_ipv6` 表示优先 IPv6，并不等于完全禁止 IPv4。
- `ipv6_only` 会导致 IPv4-only 目标无法访问，请按实际用途选择。
- Reality SNI 的自动探测结果取决于 VPS 当时的网络环境，必要时可手动指定。
- 若 Reality 自测日志显示 IPv6 地址的 `no route to host`，说明 VPS 缺少可用 IPv6 出口；更新到最新正式版后重新运行脚本，自测会使用已解析并固定的实际端点（优先 IPv4）探测，不必为此开启 IPv6 或逐个更换 SNI。
- 修改生产节点前建议保留现有 SSH 会话，并先做好配置备份。

---

## 🙏 特别鸣谢以下商家对本项目的赞助支持

<div align="center">

<table>
  <tr>
    <td align="center" width="220">
      <a href="https://app.kaze.network/" target="_blank">
        <img src="https://app.kaze.network/templates/lagom2/assets/img/logo/logo_big.634794647.svg" width="100" alt="Kaze" />
        <br><sub><b>Kaze</b></sub>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://console.alice.sh/" target="_blank">
        <img src="https://console.alice.sh/assets/images/logo-yellow.svg" width="100" alt="AliceNetworks" />
        <br><sub><b>AliceNetworks</b></sub>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://lxc.lazycat.wiki" target="_blank">
        <img src="https://lxc.lazycat.wiki/upload/logo2.png" width="100" alt="懒猫云" />
        <br><sub><b>懒猫云</b></sub>
      </a>
    </td>
    <td align="center" width="220">
      <a href="https://www.lxc.wiki/" target="_blank">
        <img src="https://www.lxc.wiki/themes/web/starvm-phj/img/logo.png" width="100" alt="拼好鸡" />
        <br><sub><b>拼好鸡</b></sub>
      </a>
    </td>
  </tr>
</table>

</div>

---

## 📌 项目地址

GitHub：`shaolonger/singbox-deploy`

一键安装：使用上文的[一键部署命令](#-一键部署命令)，自动获取最新正式 Release。

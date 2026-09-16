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

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/singbox-deploy/main/install-singbox-yyds.sh)"
```

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

例如：

```bash
SINGBOX_PROTOCOLS="1 4" \
SINGBOX_SS_METHOD="2022-blake3-aes-128-gcm" \
SINGBOX_SS_IP_MODE="prefer_ipv6" \
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/singbox-deploy/main/install-singbox-yyds.sh)"
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

一键安装：

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/shaolonger/singbox-deploy/main/install-singbox-yyds.sh)"
```

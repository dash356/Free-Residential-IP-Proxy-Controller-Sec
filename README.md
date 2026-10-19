本项目资源完全免费，均免费来自于互联网整合而成，如果有人问你收费，你肯定是上当受骗了！！！

# 🛡️ 安全加固版说明

本分支是 [a6216abcd/Free-Residential-IP-Proxy-Controller](https://github.com/a6216abcd/Free-Residential-IP-Proxy-Controller) 的安全加固 fork，修复了原版中发现的多项网络安全问题。功能与原版保持一致。

## 已修复的安全问题

| # | 问题 | 修复方式 |
|---|------|----------|
| 1 | `/scripts/*.py`、`/agent` 无鉴权，且下发代码硬编码全部口令 → 任意人可下载脚本拿到面板/代理账号 | 统一鉴权门覆盖所有敏感路由；口令移出下发代码，改为 VPS 本机 `c2.json`（600 权限） |
| 2 | 弱默认口令（`admin/admin888`）写死在仓库和代码里 | 未配置强口令（≥12 位、非常见弱口令）时 Worker 直接拒绝服务（fail-closed） |
| 3 | 以 root 身份执行未经消毒的第三方 VPNGate `.ovpn`（`--route-nopull` 挡不住配置文件内手写的 `redirect-gateway`/`route`/`dhcp-option`/`up` 等指令） | 下发前做指令黑名单过滤，含危险指令的节点直接拒收并拉黑 24h |
| 4 | Socks5/HTTP 代理全程明文，Basic 认证可被嗅探 | （架构级）代理仍为明文协议——**务必用防火墙限制代理端口来源 IP，或在 VPS 前加 stunnel/TLS**；代码侧新增连接数上限（200）与空闲超时（300s）防 DoS |
| 5 | 面板 `innerHTML` 直接拼接服务端数据 → 存储型 XSS | 全局 `esc()` 转义；响应附加 CSP / `X-Frame-Options: DENY` / `nosniff` 防点击劫持 |
| 6 | 无任何暴力破解防护 | 鉴权失败计数限流（1 分钟 10 次失败封 5 分钟）；口令比较改用常量时间比较；含冒号口令可正常使用 |
| 7 | 住宅 IP 质检查的是 VPN **服务器** IP，而非隧道真实出口 IP | 改为先经隧道获取真实出口 IP 再鉴定 |
| 8 | 代理目标域名的 DNS 解析走 VPS 本机，暴露访问目标 | DNS 查询经隧道内 UDP 直连 8.8.8.8（`SO_BINDTODEVICE`），失败回退系统解析 |

## 部署后必做

1. 在 Cloudflare 控制台设置强口令（`WEB_PASS` / `PROXY_PASS` ≥ 12 位），否则 Worker 不会工作。
2. 在 VPS 防火墙（iptables/云厂商安全组）上把代理端口的来源限制为你自己的 IP。
3. 如需更高安全，可在代理端口前加装 stunnel 或改走 SSH 隧道。

## 已知限制

- 代理协议本身仍无传输加密（见上表 #4），这是架构级取舍：要根治需引入 TLS 代理协议。
- 内存限流仅在单个 isolate 内生效，生产环境请再叠加 Cloudflare 控制台的 Rate Limiting 规则。

## 🆕 本分支新增功能（相对上游安全加固版）

### 1. 美观登录页
- 浏览器原生 Basic Auth 弹窗已替换为深色玻璃拟态登录页（渐变光斑 + 动画 + 密码可见切换 + 错误抖动反馈）。
- 登录成功后签发 HMAC 签名的 `HttpOnly` 会话 Cookie（7 天有效，访问面板时滑动续期）；退出登录一键清除。
- VPS Agent 与 API 工具（curl 等）继续使用 Basic Auth，不受影响；登录接口保留暴力破解限流（1 分钟 10 次失败封 5 分钟）。

### 2. 多 VPS 独立策略（分机分 IP）
- 每个 VPS 在面板上拥有独立策略卡片：出口国家、自动/手动模式、手动指定 vpngate 节点、YouTube 检测开关，可分别为不同 VPS 分配不同国家的代理 IP。
- Agent 上报心跳时携带本机公网 IP 拉取专属配置；「强制换 IP」按单台 VPS 生效。
- 全局设置保留：代理监听端口、Agent 拉配置/心跳间隔、面板轮询间隔下发到所有 VPS；「新 VPS 默认国家」仅用于新纳管机器的初始策略。
- **同一出口 IP 下多台机器**（NAT/共享网关）：上报身份为 `IP|启动标识`，各自独立成行、独立策略、独立卸载，互不覆盖；面板上同 IP 的机器会显示 `#xxxxxx` 区分徽标。老版本 Agent（不上报启动标识）行为不变。

### 3. VPS 删除（含远程卸载）
- 面板每台 VPS 卡片新增「删除 VPS」按钮，二次确认后二选一：
  - **远程卸载并删除（推荐）**：向 VPS 下发卸载指令，Agent 在下次同步（约 15 秒内）自动执行：停止并移除 `proxy-lite.service`、强杀 OpenVPN 残留进程、清理策略路由表、删除 `/opt/proxy_lite`（含引擎代码与凭证），最后向调度中心注销，面板记录自动消失；
  - **仅删记录**：只从面板数据库移除（VPS 失联时用，残留文件需手动清理）。
- 卸载中的 VPS 在面板显示「卸载中」状态并保留到注销完成，过期清理不会误删。

### 4. 顺手修复
- 修复了下发的 `lite_manager.py` 中一处转义 bug（模板内单 `\n` 被 JS 求值成真换行，导致 served 脚本有 Python 语法错误、Agent 无法启动）。

> ⚠️ **已纳管 VPS 请重新执行一次面板右上角的纳管命令**，以更新引擎（`lite_manager.py`）获得分机策略与远程卸载支持；未更新的老 Agent 仍按全局默认国家工作，不受影响。

---

# 一键极速部署  

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://https://github.com/dash356/Free-Residential-IP-Proxy-Controller-Sec)

一键极速部署如果报400的错误,就是CF账户风控了，重新注册一个CF新号即可部署成功

KUI面板正在集成融合免费免费住宅IP代理调度系统 https://github.com/a6216abcd/K-UI

老用户覆盖代码，记得重新去vps运行agent命令，长时间获取不到IP，记得装一下warp ipv4,安装warp ipv4后，导出的IP会变warp ipv4需要手动修改成本机真实IP

```bash
wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && bash menu.sh

```

# 免费住宅IP代理调度系统 (Active-Standby 终极版) 🌐

这是一个轻量级且极具韧性的智能代理调度系统。基于 Cloudflare Workers 与 D1 数据库构建中心控制节点，配合 VPS 守护进程，实现 **主备双活 (Active-Standby)** 无缝切换、自动优选纯净住宅 IP 的 Socks5/HTTP 代理服务。

系统资源占用极低，同时集成了顶级的 IP 资产测绘引擎，非常适合用于个人量化交易、跨境电商防关联、网络测试或高频数据抓取。

<img width="3715" height="1759" alt="图片" src="https://github.com/user-attachments/assets/2877288a-d969-475f-92b1-18ceef651273" />
<img width="3715" height="1759" alt="图片" src="https://github.com/user-attachments/assets/c8df6abe-029a-4b55-ad25-d367257ccec2" />

> **致谢**：本项目的原生 IP 深度质检与风险评分感知模块，由 [TestISP.info](https://testisp.info) (商业级住宅IP与本地环境检测沙箱平台) 提供 API 支持。

---

## ✨ 核心特性

* **⚔️ 主备双活引擎 (Active-Standby)**：彻底重构底层网络，双路隧道 (`tun_main` / `tun_backup`) 并发建连。当主卡突发断流或死亡时，软开关秒级接管业务至备用卡，真正实现业务零感知切换。
* **🏠 双ISP住宅IP检测**：内置原生判定逻辑，无缝对接 https://testisp.info  执行 BGP 宣告审计、rDNS 探测、Geo-Drift 物理偏移计算与 Spamhaus 全球蜜罐预警，冷酷剔除一切机房 (Hosting/Datacenter) 伪装 IP。
* **⚡ 毫秒级极速调度与容错**：多维 HTTP/ICMP 探针高频心跳检测，采用 5 秒超时设定与高频蓄水池抓取机制，节点假死后立刻踢线熔断。
* **🔄 主动热切与端口云控**：支持面板一键发送时间戳指令强制清退当前通道并重拨；支持云端下发服务端口变更指令，守护进程自动重启适配。
* **📊 Serverless 全息看板**：零服务器成本部署控制端，提供可视化 Web UI，实时渲染 VPS 日志流、通道存活状态与 IP 深度质检体检报告。面板集成防呆复制设计，一键直达 TestISP 官网复核。
* **🚀 极简纳管**：VPS 节点端（Agent）无需复杂环境配置，一行 Bash 命令即可完成内核反向路径过滤 (`rp_filter`) 修复、依赖安装与守护进程驻留。

---

## 🛠️ 架构说明

1. **C2 控制端 (Cloudflare Workers)**：负责下发国家策略、端口配置、处理主动换 IP 指令、提供 Web 面板及可视化报告、存储节点心跳状态。
2. **状态存储 (Cloudflare D1)**：轻量级 SQLite 数据库，记录全局调度配置和 VPS 纳管矩阵。
3. **VPS 节点端 (Python3)**：作为高可用执行单元，拉取全球节点快照，建立主备 OpenVPN 隧道，双重质检（TestISP 探测 + YouTube 流媒体验证），并对外提供原生纯净的 Socks5/HTTP 代理端口。
4. **质检网关 (TestISP.info)**：负责为 C2 总控面板提供 IP 的原生性、ISP 商业属性及风险维度的深度数据支撑。

---

## 🚀 部署指南

### 第一步：创建 Cloudflare D1 数据库

1. 登录 Cloudflare 控制台，进入 **Workers & Pages** -> **D1 SQL Database**。
2. 点击 **Create database**，创建一个数据库（例如命名为 `proxy-db`）。

> **注意**：无需手动建表，系统首次运行将自动初始化表结构。

### 第二步：部署 Cloudflare Worker

1. 进入 **Workers & Pages**，点击 **Create application** -> **Create Worker**，随意命名（例如 `proxy-controller`）并部署。
2. 点击刚创建的 Worker，进入 **Settings** -> **Variables**。
3. **绑定 D1 数据库**：
   * 在 `D1 Database Bindings` 处添加绑定。
   * **Variable name** 必须严格填入：`DB`
   * **D1 Database** 选择第一步创建的 `proxy-db`。
4. **配置环境变量 (Environment Variables)**（必须设置！！！`WEB_PASS` / `PROXY_PASS` 长度至少 12 位且不能是常见弱口令，否则 Worker 将直接拒绝服务 fail-closed）：

| 变量名 | 作用说明 |
| --- | --- |
| `WEB_USER` | 面板 Web 登录用户名 |
| `WEB_PASS` | 面板 Web 登录密码（≥12 位，强口令） |
| `PROXY_USER` | Socks5/HTTP 代理连接用户名 |
| `PROXY_PASS` | Socks5/HTTP 代理连接密码（≥12 位，强口令） |

> 部署完成后请立即在 Cloudflare 控制台 **Settings → Variables** 中设置以上变量并重新部署。**切勿把真实口令提交到版本库。**

5. 进入 **Quick edit**（快速编辑），将本仓库提供的 `Worker` 全量代码粘贴覆盖，点击 **Save and Deploy**。

### 第三步：纳管 VPS 节点

准备一台干净的 Linux VPS（推荐 Ubuntu 20.04/22.04 或 Debian 11/12 系统），通过 SSH 以 `root` 身份登录。

访问您刚才部署的 Cloudflare Worker 域名（需输入配置的 `WEB_USER` 和 `WEB_PASS` 进行 Basic Auth 认证）。在面板右上角复制自动生成的纳管命令并执行（命令已携带鉴权信息，**请勿外泄此命令**）：

```bash
bash <(curl -sL -u "面板用户名:面板密码" https://您的worker域名.workers.dev/agent)

```

脚本将自动执行以下操作：

1. 修复 Linux 内核 `rp_filter`（防止双网卡路由回包丢弃）。
2. 安装 OpenVPN 核心包及相关依赖。
3. 从 C2 控制端拉取最新版本的双活调度引擎（`lite_manager.py` / `proxy_server.py`）。
4. 配置并启动 `proxy-lite.service` 系统级守护进程。

---

## 💻 面板使用与客户端连接

### 管理面板核心功能

直接在浏览器访问您的 Worker 域名进入总控中心。

* **策略下发与端口云配**：在主控区输入目标国家代码（如 `JP`, `US`, `GB`）并可动态修改节点监听端口（默认 `7920`）。点击**下发策略**，Agent 将在下一次心跳周期（~15s）内无缝应用。
* **强制斩断与重拨**：点击紫色的**强制更换 IP**，系统将瞬间销毁当前双活通道，将物理 IP 关入黑名单，并从底层重新拉起建连。
* **TestISP 深度质检报告**：面板下方自动生成当前活跃出口 (Active) 的深度体检报告（包含原生性、运营类型、Spamhaus 情报等）。点击右上角**原版页面**，系统会自动将该 IP 复制到您的剪贴板并跳转至 TestISP.info 官网供您比对查验。
* **实时 Auto-Sync 日志流**：面板底部可直接窥视 VPS 母机的实时运行日志，方便排查故障。

### 代理调用格式

系统提供了一个直链 API，用于快速提取当前 Active 状态的代理地址（完美兼容量化程序和指纹浏览器插件导入）：

```http
GET [https://您的worker域名.workers.dev/api/proxies](https://您的worker域名.workers.dev/api/proxies)

```

*(注：调用此 API 需携带 `Authorization: Basic <Base64>` 认证头)*

**标准客户端连接格式：**

```text
socks5://<PROXY_USER>:<PROXY_PASS>@<VPS母机IP>:<服务端口>
http://<PROXY_USER>:<PROXY_PASS>@<VPS母机IP>:<服务端口>

```

---

## 🗑️ 卸载

**推荐方式**：直接在面板对应 VPS 卡片点击「删除 VPS」→「远程卸载并删除」，VPS 会自动清理并注销，无需手动 SSH。

如需手动彻底移除 VPS 上的节点调度程序并恢复网络路由状态，请执行以下命令（已适配单端口表 100）：

```bash
# 1. 停止并禁用守护进程
systemctl stop proxy-lite.service 2>/dev/null
systemctl disable proxy-lite.service 2>/dev/null
rm -f /lib/systemd/system/proxy-lite.service
systemctl daemon-reload

# 2. 强杀残留的 Python 调度器和 OpenVPN 进程
pkill -f "lite_manager.py" 2>/dev/null
pkill -f "proxy_server.py" 2>/dev/null
pkill -f "openvpn.*tun[0-9]" 2>/dev/null

# 3. 清理单端口策略路由 (防止宿主机断网)
ip rule del table 100 2>/dev/null
ip route flush table 100 2>/dev/null

# 4. 删除所有引擎代码和配置文件
rm -rf /opt/proxy_lite
rm -f /lib/systemd/system/proxy-lite.service
systemctl daemon-reload

echo "✅ 代理引擎及所有配置已彻底卸载清理完毕！"

```

---

## ⚠️ 声明与限制

* **合法合规**：本系统仅供个人网络学习、数据科学实验与路由隔离技术测试。请务必确保您的网络抓取及访问行为严格遵守您所在国家以及目标服务器所在国家/地区的法律法规。
* **严禁滥用**：请勿将系统用于发送垃圾邮件、发动 DDoS 攻击或其他任何导致上游提供商触发 `Spamhaus` 封禁的行为。

```

```

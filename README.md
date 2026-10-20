# netwatch-ai 🛰️

**网络巡检 + AI 告警**：定时巡检局域网设备 → **分层探测**（ICMP / TCP 端口 / HTTP / DNS 解析）定位到底哪一层断了，判定异常再**按需补一次 traceroute** 说清断在第几跳 → 规则先判断影响面，AI 再说清根因 → 只在真出事时通知你（终端打印 + webhook 推送，渠道可插拔）。

[![CI](https://github.com/zhong5666/netwatch-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/zhong5666/netwatch-ai/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## 它解决什么

网络运维最烦的不是"设备挂了"，而是**挂了没人知道**，以及**知道挂了但不知道挂在哪**。

普通 ping 脚本只能告诉你「不通」，而这三种情况的处理方式完全不同：

| 现象 | 真实原因 | 该怎么查 |
|---|---|---|
| ICMP 不通 | 设备宕机 / 断网 | 电源、网线、交换机端口 |
| ICMP 通，TCP 端口不通 | 设备活着，服务没起 | 登录设备看服务进程 |
| ICMP 通，HTTP 返回 500 | 设备和服务都在，程序自己报错 | 看应用日志 |
| 别的都通，域名解析不了 | 网没坏，是 DNS 挂了 | 查 DNS 服务器 / 本机解析配置（不是去拔网线） |
| ICMP 不通，traceroute 卡在第 N 跳之后 | 断点之前是通的，之后不通 | 先看断在哪一段：本机 / 局域网 / 公网，再查对应那段 |

netwatch-ai 把这四层分开探，**每个设备的明细都留在报告里**，再交给大模型说清根因和第一步该干什么。

其中「多台设备同时 DNS 解析失败」由**规则层**直接点破：线路多半是通的，先查 DNS 服务器，别去拆交换机 —— `dns:` 这项探测就是为了抓这种最容易被误诊的故障。

设备**已经判定异常**时，netwatch 会按需补跑一次 traceroute（`check.traceroute: auto`，默认开），把结论并进同一行明细：

- **本机这边就出不去** —— Windows 在同网段没人应答时会把**本机自己的地址**印成第一跳，程序拿本机出口地址一比就认得出 → 先查本机网卡 / 网线 / 无线，别去查远端；
- **过了第 N 跳才不通** —— 并区分那一跳是私网还是公网地址：断在局域网侧（查交换机 / 该设备）还是已出内网（查线路 / 目标侧）；
- **已到目标** —— 链路是通的，问题在这台设备本身（服务 / 端口 / 防火墙策略）。

它只在**报警的那一轮**跑（和推送同一时机），常态巡检一分钱不花；人工排查想每轮都看，加 `--alert-on all`。
`demo/config.demo.yaml` 里显式关掉了它 —— 演示承诺不往真实链路发包，而且跳数随所在网络变、README 引用的输出就不可复现了。

## 效果（真实终端输出）

下面这段来自 `demo/sample_output.txt`（不是示意图，是 `python demo/run_demo.py --ai` 实际跑出来的）：把本地 8899 服务 kill 掉之后再跑一次 ——

```text
=== netwatch-ai 巡检报告 2026-10-20 09:42:16 ===
✓ localhost          127.0.0.1   在线 (连续离线 0 次)
      └ ICMP 通 (RTT <1ms)
⚠️ local-web          127.0.0.1   离线 (连续离线 1 次)
      └ ICMP 通 (RTT <1ms) | TCP 8899 连不上 (timed out) | HTTP 连不上 (<urlopen error [WinError 10061] 由于目标计算机积极拒绝，无法连接。>)
✓ dns-local          127.0.0.1   在线 (连续离线 0 次)
      └ DNS 解析 localhost → 127.0.0.1 等 2 个 (12ms)
⚠️ unreachable-demo   192.0.2.1   离线 (连续离线 2 次)
      └ ICMP 不通 (rc=1)

⚠️ 发现 2 台异常设备: local-web, unreachable-demo
🔄 本次变化: ⚠️ local-web 新出现异常 (连续离线 1 次)

🧭 影响面判断:
规则判断：**多台不可达**（共 2 台）→ 优先怀疑共同上级（交换机/网关/VLAN）。

🤖 AI 分析:
(AI 分析失败: AI 接口超时或不可达（上限 60 秒，可用 NETWATCH_TIMEOUT 调大）：The read operation timed out)
```

注意 `local-web` 那一行：**ICMP 通、TCP/HTTP 不通** —— 一眼就知道是服务挂了而不是设备失联。

AI 段是**结构化卡片**：大模型只回 JSON（类型 / 置信度 / 影响面 / 原因 / 第一步命令），由程序渲染成卡片。解析失败也不丢内容 —— 退回原文渲染，并在卡片上标注「未按 JSON 返回」。

服务恢复后它会主动补一条「恢复通知」（不用你去盯）：

```text
🔄 本次变化: ✅ local-web 已恢复在线 (中断不到 1 分钟)
```

`demo/sample_output.txt` 里有连着跑的五个场景：正常 → 服务挂 → 状态没变化（**不重复告警**）→ 恢复 → 可用率报告；同一份演示数据落成的静态页在 `demo/sample_report.html`。

README 里逐字引用这份输出的两段（上面「效果」段里的巡检报告、下面「可用率报告」段）是**脚本同步**的：`python tools/sync_readme_block.py` 只比对（有漂移退出码 1），加 `--write` 才写回 —— AI 卡片是 60 列宽的边框，手抄必错列，肉眼还看不出来。

## 架构

![架构图](docs/architecture.svg)

```
probes.py     探测层：ICMP / TCP / HTTP / DNS 解析 + 按需 traceroute，跨平台（Windows/Linux/macOS 参数差异都在这里消化）
netwatch.py   编排层：设备清单、连续离线计数、阈值判定、告警去重、报告渲染
analyzer.py   AI 层：规则先判影响面，再让大模型说根因（key 只走环境变量）
notifiers.py  通知层：把报告推到 webhook 等渠道（插件化，失败不影响巡检）
history.py    历史层：SQLite 落库（零依赖标准库），算可用率 / 中断时长 / 延迟趋势
report_html.py 报告层：只读历史库，落成自包含静态 HTML（零服务、零外链、不探测）
```

## 快速开始

```bash
git clone https://github.com/zhong5666/netwatch-ai.git
cd netwatch-ai
pip install -r requirements.txt

cp config.example.yaml config.yaml     # 改成你自己的设备清单
python netwatch.py --config config.yaml
```

想立刻看效果（用演示配置，不需要任何真实设备）：

```bash
python demo/run_demo.py --ai     # 自己起/杀本地 8899 服务，跑完五个场景
```

或者手动跑单轮：

```bash
python -m http.server 8899 &                              # 起个本地服务
python netwatch.py --config demo/config.demo.yaml          # 127.0.0.1 在线 / 192.0.2.1 必然离线
```

想开 AI 分析：

```bash
export NETWATCH_API_KEY=sk-xxxx                            # 只走环境变量，不写进文件
python netwatch.py --config config.yaml --ai
```

默认走 DeepSeek 的 OpenAI 兼容接口，任何兼容端点都能换：

```bash
export NETWATCH_API_BASE=https://api.deepseek.com/v1       # 或你的中转 / 自建网关
export NETWATCH_MODEL=deepseek-chat
```

进阶变量（都有保守默认值，不设也能跑）：

| 变量 | 默认 | 作用 |
|---|---|---|
| `NETWATCH_NO_THINKING` | 关 | `1` = 请求里带 `enable_thinking=false`，**推理模型必开**（否则思考会把 token 预算烧光、正文永远为空） |
| `NETWATCH_JSON_MODE` | 开 | 带 `response_format={"type":"json_object"}` 强制模型回 JSON；中转若回 400 会自动降级重发 |
| `NETWATCH_MAX_TOKENS` | `2000` | 单次分析的最大输出 token |
| `NETWATCH_TIMEOUT` | `60` | 单次分析超时（秒），网络慢的中转可以再放大 |

> 推理模型（deepseek-v4 系列）用 `NETWATCH_NO_THINKING=1`；普通对话模型不用管这些开关。

## 配置说明

```yaml
devices:
  - name: router
    ip: 192.168.1.1
    checks: [icmp]                                        # 不写 checks 时默认就是 [icmp]

  - name: nas
    ip: 192.168.1.10
    checks: [icmp, tcp:22, http://192.168.1.10:5000/health]   # 全部通过才算在线

  - name: cloud-vm
    ip: 10.0.0.8
    checks: [tcp:22]                                      # 云主机禁 ICMP → 只探端口

  - name: dns-check
    ip: 223.5.5.5
    checks: [dns:www.baidu.com]                           # 解析失败即判异常（抓 DNS 故障）

  - name: core-sw
    ip: 192.168.1.2
    checks: [icmp, snmp:sysUpTime]                        # 顺带看它跑了多久：重启过会被抓到

check:
  ping_count: 3          # 每次 ping 几个包
  ping_timeout: 1        # 单包超时(秒)
  tcp_timeout: 2         # TCP 连接超时(秒)
  http_timeout: 3        # HTTP 请求超时(秒)
  dns_timeout: 5         # DNS 解析超时(秒)
  snmp_timeout: 2        # SNMP 等应答超时(秒)
  snmp_community: public # 团体名（凭据：可用 NETWATCH_SNMP_COMMUNITY 覆盖；不会进报告/历史库）
  down_threshold: 2      # 连续 N 轮离线才算异常（抗网络抖动）
  traceroute: auto       # 设备判定异常时按需补跑一次（auto 默认 = 开；false 关掉）
  traceroute_hops: 5     # traceroute 最多探几跳
  traceroute_timeout: 1  # traceroute 每跳等几秒（Windows 内部换算成毫秒）

ai:
  enabled: true

notify:                       # 通知渠道（可选；不配就只打印到终端）
  timeout: 5                  # 单渠道超时(秒)，通知卡住不能拖慢巡检
  channels:
    - type: webhook
      url: https://example.com/netwatch-hook    # 任何收 POST 的网关都行
```

| checks 写法 | 含义 |
|---|---|
| `icmp` | ping |
| `tcp:22` | TCP 端口能否建立连接 |
| `http://ip:port/path` | HTTP 有没有响应（4xx 算在线，5xx 算异常） |
| `dns:example.com` | 域名能否解析成 IP（走系统解析器，用 `dns_timeout` 兜超时） |
| `snmp:sysDescr` | 问一个 OID 的值（SNMP **v2c GET**）。预设名：`sysDescr` / `sysName` / `sysUpTime` / `sysLocation` / `sysContact`，也可以直接写 `snmp:1.3.6.1.2.1.1.3.0` |

多个 check 是 **AND** 语义：任意一项失败即判该设备异常，但**明细全部保留**。

**SNMP 只做 v2c 的单点 GET**，够用就行：它抓的是 ICMP 看不出来的事 —— 设备还 ping 得通、但最近重启过（`sysUpTime` 掉回几十秒）、主机名/位置/型号对不上。没有引 pysnmp：v2c 的 GetRequest 也就四十来个字节，编解码自己写（`probes.py` 里 `build_snmp_get` / `parse_snmp_response`），报文结构用 pysnmp 7.1.30 交叉验证过 —— `tests/test_snmp.py` 里的参照字节都是它生成的，我们发的包必须和它**字节级相同**，它造的应答我们必须解得对。

四种失败分得清，因为处置完全不同：

| 明细里的说法 | 真实含义 |
|---|---|
| `SNMP 无应答` | 设备没开 SNMP / 团体名不对 / 被 ACL 拦（**不是主机不可达**） |
| `SNMP 端口不可达` | 对端 161 根本没有服务，回了 ICMP 拒绝 |
| `SNMP 返回错误 noSuchName(2)` | 应答报错：OID 不存在或不可读 |
| `→ <noSuchInstance>` | 设备认得这个 OID，但这一项没有实例 |

团体名是**凭据**：只从配置或 `NETWATCH_SNMP_COMMUNITY` 取，不进明细、不进历史库、不进 HTML。没做的：v3（USM 认证/加密）、getnext/walk、trap 接收 —— 需要这些请直接上 pysnmp。

traceroute 不是 check —— 它是**判定异常之后**的补充诊断，写在 `check.traceroute`，不参与 AND 判定，也不进「探测耗时 / 平均RTT」口径。

**两个耗时不是一个尺子**（报告里分两列，别自己吓自己）：

| 列 | 是什么 | 什么时候会大 |
|---|---|---|
| 探测耗时 | 每轮最慢一项的**墙钟**耗时 | ICMP 恒 >1 秒：`ping -n 3` 要等三个包回来，这是命令本身的节奏 |
| 平均RTT | 该机械的**真实往返** | ICMP 取 ping 报的单包 RTT，TCP/HTTP/DNS 取自身耗时；**超时类失败没有 RTT**，留 `-` |

所以本机回环 ping 的「探测耗时 1021ms + 平均RTT <1ms」并不矛盾：前者是等待，后者才是延迟。

## 命令行

| 参数 | 作用 |
|---|---|
| `--config PATH` | 指定配置文件（默认 `./config.yaml`） |
| `--ai` | 出现**新**异常时调大模型分析根因 |
| `--silent-ok` | 没有新变化时只输出 `[SILENT]`，供定时任务抑制投递 |
| `--alert-on change\|all` | `change`（默认）只在状态变化时告警；`all` 每轮异常都告警，并且每轮都给 traceroute 明细（人工排查用） |
| `--report 7d` | 不探测，直接出可用率报告（`7d` / `24h` / `30m`）；表里同时给「探测耗时」与「平均RTT」 |
| `--html report.html` | 不探测，把同一份报告落成**自包含静态 HTML**（零服务、零外链，双击即看；窗口跟着 `--report` 走，默认 `7d`） |
| `--no-history` | 本轮不写历史库 |
| `--notify` | 按 `notify.channels` 把报告推到外部渠道（**没这个参数绝不发送**） |
| `--test-notify` | 不探测，只发一条样例消息，自检通知渠道通不通 |
| `--once` | 只跑一轮（默认行为，保留以兼容旧命令） |

## 告警去重与恢复通知

定时巡检最容易翻车的不是漏报，是**刷屏**：一台设备挂了，10 分钟一次的巡检能连推三天，最后你把通知一关 —— 真出事时反而没人知道。

所以默认 `--alert-on change`，只在**状态变化**时吭声：

| 状态 | 是否通知 |
|---|---|
| 正常 → 异常 | ✅ 报一次（含影响面判断 + AI 分析） |
| 一直异常 | ❌ 不重复（报告里状态照旧显示异常） |
| 异常 → 正常 | ✅ 补一条「已恢复，中断约 X 分钟」 |
| 一直正常 | ❌ `[SILENT]` |

顺带省了 token：只有**新**故障才进 prompt，长期没修的故障不会每轮都调一次模型。去重状态存在 `.state.yaml`（跟配置文件放一起，已被 `.gitignore` 忽略）。

想「每轮都提醒」（故障必须钉到修好为止），加 `--alert-on all`。

## 通知：推到手机 / 群（插件化）

终端里打印只是自娱自乐，**推到人手上**才算告警。配一个渠道就能发：

```yaml
notify:
  timeout: 5             # 单个渠道超时(秒)
  channels:
    - type: webhook
      url: https://example.com/netwatch-hook
```

```bash
python netwatch.py --config config.yaml --notify         # 真有事的那轮才发
python netwatch.py --config config.yaml --test-notify    # 自检渠道通不通（不探测、不写历史）
```

两道闸门是刻意的，都是为了**别误推生产群、别把渠道刷爆**：

| 闸门 | 规则 |
|---|---|
| 配了渠道 ≠ 会发 | 必须显式加 `--notify`；配了但忘加、而那轮又真有事，报告末尾会提示一句 |
| 有事才发 | 复用编排层的告警去重结论：新异常 / 恢复才发，「一直异常」和 `[SILENT]` 轮都不发 |

推送载荷是固定 JSON，任何能收 POST 的网关都能接（自建 / 钉钉中转 / 企业微信代理 / n8n / IFTTT）：

```json
{"source": "netwatch-ai", "title": "⚠️ netwatch-ai: local-web 异常", "level": "warn",
 "summary": "⚠️ local-web 新异常 (连续离线 2 次)", "devices": ["local-web"],
 "text": "<终端里看到的那份完整报告>", "ts": "2026-10-19 11:09:13"}
```

其中 `text` 和终端输出**逐字一致**（含影响面判断和 AI 卡片），出问题能直接对账。

本地验证不用真渠道，仓库里带了个假接收端：

```bash
python demo/hook_receiver.py 8898 &                                   # 收到的 JSON 追加到 hook.log
# 给 demo/config.demo.yaml 取消注释末尾的 notify 段，然后：
python netwatch.py --config demo/config.demo.yaml --notify            # 看 hook.log 里出现了完整载荷
```

**通知失败不算巡检失败**：单渠道失败重试 1 次，仍失败只打印一行 `⚠️ 通知失败: …` —— 不影响巡检结论、不影响退出码，也不影响其它渠道。

现在只有 `webhook` 一种渠道（基座）；钉钉、企业微信的签名和消息体结构各不相同，后续各作为一个插件加进来。

## 历史数据与可用率报告

每轮巡检往 SQLite 落一条记录（`history.py`，标准库 `sqlite3`，无额外依赖、不开后台进程、跑完即退）：

```bash
python netwatch.py --report 7d      # 也支持 24h / 30m
```

```
=== netwatch-ai 可用率报告 (2026-10-13 09:43:34 ~ 2026-10-20 09:43:34) ===

设备                 地址              轮次      可用率       最长中断       探测耗时     平均RTT
---------------------------------------------------------------------------------
unreachable-demo   192.0.2.1        4     0.0% 4 轮 起10-20 09:41     2890ms         -
local-web          127.0.0.1        4    50.0% 2 轮 起10-20 09:42     1542ms      14ms
dns-local          127.0.0.1        4   100.0%        0 轮        7ms       7ms
localhost          127.0.0.1        4   100.0%        0 轮     1030ms      <1ms

探测耗时 = 每轮最慢一项探测的墙钟耗时（ICMP 含 ping -n 3 三个包的等待）；
平均RTT  = 该项的真实往返（ICMP 取 ping 报的单包 RTT，TCP/HTTP/DNS 取自身耗时）；
           只统计量到该口径的轮次，升级前的历史记录没有这个数。

⚠️ 可用率低于 99% 的设备 2 台：unreachable-demo(0.0%), local-web(50.0%)
```

（演示数据只有 4 轮，真实用一周就是几百轮。）

- **可用率** = 在线轮次 / 总轮次，最差的排最前
- **最长中断** = 最长的一段连续离线**轮次**，并标出从哪一轮开始（用轮次而非分钟，因为巡检间隔由你的定时任务决定）
- **探测耗时** = 该设备每轮最慢那项探测的**墙钟**耗时（`ping -n 3` 要等三个包，ICMP 恒 >1 秒，这是命令的节奏不是网络的锅）
- **平均RTT** = 同一个「最慢项」的**真实往返**：ICMP 取 ping 报的单包 RTT，TCP/HTTP/DNS 取自身耗时；超时类失败没有 RTT，显示 `-`。上面 `localhost` 的「1030ms + <1ms」不矛盾 —— 前者在等包，后者才是延迟
- 平均RTT 只统计量到该口径的轮次（老库升级前的记录没有这个数），不会拿 0 去凑平均
- 库里没数据会提示你先跑一轮，不会甩一张空表给你

## 静态 HTML 报告：点开就能看，不占本机

终端报告适合自己扫一眼，**要给别人看（同事 / 面试官）就换成一张静态页**：

```bash
python netwatch.py --report 7d --html report.html   # 读 .history.db，落一个自包含 HTML，跑完即退
```

**为什么是静态文件、而不是常驻 Web 面板**：这台机器是要打游戏的，任何常驻进程和端口都是帧率负担。静态文件跑完即退，浏览器打开时它也不占本机资源；顺带换来两个好处 —— 不用装任何依赖（纯标准库拼 HTML）、能直接发出去。

页面里有四块：**概要 KPI**（设备数 / 中断段 / 平均可用率）、**可用率表**、**每台设备的在线时间条 + 全部中断段**（终端报告只给「最长中断」，这里列全，并带上当时那行明细）、**异常明细**。

规矩：

| 项 | 说明 |
|---|---|
| 只读 `.history.db` | 不探测、不联网、不写库；库坏了只打印一行说明，不影响终端报告 |
| 零外链 | 不引 CDN / 图表库，样式和图形全是内联 CSS + SVG，**断网也能打开** |
| 跑完即退 | 没有服务、没有端口、没有后台进程，退出码和巡检一致 |
| 公开前先确认 | 真实报告里有内网地址（如 `10.60.43.x`），所以 `report.html` 被 `.gitignore` 忽略；仓库里只放演示数据生成的 `demo/sample_report.html` |

（想看长什么样：直接点开仓库里的 `demo/sample_report.html`。）

## 接入定时任务

```bash
# 每 10 分钟巡检一次：只在状态变化时通知（默认），新故障才调 AI
*/10 * * * * cd /opt/netwatch-ai && NETWATCH_API_KEY=sk-xxx /usr/bin/python3 netwatch.py --ai --silent-ok --notify
```

Windows 任务计划（示例，路径改成你自己的）：

```bat
schtasks /create /tn netwatch /sc minute /mo 10 ^
  /tr "C:\netwatch-ai\.venv\Scripts\python.exe C:\netwatch-ai\netwatch.py --ai --silent-ok --notify"
```

`--silent-ok` 是给定时任务用的约定：**没有新变化时只输出 `[SILENT]`**，调度器看到它就不投递消息。

| 本轮情况 | 输出 | 调度器行为 |
|---|---|---|
| 全部正常 | `[SILENT]` | 不投递 |
| 有设备新掉线 | 完整报告 + 影响面 + AI 分析 | 投递（微信 / 钉钉 / 邮件 / webhook） |
| 故障仍在持续 | `[SILENT]` | 不投递（不刷屏） |
| 设备恢复 | 报告 + 「已恢复，中断约 X 分钟」 | 投递 |

本机就是这么跑的：定时任务每 10 分钟一轮，报告直接推到手机，正常时整天一条消息都没有。

## 设计取舍

- **多协议 AND + 分层明细**：不追求"探得越多越好"，而是让报告能区分「设备失联」和「服务挂了」——这是运维真正需要的判断。
- **连续离线阈值**：单次 ping 失败太常见（无线抖动、ARP 超时），用 `down_threshold` 抗抖动，避免误报。
- **告警去重 + 恢复通知**：运维助手最大的敌人是刷屏。故障期间闭嘴，恢复时说一声，比每 10 分钟报一次有用得多。
- **规则先行，AI 补充**：全网断 vs 单台断是两条完全不同的排查路线，用确定性规则判断比让大模型猜更可靠；AI 只负责讲清原因和第一步。影响面规则看**当前全量**异常（判断面），AI 只看**新**故障（省 token）。
- **AI 挂了不影响巡检**：AI 调用失败只打印一行提示，巡检结果本身照常输出。
- **历史层只用标准库**：SQLite 单文件、无依赖、无常驻进程 —— 巡检跑完就退，不和用户的游戏抢资源。
- **AI 只回 JSON，渲染由程序做**：字段固定（类型/置信度/影响面/原因/第一步），缺字段就留空、解析失败退回原文 —— 屏上永远不会因为模型不听话而空白。置信度还做了容错：模型写 `85` 或 `"85%"` 都按百分数理解。
- **护栏不能自己变成故障源**：强制 JSON、关思考这些字段并非所有中转都认，遇 400 自动去掉重发一次；超时/截断/限流分类报错并给出解法，不会把巡检本身搞挂。
- **DNS 失败要说清是「解析失败」**：明细里从不写「主机不可达」—— 否则运维会去查设备、查网线，而真正坏的是 DNS 服务器。
- **规则层认得「扎堆的 DNS 故障」**：异常设备里多数栽在 `dns:` 上就直接指向 DNS 服务器，而不是甩一句「优先怀疑共同上级（交换机）」；但全网都异常时仍先怀疑上游 —— 那时 DNS 失败只是表象。
- **通知层不做第二套判断**：要不要发由编排层的去重结论（`has_news`）决定，通知层只管发 —— 两处各判一次，迟早分叉成「日志说没变化、渠道却收到消息」。
- **通知失败不算巡检失败**：渠道超时或 5xx 只打印一行，退出码仍是 0 —— 否则「巡检挂了」会变成假警报。
- **key 只走环境变量**：仓库里永远不出现密钥；`config.yaml` 也被 `.gitignore` 忽略（真实内网 IP 不外泄），只提交 `config.example.yaml`。
- **测试不碰真实网络**：没有测试会去 ping 真实设备，所以 CI 三平台都能稳定跑。

## 踩坑记录（都是真踩过的）

1. **Windows ping 的判定不能看输出文本**。全丢包时输出 `损失 = 4 (100% 丢失)`，而字符串 `"100%"` 的末尾两个字符恰好是 `"0%"` —— 任何「搜到 `0%` 就当全通」的写法都会把全丢包误判成在线。只能看 `returncode`（0 = 有回应）。这条已经写成回归测试 `test_judge_ping_trusts_returncode_only`。
2. **Windows ping 输出是 GBK**，用 UTF-8 解码会乱码；只是显示问题，但会影响 AI 读明细。
3. **跨平台 ping 参数不通用**：Windows `-n/-w(毫秒)`、Linux `-c/-W(秒)`、macOS `-c/-W(毫秒)`。所以才有 `build_ping_cmd()` 这个纯函数。
4. **很多设备默认拒绝 ICMP**（云主机、带防火墙的交换机）。只 ping 会一直误报，必须能降级到 TCP 端口探测。
5. **状态文件跟着配置文件走**：否则用演示配置跑一次就会污染真实巡检的连续离线计数。
6. **AI 接口可能返回 200 但内容为空**（限流、或下面的推理模型问题）：静默吞掉会让人以为"没故障"，所以显式报错，并把 `finish_reason` 一起打出来。
7. **推理模型会把 token 预算全烧在思考上**：`deepseek-v4` 系列把预算花在 reasoning 上，`finish_reason=length`、正文永远为空 —— 预算从 300 加到 4000 都治不了。实测有效组合是 `enable_thinking=false` + `response_format={"type":"json_object"}` **同时**开；只关思考会被真实 prompt 无视（reasoning=1941 token，照样空）。
8. **强制 JSON 不能变成故障源**：中转对 `response_format` / `enable_thinking` 这类字段可能回 400，所以遇 400 自动去掉这些字段重发一次，保证巡检不会因为"护栏"挂掉。
9. **`socket.getaddrinfo` 没有 timeout 参数**：DNS 服务器不应答时，Windows 上能卡几十秒，整轮巡检一起陪葬。所以 DNS 探测丢进 daemon 线程里跑、主线程只等 `dns_timeout` 秒 —— 超时后不再等它（daemon 不阻止进程退出）。已写成测试 `test_probe_dns_timeout_does_not_block`（要求 0.2 秒超时的探测在 1.5 秒内返回）。
10. **演示脚本的结束标记不能靠缩进猜**：`refresh_demo.py` 原来用「第一行以 `└` 开头」当报告结束位置，而明细行都有 6 个空格前缀 —— 这个条件永远不成立，脚本直接 `StopIteration` 崩掉；就算改成 `strip()` 后再匹配也会把 AI 卡片截掉。改成「下一场的 `====` 标题行」才对。这条规则现在住在 `tools/sync_readme_block.py`（「效果」段与「可用率报告」段共用这一份实现，不再各写一套切块逻辑）。
11. **端口没清干净会让演示假通过**：`demo/run_demo.py` 的场景二是 kill 掉自己起的 8899 服务，但如果机器上早有个 8899 的监听（比如上次调试留下的 `http.server`），kill 掉自己的子进程后端口照样有人应答 —— 巡检报告显示「服务在线」，README 引用的输出就变成假的。跑演示前先 `netstat -ano | findstr :8899` 确认没人占。

12. **SNMP 的 Gauge32 / Counter32 是无符号的**：`0xffffffff` 若按有符号整数解会变成 `-1`，网卡流量、接口计数全会显示成负数。按 tag 区分（`0x41`/`0x42`/`0x46` 走无符号）已经写成测试 `test_counter_is_unsigned_not_signed`。
13. **OID 的前两段是「合成」成一个子标识符的**（`40*第一段+第二段`），而这个合成值同样要按 base-128 变长编码：`2.100.3` 编出来是 `81 34 03`，不是 `b4 03`。一开始按「单字节」写，只对 `1.3.6.x` 这种常见前缀碰巧正确。
14. **SNMP 团体名是凭据**：明细会流进终端、历史库、HTML 报告和 AI prompt，所以「无应答」的提示里只说「没开 SNMP 或团体名不对」，**永不回显团体名本身**（`test_probe_detail_never_leaks_community`）。
15. **「端口不可达」的异常类三个平台不一样**：Windows 收 ICMP 是 `ConnectionResetError [WinError 10054]`，Linux / macOS 是 `ConnectionRefusedError [Errno 111/61]`。只 catch `socket.timeout` 会把整轮巡检打断；只 catch `ConnectionResetError` 则 Windows 绿、CI 的 Linux/macOS 六个作业一起红（**实踩**：`f0cd889` 推送后 CI 6/9）。正确写法是 catch 共同父类 `ConnectionError`，报「SNMP 端口不可达」而不是「主机不可达」，并用假 socket 把两种异常都参数化测一遍（不依赖跑测试的机器）。
16. **手写协议需要外部参照，不然是「两边一起错」**：我们自己编码、自己解码，写歪了测试也照样绿。所以参照报文由 pysnmp 7.1.30 独立生成并写死进测试（我们发的包必须与它字节级相同，它造的应答我们必须解得对），pysnmp 本身不进依赖、不进 CI。

17. **假服务不要「先借端口、再让线程 bind」**：测试里的 UDP 假 agent 一开始是 `_free_port()` 拿号 → `close()` → 线程里再 `bind(port)`。本地 Windows 一直绿，macOS 的 CI runner 上却偶发「端口不可达」——线程还没 bind，探针的包已经发出去了，对方回 ICMP 拒绝，`noSuchInstance` 那个用例就红（`39440978532` 8/9）。改成**主线程同步 bind 已绑好的 socket 再交给线程**（端口让内核给），端口一开始就处于监听状态，窗口为零。

## 测试

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q        # 317 个用例，覆盖探测逻辑（含 DNS 超时与影响面规则 / SNMP 报文编解码与参照报文比对）/ RTT 与墙钟两种耗时口径 / 阈值状态机 / 告警去重 / 恢复通知 / 历史统计（含老库迁移）/ AI 输出解析与卡片渲染 / 通知渠道与两道闸门 / 静态报告 / README 引用段同步 / 收工自检 / py3.9 兼容闸门 / CLI 行为
```

本仓库的 Python floor 是 **3.9**（CI 是 Win·macOS·Linux × 3.9/3.11/3.12 九个作业）。本地 venv 通常是 3.11，用了 3.10+ 的 API 会「本地全绿、CI 三个 3.9 作业红」，所以有两道自检：

```bash
uv run --python 3.9 --with pytest --with PyYAML python -m pytest -q   # 用真实 3.9 跑一遍（uv 会自己下解释器）
python tools/sync_readme_block.py                                     # README 引用段还没漂移（漂移退出码 1）
```

上面三条收工时容易漏其中一条，所以合成了一条命令（全部本地，`--ci` 才联网）：

```bash
python tools/preflight.py            # README 引用段 + 双版本 pytest + 工作区干净，全通过退出码 0
python tools/preflight.py --fast     # 跳过测试，只查 README 和工作区（2 秒）
python tools/preflight.py --ci       # 额外核对「最新 CI 结论」和「远程 HEAD 是否就是本地 HEAD」
```

它只做三件本该在收工前做的事：README 两段是否还与 `demo/sample_output.txt` 逐字一致、本地 `.venv` 与 py3.9 两个解释器是否都绿、工作区有没有残留的 `.tmp` / `.bak` / 临时 `.db`（`git add -A` 前最该看的就是它们）。缺 `uv`、缺 `gh`、没有 `.venv` 时明确标「跳过」而不算失败 —— 跳过不是通过，只是把它摆在明面上。**跳过项的措辞是刻意的**：没验过的东西不该被说成绿的。

`tests/test_py39_floor.py` 是静态闸门：扫全仓库真代码里有没有 `Path.write_text(newline=)`（3.10+）、`zip(strict=)`（3.10+）、`datetime.UTC` / `tomllib`（3.11+），注释和文档里的反面例子不算。

## Roadmap

- [x] 历史数据落 SQLite：可用率 / 最长中断 / 延迟趋势 + `--report 7d`
- [x] 恢复通知（down → up 时说一句「中断 X 分钟」）与告警去重
- [x] 结构化 AI 输出（故障类型 / 置信度 / 影响面 JSON），渲染成告警卡片
- [x] 通知渠道插件化：`notifiers.py` + webhook 渠道（钉钉 / 企业微信待接）
- [x] 探测项扩展 · DNS 解析：`dns:域名` + `dns_timeout`，明细写「解析失败」而非「不可达」，规则层认得扎堆的 DNS 故障
- [x] 探测项扩展 · traceroute（只在判定不通时按需跑）
- [x] 探测项扩展 · SNMP：`snmp:sysUpTime` 等 5 个预设 + 任意 OID，v2c 单点 GET 自己编解码（零新依赖），四种失败分类
- [x] 小口径修复 · 两种耗时分开：**探测耗时**（墙钟，`ping -n 3` 天然 ~1s）与**平均RTT**（真实往返）各占一列，ICMP 明细直接显示 `RTT 35ms`
- [x] 轻量面板 · 落地为静态单文件 HTML：只读历史库，跑完即退，无常驻/无端口/零依赖

## 项目结构

```
netwatch-ai/
├── netwatch.py              编排层：巡检主流程 + 告警去重 + 报告
├── probes.py                探测层：ICMP / TCP / HTTP / DNS 解析 / SNMP v2c GET
├── analyzer.py              AI 层：规则判断 + 大模型分析
├── notifiers.py             通知层：webhook 插件化推送（失败不影响巡检）
├── history.py               历史层：SQLite 落库 + 可用率统计
├── report_html.py           报告层：历史库 → 静态单文件 HTML（零服务/零外链）
├── config.example.yaml      配置示例（真实 config.yaml 不进仓库）
├── demo/
│   ├── run_demo.py          一键复现下面那份输出（自己起/杀本地服务）
│   ├── refresh_demo.py      重抓输出，再调 tools/ 的同步工具写回 README（开发用）
│   ├── hook_receiver.py     本地假 webhook 接收端（验证通知用）
│   ├── config.demo.yaml     演示配置（本机 + 保留测试段）
│   ├── sample_output.txt    真实跑出来的五个场景输出
│   └── sample_report.html   同一份演示数据落成的静态 HTML 报告
├── docs/architecture.svg    架构图
├── tools/
│   ├── preflight.py         开发工具：收工自检（README 同步 + 双版本测试 + 工作区）
│   └── sync_readme_block.py 开发工具：README 逐字引用段的比对 / 同步
├── tests/                   pytest 单测（不依赖外网）
└── .github/workflows/ci.yml 三平台 CI
```

## License

MIT

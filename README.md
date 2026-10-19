# netwatch-ai 🛰️

**网络巡检 + AI 告警**：定时巡检局域网设备 → **分层探测**（ICMP / TCP 端口 / HTTP）定位到底哪一层断了 → 规则先判断影响面，AI 再说清根因 → 只在真出事时通知你（终端打印 + webhook 推送，渠道可插拔）。

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

netwatch-ai 把这三层分开探，**每个设备的明细都留在报告里**，再交给大模型说清根因和第一步该干什么。

## 效果（真实终端输出）

下面这段来自 `demo/sample_output.txt`（不是示意图，是 `python demo/run_demo.py --ai` 实际跑出来的）：把本地 8899 服务 kill 掉之后再跑一次 ——

```text
=== netwatch-ai 巡检报告 2026-10-19 10:28:13 ===
✓ localhost          127.0.0.1   在线 (连续离线 0 次)
      └ ICMP 通 (1026ms)
⚠️ local-web          127.0.0.1   离线 (连续离线 1 次)
      └ ICMP 通 (1013ms) | TCP 8899 连不上 (timed out) | HTTP 连不上 (<urlopen error [WinError 10061] 由于目标计算机积极拒绝，无法连接。>)
⚠️ unreachable-demo   192.0.2.1   离线 (连续离线 2 次)
      └ ICMP 不通 (rc=1)

⚠️ 发现 2 台异常设备: local-web, unreachable-demo
🔄 本次变化: ⚠️ local-web 新出现异常 (连续离线 1 次)

🧭 影响面判断:
规则判断：**多台不可达**（共 2 台）→ 优先怀疑共同上级（交换机/网关/VLAN）。

🤖 AI 分析:
🤖 AI 故障卡片
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 类型  : 端口或服务异常                                                                      │
│ 置信度: 80%                                                                                 │
│ 影响面: 影响 local-web 上 TCP 8899 及 HTTP 服务，业务不可用                                 │
│ 原因  : ICMP 通说明主机在线，但 TCP 8899 连接超时且 HTTP 连接被拒绝，服务未监听或进程未运行 │
│ 第一步: 执行 netstat -ano | findstr :8899 检查端口监听状态                                  │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

注意 `local-web` 那一行：**ICMP 通、TCP/HTTP 不通** —— 一眼就知道是服务挂了而不是设备失联。

AI 段是**结构化卡片**：大模型只回 JSON（类型 / 置信度 / 影响面 / 原因 / 第一步命令），由程序渲染成卡片。解析失败也不丢内容 —— 退回原文渲染，并在卡片上标注「未按 JSON 返回」。

服务恢复后它会主动补一条「恢复通知」（不用你去盯）：

```text
🔄 本次变化: ✅ local-web 已恢复在线 (中断不到 1 分钟)
```

`demo/sample_output.txt` 里有连着跑的五个场景：正常 → 服务挂 → 状态没变化（**不重复告警**）→ 恢复 → 可用率报告。

## 架构

![架构图](docs/architecture.svg)

```
probes.py     探测层：ICMP / TCP / HTTP，跨平台（Windows/Linux/macOS 参数差异都在这里消化）
netwatch.py   编排层：设备清单、连续离线计数、阈值判定、告警去重、报告渲染
analyzer.py   AI 层：规则先判影响面，再让大模型说根因（key 只走环境变量）
notifiers.py  通知层：把报告推到 webhook 等渠道（插件化，失败不影响巡检）
history.py    历史层：SQLite 落库（零依赖标准库），算可用率 / 中断时长 / 延迟趋势
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

check:
  ping_count: 3          # 每次 ping 几个包
  ping_timeout: 1        # 单包超时(秒)
  tcp_timeout: 2         # TCP 连接超时(秒)
  http_timeout: 3        # HTTP 请求超时(秒)
  down_threshold: 2      # 连续 N 轮离线才算异常（抗网络抖动）

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

多个 check 是 **AND** 语义：任意一项失败即判该设备异常，但**明细全部保留**。

## 命令行

| 参数 | 作用 |
|---|---|
| `--config PATH` | 指定配置文件（默认 `./config.yaml`） |
| `--ai` | 出现**新**异常时调大模型分析根因 |
| `--silent-ok` | 没有新变化时只输出 `[SILENT]`，供定时任务抑制投递 |
| `--alert-on change\|all` | `change`（默认）只在状态变化时告警；`all` 每轮异常都告警 |
| `--report 7d` | 不探测，直接出可用率报告（`7d` / `24h` / `30m`） |
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

```text
=== netwatch-ai 可用率报告 (2026-10-10 17:18:12 ~ 2026-10-17 17:18:12) ===

设备                 地址              轮次      可用率       最长中断           平均探测
-------------------------------------------------------------------------
unreachable-demo   192.0.2.1        4     0.0% 4 轮 起10-17 17:17         2794ms
local-web          127.0.0.1        4    50.0% 2 轮 起10-17 17:17         1535ms
localhost          127.0.0.1        4   100.0%        0 轮         1017ms

⚠️ 可用率低于 99% 的设备 2 台：unreachable-demo(0.0%), local-web(50.0%)
```

（演示数据只有 4 轮，真实用一周就是几百轮。）

- **可用率** = 在线轮次 / 总轮次，最差的排最前
- **最长中断** = 最长的一段连续离线**轮次**，并标出从哪一轮开始（用轮次而非分钟，因为巡检间隔由你的定时任务决定）
- **平均探测** = 该设备每轮最慢那项探测的耗时，用来发现「还没断但开始变慢」的设备
- 库里没数据会提示你先跑一轮，不会甩一张空表给你

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

## 测试

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest -q        # 134 个用例，覆盖探测逻辑 / 阈值状态机 / 告警去重 / 恢复通知 / 历史统计 / AI 输出解析与卡片渲染 / 通知渠道与两道闸门 / CLI 行为
```

## Roadmap

- [x] 历史数据落 SQLite：可用率 / 最长中断 / 延迟趋势 + `--report 7d`
- [x] 恢复通知（down → up 时说一句「中断 X 分钟」）与告警去重
- [x] 结构化 AI 输出（故障类型 / 置信度 / 影响面 JSON），渲染成告警卡片
- [x] 通知渠道插件化：`notifiers.py` + webhook 渠道（钉钉 / 企业微信待接）
- [ ] 探测项扩展：SNMP、DNS 解析、traceroute
- [ ] 轻量 Web 面板（可用率趋势）

## 项目结构

```
netwatch-ai/
├── netwatch.py              编排层：巡检主流程 + 告警去重 + 报告
├── probes.py                探测层：ICMP / TCP / HTTP
├── analyzer.py              AI 层：规则判断 + 大模型分析
├── notifiers.py             通知层：webhook 插件化推送（失败不影响巡检）
├── history.py               历史层：SQLite 落库 + 可用率统计
├── config.example.yaml      配置示例（真实 config.yaml 不进仓库）
├── demo/
│   ├── run_demo.py          一键复现下面那份输出（自己起/杀本地服务）
│   ├── refresh_demo.py      重抓输出并同步 README 引用段（开发用）
│   ├── hook_receiver.py     本地假 webhook 接收端（验证通知用）
│   ├── config.demo.yaml     演示配置（本机 + 保留测试段）
│   └── sample_output.txt    真实跑出来的五个场景输出
├── docs/architecture.svg    架构图
├── tests/                   pytest 单测（不依赖外网）
└── .github/workflows/ci.yml 三平台 CI
```

## License

MIT

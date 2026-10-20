#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""netwatch-ai 探测层：ICMP ping / TCP 端口 / HTTP 健康检查。

设计目标
--------
1. **跨平台**：Windows 的 ping 超时参数是 ``-w <毫秒>``，Linux 是 ``-W <秒>``，
   macOS 是 ``-W <毫秒>``。这里按平台自动拼参数，用户不用改代码。
2. **声明式**：探测什么写在 config.yaml 的 ``devices[].checks`` 里，
   不写就默认 ``[icmp]``（向后兼容老配置）。
3. **AND 语义**：一台设备的多个 check 全部通过才算「在线」；
   每一项的结果都写进 detail —— 一眼能看出是 ICMP 被禁、端口没起，还是服务返回 5xx。
4. **判定与执行分离**：``judge_ping`` / ``judge_http`` 是纯函数，
   单测不需要真实网络，CI 在三平台都能稳定跑（测试不 ping 任何真实设备）。

配置示例
--------
    devices:
      - name: router
        ip: 192.168.1.1
        checks: [icmp]                                  # 家用路由，ping 够用
      - name: nas
        ip: 192.168.1.10
        checks: [icmp, tcp:22, http://192.168.1.10:5000/health]
      - name: cloud-vm
        ip: 10.0.0.8
        checks: [tcp:22]                                # 云主机常禁 ICMP，直接探端口
      - name: dns-ok
        ip: 223.5.5.5
        checks: [dns:example.com]                       # 抓「网通但 DNS 挂了」

``check.traceroute: auto``（默认）时，**判定异常**的设备会额外补跑一次 traceroute，
回答「断在第几跳」—— 正常设备一分钱不花（见 ``probe_traceroute``）。
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

PING_COUNT_DEFAULT = 3
PING_TIMEOUT_DEFAULT = 1     # 秒
TCP_TIMEOUT_DEFAULT = 2      # 秒
HTTP_TIMEOUT_DEFAULT = 3     # 秒
DNS_TIMEOUT_DEFAULT = 5      # 秒；DNS 卡住是最常见的慢性故障，给宽点
TRACEROUTE_HOPS_DEFAULT = 5      # 最多探几跳
TRACEROUTE_TIMEOUT_DEFAULT = 1   # 秒/跳（Windows 的 tracert 要毫秒，这里内部换算）


@dataclass
class ProbeResult:
    """一次单项探测的结果。"""

    kind: str      # icmp / tcp / http / dns / traceroute
    target: str    # 探测目标：ip / ip:port / url
    ok: bool
    ms: int        # **墙钟**耗时(毫秒)：整个探测动作花了多久（ICMP 含 ping -n 3 的等待）
    detail: str    # 人类可读的一行结论
    rtt_ms: int | None = None   # **真实往返**耗时(毫秒)：拿不到这个口径的项为 None

    def __str__(self) -> str:
        return self.detail


def current_system() -> str:
    """返回 windows / darwin / linux（小写）。"""
    return (platform.system() or "Linux").lower()


def _console_encoding(system: str | None = None) -> str:
    """ping 输出的编码：Windows 中文控制台是 GBK，其余平台 UTF-8。

    只影响 detail 的文字是否乱码，不影响判定（判定只看 returncode）。
    """
    return "gbk" if (system or current_system()) == "windows" else "utf-8"


def build_ping_cmd(host: str,
                   count: int = PING_COUNT_DEFAULT,
                   timeout: int = PING_TIMEOUT_DEFAULT,
                   system: str | None = None) -> list:
    """按平台拼 ping 命令（纯函数，便于单测）。"""
    sysname = system or current_system()
    if sysname == "windows":
        return ["ping", "-n", str(count), "-w", str(timeout * 1000), host]
    if sysname == "darwin":
        return ["ping", "-c", str(count), "-W", str(timeout * 1000), host]  # macOS: 毫秒
    return ["ping", "-c", str(count), "-W", str(timeout), host]             # Linux: 秒


def judge_ping(returncode: int, stdout: str = "") -> bool:
    """只根据 returncode 判定 ping 是否通。

    为什么不能看输出文本：Windows ping 全丢包时打印「丢失 = 4 (100% 丢失)」，
    这里面**含有子串 "0%"**（"100%" 的末尾两个字符恰好是 "0%"）——
    任何「搜到 0% 就当成全通」的写法都会把全丢包误判为在线。
    returncode 0 = 有回应、1 = 全丢包，是唯一可靠的判据。
    """
    return returncode == 0


# ping 输出里的单包往返时间，一处正则吃下四种写法：
#   中文 Windows「时间=1ms」「时间<1ms」 / 英文 Windows「time=1ms」 / Unix「time=0.045 ms」
_RTT_RE = re.compile(r"(?:时间|time)\s*([=<])\s*([\d.]+)\s*ms", re.IGNORECASE)


def parse_ping_rtt(stdout: str):
    """从 ping 输出里取出**单包真实 RTT**（毫秒，取各包最大值）。

    为什么必须和 ``ms``（墙钟）分家：``ping -n 3`` 要等三个包回来，墙钟天然 ~1 秒，
    把它当「网络延迟」看，一条通畅的链路会被显示成 1000ms+（本地回环也“慢”）。
    真实 RTT 只有几毫秒 —— 报告里两个数分开列，才不会被自己吓到。

    ``时间<1ms`` 与 Unix 的 ``0.045ms`` 都按 0 处理（显示层用 :func:`fmt_rtt` 渲染成 ``<1ms``）。
    解析不出来（未知本地化措辞 / 异常输出）返回 None —— **宁可显示「-」，也不编一个数**。
    """
    best = None
    for op, value in _RTT_RE.findall(stdout or ""):
        v = 0.0 if op == "<" else float(value)
        best = v if best is None else max(best, v)
    return None if best is None else int(best)


def fmt_rtt(rtt_ms) -> str:
    """RTT 显示口径：0 = 小于 1ms（对应 ping 的「<1ms」），None = 没量到。"""
    if rtt_ms is None:
        return "-"
    return "<1ms" if int(rtt_ms) <= 0 else "%dms" % int(rtt_ms)


def _short(exc: BaseException, limit: int = 60) -> str:
    """异常信息压成一行，避免 detail 太长。"""
    text = str(exc).replace("\n", " ").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def probe_icmp(host: str,
               count: int = PING_COUNT_DEFAULT,
               timeout: int = PING_TIMEOUT_DEFAULT,
               system: str | None = None) -> ProbeResult:
    """ICMP ping 探测。"""
    sysname = system or current_system()
    cmd = build_ping_cmd(host, count, timeout, sysname)
    t0 = time.perf_counter()
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            encoding=_console_encoding(sysname),
            errors="replace",
            timeout=count * timeout + 5,
        )
    except subprocess.TimeoutExpired:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("icmp", host, False, ms, "ICMP 超时(命令卡住 >%ds)" % (count * timeout + 5))
    except (FileNotFoundError, OSError) as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("icmp", host, False, ms, "ICMP 不可用(%s)" % _short(e))

    ms = int((time.perf_counter() - t0) * 1000)
    if judge_ping(res.returncode, res.stdout):
        rtt = parse_ping_rtt(res.stdout)
        # 明细写真实 RTT：写墙钟（~1 秒）会让人以为网络很慢
        text = ("ICMP 通 (RTT %s)" % fmt_rtt(rtt) if rtt is not None
                else "ICMP 通 (耗时 %dms)" % ms)
        return ProbeResult("icmp", host, True, ms, text, rtt)
    # 不通时耗时就等于超时等待，不是 RTT —— 留 None
    return ProbeResult("icmp", host, False, ms, "ICMP 不通 (rc=%d)" % res.returncode)


def probe_tcp(host: str, port: int, timeout: int = TCP_TIMEOUT_DEFAULT) -> ProbeResult:
    """TCP 端口探测：能完成三次握手即在线（用来绕开禁用 ICMP 的设备）。"""
    target = "%s:%d" % (host, port)
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("tcp", target, True, ms, "TCP %d 可连 (%dms)" % (port, ms), ms)
    except OSError as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("tcp", target, False, ms, "TCP %d 连不上 (%s)" % (port, _short(e)))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def judge_http(status) -> bool:
    """HTTP 判定：拿到响应就算服务在线（含 401/403 —— 端口和服务都活着，只是没权限）；
    5xx 视为异常（服务端自己出错）；完全没响应 = 不通。
    """
    if status is None:
        return False
    return int(status) < 500


def probe_http(url: str, timeout: int = HTTP_TIMEOUT_DEFAULT) -> ProbeResult:
    """HTTP 健康检查：只 GET 一个 URL，看有没有响应、响应码多少。"""
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            ms = int((time.perf_counter() - t0) * 1000)
            status = int(getattr(resp, "status", 200) or 200)
            return ProbeResult("http", url, judge_http(status), ms,
                               "HTTP %d (%dms)" % (status, ms), ms)
    except urllib.error.HTTPError as e:      # 4xx/5xx 会走这个分支
        ms = int((time.perf_counter() - t0) * 1000)
        ok = judge_http(e.code)
        tail = "" if ok else " 服务端异常"
        return ProbeResult("http", url, ok, ms, "HTTP %d%s" % (e.code, tail), ms)
    except (urllib.error.URLError, OSError, ValueError) as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("http", url, False, ms, "HTTP 连不上 (%s)" % _short(e))


def _fmt_secs(v) -> str:
    """把秒数渲染得好看：5 → "5"、0.2 → "0.2"。"""
    return "%g" % v


def resolve_with_timeout(host: str, timeout=DNS_TIMEOUT_DEFAULT, resolver=None):
    """在线程里跑 getaddrinfo 并加超时。

    标准库的 ``socket.getaddrinfo`` **没有 timeout 参数**：DNS 服务器不应答时
    Windows 上能卡几十秒，足以把整轮巡检拖住。所以丢进 daemon 线程，
    主线程只等 ``timeout`` 秒；超时后不再等它（daemon 不会阻止进程退出）。

    ``resolver`` 只为单测预留（注入假解析器，测试不碰真 DNS）。
    返回 ``(addrinfo 列表, None)`` 或 ``(None, 异常 / "timeout")``。
    """
    box: dict = {}
    lookup = resolver or socket.getaddrinfo

    def work():
        try:
            box["addrs"] = lookup(host, None)
        except BaseException as e:          # gaierror / UnicodeError / 系统级异常都算解析失败
            box["err"] = e

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    if "err" in box:
        return None, box["err"]
    if "addrs" not in box:
        return None, "timeout"
    return box["addrs"], None


def pick_addrs(addrinfo) -> list:
    """从 getaddrinfo 结果里取出真实 IP（去重且保序）。"""
    ips = []
    for item in addrinfo or []:
        try:
            ip = item[4][0]
        except (IndexError, TypeError):
            continue
        if ip and ip not in ips:
            ips.append(ip)
    return ips


def probe_dns(name: str, timeout=DNS_TIMEOUT_DEFAULT, resolver=None) -> ProbeResult:
    """DNS 解析探测：域名能否解析成 IP，以及花了多久。

    抓的是「网能通、但 DNS 挂了」这类故障 —— 只 ping 网关根本发现不了。
    解析失败即判该项失败（配置里写了就是契约），但明细必须写清是**解析失败**，
    不能写成「主机不可达」，否则会把 DNS 问题误诊成设备问题。
    """
    t0 = time.perf_counter()
    addrs, err = resolve_with_timeout(name, timeout, resolver)
    ms = int((time.perf_counter() - t0) * 1000)
    if err == "timeout":
        return ProbeResult("dns", name, False, ms, "DNS 解析超时 (>%ss)" % _fmt_secs(timeout))
    if err is not None:
        return ProbeResult("dns", name, False, ms, "DNS 解析失败 (%s)" % _short(err))
    ips = pick_addrs(addrs)
    if not ips:
        return ProbeResult("dns", name, False, ms, "DNS 解析无结果 (返回 0 个地址)")
    more = "" if len(ips) == 1 else " 等 %d 个" % len(ips)
    return ProbeResult("dns", name, True, ms,
                       "DNS 解析 %s → %s%s (%dms)" % (name, ips[0], more, ms), ms)


# ---------------------------------------------------------------- traceroute（按需诊断）

_TRACEROUTE_OFF = {"false", "off", "no", "0", "none"}


def traceroute_enabled(raw) -> bool:
    """``check.traceroute`` 的取值：auto/true/on/yes → 开，false/off/no/0/none → 关。

    默认 **auto（开）**：它只在设备**已经判定异常**时才按需跑一次，正常设备零开销，
    所以默认开着不会破坏「不增加常态成本」这条线。
    认不出的值一律按默认走 —— 一个拼写错误不该让诊断功能静默消失。
    """
    if raw is None:
        return True
    return str(raw).strip().lower() not in _TRACEROUTE_OFF


def build_traceroute_cmd(host: str,
                         hops: int = TRACEROUTE_HOPS_DEFAULT,
                         timeout=TRACEROUTE_TIMEOUT_DEFAULT,
                         system: str | None = None) -> list:
    """按平台拼 traceroute 命令（纯函数，便于单测）。

    这里的坑和 ping **是反的**，别照搬：ping 在 macOS 用毫秒、Linux 用秒；
    traceroute 的 ``-w`` 在 macOS 和 Linux **都是秒**（macOS 默认 3 秒、Linux 默认 5 秒，
    官方手册写的就是 seconds），只有 Windows 的 ``tracert -w`` 是毫秒。

    ``-d`` / ``-n`` 关掉反向解析：本来只想知道「哪一跳断了」，不做 5 次 DNS 反查，
    更快也不会被坏 DNS 拖住；Unix 再加 ``-q 1``（默认每跳发 3 个包，诊断不需要）。
    """
    sysname = system or current_system()
    if sysname == "windows":
        return ["tracert", "-d", "-h", str(hops), "-w", str(int(float(timeout) * 1000)), host]
    return ["traceroute", "-n", "-q", "1", "-m", str(hops), "-w", _fmt_secs(timeout), host]


_HOP_RE = re.compile(r"^\s*(\d{1,2})[\s.:]+(\S.*)$")
_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

# 「到不了目标」的标注：Windows 打完星号后跟一句「报告: 无法访问目标主机。」，
# Unix 的 traceroute 在行尾标 !H / !N / !X / !A。**这不是「这一跳回应了」**。
_UNREACH_MARKS = ("无法访问目标主机", "无法访问网络", "目标主机不可达", "!H", "!N", "!X", "!A")

NOTE_UNREACH_LOCAL = "unreachable"        # 三个探测全丢星号 + 到不了：本机这边就出不去
NOTE_UNREACH_HOP = "unreachable-hop"      # 某一跳回了「目标不可达」：过了它才不通


def parse_traceroute(text: str) -> list:
    """把 tracert / traceroute 的输出解析成 ``[(跳号, IP 或 None, 说明), ...]``（保序）。

    两种实现的排版差得很远（Windows 是三列毫秒 + 中文「请求超时。」，
    Unix 是 ``1  10.0.0.1  1.234 ms``），但「行首跳号 + 本跳内容」这个骨架是一样的。
    只认这个骨架：认不出 IP 就记 None（这一跳没人应），整行认不出就跳过（不猜、不编）；
    最坏情况返回空列表，由调用方退回「没拿到可解析的跳」这种说法。

    说明列只有三种值：

    * ``""`` —— 正常回应的跳（或只是超时，IP 为 None）；
    * ``"unreachable"`` —— 全丢星号且报「无法访问目标主机」：**本机这边就出不去**
      （Windows 这时会把本机自己的地址印在跳号后面，别当成本机的「回应」）；
    * ``"unreachable-hop"`` —— 某一跳明确回了「目标不可达」：包到了它，再往后不通。
    """
    hops = []
    for line in (text or "").splitlines():
        m = _HOP_RE.match(line)
        if not m:
            continue
        num, rest = int(m.group(1)), m.group(2)
        note = ""
        if any(mark in rest for mark in _UNREACH_MARKS):
            # 第一个探测位是星号 → 本机没收到任何回应，那句「不可达」是本地协议栈给的
            note = NOTE_UNREACH_LOCAL if re.match(r"^\s*\*", rest) else NOTE_UNREACH_HOP
        found = _IP_RE.search(rest)
        # 「本机这边出不去」的那种，行里印的是**本机自己的地址**，不能当成本机的「回应」；
        # 「某一跳回了目标不可达」则保留它的地址（包确实到了它）
        ip = found.group(0) if (found and note != NOTE_UNREACH_LOCAL) else None
        if hops and hops[-1][0] == num:      # 同一跳的后续行（等价多路径）：补齐缺口就好
            p_num, p_ip, p_note = hops[-1]
            hops[-1] = (num, p_ip or ip, p_note or note)
            continue
        hops.append((num, ip, note))
    return hops


def local_addr_for(target: str) -> str:
    """问内核「去这个目标你打算用本机哪个地址出去」—— 只查路由表，一个包都不发。

    UDP connect 不握手，只是让内核选一条出接口。绑不上（没路由）就返回 ""，
    调用方据此退回「地址类型没认出来」的说法，不猜。
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((target, 9))      # discard 端口，只用来选路
            return sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return ""


def _ip_kind(ip) -> str:
    """粗判地址是私网还是公网 —— 只用来选措辞，判不出来就说 unknown。"""
    try:
        return "private" if ipaddress.ip_address(ip).is_private else "public"
    except (ValueError, TypeError):
        return "unknown"


def summarize_traceroute(hops: list, target: str = "", local_ip: str = "") -> str:
    """把跳数列表压成一句人话，重点回答**断在哪一段**。

    - 「无法访问目标主机」+ 全星号，或那一跳的地址就是本机 → 本机这边就出不去（先查本机网络）
    - 某一跳明确回「目标不可达」 → 包到了它，再往后不通（查它后面的网段/上游）
    - 一跳都没回 → 本机到网关这段就不通，别急着骂运营商
    - 最后一跳就是目标本身 → 链路是通的，问题在这台设备本身（别再说成「不回 ICMP」：
      触发诊断的可能是 TCP/HTTP 挂了，ICMP 说不定好好的）
    - 最后一跳是私网地址 → 断在内网（局域网侧）；是公网地址 → 断在公网/运营商侧

    ``local_ip`` 是本机去目标方向的出口地址（``local_addr_for``）：Windows 在同网段
    没人应答时**会把本机自己的地址印在跳号后面**，只有拿它对比才知道该说「本机这边出不去」
    还是「过了某一跳才不通」—— 说反了，运维的方向就全反了。
    """
    if not hops:
        return "traceroute: 没拿到可解析的跳"

    # ① 本机这边就出不去：两种情况一起判 ——
    #    a) 探测位全丢星号 + 报「无法访问目标主机」；
    #    b) 报不可达的那一跳，地址就是本机自己（Windows 常把自己的地址印上去）
    mine = local_ip and [h[0] for h in hops if h[2] == NOTE_UNREACH_HOP and h[1] == local_ip]
    out_of_local = [h[0] for h in hops if h[2] == NOTE_UNREACH_LOCAL] or list(mine or [])
    if out_of_local:
        return ("traceroute: 第 %d 跳就报「无法访问目标主机」，而且是本机这边没出去 → "
                "先查本机网络 / 网线 / 无线，别去查远端" % out_of_local[0])

    hop_unreach = [(h[0], h[1]) for h in hops if h[2] == NOTE_UNREACH_HOP]
    if hop_unreach:
        num, ip = hop_unreach[0]
        at = ("第 %d 跳 %s " % (num, ip)) if ip else "第 %d 跳 " % num
        return "traceroute: %s回了「无法访问目标主机」→ 包到得了它，再往后不通（查它后面的网段 / 上游）" % at

    answered = [(h[0], h[1]) for h in hops if h[1]]
    if not answered:
        return "traceroute: 前 %d 跳全部无响应 → 本机到网关这段就不通，先查本机网络" % hops[-1][0]
    num, ip = answered[-1]
    if target and ip == target:
        return ("traceroute: 已到目标（第 %d 跳 %s）→ 链路是通的，问题在这台设备本身"
                "（服务 / 端口 / 防火墙策略）" % (num, ip))
    where = {
        "private": "断在内网（局域网侧）：查这一跳的交换机 / 该设备",
        "public": "已出内网，断在公网/运营商侧：查宽带线路或目标侧",
    }.get(_ip_kind(ip), "断在链路中段（这一跳的地址类型没认出来，看上面这个 IP）")
    return "traceroute: 第 %d 跳 %s 之后无响应 → %s" % (num, ip, where)


def probe_traceroute(host: str,
                     hops: int = TRACEROUTE_HOPS_DEFAULT,
                     timeout=TRACEROUTE_TIMEOUT_DEFAULT,
                     system: str | None = None) -> ProbeResult:
    """设备判定不通时按需补一次 traceroute，回答「断在第几跳」。

    **只在已经判定异常的设备上调用**：正常设备一分钱不花。
    耗时以秒计（一跳一轮），所以它这一项不进「探测耗时 / 平均RTT」口径 ——
    ``history.record`` 会跳过 kind=traceroute，免得把一个 5 秒的诊断混进延迟统计里。
    """
    sysname = system or current_system()
    cmd = build_traceroute_cmd(host, hops, timeout, sysname)
    # 预算按「每跳 3 个探测包」算：Windows 的 tracert 每跳发 3 个（Unix 侧用 -q 1 只发 1 个），
    # 按 1 倍算会把它掐成「超时」，真结论（断在第几跳）反而丢了
    budget = int(hops * timeout * 3) + 5
    t0 = time.perf_counter()
    try:
        res = subprocess.run(
            cmd,
            capture_output=True,
            encoding=_console_encoding(sysname),
            errors="replace",
            timeout=budget,
        )
    except subprocess.TimeoutExpired:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("traceroute", host, False, ms, "traceroute 超时 (命令卡住 >%ds)" % budget)
    except (FileNotFoundError, OSError) as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("traceroute", host, False, ms, "traceroute 不可用 (%s)" % _short(e))

    ms = int((time.perf_counter() - t0) * 1000)
    hop_list = parse_traceroute(res.stdout)
    # local_addr_for 只为区分「本机这边出不去」和「过了某一跳才不通」——
    # 同网段没人应答时 Windows 会把自己的地址印在跳号后面，得知道那是自己
    summary = summarize_traceroute(hop_list, host, local_addr_for(host))
    # ok 只表示「这次诊断跑通了、给出了可读结论」，**不参与设备的 AND 判定** ——
    # 它是在判定之后才跑的，纯补充信息（设备该异常还是异常）。
    return ProbeResult("traceroute", host, bool(hop_list), ms, "%s（%dms）" % (summary, ms))


# ---------------------------------------------------------------- SNMP（v2c GET，零依赖）
#
# 巡检只需要「问一个 OID 的值」这一件事，为此引入 pysnmp + pyasn1 两个依赖不划算：
# v2c 的 GetRequest 一共 40 个字节，编解码各几十行就够。报文结构已用 pysnmp 7.1.30
# 交叉验证过（它解得开我们发的包，我们解得出它构造的应答，见 tests/test_snmp.py）。
# 不做：v3（要 USM 认证/加密）、getnext/walk、trap 接收 —— 需要这些请直接上 pysnmp。
SNMP_TIMEOUT_DEFAULT = 2      # 秒
SNMP_COMMUNITY_DEFAULT = "public"

# 常用 OID 起个名，配置里写 snmp:sysDescr 比写一长串数字好认（也少打错）
SNMP_NAMES = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",      # 设备描述（型号/系统）
    "sysName": "1.3.6.1.2.1.1.5.0",       # 主机名
    "sysUpTime": "1.3.6.1.2.1.1.3.0",     # 运行时长（TimeTicks）
    "sysLocation": "1.3.6.1.2.1.1.6.0",   # 位置
    "sysContact": "1.3.6.1.2.1.1.4.0",    # 联系人
}

_SNMP_ERR = {0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
             4: "readOnly", 5: "genErr"}
_SNMP_MISSING = {0x80: "noSuchObject", 0x81: "noSuchInstance", 0x82: "endOfMibView"}


def encode_oid(dotted: str) -> bytes:
    """把 "1.3.6.1.2.1.1.1.0" 编成 BER 的 OID 内容字节（不含 tag/长度）。"""
    parts = [p for p in str(dotted).strip().split(".") if p != ""]
    if len(parts) < 2:
        raise ValueError("OID 至少要有两段: %r" % dotted)
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise ValueError("OID 里有非数字段: %r" % dotted)
    if any(n < 0 for n in nums):
        raise ValueError("OID 段不能是负数: %r" % dotted)
    if nums[0] > 2 or (nums[0] < 2 and nums[1] > 39):
        raise ValueError("OID 开头不合法: %r（第一段 ≤2，第一段<2 时第二段 ≤39）" % dotted)
    out = bytearray(_oid_varint(nums[0] * 40 + nums[1]))
    for n in nums[2:]:
        out.extend(_oid_varint(n))
    return bytes(out)


def _oid_varint(n: int) -> bytes:
    """OID 子标识符的 base-128 变长编码（第一段 2.100 这种合成值也是这么编的）。"""
    chunk = [n & 0x7F]
    n >>= 7
    while n:
        chunk.append((n & 0x7F) | 0x80)
        n >>= 7
    return bytes(reversed(chunk))


def decode_oid(raw: bytes) -> str:
    """encode_oid 的逆操作：BER OID 内容字节 → 点分字符串。"""
    if not raw:
        raise ValueError("OID 内容为空")
    vals = []
    val = 0
    for byte in raw:
        val = (val << 7) | (byte & 0x7F)
        if not byte & 0x80:
            vals.append(val)
            val = 0
    if raw[-1] & 0x80:
        raise ValueError("OID 编码被截断")
    first = vals[0]
    if first < 40:
        nums = [0, first]
    elif first < 80:
        nums = [1, first - 40]
    else:
        nums = [2, first - 80]
    nums.extend(vals[1:])
    return ".".join(str(n) for n in nums)


def _ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _ber_tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _ber_len(len(payload)) + payload


def _ber_int(value: int) -> bytes:
    """最小长度补码编码（正数最高位是 1 时前面补 0x00，避免被读成负数）。"""
    if value >= 0:
        body = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big")
    else:
        width = max(1, ((value + 1).bit_length() + 8) // 8)
        body = value.to_bytes(width, "big", signed=True)
    return _ber_tlv(0x02, body)


def build_snmp_get(oid: str, community: str = SNMP_COMMUNITY_DEFAULT,
                   request_id: int = 1) -> bytes:
    """构造 v2c GetRequest（纯函数，便于和抓包/其它实现比对）。"""
    if not 0 <= request_id < 0x80000000:
        # request-id 是 Integer32：越界会编码成 5~6 字节，严格实现的 agent 会拒收
        raise ValueError("request-id 超出 Integer32: %r" % (request_id,))
    varbind = _ber_tlv(0x30, _ber_tlv(0x06, encode_oid(oid)) + _ber_tlv(0x05, b""))
    pdu_body = (_ber_int(request_id) + _ber_int(0) + _ber_int(0)
                + _ber_tlv(0x30, varbind))
    comm = str(community).encode("utf-8", "replace")
    body = _ber_int(1) + _ber_tlv(0x04, comm) + _ber_tlv(0xA0, pdu_body)   # 0xA0 = GetRequest
    return _ber_tlv(0x30, body)


def _read_tlv(buf: bytes, i: int):
    """从 buf[i] 读一个 TLV，返回 (tag, payload, 下一个位置)。"""
    if i + 2 > len(buf):
        raise ValueError("报文被截断（读 tag/长度时越界）")
    tag = buf[i]
    i += 1
    first = buf[i]
    i += 1
    if first < 0x80:
        length = first
    else:
        num = first & 0x7F
        if num == 0 or i + num > len(buf):
            raise ValueError("长度字段不合法")
        length = int.from_bytes(buf[i:i + num], "big")
        i += num
    if i + length > len(buf):
        raise ValueError("报文被截断（声明 %d 字节，实际只剩 %d）" % (length, len(buf) - i))
    return tag, buf[i:i + length], i + length


def _read_int(payload: bytes) -> int:
    if not payload:
        raise ValueError("INTEGER 内容为空")
    return int.from_bytes(payload, "big", signed=True)


def parse_snmp_response(data: bytes) -> dict:
    """解析 v2c 应答报文；结构不对就抛 ValueError（调用方统一兜成一行明细）。

    返回 ``{version, community, pdu_tag, request_id, error_status, error_index,
    varbinds: [(oid, 值tag, 值内容)]}``。注意这里**不判业务成败**，只负责解包。
    """
    tag, body, _ = _read_tlv(data, 0)
    if tag != 0x30:
        raise ValueError("不是 SEQUENCE（tag=0x%02x）" % tag)
    i = 0
    tag, ver, i = _read_tlv(body, i)
    if tag != 0x02:
        raise ValueError("version 字段不是 INTEGER")
    version = _read_int(ver)
    tag, comm, i = _read_tlv(body, i)
    if tag != 0x04:
        raise ValueError("community 字段不是 OCTET STRING")
    tag, pdu, i = _read_tlv(body, i)
    if tag not in (0xA2, 0xA8):          # A2=Response, A8=Report（v3 的 report 也可能是 A8）
        raise ValueError("不是 GetResponse（tag=0x%02x，可能是错误或 trap）" % tag)

    j = 0
    tag, raw_id, j = _read_tlv(pdu, j)
    request_id = _read_int(raw_id) if tag == 0x02 else None
    tag, raw_err, j = _read_tlv(pdu, j)
    error_status = _read_int(raw_err) if tag == 0x02 else 0
    tag, raw_idx, j = _read_tlv(pdu, j)
    error_index = _read_int(raw_idx) if tag == 0x02 else 0

    varbinds = []
    tag, vbl, _ = _read_tlv(pdu, j)
    if tag == 0x30:
        k = 0
        while k < len(vbl):
            t, one, k = _read_tlv(vbl, k)
            if t != 0x30:
                raise ValueError("VarBind 不是 SEQUENCE")
            m = 0
            t_oid, raw_oid, m = _read_tlv(one, m)
            t_val, raw_val, m = _read_tlv(one, m)
            if t_oid != 0x06:
                raise ValueError("VarBind 里的 OID 不是 OBJECT IDENTIFIER")
            varbinds.append((decode_oid(raw_oid), t_val, raw_val))
    return {
        "version": version,
        "community": comm.decode("utf-8", "replace"),
        "pdu_tag": tag,
        "request_id": request_id,
        "error_status": error_status,
        "error_index": error_index,
        "varbinds": varbinds,
    }


def fmt_snmp_value(tag: int, raw: bytes, limit: int = 120) -> str:
    """把 varbind 的值渲染成一行可读文本（只影响观感，不参与判定）。"""
    if tag in _SNMP_MISSING:
        return "<%s>" % _SNMP_MISSING[tag]
    if tag == 0x02:
        return str(int.from_bytes(raw, "big", signed=True)) if raw else "0"
    if tag in (0x41, 0x42, 0x46):        # Counter32 / Gauge32 / Counter64
        return str(int.from_bytes(raw, "big", signed=False)) if raw else "0"
    if tag == 0x43:                      # TimeTicks：百分之一秒，人看得懂的是多久
        ticks = int.from_bytes(raw, "big", signed=False) if raw else 0
        return "%d ticks (%s)" % (ticks, _fmt_ticks(ticks))
    if tag == 0x06:
        try:
            return decode_oid(raw)
        except ValueError:
            return "0x" + raw.hex()
    if tag == 0x40:
        return ".".join(str(b) for b in raw) if len(raw) == 4 else "0x" + raw.hex()
    if tag == 0x05:
        return "-"
    if tag == 0x04:
        text = raw.decode("utf-8", "replace")
        if all(ch.isprintable() for ch in text):
            return '"%s"' % (text if len(text) <= limit else text[:limit] + "…")
        return "0x" + raw.hex()
    return "0x" + raw.hex()


def _fmt_ticks(ticks: int) -> str:
    secs = ticks // 100
    days, rest = divmod(secs, 86400)
    hours, rest = divmod(rest, 3600)
    mins, secs = divmod(rest, 60)
    return "%dd %02d:%02d:%02d" % (days, hours, mins, secs)


def snmp_target(raw) -> str:
    """``snmp:`` 后面的部分 → OID 点分串。支持预设名（大小写不敏感）或直接写 OID。"""
    text = str(raw or "").strip()
    if not text:
        raise ValueError("snmp: 后面要跟 OID 或预设名（sysDescr / sysName / sysUpTime …）")
    for name, oid in SNMP_NAMES.items():
        if text.lower() == name.lower():
            return oid
    encode_oid(text)          # 只想借它做合法性校验，不合法会抛 ValueError
    return text


def snmp_label(oid: str) -> str:
    """OID → 报告里显示的短名（预设名优先，认不出就原样显示点分串）。"""
    for name, value in SNMP_NAMES.items():
        if value == oid:
            return name
    return oid


def _snmp_request_id() -> int:
    """请求 id：毫秒时间戳**截到 31 位**。

    截断不是为了省字节：request-id 在协议里是 Integer32（有符号 32 位），
    而毫秒时间戳是 41 位 —— 按原值编码会变成一个 6 字节整数，严格实现的 agent 直接拒收。
    """
    return int(time.time() * 1000) & 0x7FFFFFFF


def probe_snmp(host: str, target, community: str = SNMP_COMMUNITY_DEFAULT,
               timeout=SNMP_TIMEOUT_DEFAULT, port: int = 161) -> ProbeResult:
    """SNMP v2c GET 探测：问一个 OID 的值。

    判定 = 「收到合法应答 + error-status 为 0 + 值不是 noSuch*」。
    明细必须分清三种失败：**没有应答**（设备没开 SNMP / 团体名不对 / 被 ACL 拦）、
    **端口不可达**（对端根本没有 SNMP 服务，Windows 会回 ICMP 拒绝）、
    **应答报错**（OID 不存在 / 该 OID 不可读）—— 三者运维处置完全不同。
    团体名属于凭据，**不进明细**（明细会进报告、历史库、HTML）。
    """
    oid = snmp_target(target)
    label = snmp_label(oid)
    target_txt = label
    req_id = _snmp_request_id()

    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)
    except socket.gaierror as e:
        return ProbeResult("snmp", target=str(target), ok=False, ms=0,
                           detail="SNMP 目标解析失败 (%s)" % _short(e))
    family = infos[0][0]
    addr = infos[0][4]

    t0 = time.perf_counter()
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect(addr)         # connect 后 recv 只收这个对端，也才收得到 ICMP 报错
        sock.send(build_snmp_get(oid, community, req_id))
        deadline = time.perf_counter() + timeout
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                raise socket.timeout()
            sock.settimeout(left)
            data = sock.recv(4096)
            rtt = int((time.perf_counter() - t0) * 1000)
            try:
                parsed = parse_snmp_response(data)
            except ValueError as e:
                return ProbeResult("snmp", target_txt, False, int((time.perf_counter() - t0) * 1000),
                                   "SNMP 应答无法解析（%d 字节）: %s" % (len(data), _short(e)))
            if parsed.get("request_id") not in (None, req_id):
                continue           # 不是我们这一问的应答（重发/串包），接着等
            break
    except socket.timeout:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("snmp", target_txt, False, ms,
                           "SNMP 无应答 (>%ss)：设备可能没开 SNMP、团体名不对或被 ACL 拦" % _fmt_secs(timeout))
    except ConnectionError:
        # 同一个「对方 161 没服务」，三个平台报的异常不是一个类：
        # Windows 收 ICMP 端口不可达 → ConnectionResetError(10054)
        # Linux / macOS → ConnectionRefusedError(ECONNREFUSED)
        # 所以必须 catch 共同父类 ConnectionError，只 catch Reset 会让 Linux 掉进下面的 OSError 兜底
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("snmp", target_txt, False, ms,
                           "SNMP 端口不可达（对端 %d 没有 SNMP 服务，回了 ICMP 拒绝）" % port)
    except OSError as e:
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("snmp", target_txt, False, ms, "SNMP 探测失败 (%s)" % _short(e))
    finally:
        sock.close()

    ms = int((time.perf_counter() - t0) * 1000)
    status = parsed.get("error_status") or 0
    if status:
        err = _SNMP_ERR.get(status, "unknown")
        return ProbeResult("snmp", target_txt, False, ms,
                           "SNMP 返回错误 %s(%d)，error-index=%s——该 OID 读不到"
                           % (err, status, parsed.get("error_index")), rtt)
    if not parsed["varbinds"]:
        return ProbeResult("snmp", target_txt, False, ms, "SNMP 应答里没有 varbind", rtt)
    oid_back, vt, raw_val = parsed["varbinds"][0]
    text = fmt_snmp_value(vt, raw_val)
    if vt in _SNMP_MISSING:
        return ProbeResult("snmp", target_txt, False, ms,
                           "SNMP %s → %s（设备上没有这个 OID）" % (label, text), rtt)
    return ProbeResult("snmp", target_txt, True, ms,
                       "SNMP %s = %s (%dms)" % (label, text, rtt), rtt)


def parse_checks(raw) -> list:
    """把配置里的 checks 规范化成探测指令列表（纯函数）。

    合法写法：``icmp`` / ``tcp:22`` / ``dns:example.com`` / ``snmp:sysDescr`` / ``snmp:1.3.6.1.2.1.1.1.0``
    / ``http://host:port/path`` / ``https://...``
    不写（None 或空）→ 默认 ``["icmp"]``；写错直接抛 ValueError，让配置问题当场暴露。
    """
    if raw is None or raw == "" or raw == []:
        return ["icmp"]
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        raise ValueError("checks 必须是列表，例如 checks: [icmp, tcp:22]")

    out = []
    for item in raw:
        s = str(item).strip()
        low = s.lower()
        if low == "icmp":
            out.append("icmp")
        elif low.startswith("tcp:"):
            port_text = s.split(":", 1)[1].strip()
            if not port_text.isdigit() or not (1 <= int(port_text) <= 65535):
                raise ValueError("checks 里的 TCP 端口不合法: %r（应为 1-65535）" % s)
            out.append("tcp:%d" % int(port_text))
        elif low.startswith("dns:"):
            name = s.split(":", 1)[1].strip()
            if not name or any(c.isspace() for c in name) or "/" in name:
                raise ValueError("checks 里的 DNS 域名不合法: %r（形如 dns:example.com）" % s)
            out.append("dns:" + name)
        elif low.startswith("snmp:"):
            out.append("snmp:" + snmp_target(s.split(":", 1)[1]))
        elif low.startswith("http://") or low.startswith("https://"):
            out.append(s)
        else:
            raise ValueError("不认识的 check: %r（支持 icmp / tcp:PORT / dns:HOST / snmp:OID / http(s)://…）" % s)
    return out


def describe_checks(raw) -> str:
    """把 checks 渲染成短标签，用于报告里显示「这台设备探了什么」。"""
    return "+".join(parse_checks(raw))


def run_checks(host: str,
               checks=None,
               ping_count: int = PING_COUNT_DEFAULT,
               ping_timeout: int = PING_TIMEOUT_DEFAULT,
               tcp_timeout: int = TCP_TIMEOUT_DEFAULT,
               http_timeout: int = HTTP_TIMEOUT_DEFAULT,
               dns_timeout: int = DNS_TIMEOUT_DEFAULT,
               snmp_timeout: int = SNMP_TIMEOUT_DEFAULT,
               snmp_community: str = SNMP_COMMUNITY_DEFAULT):
    """执行一台设备的全部探测。

    返回 ``(是否在线, detail 汇总, [ProbeResult, ...])``。
    多协议是 AND 语义：任何一项失败即判该设备异常，但明细全部保留，
    便于区分「ICMP 被禁」和「服务真的挂了」。
    """
    parsed = parse_checks(checks)
    results = []
    for item in parsed:
        if item == "icmp":
            results.append(probe_icmp(host, ping_count, ping_timeout))
        elif item.startswith("tcp:"):
            results.append(probe_tcp(host, int(item.split(":", 1)[1]), tcp_timeout))
        elif item.startswith("dns:"):
            results.append(probe_dns(item.split(":", 1)[1], dns_timeout))
        elif item.startswith("snmp:"):
            results.append(probe_snmp(host, item.split(":", 1)[1], snmp_community, snmp_timeout))
        else:
            results.append(probe_http(item, http_timeout))

    ok = all(r.ok for r in results)
    detail = " | ".join(r.detail for r in results)
    return ok, detail, results


if __name__ == "__main__":  # 手动自测：python probes.py
    for target in ("127.0.0.1", "192.0.2.1"):     # 192.0.2.0/24 是 RFC5737 保留段，永不响应
        ok, detail, items = run_checks(target, ["icmp", "tcp:65000"])
        print("%-12s 在线=%s  %s" % (target, ok, detail))
        print(" " * 12 + probe_traceroute(target).detail)   # 按需诊断长什么样

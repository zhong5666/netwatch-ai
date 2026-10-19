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
"""
from __future__ import annotations

import platform
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


@dataclass
class ProbeResult:
    """一次单项探测的结果。"""

    kind: str      # icmp / tcp / http
    target: str    # 探测目标：ip / ip:port / url
    ok: bool
    ms: int        # 墙钟耗时(毫秒)
    detail: str    # 人类可读的一行结论

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
        return ProbeResult("icmp", host, True, ms, "ICMP 通 (%dms)" % ms)
    return ProbeResult("icmp", host, False, ms, "ICMP 不通 (rc=%d)" % res.returncode)


def probe_tcp(host: str, port: int, timeout: int = TCP_TIMEOUT_DEFAULT) -> ProbeResult:
    """TCP 端口探测：能完成三次握手即在线（用来绕开禁用 ICMP 的设备）。"""
    target = "%s:%d" % (host, port)
    t0 = time.perf_counter()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        ms = int((time.perf_counter() - t0) * 1000)
        return ProbeResult("tcp", target, True, ms, "TCP %d 可连 (%dms)" % (port, ms))
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
            return ProbeResult("http", url, judge_http(status), ms, "HTTP %d (%dms)" % (status, ms))
    except urllib.error.HTTPError as e:      # 4xx/5xx 会走这个分支
        ms = int((time.perf_counter() - t0) * 1000)
        ok = judge_http(e.code)
        tail = "" if ok else " 服务端异常"
        return ProbeResult("http", url, ok, ms, "HTTP %d%s" % (e.code, tail))
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
    return ProbeResult("dns", name, True, ms, "DNS 解析 %s → %s%s (%dms)" % (name, ips[0], more, ms))


def parse_checks(raw) -> list:
    """把配置里的 checks 规范化成探测指令列表（纯函数）。

    合法写法：``icmp`` / ``tcp:22`` / ``dns:example.com`` / ``http://host:port/path`` / ``https://...``
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
        elif low.startswith("http://") or low.startswith("https://"):
            out.append(s)
        else:
            raise ValueError("不认识的 check: %r（支持 icmp / tcp:PORT / dns:HOST / http(s)://…）" % s)
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
               dns_timeout: int = DNS_TIMEOUT_DEFAULT):
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
        else:
            results.append(probe_http(item, http_timeout))

    ok = all(r.ok for r in results)
    detail = " | ".join(r.detail for r in results)
    return ok, detail, results


if __name__ == "__main__":  # 手动自测：python probes.py
    for target in ("127.0.0.1", "192.0.2.1"):     # 192.0.2.0/24 是 RFC5737 保留段，永不响应
        ok, detail, items = run_checks(target, ["icmp", "tcp:65000"])
        print("%-12s 在线=%s  %s" % (target, ok, detail))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""探测层单测。

原则：**不 ping 任何真实设备**，只用纯函数 + 本机回环端口来验证逻辑，
所以 CI（含 GitHub Actions 三平台）能稳定跑，不需要外网。
"""
import socket
import threading

import pytest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import probes


# ---------------------------------------------------------------- 配置解析

@pytest.mark.parametrize("raw,expected", [
    (None, ["icmp"]),                       # 不写 → 默认 icmp（向后兼容）
    ("", ["icmp"]),
    ([], ["icmp"]),
    ("icmp", ["icmp"]),                     # 单个字符串也接受
    (["ICMP"], ["icmp"]),                   # 大小写不敏感
    (["tcp:22"], ["tcp:22"]),
    (["tcp: 22"], ["tcp:22"]),              # 容忍空格
    (["ICMP", "tcp:5000", "http://h/x"], ["icmp", "tcp:5000", "http://h/x"]),
    (["https://h/p"], ["https://h/p"]),
    (["dns:example.com"], ["dns:example.com"]),
    (["DNS:Example.COM"], ["dns:Example.COM"]),   # 前缀大小写不敏感，域名原样保留
    (["dns: example.com"], ["dns:example.com"]),  # 容忍空格
])
def test_parse_checks_ok(raw, expected):
    assert probes.parse_checks(raw) == expected


@pytest.mark.parametrize("bad", [
    ["icmp-ping"],          # 不认识的关键字
    ["tcp:"],               # 端口空
    ["tcp:0"],              # 端口越界
    ["tcp:70000"],
    ["tcp:abc"],
    {"icmp": True},         # 不是列表
    ["ftp://h"],            # 不支持的协议
    ["dns:"],               # 域名为空
    ["dns:a b"],            # 域名里有空格
    ["dns:a.com/x"],        # 混进了 URL 路径
])
def test_parse_checks_reject(bad):
    with pytest.raises(ValueError):
        probes.parse_checks(bad)


def test_describe_checks():
    assert probes.describe_checks(["icmp", "tcp:22"]) == "icmp+tcp:22"
    assert probes.describe_checks(None) == "icmp"


# ---------------------------------------------------------------- ping 命令拼装

def test_build_ping_cmd_windows():
    assert probes.build_ping_cmd("1.2.3.4", 3, 1, "windows") == \
        ["ping", "-n", "3", "-w", "1000", "1.2.3.4"]


def test_build_ping_cmd_linux():
    assert probes.build_ping_cmd("1.2.3.4", 3, 2, "linux") == \
        ["ping", "-c", "3", "-W", "2", "1.2.3.4"]


def test_build_ping_cmd_macos():
    assert probes.build_ping_cmd("1.2.3.4", 3, 2, "darwin") == \
        ["ping", "-c", "3", "-W", "2000", "1.2.3.4"]


# ---------------------------------------------------------------- ping 判定（真实踩过的坑）

def test_judge_ping_trusts_returncode_only():
    """回归测试：Windows 全丢包的输出里含 "0%" 子串，绝不能被当成「通」。"""
    windows_all_lost = (
        "正在 Ping 192.0.2.1 具有 32 字节的数据:\r\n"
        "请求超时。\r\n"
        "192.0.2.1 的 Ping 统计信息:\r\n"
        "    数据包: 已发送 = 4，已接收 = 0，丢失 = 4 (100% 丢失)，"
    )
    assert probes.judge_ping(1, windows_all_lost) is False      # 用 returncode 判 = 正确
    assert "0%" in windows_all_lost                             # 这正是坑的来源
    assert probes.judge_ping(0, "来自 127.0.0.1 的回复: 字节=32 时间<1ms") is True


# ---------------------------------------------------------------- HTTP 判定

@pytest.mark.parametrize("status,expected", [
    (200, True),
    (204, True),
    (301, True),
    (401, True),     # 要密码 ≠ 服务挂了
    (403, True),     # 拒绝访问 ≠ 服务挂了
    (404, True),     # 路径不存在但服务活着
    (500, False),    # 服务端自己报错 = 异常
    (503, False),
    (None, False),   # 完全没响应
])
def test_judge_http(status, expected):
    assert probes.judge_http(status) is expected


# ---------------------------------------------------------------- TCP 探测（本机回环，真实 socket）

def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_probe_tcp_open_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        result = probes.probe_tcp("127.0.0.1", port, timeout=1)
        assert result.ok is True
        assert "可连" in result.detail
        assert result.kind == "tcp"
    finally:
        server.close()


def test_probe_tcp_closed_port():
    result = probes.probe_tcp("127.0.0.1", _free_port(), timeout=1)
    assert result.ok is False
    assert "连不上" in result.detail


# ---------------------------------------------------------------- HTTP 探测（本机起真实服务）

class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):                                  # noqa: N802
        code = 500 if self.path.startswith("/bad") else 200
        self.send_response(code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):                      # 别把访问日志打到测试输出里
        pass


@pytest.fixture()
def local_http():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1]
    httpd.shutdown()
    httpd.server_close()


def test_probe_http_ok(local_http):
    result = probes.probe_http(local_http + "/ok", timeout=2)
    assert result.ok is True
    assert "HTTP 200" in result.detail


def test_probe_http_5xx_is_abnormal(local_http):
    result = probes.probe_http(local_http + "/bad", timeout=2)
    assert result.ok is False
    assert "500" in result.detail


def test_probe_http_no_server():
    result = probes.probe_http("http://127.0.0.1:%d/" % _free_port(), timeout=2)
    assert result.ok is False
    assert "连不上" in result.detail


# ---------------------------------------------------------------- run_checks 的 AND 语义

def test_run_checks_all_must_pass(monkeypatch):
    monkeypatch.setattr(probes, "probe_icmp",
                        lambda host, count, timeout: probes.ProbeResult("icmp", host, True, 1, "ICMP 通"))
    monkeypatch.setattr(probes, "probe_tcp",
                        lambda host, port, timeout: probes.ProbeResult("tcp", host, False, 1, "TCP 连不上"))

    ok, detail, items = probes.run_checks("10.0.0.1", ["icmp", "tcp:22"])
    assert ok is False                       # 一项失败 → 设备判离线
    assert len(items) == 2
    assert "ICMP 通" in detail and "TCP 连不上" in detail


def test_run_checks_all_pass(monkeypatch):
    monkeypatch.setattr(probes, "probe_icmp",
                        lambda host, count, timeout: probes.ProbeResult("icmp", host, True, 1, "ICMP 通"))
    ok, detail, _ = probes.run_checks("10.0.0.1", None)      # 不写 checks
    assert ok is True
    assert detail == "ICMP 通"


def test_run_checks_icmp_disabled_workaround():
    """真实运维场景：设备禁 ICMP，只探端口 —— 此时不应因 ICMP 丢掉这台设备。"""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        ok, detail, _ = probes.run_checks("127.0.0.1", ["tcp:%d" % port],
                                          tcp_timeout=1, http_timeout=1)
        assert ok is True
        assert "可连" in detail
    finally:
        server.close()


# ---------------------------------------------------------------- DNS 解析探测（不碰真 DNS）

def _addr(ip):
    """拼一条 getaddrinfo 风格的记录。"""
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))


def test_pick_addrs_dedup_and_order():
    """同一域名常返回重复/多协议地址：去重且保序，报告里不刷一长串。"""
    raw = [_addr("1.2.3.4"), _addr("1.2.3.4"), _addr("5.6.7.8"), _addr("1.2.3.4")]
    assert probes.pick_addrs(raw) == ["1.2.3.4", "5.6.7.8"]
    assert probes.pick_addrs(None) == []
    assert probes.pick_addrs([("裸元组",)]) == []          # 结构不对也不能崩


def test_probe_dns_ok_shows_ip_and_ms():
    res = probes.probe_dns("example.com", resolver=lambda host, port: [_addr("93.184.216.34")])
    assert res.ok is True
    assert res.kind == "dns" and res.target == "example.com"
    assert "93.184.216.34" in res.detail and "ms)" in res.detail
    assert "等" not in res.detail                          # 只有一个地址时不啰嗦


def test_probe_dns_ok_multiple_addrs():
    res = probes.probe_dns("example.com", resolver=lambda host, port: [_addr("1.1.1.1"), _addr("2.2.2.2")])
    assert res.ok is True
    assert "1.1.1.1" in res.detail and "等 2 个" in res.detail


def test_probe_dns_failure_says_dns_not_unreachable():
    """关键：DNS 失败必须写成「解析失败」，不能写成「主机不可达」——
    否则运维会去查设备/线路，而真正坏的是 DNS 服务器。"""
    def boom(host, port):
        raise socket.gaierror(11001, "getaddrinfo failed")

    res = probes.probe_dns("nonexistent.invalid", resolver=boom)
    assert res.ok is False
    assert "DNS 解析失败" in res.detail
    assert "不可达" not in res.detail and "超时" not in res.detail


def test_probe_dns_timeout_does_not_block():
    """getaddrinfo 卡住时必须在 timeout 内返回，而不是陪着一起卡。"""
    import time as _t

    def hang(host, port):
        _t.sleep(3)
        return [_addr("1.1.1.1")]

    t0 = _t.perf_counter()
    res = probes.probe_dns("slow.invalid", timeout=0.2, resolver=hang)
    elapsed = _t.perf_counter() - t0
    assert res.ok is False
    assert "超时" in res.detail and "0.2s" in res.detail
    assert elapsed < 1.5, "线程超时没生效，主线程被拖住了"


def test_probe_dns_empty_answer_is_failure():
    """解析器返回空列表（有些环境解析 placeholder 域会这样）不能算通。"""
    res = probes.probe_dns("weird.invalid", resolver=lambda host, port: [])
    assert res.ok is False and "无结果" in res.detail


def test_run_checks_dispatches_dns(monkeypatch):
    monkeypatch.setattr(probes.socket, "getaddrinfo", lambda host, port: [_addr("10.0.0.9")])
    ok, detail, items = probes.run_checks("223.5.5.5", ["dns:example.com"], dns_timeout=2)
    assert ok is True
    assert items[0].kind == "dns"
    assert "DNS 解析 example.com → 10.0.0.9" in detail


def test_run_checks_dns_failure_hits_device(monkeypatch):
    """AND 语义：DNS 挂了（哪怕 ICMP 通）这台设备也算异常 —— 配置里写了就是契约。"""
    monkeypatch.setattr(probes, "probe_icmp",
                        lambda host, count, timeout: probes.ProbeResult("icmp", host, True, 1, "ICMP 通"))

    def boom(host, port):
        raise socket.gaierror(11001, "getaddrinfo failed")

    monkeypatch.setattr(probes.socket, "getaddrinfo", boom)
    ok, detail, _ = probes.run_checks("10.0.0.1", ["icmp", "dns:example.com"], dns_timeout=2)
    assert ok is False
    assert "ICMP 通" in detail and "DNS 解析失败" in detail

# ---------------------------------------------------------------- traceroute（按需诊断，不碰真网络）

WIN_TRACERT = """通过最多 5 个跃点跟踪到 192.0.2.1 的路由

  1     4 ms     5 ms     4 ms  10.60.43.254
  2     *        *        *     请求超时。
  3     *        *        *     请求超时。

跟踪完成。
"""

UNIX_TRACEROUTE = """traceroute to 192.0.2.1 (192.0.2.1), 5 hops max, 60 byte packets
 1  10.60.43.254  4.113 ms
 2  *
 3  *
"""

# 真实抓的：同网段但没人应答（Windows 会把自己的地址印在跳号后，别当成本机回应）
WIN_UNREACH_LOCAL = "\r\n通过最多 5 个跃点跟踪到 10.60.43.250 的路由\r\n\r\n  1     *     10.60.42.62  报告: 无法访问目标主机。\r\n\r\n跟踪完成。\r\n"

# 某一跳明确回了「目标不可达」：三个探测位都有值，说明包确实到了它
WIN_UNREACH_HOP = """通过最多 5 个跃点跟踪到 192.0.2.1 的路由

  1     4 ms     5 ms     4 ms  10.60.43.254
  2     *        *        *     请求超时。
  3     2 ms     2 ms     2 ms  172.16.0.9  报告: 无法访问目标主机。
"""


class _FakeProc:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.returncode = stdout, returncode


def test_build_traceroute_cmd_windows_milliseconds():
    """Windows 的 tracert -w 是**毫秒**，而且跳数上限是 -h。"""
    cmd = probes.build_traceroute_cmd("192.0.2.1", hops=5, timeout=1, system="windows")
    assert cmd == ["tracert", "-d", "-h", "5", "-w", "1000", "192.0.2.1"]


@pytest.mark.parametrize("system", ["darwin", "linux"])
def test_build_traceroute_cmd_unix_seconds(system):
    """Unix 的 -w 是**秒** —— 和 ping 正好相反（ping 在 macOS 是毫秒），别照搬。"""
    cmd = probes.build_traceroute_cmd("192.0.2.1", hops=4, timeout=2, system=system)
    assert cmd == ["traceroute", "-n", "-q", "1", "-m", "4", "-w", "2", "192.0.2.1"]
    assert "-d" not in cmd          # -d 是 tracert 的关闭反解写法，Unix 用 -n


def test_build_traceroute_cmd_accepts_float_timeout():
    assert probes.build_traceroute_cmd("h", hops=3, timeout=0.5, system="linux")[-2] == "0.5"
    assert probes.build_traceroute_cmd("h", timeout=0.5, system="windows")[-2] == "500"


@pytest.mark.parametrize("raw,expected", [
    (None, True), ("auto", True), ("true", True), ("on", True), ("yes", True),
    ("false", False), ("off", False), ("no", False), ("0", False), ("none", False),
    ("AUTO", True), ("  off  ", False),
    ("flase", True),            # 拼错不能把诊断功能搞没：认不出一律按默认（开）
])
def test_traceroute_enabled(raw, expected):
    assert probes.traceroute_enabled(raw) is expected


def test_parse_traceroute_windows():
    """Windows 一行三列毫秒，「请求超时。」那一跳没有 IP → 记 None（不是 0.0.0.0）。"""
    assert probes.parse_traceroute(WIN_TRACERT) == [(1, "10.60.43.254", ""), (2, None, ""), (3, None, "")]


def test_parse_traceroute_unix():
    assert probes.parse_traceroute(UNIX_TRACEROUTE) == [(1, "10.60.43.254", ""), (2, None, ""), (3, None, "")]


@pytest.mark.parametrize("text", ["", None, "traceroute to x, 5 hops max, 60 byte packets\n", "跟踪完成。"])
def test_parse_traceroute_garbage_is_empty(text):
    """解析不出来就返回空列表 —— 不猜、不编，由调用方退回「没拿到可解析的跳」。"""
    assert probes.parse_traceroute(text) == []


def test_parse_traceroute_keeps_first_address_for_duplicate_hop():
    """同一跳被拆成多行（等价多路径）时留第一次出现的地址，不把跳数搞乱。"""
    text = " 3  * \n 3  10.0.0.7  1.5 ms\n 4  10.0.0.8  1.6 ms\n"
    assert probes.parse_traceroute(text) == [(3, "10.0.0.7", ""), (4, "10.0.0.8", "")]


def test_parse_traceroute_host_unreachable_is_not_an_answer():
    """真机抓到的坑：Windows 报「无法访问目标主机」时把**本机地址**印在跳号后面。

    那一行不是「第 1 跳回应了」，是「本机这边就出不去」——不区分的话，
    运维会照着一句「第 1 跳 10.60.42.62 之后无响应」去查不存在的问题。
    """
    assert probes.parse_traceroute(WIN_UNREACH_LOCAL) == [(1, None, probes.NOTE_UNREACH_LOCAL)]


def test_parse_traceroute_unreachable_from_a_hop_keeps_its_address():
    """某一跳明确回「目标不可达」时，地址要留着 —— 包确实到了它，问题在它后面。"""
    hops = probes.parse_traceroute(WIN_UNREACH_HOP)
    assert hops[0] == (1, "10.60.43.254", "")
    assert hops[-1] == (3, "172.16.0.9", probes.NOTE_UNREACH_HOP)


def test_summarize_all_timeout_blames_local_network():
    """一跳都没回：先说本机到网关这段不通，别急着怀疑运营商。"""
    s = probes.summarize_traceroute([(1, None, ""), (2, None, ""), (3, None, "")], "192.0.2.1")
    assert "前 3 跳全部无响应" in s and "本机" in s


def test_summarize_reached_target_means_link_is_fine():
    """最后一跳就是目标 → 链路是通的，是它自己不回 ICMP（禁 ping / 防火墙）。"""
    s = probes.summarize_traceroute([(1, "10.60.43.254", ""), (2, "192.0.2.1", "")], "192.0.2.1")
    assert "已到目标" in s and "链路是通的" in s
    # 别说成「它不回 ICMP」：触发诊断的可能是 TCP/HTTP 挂了，ICMP 说不定好好的
    assert "ICMP" not in s.split("→")[1]


def test_summarize_private_hop_says_lan():
    s = probes.summarize_traceroute(probes.parse_traceroute(UNIX_TRACEROUTE), "192.0.2.1")
    assert "第 1 跳 10.60.43.254 之后无响应" in s
    assert "内网" in s and "公网" not in s


def test_summarize_public_hop_says_isp_side():
    """最后一跳是公网地址 → 已经出了内网，问题在宽带线路/目标侧。"""
    s = probes.summarize_traceroute([(1, "192.168.1.1", ""), (2, "202.96.128.86", ""), (3, None, "")], "8.8.4.4")
    assert "第 2 跳 202.96.128.86" in s and "公网" in s


def test_summarize_empty_is_honest():
    assert "没拿到可解析的跳" in probes.summarize_traceroute([])


def test_summarize_host_unreachable_blames_local_side():
    """本机这边出不去：措辞要拦住「去查远端」这个错误方向。"""
    s = probes.summarize_traceroute(probes.parse_traceroute(WIN_UNREACH_LOCAL), "10.60.43.250")
    assert "本机这边没出去" in s and "先查本机网络" in s
    assert "跳之后无响应" not in s


def test_summarize_own_address_as_the_hop_means_local_side():
    """同一份输出，知道「10.60.42.62 就是本机」才能得出正确结论。

    这是真机抓的：Windows 报「无法访问目标主机」时把自己的地址印在第 1 跳，
    如果不比对本机地址，就会说成「过了第 1 跳才不通」——方向全反。
    """
    hops = [(1, "10.60.42.62", probes.NOTE_UNREACH_HOP)]
    s = probes.summarize_traceroute(hops, "10.60.43.250", local_ip="10.60.42.62")
    assert "本机这边没出去" in s and "先查本机网络" in s
    # 不知道本机地址时，只能保守地说「过了它才不通」，但绝不能说成「本机出不去」
    s2 = probes.summarize_traceroute(hops, "10.60.43.250")
    assert "再往后不通" in s2


def test_local_addr_for_returns_empty_when_no_route(monkeypatch):
    """选不出接口（没路由）时返回空串，让调用方退回保守说法，而不是抛异常。"""
    def boom(*a, **kw):
        raise OSError("no route")
    monkeypatch.setattr(probes.socket, "socket", boom)
    assert probes.local_addr_for("192.0.2.1") == ""


def test_probe_traceroute_budget_covers_three_probes_per_hop(monkeypatch):
    """预算要按「每跳 3 个探测包」给 —— 按 1 倍算会把真结论掐成「超时」。"""
    seen = {}

    def fake_run(cmd, **kwargs):
        seen["budget"] = kwargs.get("timeout")
        return _FakeProc(stdout="")

    monkeypatch.setattr(probes.subprocess, "run", fake_run)
    monkeypatch.setattr(probes, "local_addr_for", lambda host: "")
    probes.probe_traceroute("192.0.2.1", hops=5, timeout=1)
    assert seen["budget"] == 5 * 1 * 3 + 5


def test_summarize_unreachable_from_a_hop_points_upstream():
    """某一跳回「目标不可达」：包到得了它，问题在它后面（别去怪目标设备）。"""
    s = probes.summarize_traceroute(probes.parse_traceroute(WIN_UNREACH_HOP), "192.0.2.1")
    assert "第 3 跳 172.16.0.9" in s and "再往后不通" in s


def test_probe_traceroute_parses_real_output(monkeypatch):
    monkeypatch.setattr(probes.subprocess, "run", lambda *a, **k: _FakeProc(WIN_TRACERT))
    res = probes.probe_traceroute("192.0.2.1", hops=5, timeout=1, system="windows")
    assert res.kind == "traceroute" and res.target == "192.0.2.1"
    assert "断在内网" in res.detail and "10.60.43.254" in res.detail


def test_probe_traceroute_missing_binary_is_reported_not_raised(monkeypatch):
    """没装 traceroute 的机器上不能把整轮巡检搞崩：退回一行「不可用」。"""
    def boom(*a, **k):
        raise FileNotFoundError("traceroute")
    monkeypatch.setattr(probes.subprocess, "run", boom)
    res = probes.probe_traceroute("192.0.2.1", system="linux")
    assert res.ok is False and "不可用" in res.detail


def test_probe_traceroute_timeout_is_bounded(monkeypatch):
    """命令卡住时必须按 hops*timeout+5 秒兜底，不能陪着一起卡。"""
    def boom(*a, **k):
        raise probes.subprocess.TimeoutExpired("traceroute", 6)
    monkeypatch.setattr(probes.subprocess, "run", boom)
    res = probes.probe_traceroute("192.0.2.1", hops=1, timeout=1, system="linux")
    # 预算 = 每跳 3 个探测包 × 跳数 × 每跳秒数 + 5s（tracert 每跳发 3 个，按 1 倍算会掐掉真结论）
    assert res.ok is False and "超时" in res.detail and ">8s" in res.detail


def test_probe_traceroute_unparsable_output_is_not_ok(monkeypatch):
    """输出解析不了：ok=False（这次诊断没结论），但明细不编内容。"""
    monkeypatch.setattr(probes.subprocess, "run", lambda *a, **k: _FakeProc("乱码一堆\n"))
    res = probes.probe_traceroute("192.0.2.1", system="windows")
    assert res.ok is False and "没拿到可解析的跳" in res.detail

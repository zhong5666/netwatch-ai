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

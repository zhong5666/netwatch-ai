#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNMP v2c 探测单测。

原则：**不查真实设备**。两路证据各自独立：

1. **参照报文**：下面 ``REF_*`` 里的十六进制由 pysnmp 7.1.30 生成（开发期一次性
   oracle，不进仓库、不进 CI）。我们构造的请求必须和它**字节级相同**，它构造的应答
   我们必须解得对 —— 两边对得上，才敢说「手写的 BER 没写歪」。
2. **回环往返**：本机假 agent 把参照应答原样吐回来，走的是真 UDP socket
   （超时、端口不可达、串包丢弃都在这一层验）。
"""
import socket
import threading

import pytest

import probes

# ---------------------------------------------------------------- 参照报文（pysnmp 7.1.30 生成）
REF_REQ_PUBLIC_SYSDESCR = (
    "302702010104067075626c6963a01a02022a2a020100020100300e300c06082b060102010101000500")
REF_REQ_PRIVATE_SYSUPTIME = (
    "3028020101040770726976617465a01a020204d2020100020100300e300c06082b060102010103000500")
REF_RSP_STR = (
    "303902010104067075626c6963a22c02022a2a0201000201003020301e06082b0601020101010004"
    "125562756e74752032322e303420736e6d7064")
REF_RSP_INT = (
    "302a02010104067075626c6963a21d02022a2a0201000201003011300f060a2b060102010202010a"
    "010201d6")
REF_RSP_TICKS = (
    "302b02010104067075626c6963a21e02022a2a0201000201003012301006082b060102010103004304"
    "075bcd15")
REF_RSP_COUNTER = (
    "302e02010104067075626c6963a22102022a2a02010002010030153013060a2b060102010202010a01"
    "410500ffffffff")
REF_RSP_IP = (
    "302b02010104067075626c6963a21e02022a2a0201000201003012301006082b060102010106004004"
    "c0a80101")
REF_RSP_EMPTY_STR = (
    "302702010104067075626c6963a21a02022a2a020100020100300e300c06082b060102010106000400")
REF_RSP_ERR_NOSUCHNAME = (
    "302702010104067075626c6963a21a02022a2a020102020101300e300c06082b060102010101000500")
REF_RSP_NO_SUCH_INSTANCE = (
    "302702010104067075626c6963a21a02022a2a020100020100300e300c06082b060102010101008100")

# 参照报文里的 request-id 是 0x2A2A；把自家的 request-id 钉住，假 agent 才能原样回吐
REF_REQUEST_ID = 0x2A2A


@pytest.fixture
def fixed_request_id(monkeypatch):
    monkeypatch.setattr(probes, "_snmp_request_id", lambda: REF_REQUEST_ID)


def _serve_once(payload, port):
    """在 port 上收一个包，回一段固定字节；返回线程（daemon，测试挂了也不拖住进程）。"""

    def run():
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            srv.bind(("127.0.0.1", port))
            srv.settimeout(5)
            _, peer = srv.recvfrom(4096)
            srv.sendto(payload, peer)
        except OSError:
            pass
        finally:
            srv.close()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return th


def _free_port():
    """先占一个端口再放掉，拿到一个大概率没人用的号（避免和真服务撞车）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------------------------------------------------------------- 编码

def test_request_matches_reference_implementation_byte_for_byte():
    """我们发的 GetRequest 必须和 pysnmp 生成的完全一致（同样的 community/OID/request-id）。"""
    mine = probes.build_snmp_get("1.3.6.1.2.1.1.1.0", "public", REF_REQUEST_ID)
    assert mine.hex() == REF_REQ_PUBLIC_SYSDESCR
    assert len(mine) == 41


def test_request_with_other_community_and_oid_still_matches():
    mine = probes.build_snmp_get("1.3.6.1.2.1.1.3.0", "private", 1234)
    assert mine.hex() == REF_REQ_PRIVATE_SYSUPTIME


def test_request_id_fits_integer32():
    """request-id 是 Integer32：毫秒时间戳不截位会编成 6 字节整数，真 agent 会拒收。"""
    rid = probes._snmp_request_id()
    assert 0 <= rid < 0x80000000
    assert len(probes._ber_int(rid)) <= 6            # 2 字节 tag/长度 + 最多 4 字节整数
    with pytest.raises(ValueError):
        probes.build_snmp_get("1.3.6.1.2.1.1.1.0", "public", 0x80000000)


@pytest.mark.parametrize("dotted", [
    "1.3.6.1.2.1.1.1.0",
    "1.3.6.1.4.1.311.1.1.3.1",       # 长弧段：每段 >127 要拆成多字节
    "2.100.3",                       # 第一段 2 时第二段可以超过 39
    "1.3.6.1.4.1.4294967295",        # 32 位上限，最考验变长编码
])
def test_oid_encodes_and_decodes_back(dotted):
    assert probes.decode_oid(probes.encode_oid(dotted)) == dotted


def test_oid_first_byte_packs_two_arcs():
    assert probes.encode_oid("1.3.6.1.2.1.1.1.0").hex() == "2b06010201010100"
    assert probes.encode_oid("2.100.3").hex() == "813403"


@pytest.mark.parametrize("bad", ["", "1", "abc.1", "1.3.x", "9.1.1", "1.99.1", "-1.3"])
def test_oid_rejects_invalid(bad):
    with pytest.raises(ValueError):
        probes.encode_oid(bad)


# ---------------------------------------------------------------- 解码（吃 pysnmp 造的应答）

@pytest.mark.parametrize("hex_text,oid,value_text", [
    (REF_RSP_STR, "1.3.6.1.2.1.1.1.0", '"Ubuntu 22.04 snmpd"'),
    (REF_RSP_INT, "1.3.6.1.2.1.2.2.1.10.1", "-42"),
    (REF_RSP_TICKS, "1.3.6.1.2.1.1.3.0", "123456789 ticks (14d 06:56:07)"),
    (REF_RSP_COUNTER, "1.3.6.1.2.1.2.2.1.10.1", "4294967295"),
    (REF_RSP_IP, "1.3.6.1.2.1.1.6.0", "192.168.1.1"),
    (REF_RSP_EMPTY_STR, "1.3.6.1.2.1.1.6.0", '""'),
    (REF_RSP_NO_SUCH_INSTANCE, "1.3.6.1.2.1.1.1.0", "<noSuchInstance>"),
])
def test_parse_reference_responses(hex_text, oid, value_text):
    parsed = probes.parse_snmp_response(bytes.fromhex(hex_text))
    assert parsed["version"] == 1                 # v2c 的 version 字段是 1
    assert parsed["request_id"] == REF_REQUEST_ID
    assert parsed["error_status"] == 0
    (got_oid, tag, raw), = parsed["varbinds"]
    assert got_oid == oid
    assert probes.fmt_snmp_value(tag, raw) == value_text


def test_parse_keeps_error_status_and_index():
    parsed = probes.parse_snmp_response(bytes.fromhex(REF_RSP_ERR_NOSUCHNAME))
    assert (parsed["error_status"], parsed["error_index"]) == (2, 1)


def test_counter_is_unsigned_not_signed():
    """4294967295 若按有符号解会变成 -1 —— 这是 Gauge32/Counter32 最容易踩的坑。"""
    parsed = probes.parse_snmp_response(bytes.fromhex(REF_RSP_COUNTER))
    _, tag, raw = parsed["varbinds"][0]
    assert probes.fmt_snmp_value(tag, raw) == "4294967295"


@pytest.mark.parametrize("payload", [
    b"",
    b"\x30",                                            # 只有外层 tag
    bytes.fromhex(REF_RSP_STR)[:-5],                    # 尾部截断
    b"\x30\x03\x02\x01\x01",                            # 少了 community / PDU
    b"\xa2\x02\x02\x01",                                # 根本不是 SEQUENCE
])
def test_parse_rejects_malformed_without_crashing(payload):
    with pytest.raises(ValueError):
        probes.parse_snmp_response(payload)


def test_non_printable_octet_string_renders_as_hex():
    """设备描述里混进二进制（有些厂商会塞 MAC/序列号的原始字节）不能把表格撑乱。"""
    assert probes.fmt_snmp_value(0x04, b"\x00\x01\x02") == "0x000102"


# ---------------------------------------------------------------- 回环往返（真 socket）

def test_probe_ok_against_reference_response(fixed_request_id):
    port = _free_port()
    _serve_once(bytes.fromhex(REF_RSP_STR), port)
    res = probes.probe_snmp("127.0.0.1", "sysDescr", port=port, timeout=3)
    assert res.ok
    assert res.kind == "snmp"
    assert "Ubuntu 22.04 snmpd" in res.detail
    assert res.rtt_ms is not None and res.rtt_ms >= 0


def test_probe_detail_never_leaks_community(fixed_request_id):
    """团体名是凭据：明细会进终端报告、历史库和 HTML，绝不能带出来。"""
    port = _free_port()
    _serve_once(bytes.fromhex(REF_RSP_STR), port)
    res = probes.probe_snmp("127.0.0.1", "sysDescr", community="s3cr3t-ro",
                            port=port, timeout=3)
    assert "s3cr3t-ro" not in res.detail
    assert "public" not in res.detail


def test_probe_reports_error_status(fixed_request_id):
    port = _free_port()
    _serve_once(bytes.fromhex(REF_RSP_ERR_NOSUCHNAME), port)
    res = probes.probe_snmp("127.0.0.1", "sysDescr", port=port, timeout=3)
    assert not res.ok
    assert "noSuchName" in res.detail and "error-index=1" in res.detail


def test_probe_reports_missing_oid(fixed_request_id):
    port = _free_port()
    _serve_once(bytes.fromhex(REF_RSP_NO_SUCH_INSTANCE), port)
    res = probes.probe_snmp("127.0.0.1", "sysDescr", port=port, timeout=3)
    assert not res.ok
    assert "noSuchInstance" in res.detail


def test_probe_no_answer_says_snmp_not_host_unreachable():
    """没人应答时必须说「没有 SNMP 应答」，不能糊成「主机不可达」——否则误诊成设备挂了。"""
    port = _free_port()
    res = probes.probe_snmp("127.0.0.1", "sysDescr", port=port, timeout=0.3)
    assert not res.ok
    assert "SNMP" in res.detail
    assert "端口不可达" in res.detail or "无应答" in res.detail
    assert res.rtt_ms is None



class _RaisingSock:
    """把 recv 换成「抛指定异常」，用来锁跨平台异常类差异（不依赖跑测试的机器）。"""

    def __init__(self, exc):
        self._exc = exc

    def settimeout(self, _t):
        pass

    def connect(self, _addr):
        pass

    def send(self, _pkt):
        return 0

    def recv(self, _n):
        raise self._exc

    def close(self):
        pass


@pytest.mark.parametrize("exc", [
    ConnectionResetError(10054, "Connection reset by peer"),    # Windows：ICMP 端口不可达
    ConnectionRefusedError(111, "Connection refused"),          # Linux / macOS：ECONNREFUSED
])
def test_port_unreachable_maps_both_platform_exceptions(monkeypatch, exc):
    """同一个「161 没服务」，三平台抛的异常类不同 —— 只 catch Reset 会让 Linux 掉进 OSError 兜底。"""
    monkeypatch.setattr(probes.socket, "socket", lambda *a, **kw: _RaisingSock(exc))
    res = probes.probe_snmp("127.0.0.1", "sysDescr", timeout=1, port=16161)
    assert res.ok is False
    assert "端口不可达" in res.detail
    assert "不可达" in res.detail and "主机" not in res.detail

def test_probe_drops_stray_response_with_wrong_request_id(fixed_request_id):
    """串包/重发：request-id 对不上的应答要丢掉，不能拿来判「在线」。"""
    port = _free_port()
    others = bytes.fromhex(REF_RSP_STR).replace(b"\x02\x02\x2a\x2a", b"\x02\x02\x11\x11")
    _serve_once(others, port)
    res = probes.probe_snmp("127.0.0.1", "sysDescr", port=port, timeout=0.4)
    assert not res.ok


# ---------------------------------------------------------------- 配置写法

def test_parse_checks_accepts_preset_and_raw_oid():
    got = probes.parse_checks(["snmp:sysDescr", "SNMP:sysname", "snmp:1.3.6.1.2.1.1.3.0"])
    assert got == ["snmp:1.3.6.1.2.1.1.1.0",            # 预设名展开成 OID
                   "snmp:1.3.6.1.2.1.1.5.0",            # 大小写不敏感
                   "snmp:1.3.6.1.2.1.1.3.0"]


@pytest.mark.parametrize("bad", ["snmp:", "snmp:abc", "snmp:9.1.1", "snmp:1.3.6.1.x"])
def test_parse_checks_rejects_bad_snmp(bad):
    with pytest.raises(ValueError):
        probes.parse_checks([bad])


def test_run_checks_treats_snmp_as_part_of_and(monkeypatch):
    """多协议是 AND：ICMP 通但 SNMP 读不到，这台设备就是异常（明细两条都在）。"""
    monkeypatch.setattr(probes, "probe_icmp",
                        lambda *a, **k: probes.ProbeResult("icmp", "h", True, 5, "ping 通", 5))
    monkeypatch.setattr(probes, "probe_snmp",
                        lambda *a, **k: probes.ProbeResult("snmp", "sysDescr", False, 8, "SNMP 无应答"))
    ok, detail, items = probes.run_checks("10.0.0.1", ["icmp", "snmp:sysDescr"])
    assert not ok
    assert len(items) == 2
    assert "ping 通" in detail and "SNMP 无应答" in detail


def test_run_checks_passes_community_and_timeout(monkeypatch):
    seen = {}

    def fake_snmp(host, target, community=None, timeout=None, port=161):
        seen.update(host=host, target=target, community=community, timeout=timeout)
        return probes.ProbeResult("snmp", target, True, 1, "ok", 1)

    monkeypatch.setattr(probes, "probe_snmp", fake_snmp)
    probes.run_checks("10.0.0.1", ["snmp:sysName"], snmp_community="ro-community", snmp_timeout=7)
    assert seen == {"host": "10.0.0.1", "target": "1.3.6.1.2.1.1.5.0",
                    "community": "ro-community", "timeout": 7}

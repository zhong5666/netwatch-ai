#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI 结构化输出的单测：解析 + 卡片渲染，全程离线（不联网、不需要 API key）。

覆盖的重点是「模型不听话时不能丢信息」：
真接口偶尔会围栏、会加客套话、会把置信度写成 85%，这些都必须能救回来。
"""
import io
import json
import urllib.error

import pytest

import analyzer
import netwatch
import probes
from tests.test_netwatch import fake_probe_factory          # 复用假探测函数


GOOD = {
    "fault_type": "端口或服务异常",
    "confidence": 0.85,
    "impact": "仅 nas 的 5000 端口服务不可用",
    "reason": "ICMP 通但 TCP 5000 拒绝连接，服务进程未监听",
    "first_step": "在 nas 上执行 netstat -lntp | grep 5000 确认监听状态",
}
GOOD_JSON = (
    '{"fault_type": "端口或服务异常", "confidence": 0.85, '
    '"impact": "仅 nas 的 5000 端口服务不可用", '
    '"reason": "ICMP 通但 TCP 5000 拒绝连接，服务进程未监听", '
    '"first_step": "在 nas 上执行 netstat -lntp | grep 5000 确认监听状态"}'
)


# ---------------------------------------------------------------- 解析

def test_parse_plain_json():
    p = analyzer.parse_analysis(GOOD_JSON)
    assert p["ok"] is True
    assert p["fault_type"] == "端口或服务异常"
    assert p["confidence"] == 0.85
    assert p["missing"] == []


def test_parse_markdown_fenced_json():
    """模型最常见的犯规：外面套 ```json 围栏。"""
    p = analyzer.parse_analysis("```json\n%s\n```" % GOOD_JSON)
    assert p["ok"] is True
    assert p["first_step"].startswith("在 nas 上执行")


def test_parse_json_wrapped_in_prose():
    p = analyzer.parse_analysis("好的，分析如下：\n%s\n以上，请参考。" % GOOD_JSON)
    assert p["ok"] is True
    assert p["reason"].startswith("ICMP 通")


def test_parse_garbage_keeps_raw():
    """解析失败不抛异常、不丢原文 —— AI 的结论是花钱换来的。"""
    text = "这台设备应该是网线松了，建议先去看一眼机柜。"
    p = analyzer.parse_analysis(text)
    assert p["ok"] is False
    assert p["raw"] == text
    assert set(p["missing"]) == set(analyzer.ANALYSIS_FIELDS)


def test_parse_empty_and_non_object():
    assert analyzer.parse_analysis("")["ok"] is False
    assert analyzer.parse_analysis("   ")["ok"] is False
    assert analyzer.parse_analysis('["a", "b"]')["ok"] is False   # 是 JSON，但不是对象


def test_parse_truncated_json_falls_back():
    """模型被 max_tokens 截断时给半截 JSON —— 不能崩，退回原文。"""
    p = analyzer.parse_analysis('{"fault_type": "网络中断", "reason": "上游')
    assert p["ok"] is False
    assert "网络中断" in p["raw"]


# ---------------------------------------------------------------- 置信度归一

def test_confidence_variants():
    assert analyzer.parse_analysis('{"confidence": 0.85}')["confidence"] == 0.85
    assert analyzer.parse_analysis('{"confidence": 85}')["confidence"] == 0.85      # 百分数
    assert analyzer.parse_analysis('{"confidence": "85%"}')["confidence"] == 0.85   # 带百分号
    assert analyzer.parse_analysis('{"confidence": "0.6"}')["confidence"] == 0.6    # 字符串小数
    assert analyzer.parse_analysis('{"confidence": 1.5}')["confidence"] == 1.0      # 超范围截到 1.0


def test_confidence_unrecognized_is_none_not_guessed():
    p = analyzer.parse_analysis('{"fault_type": "其他", "confidence": "高"}')
    assert p["confidence"] is None
    assert p["confidence_raw"] == "高"
    assert "confidence" in p["missing"]


# ---------------------------------------------------------------- 缺字段 / 异形值

def test_missing_field_recorded_but_partial_ok():
    p = analyzer.parse_analysis('{"reason": "网关侧掉线"}')
    assert p["ok"] is True                       # 有内容可用就不算失败
    assert p["reason"] == "网关侧掉线"
    assert "first_step" in p["missing"] and "fault_type" in p["missing"]


def test_list_and_dict_values_flattened():
    """模型偶尔把建议写成数组 —— 压成一行，不让卡片里出现 python 字面量。"""
    p = analyzer.parse_analysis(
        '{"fault_type": "网络中断", "first_step": ["先 ping 网关", "再看交换机端口灯"]}')
    assert p["first_step"] == "先 ping 网关；再看交换机端口灯"


# ---------------------------------------------------------------- 卡片渲染

def test_render_card_contains_all_fields():
    card = analyzer.render_card(analyzer.parse_analysis(GOOD_JSON))
    assert "AI 故障卡片" in card
    assert "端口或服务异常" in card
    assert "85%" in card
    assert "netstat -lntp" in card
    assert "缺失" not in card                    # 字段齐全时不出现「缺失」行
    assert card.count("│") == 10                 # 5 行内容，每行两个竖线：边框成对


def test_render_card_falls_back_to_raw_text():
    raw = "建议先重启路由器。"
    card = analyzer.render_card(analyzer.parse_analysis(raw))
    assert "未按 JSON 返回" in card
    assert raw in card                            # 原文一字不删


def test_render_card_unknown_confidence_shown_as_raw():
    card = analyzer.render_card(analyzer.parse_analysis('{"fault_type": "其他", "confidence": "高"}'))
    assert "未识别(高)" in card


def test_render_card_with_rule_hint_prefix():
    card = analyzer.render_card(analyzer.parse_analysis(GOOD_JSON), rule_text="规则判断：仅单台设备不可达")
    assert card.splitlines()[0].startswith("规则判断")


# ---------------------------------------------------------------- 与编排层串起来

def test_main_prints_structured_card(tmp_path, monkeypatch, capsys):
    """端到端：--ai 时卡片进 stdout（analyze 换成假函数，不联网）。"""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: nas\n    ip: 192.0.2.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory(set()))
    monkeypatch.setattr(netwatch, "analyze",
                        lambda *a, **k: '```json\n%s\n```' % GOOD_JSON)

    netwatch.main(["--config", str(cfg), "--silent-ok", "--ai"])
    out = capsys.readouterr().out
    assert "AI 故障卡片" in out
    assert "端口或服务异常" in out and "85%" in out


def test_main_falls_back_when_model_ignores_json(tmp_path, monkeypatch, capsys):
    """模型不按约定回 JSON 时，原文照样要打出来（回归：曾差点整段丢掉）。"""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: nas\n    ip: 192.0.2.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory(set()))
    monkeypatch.setattr(netwatch, "analyze", lambda *a, **k: "设备大概没电了，去看看吧。")

    netwatch.main(["--config", str(cfg), "--silent-ok", "--ai"])
    out = capsys.readouterr().out
    assert "设备大概没电了" in out
    assert "未按 JSON 返回" in out


def test_prompt_demands_json():
    """prompt 必须把字段名写清楚，否则模型爱回散文。"""
    prompt = analyzer.build_prompt([], [], ts_text="2026-10-18 12:00")
    for field in analyzer.ANALYSIS_FIELDS:
        assert field in prompt
    assert "JSON" in prompt


# ---------------------------------------------------------------- 接口返回异常要分类

class _FakeResp:
    """只实现 urlopen 用到的两个方法：read() 和上下文管理器。"""

    def __init__(self, payload):
        self._data = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_urlopen(payload, seen=None):
    def _open(req, timeout=0):
        if seen is not None:
            seen["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResp(payload)
    return _open


ABNORMAL = [{"name": "nas", "ip": "10.0.0.2", "streak": 2, "detail": "ICMP 通 (12ms) | TCP 5000 连不上"}]
ALL_DEVICES = [{"name": "nas", "ip": "10.0.0.2", "status": "离线", "streak": 2}]


def test_analyze_truncation_error_is_specific(monkeypatch):
    """推理模型把预算全花在思考上 → 报错要指明 max_tokens，别只说「空内容」。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "length",
                                                    "message": {"content": ""}}]}))
    with pytest.raises(RuntimeError) as e:
        analyzer.analyze(ABNORMAL, ALL_DEVICES)
    msg = str(e.value)
    assert "max_tokens" in msg
    assert "NETWATCH_NO_THINKING" in msg   # 报错要给出真正的解法（只加大预算实测无效）


def test_analyze_empty_content_error(monkeypatch):
    """限流：200 + 空内容（老问题，回归保护）。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": "   "}}]}))
    with pytest.raises(RuntimeError) as e:
        analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert "空内容" in str(e.value)


def test_analyze_sends_json_prompt_and_budget(monkeypatch):
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    seen = {}
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": GOOD_JSON}}]}, seen))
    text = analyzer.analyze(ABNORMAL, ALL_DEVICES, ts_text="2026-10-18 12:00")

    assert analyzer.parse_analysis(text)["ok"] is True       # 返回的 JSON 能直接解析成卡片
    assert seen["body"]["max_tokens"] == analyzer.MAX_TOKENS  # 预算足够推理模型思考
    assert "JSON" in seen["body"]["messages"][0]["content"]   # system 里也强调了格式


def test_int_env_bad_value_falls_back(monkeypatch):
    """环境变量写错不能把 import 搞崩。"""
    monkeypatch.setenv("NETWATCH_MAX_TOKENS", "八百")
    assert analyzer._int_env("NETWATCH_MAX_TOKENS", 800) == 800


def test_default_budget_is_reasoning_safe():
    """推理模型的思考会吃掉一截预算：默认值必须留足（实测 300 必然空返回、800 会偶发截断）。"""
    assert analyzer.MAX_TOKENS >= 1500


def test_analyze_timeout_message_mentions_env(monkeypatch):
    """超时要说清是超时、以及怎么调（别丢个 'timed out' 让人猜）。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")

    def _boom(req, timeout=0):
        raise urllib.error.URLError("timed out")

    monkeypatch.setattr(analyzer.urllib.request, "urlopen", _boom)
    with pytest.raises(RuntimeError) as e:
        analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert "NETWATCH_TIMEOUT" in str(e.value)


def test_no_thinking_flag_is_sent_when_enabled(monkeypatch):
    """开着 NETWATCH_NO_THINKING 时请求里必须带 enable_thinking=false，否则推理模型只回思考、正文全空。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer, "NO_THINKING", True)
    seen = {}
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": GOOD_JSON}}]}, seen))
    analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert seen["body"]["enable_thinking"] is False


def test_no_thinking_flag_absent_by_default(monkeypatch):
    """默认不塞这个字段：非推理模型不接受未知字段时不该被我们搞出 400。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer, "NO_THINKING", False)
    seen = {}
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": GOOD_JSON}}]}, seen))
    analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert "enable_thinking" not in seen["body"]


def test_json_mode_and_no_thinking_together(monkeypatch):
    """实测结论：光关思考压不住空想，必须再带 response_format=json_object 才收敛。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer, "NO_THINKING", True)
    monkeypatch.setattr(analyzer, "JSON_MODE", True)
    seen = {}
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": GOOD_JSON}}]}, seen))
    analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert seen["body"]["enable_thinking"] is False
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_json_mode_can_be_turned_off(monkeypatch):
    """老模型/别的中转不认这个字段时，用 NETWATCH_JSON_MODE=0 关掉。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer, "JSON_MODE", False)
    seen = {}
    monkeypatch.setattr(analyzer.urllib.request, "urlopen",
                        _fake_urlopen({"choices": [{"finish_reason": "stop",
                                                    "message": {"content": GOOD_JSON}}]}, seen))
    analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert "response_format" not in seen["body"]


def test_http400_retries_without_response_format(monkeypatch):
    """400 = 中转不认护栏字段 → 去掉该字段重试一次，别让护栏本身变成故障源。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")
    monkeypatch.setattr(analyzer, "JSON_MODE", True)
    sent = []

    def _fake(req, timeout=0):
        sent.append("response_format" in json.loads(req.data.decode("utf-8")))
        if sent[-1]:
            raise urllib.error.HTTPError("u", 400, "Bad Request", {}, io.BytesIO(b"unknown field"))
        return _FakeResp({"choices": [{"finish_reason": "stop", "message": {"content": GOOD_JSON}}]})

    monkeypatch.setattr(analyzer.urllib.request, "urlopen", _fake)
    out = analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert sent == [True, False]
    assert analyzer.parse_analysis(out)["ok"] is True


def test_http400_without_retry_path_raises(monkeypatch):
    """401 这种跟字段无关的错误要原样报出来，不能悄悄重试。"""
    monkeypatch.setenv("NETWATCH_API_KEY", "sk-test")

    def _fake(req, timeout=0):
        raise urllib.error.HTTPError("u", 401, "Unauthorized", {}, io.BytesIO(b"bad key"))

    monkeypatch.setattr(analyzer.urllib.request, "urlopen", _fake)
    with pytest.raises(RuntimeError) as e:
        analyzer.analyze(ABNORMAL, ALL_DEVICES)
    assert "401" in str(e.value)


# ---------------------------------------------------------------- DNS 故障的影响面规则（v0.5）

def _dev(name, checks):
    return {"name": name, "ip": "10.0.0.1", "checks": checks}


DNS_BAD = {"kind": "dns", "target": "x.com", "ok": False, "ms": 3, "detail": "DNS 解析失败"}
ICMP_BAD = {"kind": "icmp", "target": "10.0.0.1", "ok": False, "ms": 1, "detail": "ICMP 不通"}
OK_DEV = {"name": "fine", "ip": "10.0.0.2", "checks": [{"kind": "icmp", "ok": True}]}


def test_dns_failures_uses_structured_checks():
    devs = [_dev("a", [ICMP_BAD, DNS_BAD]), _dev("b", [DNS_BAD]), _dev("c", [ICMP_BAD])]
    assert [d["name"] for d in analyzer.dns_failures(devs)] == ["a", "b"]


def test_dns_failures_tolerates_missing_checks():
    """老数据/假探测结果里没有 checks 字段，不能因此崩掉。"""
    assert analyzer.dns_failures([{"name": "old"}]) == []
    assert analyzer.dns_failures(None) == []


def test_dns_failures_judges_by_kind_not_by_text():
    """只按 kind/ok 判定：改文案不该改变结论。"""
    odd = {"kind": "dns", "target": "x", "ok": False, "ms": 1, "detail": "随便写点什么"}
    assert len(analyzer.dns_failures([_dev("a", [odd])])) == 1


def test_rule_hint_blames_dns_when_dns_failures_dominate():
    devs = [_dev("pc1", [DNS_BAD]), _dev("pc2", [DNS_BAD]), _dev("switch", [ICMP_BAD])]
    text = analyzer.rule_hint(devs, devs + [OK_DEV])
    assert "多台设备 DNS 解析失败" in text
    assert "DNS 服务器" in text and "交换机" in text      # 明确排除「共同上级」这个方向
    assert "共同上级" not in text


def test_rule_hint_single_dns_failure_points_at_resolver():
    devs = [_dev("pc1", [DNS_BAD])]
    text = analyzer.rule_hint(devs, devs + [OK_DEV])
    assert "DNS 解析失败" in text
    assert "该设备自身" not in text                        # 不是设备坏了，是解析不了


def test_rule_hint_total_outage_wins_over_partial_dns():
    """全部设备都异常时，先怀疑上游 —— 别被「其中几台是 DNS 失败」带偏到 DNS 服务器。"""
    devs = [_dev("pc1", [DNS_BAD]), _dev("pc2", [DNS_BAD]), _dev("pc3", [ICMP_BAD])]
    assert "全部设备不可达" in analyzer.rule_hint(devs, devs)


def test_rule_hint_non_dns_multi_still_blames_upstream():
    devs = [_dev("pc1", [ICMP_BAD]), _dev("pc2", [ICMP_BAD])]
    assert "共同上级" in analyzer.rule_hint(devs, devs + [OK_DEV])


def test_dns_fault_type_is_declared_in_prompt():
    """FAULT_TYPES 和提示词里的枚举必须一致（枚举由 FAULT_TYPES 生成）。"""
    assert "DNS 解析异常" in analyzer.FAULT_TYPES
    assert "DNS 解析异常" in analyzer.JSON_INSTRUCTION

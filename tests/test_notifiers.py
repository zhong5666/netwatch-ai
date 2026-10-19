#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""notifiers.py 的离线单测：不连任何真实服务，urlopen 全部用假的注入。"""
from __future__ import annotations

import io
import json
import urllib.error

import pytest

import notifiers as N


# ---------------------------------------------------------------- 配置解析

def test_no_config_means_no_channels():
    """安全默认：没配 notify 就一个渠道都没有（不会误发消息）。"""
    assert N.build_notifiers({}) == []
    assert N.build_notifiers({"notify": {}}) == []
    assert N.build_notifiers({"notify": {"channels": []}}) == []
    assert N.build_notifiers(None) == []


def test_build_webhook_channel():
    chans = N.build_notifiers({"notify": {"channels": [
        {"type": "webhook", "url": "http://127.0.0.1:8898/hook"}]}})
    assert len(chans) == 1
    assert isinstance(chans[0], N.WebhookNotifier)
    assert chans[0].url == "http://127.0.0.1:8898/hook"
    assert "webhook" in chans[0].describe()


def test_unknown_channel_type_is_loud():
    with pytest.raises(N.NotifyConfigError) as e:
        N.build_notifiers({"notify": {"channels": [{"type": "telepathy", "url": "http://x"}]}})
    assert "telepathy" in str(e.value) and "webhook" in str(e.value)   # 报错要列出已支持的渠道


def test_webhook_requires_valid_url():
    with pytest.raises(N.NotifyConfigError):
        N.build_notifiers({"notify": {"channels": [{"type": "webhook"}]}})
    with pytest.raises(N.NotifyConfigError):
        N.build_notifiers({"notify": {"channels": [{"type": "webhook", "url": "ftp://x/hook"}]}})


def test_channels_must_be_list_of_mappings():
    with pytest.raises(N.NotifyConfigError):
        N.build_notifiers({"notify": {"channels": "webhook"}})
    with pytest.raises(N.NotifyConfigError):
        N.build_notifiers({"notify": {"channels": ["webhook"]}})


def test_timeout_from_global_or_channel_and_never_zero():
    """超时按渠道 > 全局 > 默认取值，并且不会出现 0（0 会立刻超时）。"""
    chans = N.build_notifiers({"notify": {"timeout": 9, "channels": [
        {"type": "webhook", "url": "http://x/hook"},
        {"type": "webhook", "url": "http://y/hook", "timeout": 2},
        {"type": "webhook", "url": "http://z/hook", "timeout": "abc"},
    ]}})
    assert [c.timeout for c in chans] == [9, 2, N.NOTIFY_TIMEOUT_DEFAULT]


# ---------------------------------------------------------------- 发送

class FakeResponse(io.BytesIO):
    def __init__(self, status=200):
        super().__init__(b"ok")
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_webhook_posts_json_payload(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["ctype"] = req.get_header("Content-type")
        captured["timeout"] = timeout
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse(200)

    monkeypatch.setattr(N.urllib.request, "urlopen", fake_urlopen)
    chan = N.build_notifiers({"notify": {"channels": [
        {"type": "webhook", "url": "http://127.0.0.1:8898/hook"}]}})[0]
    msg = N.Message(title="T", text="正文", level="warn", summary="S",
                    devices=["a"], ts="2026-10-19 11:00:00")
    note = chan.send(msg)

    assert note == "HTTP 200"
    assert captured["url"] == "http://127.0.0.1:8898/hook"
    assert captured["method"] == "POST"
    assert "application/json" in captured["ctype"]
    assert captured["timeout"] == N.NOTIFY_TIMEOUT_DEFAULT
    # 载荷字段是给外部网关的契约，改这里要同步 README
    assert captured["body"] == {
        "source": "netwatch-ai", "title": "T", "text": "正文", "level": "warn",
        "summary": "S", "devices": ["a"], "ts": "2026-10-19 11:00:00"}


def test_send_all_never_raises_and_retries_once(monkeypatch):
    """渠道挂掉：不抛异常、重试一次、报一行失败，且不影响后面的渠道。"""
    calls = {"bad": 0, "good": 0}

    class Bad(N.Notifier):
        type = "bad"

        def send(self, msg):
            calls["bad"] += 1
            raise OSError("connection refused")

    class Good(N.Notifier):
        type = "good"

        def send(self, msg):
            calls["good"] += 1
            return "HTTP 204"

    lines = N.send_all([Bad(), Good()], N.sample_message("t"))
    assert calls["bad"] == 2                     # 首次 + 重试 1 次
    assert calls["good"] == 1
    assert lines[0].startswith("⚠️ 通知失败") and "connection refused" in lines[0]
    assert lines[1].startswith("✅ 已通知")


def test_send_all_retry_zero_does_not_retry(monkeypatch):
    calls = {"n": 0}

    class Bad(N.Notifier):
        type = "bad"

        def send(self, msg):
            calls["n"] += 1
            raise urllib.error.URLError("boom")

    N.send_all([Bad()], N.sample_message("t"), retry=0)
    assert calls["n"] == 1


def test_send_all_with_no_channels_is_noop():
    assert N.send_all([], N.sample_message("t")) == []


# ---------------------------------------------------------------- 消息构建

def test_build_message_levels_and_summary():
    warn = N.build_message(
        {"new_alerts": [{"name": "local-web", "streak": 2}], "recoveries": []}, "报告", "t")
    assert warn.level == "warn" and warn.devices == ["local-web"]
    # 标题必须带设备名：手机通知栏只看得到标题
    assert "local-web" in warn.title and warn.title.endswith("异常")

    both = N.build_message(
        {"new_alerts": [{"name": "a", "streak": 2}, {"name": "b", "streak": 3}],
         "recoveries": []}, "报告", "t")
    assert "a" in both.title and "b" in both.title and "2 台" in both.title

    rec = N.build_message(
        {"new_alerts": [], "recoveries": [{"name": "nas", "down_minutes": 3}]}, "报告", "t")
    assert rec.level == "recover" and "已恢复在线" not in rec.summary
    assert "中断约 3 分钟" in rec.summary

    info = N.build_message({"new_alerts": [], "recoveries": []}, "报告", "t")
    assert info.level == "info"
    assert info.to_payload()["summary"] == "netwatch-ai 巡检报告"   # 空 summary 回落标题


def test_build_message_recover_under_one_minute():
    rec = N.build_message(
        {"new_alerts": [], "recoveries": [{"name": "nas", "down_minutes": 0}]}, "报告", "t")
    assert "不到 1 分钟" in rec.summary


# ------------------------------------------------- 编排层两道闸门（notify 开关 + 有事才发）

def _stub_netwatch_notify(monkeypatch, sent):
    import netwatch

    monkeypatch.setattr(netwatch.notifiers, "build_notifiers", lambda cfg: [object()])

    def fake_send_all(channels, msg, retry=N.NOTIFY_RETRY):
        sent.append(msg)
        return ["✅ 已通知: webhook http://x/hook (HTTP 200)"]

    monkeypatch.setattr(netwatch.notifiers, "send_all", fake_send_all)
    return netwatch


CFG_OK = {"notify": {"channels": [{"type": "webhook", "url": "http://x/hook"}]}}
DATA_NEWS = {"new_alerts": [{"name": "a", "streak": 2}], "recoveries": [], "has_news": True}
DATA_QUIET = {"new_alerts": [], "recoveries": [], "has_news": False}


def test_notify_requires_flag_then_hints_once(monkeypatch):
    """闸门一：配了渠道但不加 --notify 绝不发送，只在真有事那轮提示一句。"""
    sent = []
    nw = _stub_netwatch_notify(monkeypatch, sent)
    lines = nw._notify_lines(CFG_OK, DATA_NEWS, "报告", "t", enabled=False, news=True)
    assert sent == []
    assert lines and "未加 --notify" in lines[0]
    # 没事的轮次连提示都不打，否则 cron 里每 10 分钟一行噪音
    assert nw._notify_lines(CFG_OK, DATA_QUIET, "报告", "t", enabled=False, news=False) == []


def test_notify_skips_quiet_round(monkeypatch):
    """闸门二：已告警过的轮次不重复推送（通知层和告警去重同一套判断）。"""
    sent = []
    nw = _stub_netwatch_notify(monkeypatch, sent)
    assert nw._notify_lines(CFG_OK, DATA_QUIET, "报告", "t", enabled=True, news=False) == []
    assert sent == []
    # 有事才发，且发出去的就是终端看到的那份报告
    lines = nw._notify_lines(CFG_OK, DATA_NEWS, "报告正文", "t", enabled=True, news=True)
    assert len(sent) == 1 and sent[0].text == "报告正文"
    assert lines[0].startswith("✅ 已通知")


def test_notify_bad_config_is_reported_not_raised(monkeypatch):
    """通知配置写错：报一行、不抛 —— 巡检结论不能被通知配置拖下水。"""
    import netwatch
    lines = netwatch._notify_lines({"notify": {"channels": [{"type": "telepathy"}]}},
                                   DATA_NEWS, "报告", "t", enabled=True, news=True)
    assert lines and lines[0].startswith("⚠️ 通知配置有误")


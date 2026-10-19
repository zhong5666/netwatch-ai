#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""编排层单测：注入假探测函数，全程离线。"""
from pathlib import Path

import pytest

import analyzer
import history
import netwatch
import probes

ROOT = Path(__file__).resolve().parents[1]


def fake_probe_factory(up_hosts):
    """返回一个假探测函数：up_hosts 里的设备在线，其余离线。"""
    # 用 **kwargs 收参数：编排层给探测函数加新参数时（如 dns_timeout），
    # 假探测函数不用跟着改，否则一加参数就红一片。
    def fake_probe(host, checks, **kwargs):
        ok = host in up_hosts
        detail = "ICMP 通 (1ms)" if ok else "ICMP 不通 (rc=1)"
        return ok, detail, [probes.ProbeResult("icmp", host, ok, 1, detail)]
    return fake_probe


@pytest.fixture(autouse=True)
def no_real_traceroute(monkeypatch):
    """单测一律不真跑 traceroute。

    编排层默认开着它（设备一异常就发车），真跑一次要好几秒、还依赖真实网络，
    在 CI 里既慢又不稳。这里统一换成假函数，并把调用记下来给用例断言。
    """
    calls = []

    def fake(host, hops=None, timeout=None, **kwargs):
        calls.append((host, hops, timeout))
        return probes.ProbeResult("traceroute", host, True, 7,
                                  "traceroute: 第 2 跳 10.0.0.1 之后无响应 → 断在内网（假数据）")

    monkeypatch.setattr(probes, "probe_traceroute", fake)
    return calls


def make_cfg(devices, threshold=2):
    return {
        "devices": devices,
        "check": {"down_threshold": threshold, "ping_count": 1, "ping_timeout": 1},
    }


# ---------------------------------------------------------------- 配置

def test_load_config_example():
    cfg = netwatch.load_config(ROOT / "config.example.yaml")
    assert len(cfg["devices"]) >= 3
    names = [d["name"] for d in cfg["devices"]]
    assert "router" in names
    # 多协议写在配置里，原样保留给探测层
    nas = [d for d in cfg["devices"] if d["name"] == "nas"][0]
    assert "tcp:22" in nas["checks"]


def test_state_path_follows_config(tmp_path):
    cfg_path = tmp_path / "sub" / "config.yaml"
    assert netwatch.state_path_for(cfg_path) == (tmp_path / "sub" / ".state.yaml").resolve()


# ---------------------------------------------------------------- 连续离线 / 阈值

def test_streak_and_threshold(tmp_path):
    state = tmp_path / ".state.yaml"
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=2)
    probe = fake_probe_factory(up_hosts=set())

    first = netwatch.run_check(cfg, state, probe=probe)
    assert first["results"][0]["streak"] == 1
    assert first["results"][0]["abnormal"] is False     # 第 1 次离线还不到阈值（抗抖动）

    second = netwatch.run_check(cfg, state, probe=probe)
    assert second["results"][0]["streak"] == 2
    assert second["results"][0]["abnormal"] is True     # 达到阈值 → 异常


def test_recovery_resets_streak(tmp_path):
    state = tmp_path / ".state.yaml"
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=1)

    netwatch.run_check(cfg, state, probe=fake_probe_factory(set()))
    netwatch.run_check(cfg, state, probe=fake_probe_factory(set()))
    back = netwatch.run_check(cfg, state, probe=fake_probe_factory({"10.0.0.9"}))

    assert back["results"][0]["ok"] is True
    assert back["results"][0]["streak"] == 0            # 恢复后计数归零
    assert back["results"][0]["abnormal"] is False


def test_state_is_persisted(tmp_path):
    state = tmp_path / ".state.yaml"
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=1)
    netwatch.run_check(cfg, state, probe=fake_probe_factory(set()))

    saved = netwatch.load_state(state)
    assert saved["dev"]["streak"] == 1
    assert saved["dev"]["last_ok"] is False


def test_result_contains_probe_detail(tmp_path):
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml",
                             probe=fake_probe_factory(set()))
    r = data["results"][0]
    assert "ICMP 不通" in r["detail"]
    assert r["checks"][0]["kind"] == "icmp"             # 明细被序列化成可继续处理的 dict


# ---------------------------------------------------------------- 报告渲染

def test_format_report_abnormal(tmp_path):
    cfg = make_cfg([{"name": "dead", "ip": "192.0.2.1"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml",
                             probe=fake_probe_factory(set()))
    text = netwatch.format_report(data, "2026-10-17 15:00:00")
    assert "⚠️ 发现 1 台异常设备: dead" in text
    assert "192.0.2.1" in text
    assert "└ ICMP 不通" in text                        # 明细行，能看出是哪一层断的


def test_format_report_all_ok(tmp_path):
    cfg = make_cfg([{"name": "alive", "ip": "127.0.0.1"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml",
                             probe=fake_probe_factory({"127.0.0.1"}))
    assert "✅ 全部设备正常" in netwatch.format_report(data, "t")


# ---------------------------------------------------------------- CLI 行为

def test_main_silent_when_all_ok(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: alive\n    ip: 127.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory({"127.0.0.1"}))

    assert netwatch.main(["--config", str(cfg), "--silent-ok"]) == 0
    assert capsys.readouterr().out.strip() == "[SILENT]"     # 正常时不刷消息给用户


def test_main_prints_report_when_abnormal(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: dead\n    ip: 192.0.2.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory(set()))

    assert netwatch.main(["--config", str(cfg), "--silent-ok"]) == 0
    out = capsys.readouterr().out
    assert "异常设备" in out and "dead" in out


def test_main_missing_config(tmp_path, capsys):
    assert netwatch.main(["--config", str(tmp_path / "nope.yaml")]) == 0
    assert "找不到配置文件" in capsys.readouterr().out


def test_main_empty_devices(tmp_path, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices: []\n", encoding="utf-8")
    assert netwatch.main(["--config", str(cfg)]) == 0
    assert "没有任何设备" in capsys.readouterr().out


# ---------------------------------------------------------------- AI 层（不联网）

ALL_UP = [{"name": "a", "ip": "10.0.0.1", "status": "在线", "streak": 0}]
ALL_DOWN = [
    {"name": "a", "ip": "10.0.0.1", "status": "离线", "streak": 3},
    {"name": "b", "ip": "10.0.0.2", "status": "离线", "streak": 3},
]
ONE_DOWN = [
    {"name": "a", "ip": "10.0.0.1", "status": "在线", "streak": 0},
    {"name": "b", "ip": "10.0.0.2", "status": "离线", "streak": 3},
]


def test_rule_hint_full_outage():
    """规则先判断影响面：全网断 = 查上游，不逐台查设备。"""
    assert "全部设备不可达" in analyzer.rule_hint(ALL_DOWN, ALL_DOWN)
    assert "上游/网关" in analyzer.rule_hint(ALL_DOWN, ALL_DOWN)


def test_rule_hint_single_device():
    assert "仅单台设备不可达" in analyzer.rule_hint(ONE_DOWN[1:], ONE_DOWN)


def test_rule_hint_multi_device():
    three = ALL_DOWN + [{"name": "c", "ip": "10.0.0.3", "status": "离线", "streak": 3}]
    assert "多台不可达" in analyzer.rule_hint(three, three + [dict(ALL_UP[0])])


def test_build_prompt_includes_details():
    abnormal = [dict(ONE_DOWN[1], detail="ICMP 通 (12ms) | TCP 22 连不上 (timed out)")]
    prompt = analyzer.build_prompt(abnormal, ONE_DOWN, ts_text="2026-10-17 15:00")
    assert "TCP 22 连不上" in prompt                    # 分层明细进 prompt，AI 才能区分设备失联 vs 服务挂了
    assert "2026-10-17 15:00" in prompt


def test_report_rule_only_without_ai():
    text = analyzer.report(ONE_DOWN[1:], ONE_DOWN, use_ai=False)
    assert "规则判断" in text
    assert "仅单台" in text


def test_analyze_no_abnormal_returns_early():
    assert "无需分析" in analyzer.analyze([], ALL_UP)


# ---------------------------------------------------------------- 告警去重 / 恢复通知

def test_alert_fires_once_per_outage(tmp_path):
    """同一场故障只报第一轮 —— 否则 15 分钟一次的定时任务会把手机刷爆。"""
    state = tmp_path / ".state.yaml"
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=1)
    probe = fake_probe_factory(set())

    first = netwatch.run_check(cfg, state, probe=probe)
    assert [r["name"] for r in first["new_alerts"]] == ["dev"]
    assert first["new_alerts"][0]["event"] == "down"

    second = netwatch.run_check(cfg, state, probe=probe)
    assert second["new_alerts"] == []                 # 还在故障中，但不重复告警
    assert second["recoveries"] == []
    assert second["has_news"] is False
    assert second["results"][0]["abnormal"] is True   # 状态本身照旧是异常


def test_recovery_is_reported_with_downtime(tmp_path):
    """恢复也要主动报一次，并带上中断时长。"""
    state = tmp_path / ".state.yaml"
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=1)
    netwatch.run_check(cfg, state, probe=fake_probe_factory(set()))
    back = netwatch.run_check(cfg, state, probe=fake_probe_factory({"10.0.0.9"}))

    assert [r["name"] for r in back["recoveries"]] == ["dev"]
    assert back["recoveries"][0]["event"] == "up"
    assert back["recoveries"][0]["down_minutes"] is not None    # 中断时长（分钟）
    assert back["new_alerts"] == []
    assert netwatch.load_state(state)["dev"]["alerted"] is False


def test_down_since_survives_mid_outage_rounds(tmp_path):
    """中断起点取「首次探测失败」那一刻，跨过阈值那轮也不重置。"""
    state = tmp_path / ".state.yaml"
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=3)
    probe = fake_probe_factory(set())

    first = netwatch.run_check(cfg, state, probe=probe)
    start = first["results"][0]["down_since"]
    assert start and first["new_alerts"] == []        # 未达阈值，先不报警

    netwatch.run_check(cfg, state, probe=probe)
    third = netwatch.run_check(cfg, state, probe=probe)
    assert third["results"][0]["down_since"] == start  # 没被后一轮覆盖
    assert [r["name"] for r in third["new_alerts"]] == ["dev"]   # 第 3 轮才告警


def test_old_state_file_without_alert_fields(tmp_path):
    """老状态文件（没 alerted/down_since）照样能跑，不会把已故障设备误判成新故障。"""
    state = tmp_path / ".state.yaml"
    state.write_text("dev:\n  streak: 5\n  last_ok: false\n", encoding="utf-8")
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=2)
    data = netwatch.run_check(cfg, state, probe=fake_probe_factory(set()))
    assert data["results"][0]["streak"] == 6
    assert data["new_alerts"] == []                   # 老状态没标记 → 不冒出新告警


def test_format_report_shows_changes(tmp_path):
    cfg = make_cfg([{"name": "dev", "ip": "10.0.0.9"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory(set()))
    text = netwatch.format_report(data, "2026-10-17 15:00:00")
    assert "🔄 本次变化" in text
    assert "新出现异常" in text

    quiet = netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory(set()))
    assert "不重复告警" in netwatch.format_report(quiet, "t")


def test_main_silent_when_no_new_change(tmp_path, monkeypatch, capsys):
    """第一次告警，之后就安静 —— 这是挂 cron 的前提。"""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: dead\n    ip: 192.0.2.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory(set()))

    assert netwatch.main(["--config", str(cfg), "--silent-ok"]) == 0
    assert "异常设备" in capsys.readouterr().out

    assert netwatch.main(["--config", str(cfg), "--silent-ok"]) == 0
    assert capsys.readouterr().out.strip() == "[SILENT]"


def test_main_alert_on_all_repeats_every_round(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: dead\n    ip: 192.0.2.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory(set()))

    for _ in range(2):
        assert netwatch.main(["--config", str(cfg), "--silent-ok", "--alert-on", "all"]) == 0
        assert "异常设备" in capsys.readouterr().out


def test_ai_called_only_for_new_alerts(tmp_path, monkeypatch, capsys):
    """不重复告警也意味着不重复烧 token —— 用户在意成本。"""
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: dead\n    ip: 192.0.2.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory(set()))

    calls = []
    monkeypatch.setattr(netwatch, "analyze",
                        lambda *a, **k: calls.append(a) or "AI 假结论")
    monkeypatch.setattr(netwatch, "rule_hint", lambda *a, **k: "规则假结论")

    netwatch.main(["--config", str(cfg), "--silent-ok", "--ai"])
    assert "AI 假结论" in capsys.readouterr().out
    netwatch.main(["--config", str(cfg), "--silent-ok", "--ai"])
    assert capsys.readouterr().out.strip() == "[SILENT]"

    assert len(calls) == 1                    # 第二轮没再调 AI


def test_main_writes_history_db(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: alive\n    ip: 127.0.0.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory({"127.0.0.1"}))
    netwatch.main(["--config", str(cfg)])

    db = tmp_path / ".history.db"
    assert db.exists()
    with history.open_db(db) as conn:
        assert history.availability(conn)[0]["total"] == 1


def test_history_can_be_disabled(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: alive\n    ip: 127.0.0.1\nhistory:\n  enabled: false\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory({"127.0.0.1"}))
    netwatch.main(["--config", str(cfg)])
    assert not (tmp_path / ".history.db").exists()


def test_main_report_prints_availability(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: alive\n    ip: 127.0.0.1\ncheck:\n  down_threshold: 1\n",
                   encoding="utf-8")
    monkeypatch.setattr(probes, "run_checks", fake_probe_factory({"127.0.0.1"}))
    netwatch.main(["--config", str(cfg)])

    assert netwatch.main(["--config", str(cfg), "--report", "7d"]) == 0
    out = capsys.readouterr().out
    assert "可用率报告" in out
    assert "100.0%" in out


# ---------------------------------------------------------------- 按需 traceroute

def test_traceroute_runs_only_for_abnormal_devices(tmp_path, no_real_traceroute):
    """正常设备零开销：只有跨过阈值的设备才补跑一次 traceroute。"""
    cfg = make_cfg([{"name": "up", "ip": "10.0.0.9"},
                    {"name": "down", "ip": "10.0.0.8"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory({"10.0.0.9"}))

    assert [c[0] for c in no_real_traceroute] == ["10.0.0.8"]
    down = [r for r in data["results"] if r["name"] == "down"][0]
    up = [r for r in data["results"] if r["name"] == "up"][0]
    assert "traceroute: 第 2 跳" in down["detail"]          # 明细里多了一句「断在哪」
    assert "traceroute" not in up["detail"]
    assert [c["kind"] for c in down["checks"]] == ["icmp", "traceroute"]


def test_traceroute_does_not_change_verdict(tmp_path, no_real_traceroute):
    """补充诊断不能反过来影响判定：设备该异常还是异常、该新告警还是新告警。"""
    cfg = make_cfg([{"name": "down", "ip": "10.0.0.8"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory(set()))

    row = data["results"][0]
    assert row["ok"] is False and row["abnormal"] is True
    assert [r["name"] for r in data["new_alerts"]] == ["down"]
    assert [r["name"] for r in data["recoveries"]] == []


def test_traceroute_can_be_turned_off(tmp_path, no_real_traceroute):
    cfg = {"devices": [{"name": "down", "ip": "10.0.0.8"}],
           "check": {"down_threshold": 1, "traceroute": False}}
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory(set()))

    assert no_real_traceroute == []
    assert "traceroute" not in data["results"][0]["detail"]


def test_traceroute_hops_and_timeout_come_from_config(tmp_path, no_real_traceroute):
    cfg = {"devices": [{"name": "down", "ip": "10.0.0.8"}],
           "check": {"down_threshold": 1, "traceroute": "auto",
                     "traceroute_hops": 3, "traceroute_timeout": 0.5}}
    netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory(set()))

    assert no_real_traceroute == [("10.0.0.8", 3, 0.5)]


def test_traceroute_crash_does_not_break_the_round(tmp_path, monkeypatch):
    """护栏不能变故障源：诊断自己炸了，这一轮巡检结论照常出。"""
    def boom(*a, **k):
        raise RuntimeError("诊断脚本写挂了")
    monkeypatch.setattr(probes, "probe_traceroute", boom)

    cfg = make_cfg([{"name": "down", "ip": "10.0.0.8"}], threshold=1)
    data = netwatch.run_check(cfg, tmp_path / ".state.yaml", probe=fake_probe_factory(set()))

    row = data["results"][0]
    assert row["abnormal"] is True
    assert [c["kind"] for c in row["checks"]] == ["icmp"]     # 没有 traceroute 项，但结论照旧


def test_traceroute_only_on_the_alerting_round(tmp_path, no_real_traceroute):
    """常态（--alert-on change）只在新告警那一轮补跑 —— 和「不刷屏」同一时机。

    常年不通的设备每 10 分钟重跑一遍 tracert，一台就 1~11 秒，纯浪费。
    """
    cfg = make_cfg([{"name": "down", "ip": "10.0.0.8"}], threshold=1)
    state = tmp_path / ".state.yaml"
    probe = fake_probe_factory(set())

    netwatch.run_check(cfg, state, probe=probe)          # 第 1 轮：新告警 → 跑
    assert len(no_real_traceroute) == 1
    netwatch.run_check(cfg, state, probe=probe)          # 第 2 轮：已告警过 → 不跑
    assert len(no_real_traceroute) == 1


def test_traceroute_every_round_in_alert_all_mode(tmp_path, no_real_traceroute):
    """人工排查走 --alert-on all：异常设备每轮都给「断在第几跳」，不省这点时间。"""
    cfg = make_cfg([{"name": "down", "ip": "10.0.0.8"}], threshold=1)
    state = tmp_path / ".state.yaml"
    probe = fake_probe_factory(set())

    netwatch.run_check(cfg, state, probe=probe, alert_on="all")
    netwatch.run_check(cfg, state, probe=probe, alert_on="all")
    assert len(no_real_traceroute) == 2


def test_main_report_rejects_bad_period(tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices:\n  - name: alive\n    ip: 127.0.0.1\n", encoding="utf-8")
    assert netwatch.main(["--config", str(cfg), "--report", "上周"]) == 0


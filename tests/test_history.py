#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""历史库单测：临时 SQLite，不碰真实数据。"""
import pytest

import history


def row(device="router", ip="10.0.0.1", ok=True, streak=0, ms=10, ts=None, rtt=1):
    return {"name": device, "ip": ip, "ok": ok, "streak": streak,
            "detail": "ICMP 通 (1ms)" if ok else "ICMP 不通 (rc=1)",
            "checks": [{"kind": "icmp", "target": ip, "ms": ms, "rtt_ms": rtt}]}


def data(*rows):
    return {"results": list(rows)}


# ---------------------------------------------------------------- 时间范围

@pytest.mark.parametrize("text,minutes", [("7d", 7 * 1440), ("24h", 1440), ("30m", 30)])
def test_parse_period(text, minutes):
    assert history.parse_period(text).total_seconds() == minutes * 60


@pytest.mark.parametrize("bad", ["", "7", "d7", "一周", "-3d"])
def test_parse_period_rejects_garbage(bad):
    with pytest.raises(ValueError):
        history.parse_period(bad)


def test_period_bounds():
    from datetime import datetime
    now = datetime(2026, 10, 17, 12, 0, 0)
    since, until = history.period_bounds("24h", now)
    assert since == "2026-10-16 12:00:00"
    assert until == "2026-10-17 12:00:00"


# ---------------------------------------------------------------- 写入

def test_record_and_read_back(tmp_path):
    db = tmp_path / ".history.db"
    with history.open_db(db) as conn:
        assert history.record(conn, data(row()), "2026-10-17 10:00:00") == 1
        stats = history.availability(conn)
    assert stats[0]["total"] == 1
    assert stats[0]["ok_count"] == 1
    assert stats[0]["avg_ms"] == 10


def test_record_empty_results_is_noop(tmp_path):
    with history.open_db(tmp_path / "h.db") as conn:
        assert history.record(conn, {"results": []}, "t") == 0


def test_ms_is_max_of_checks(tmp_path):
    """一台设备多个探测项时，取最慢的一项作为本轮耗时（延迟趋势看瓶颈）。"""
    d = {"name": "nas", "ip": "10.0.0.2", "ok": True, "streak": 0, "detail": "ok",
         "checks": [{"kind": "icmp", "ms": 3}, {"kind": "tcp", "ms": 88}]}
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(d), "2026-10-17 10:00:00")
        assert history.availability(conn)[0]["avg_ms"] == 88


def test_avg_rtt_is_not_wall_clock(tmp_path):
    """墙钟（ping -n 3 ≈ 1 秒）和真实往返必须分家，否则「网络好慢」是自吓。"""
    d = {"name": "router", "ip": "10.0.0.1", "ok": True, "streak": 0, "detail": "ok",
         "checks": [{"kind": "icmp", "ms": 1021, "rtt_ms": 6},
                    {"kind": "tcp", "ms": 88, "rtt_ms": 88}]}
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(d), "2026-10-20 10:00:00")
        st = history.availability(conn)[0]
    assert st["avg_ms"] == 1021        # 墙钟：最慢一项（ICMP 含三个包的等待）
    assert st["avg_rtt_ms"] == 88      # 真实往返：最慢一项的 rtt


def test_timeout_has_no_rtt(tmp_path):
    """超时类失败的耗时是「等超时」，不是延迟 —— 不能进平均 RTT。"""
    d = {"name": "router", "ip": "10.0.0.1", "ok": False, "streak": 1, "detail": "不通",
         "checks": [{"kind": "tcp", "ms": 2000, "rtt_ms": None},
                    {"kind": "icmp", "ms": 2001, "rtt_ms": None}]}
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(d), "2026-10-20 10:00:00")
        st = history.availability(conn)[0]
    assert st["avg_ms"] == 2001
    assert st["avg_rtt_ms"] is None    # 没量到就是 None，别编一个数


def test_traceroute_rtt_is_excluded_too(tmp_path):
    d = {"name": "nas", "ip": "10.0.0.2", "ok": False, "streak": 3, "detail": "不通",
         "checks": [{"kind": "icmp", "ms": 12, "rtt_ms": 4},
                    {"kind": "traceroute", "ms": 5200, "rtt_ms": 5200}]}
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(d), "2026-10-20 10:00:00")
        assert history.availability(conn)[0]["avg_rtt_ms"] == 4


def test_legacy_db_without_rtt_column_is_migrated(tmp_path):
    """v0.8 之前建的库没有 rtt_ms 列：升级后必须自动补列，不能一 INSERT 就炸。"""
    db = tmp_path / "old.db"
    import sqlite3
    conn = sqlite3.connect(str(db))
    conn.executescript(
        "CREATE TABLE checks (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
        " device TEXT NOT NULL, ip TEXT, ok INTEGER NOT NULL, streak INTEGER DEFAULT 0,"
        " ms INTEGER, detail TEXT, items TEXT);")
    conn.execute("INSERT INTO checks (ts, device, ip, ok, streak, ms) VALUES (?,?,?,?,?,?)",
                 ("2026-10-19 10:00:00", "router", "10.0.0.1", 1, 0, 1021))
    conn.commit()
    conn.close()

    with history.open_db(db) as conn:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(checks)")}
        assert "rtt_ms" in cols
        # 老行 rtt_ms 为 NULL：算平均时跳过，不当成 0
        old = history.availability(conn)[0]
        assert old["avg_ms"] == 1021
        assert old["avg_rtt_ms"] is None
        history.record(conn, data(row(ms=9, rtt=3)), "2026-10-20 10:00:00")
        assert history.availability(conn)[0]["avg_rtt_ms"] == 3


def test_traceroute_ms_is_excluded_from_latency(tmp_path):
    """按需诊断的耗时（秒级）不能混进「探测耗时」口径，否则延迟趋势被带偏。"""
    d = {"name": "nas", "ip": "10.0.0.2", "ok": False, "streak": 3, "detail": "不通",
         "checks": [{"kind": "icmp", "ms": 12},
                    {"kind": "traceroute", "ms": 5200}]}
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(d), "2026-10-19 10:00:00")
        assert history.availability(conn)[0]["avg_ms"] == 12


# ---------------------------------------------------------------- 可用率 / 中断

def test_availability_is_ok_ratio(tmp_path):
    with history.open_db(tmp_path / "h.db") as conn:
        for i, ok in enumerate([True, True, False, True]):
            history.record(conn, data(row(ok=ok)), "2026-10-17 10:0%d:00" % i)
        stats = history.availability(conn)[0]
    assert stats["total"] == 4
    assert stats["ok_count"] == 3
    assert stats["availability"] == pytest.approx(75.0)


def test_longest_downtime_run_and_when(tmp_path):
    """最长连续中断按「轮次」算，并记住它从哪一轮开始 —— 业务方最关心这个。"""
    seq = [True, False, False, True, True, False]
    with history.open_db(tmp_path / "h.db") as conn:
        for i, ok in enumerate(seq):
            history.record(conn, data(row(ok=ok)), "2026-10-17 10:0%d:00" % i)
        stats = history.availability(conn)[0]
    assert stats["longest_down"] == 2
    assert stats["longest_down_at"] == "2026-10-17 10:01:00"     # 第一段连续离线
    assert stats["last_ok"] is False                              # 最近一轮的状态


def test_time_window_filters_rows(tmp_path):
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(row(ok=True)), "2026-10-10 10:00:00")   # 窗口外
        history.record(conn, data(row(ok=False)), "2026-10-17 10:00:00")  # 窗口内
        stats = history.availability(conn, "2026-10-16 00:00:00", "2026-10-18 00:00:00")
    assert stats[0]["total"] == 1
    assert stats[0]["availability"] == 0.0


def test_multiple_devices_sorted_by_worst_first(tmp_path):
    with history.open_db(tmp_path / "h.db") as conn:
        for i in range(4):
            history.record(conn, data(row(device="good", ip="10.0.0.1", ok=True),
                                      row(device="bad", ip="10.0.0.2", ok=i % 2 == 0)),
                           "2026-10-17 10:0%d:00" % i)
        stats = history.availability(conn)
    assert [s["device"] for s in stats] == ["bad", "good"]
    assert stats[0]["availability"] == pytest.approx(50.0)


# ---------------------------------------------------------------- 渲染

def test_format_history_report_shows_both_latency_columns(tmp_path):
    """两个数一个列头，且带口径说明 —— 不然读者会把墙钟当延迟。"""
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(row(ms=1021, rtt=6)), "2026-10-20 09:00:00")
        text = history.format_history_report(
            history.availability(conn), "2026-10-19 00:00:00", "2026-10-20 12:00:00")
    assert "探测耗时" in text and "平均RTT" in text
    assert "1021ms" in text
    assert "6ms" in text
    assert "墙钟" in text          # 口径说明必须在报告里，不能只活在 README
    assert "升级前" in text        # 老记录没有 RTT：说明平均值的样本数不等于总轮次


def test_format_history_report_renders_sub_millisecond_rtt(tmp_path):
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(row(ms=1021, rtt=0)), "2026-10-20 09:00:00")
        text = history.format_history_report(
            history.availability(conn), "2026-10-19 00:00:00", "2026-10-20 12:00:00")
    assert "<1ms" in text           # 本地回环 ping 报「<1ms」，别显示成 0ms


def test_format_history_report_table(tmp_path):
    with history.open_db(tmp_path / "h.db") as conn:
        history.record(conn, data(row(device="router", ok=True)), "2026-10-17 09:00:00")
        history.record(conn, data(row(device="router", ok=False)), "2026-10-17 10:00:00")
        text = history.format_history_report(
            history.availability(conn), "2026-10-10 00:00:00", "2026-10-17 12:00:00")
    assert "可用率报告" in text
    assert "router" in text
    assert "50.0%" in text
    assert "最长中断" in text
    assert "⚠️ 可用率低于 99%" in text


def test_format_history_report_all_healthy():
    stats = [{"device": "d", "ip": "10.0.0.1", "total": 10, "ok_count": 10,
              "availability": 100.0, "longest_down": 0, "longest_down_at": None,
              "avg_ms": 5, "avg_rtt_ms": 1, "first_ts": "t", "last_ts": "t",
              "last_ok": True, "last_streak": 0}]
    text = history.format_history_report(stats, "a", "b")
    assert "✅ 所有设备可用率 ≥ 99%" in text


def test_format_history_report_empty_db():
    text = history.format_history_report([], "a", "b")
    assert "没有这段区间的巡检记录" in text
    assert "netwatch.py --once" in text          # 告诉人怎么补数据


# ---------------------------------------------------------------- CLI

def test_cli_report_on_empty_db(tmp_path, capsys):
    assert history.main(["--db", str(tmp_path / "h.db"), "--report", "7d"]) == 0
    assert "没有这段区间的巡检记录" in capsys.readouterr().out


def test_cli_rejects_bad_period(tmp_path, capsys):
    assert history.main(["--db", str(tmp_path / "h.db"), "--report", "一周"]) == 0
    assert "时间范围有误" in capsys.readouterr().out


def test_cli_report_with_fixed_now(tmp_path, capsys):
    db = tmp_path / "h.db"
    with history.open_db(db) as conn:
        history.record(conn, data(row(ok=False)), "2026-10-17 10:00:00")
    assert history.main(["--db", str(db), "--report", "24h",
                         "--now", "2026-10-17 12:00:00"]) == 0
    out = capsys.readouterr().out
    assert "2026-10-16 12:00:00 ~ 2026-10-17 12:00:00" in out
    assert "0.0%" in out

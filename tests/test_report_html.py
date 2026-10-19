#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""report_html.py 单测：临时 SQLite 库，不碰真实 .history.db，不探测任何设备。"""
import sqlite3
from datetime import datetime, timedelta

import history
import netwatch
import report_html


def _seed(db_path, rows):
    """rows: [(ts, device, ip, ok, streak, detail)] —— 直接按行写库，模拟巡检记录。"""
    with history.open_db(db_path) as conn:
        for ts, device, ip, ok, streak, detail in rows:
            history.record(conn, {"results": [{
                "name": device, "ip": ip, "ok": ok, "streak": streak,
                "detail": detail, "checks": [],
            }]}, ts)


def _window_rows(marks, detail="ICMP 不通 (rc=1)"):
    """把一串在线/离线标记铺成最近 N 轮的真实时间戳，保证落在 7d 窗口里。"""
    base = datetime.now() - timedelta(minutes=len(marks))
    rows = []
    for i, ok in enumerate(marks):
        ts = (base + timedelta(minutes=i)).strftime(history.TS_FMT)
        streak = 0
        if not ok:
            # streak 的口径是「连续」离线次数（netwatch 恢复后会归零重数），
            # 所以只往回数到第一个在线轮次为止
            streak = 1
            for m in reversed(marks[:i]):
                if m:
                    break
                streak += 1
        rows.append((ts, "dev-a", "10.0.0.1", ok, streak, detail if not ok else "ICMP 通 (5ms)"))
    return rows


# ---------------------------------------------------------------- 取数层

def test_outages_splits_into_segments(tmp_path):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, False, False, True, False]))
    with history.open_db(db) as conn:
        segs = report_html.outages(conn)
    assert len(segs) == 2, "两段离线必须切成两段，不能并成一段"
    assert (segs[0]["rounds"], segs[1]["rounds"]) == (2, 1)
    assert segs[0]["start"] < segs[0]["end"], "起止时间要分开取（起点才有排查价值）"
    assert segs[1]["start"] == segs[1]["end"], "单轮中断起止相同"


def test_outages_separate_by_device(tmp_path):
    db = tmp_path / ".history.db"
    ts = datetime.now().strftime(history.TS_FMT)
    _seed(db, [
        (ts, "dev-a", "10.0.0.1", False, 1, "a 断"),
        (ts, "dev-b", "10.0.0.2", False, 1, "b 断"),
    ])
    with history.open_db(db) as conn:
        segs = report_html.outages(conn)
    assert [s["device"] for s in segs] == ["dev-a", "dev-b"]


def test_outage_detail_keeps_first_line_only(tmp_path):
    db = tmp_path / ".history.db"
    long_line = "很长的明细" * 40
    rows = _window_rows([False], detail=long_line + "\n第二行不该出现")
    _seed(db, rows)
    with history.open_db(db) as conn:
        seg = report_html.outages(conn)[0]
    assert "第二行" not in seg["detail"]
    assert seg["detail"].endswith("…"), "超长明细要截断并留省略号"
    assert len(seg["detail"]) <= report_html.DETAIL_MAX + 1


def test_timeline_keeps_last_n_rounds(tmp_path):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, True, False, True, True]))
    with history.open_db(db) as conn:
        series = report_html.timeline(conn, limit=3)
    assert series["dev-a"] == [False, True, True], "只保留最近 3 轮，且顺序是时间正序"


# ---------------------------------------------------------------- 渲染层

def test_render_escapes_untrusted_text(tmp_path):
    db = tmp_path / ".history.db"
    evil = '<script>alert("x")</script> & "引号"'
    _seed(db, _window_rows([False], detail=evil))
    html_text = report_html.build_html(db, "7d")
    assert "<script>alert" not in html_text, "明细里的脚本标签必须被转义"
    assert "&lt;script&gt;" in html_text
    assert "&amp;" in html_text


def test_page_keeps_local_absolute_paths_out(tmp_path):
    """报告是给人看、可能被提交进仓库的：本机绝对路径（含用户名）不能出现在页面上。"""
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, False]))
    html_text = report_html.build_html(db, "7d")
    for leak in ("C:\\", "D:\\", "/home/", "/Users/", str(tmp_path)):
        assert leak not in html_text, "页面里漏出了本机路径：%s" % leak
    assert "数据源：<code>.history.db</code>" in html_text


def test_render_has_no_external_assets(tmp_path):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, False]))
    html_text = report_html.build_html(db, "7d")
    for bad in ("http://", "https://", "<script", "<link"):
        assert bad not in html_text, "报告必须自包含且无脚本：%s" % bad


def test_render_counts_segments_and_devices(tmp_path):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, False, False, True, False]))
    html_text = report_html.build_html(db, "7d")
    assert "<b>1</b><span>设备</span>" in html_text
    assert "<b>2</b><span>中断段</span>" in html_text
    assert "40.0%" in html_text, "2/5 在线 = 40.0%"


def test_render_lists_more_than_max_segments_as_a_count(tmp_path):
    marks = []
    for _ in range(report_html.OUTAGE_MAX + 3):
        marks += [True, False]          # 12 段中断
    db = tmp_path / ".history.db"
    _seed(db, _window_rows(marks))
    html_text = report_html.build_html(db, "7d")
    assert "另有 3 段中断未列出" in html_text


def test_empty_db_gives_hint_not_crash(tmp_path):
    db = tmp_path / ".history.db"
    with history.open_db(db):          # 建库但不写数据
        pass
    html_text = report_html.build_html(db, "7d")
    assert html_text.startswith("<!doctype html>")
    assert "库里没有这段区间的巡检记录" in html_text
    assert "netwatch.py --once" in html_text


def test_rows_outside_window_are_ignored(tmp_path):
    db = tmp_path / ".history.db"
    _seed(db, [("2020-01-01 00:00:00", "dev-a", "10.0.0.1", False, 1, "旧数据")])
    html_text = report_html.build_html(db, "7d")
    assert "dev-a" not in html_text, "窗口外的老数据不该出现在报告里"


# ---------------------------------------------------------------- 入口层

def test_cli_writes_file(tmp_path, capsys):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, False]))
    out = tmp_path / "sub" / "report.html"      # 顺带验证会自动建目录
    assert report_html.main(["--db", str(db), "--report", "7d", "--out", str(out)]) == 0
    assert out.exists()
    assert "HTML 报告已写入" in capsys.readouterr().out
    assert "dev-a" in out.read_text(encoding="utf-8")


def test_cli_rejects_bad_period(tmp_path, capsys):
    db = tmp_path / ".history.db"
    with history.open_db(db):
        pass
    out = tmp_path / "report.html"
    assert report_html.main(["--db", str(db), "--report", "7x", "--out", str(out)]) == 0
    assert "时间范围有误" in capsys.readouterr().out
    assert not out.exists(), "参数不合法就不该落一个半成品文件"


def test_netwatch_html_flag_writes_report_and_keeps_terminal_report(tmp_path, capsys):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, False]))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices: []\n", encoding="utf-8")
    out = tmp_path / "report.html"
    code = netwatch.main(["--config", str(cfg), "--report", "7d", "--html", str(out)])
    printed = capsys.readouterr().out
    assert code == 0
    assert "可用率报告" in printed, "终端报告照旧打印"
    assert "HTML 报告已写入" in printed
    assert out.exists() and "dev-a" in out.read_text(encoding="utf-8")


def test_netwatch_html_defaults_to_7d_window(tmp_path, capsys):
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True, True]))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices: []\n", encoding="utf-8")
    out = tmp_path / "report.html"
    assert netwatch.main(["--config", str(cfg), "--html", str(out)]) == 0
    assert "dev-a" in out.read_text(encoding="utf-8")


def test_netwatch_html_bad_period_does_not_write_file(tmp_path, capsys):
    db = tmp_path / ".history.db"
    with history.open_db(db):
        pass
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices: []\n", encoding="utf-8")
    out = tmp_path / "report.html"
    assert netwatch.main(["--config", str(cfg), "--report", "7x", "--html", str(out)]) == 0
    assert "时间范围有误" in capsys.readouterr().out
    assert not out.exists()


def test_netwatch_html_degrades_when_module_missing(tmp_path, capsys, monkeypatch):
    """report_html 缺失时只少一份 HTML，终端报告照旧 —— 不能反过来把报告带崩。"""
    db = tmp_path / ".history.db"
    _seed(db, _window_rows([True]))
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices: []\n", encoding="utf-8")
    out = tmp_path / "report.html"
    monkeypatch.setattr(netwatch, "report_html", None)
    assert netwatch.main(["--config", str(cfg), "--report", "7d", "--html", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "report_html.py 不可用" in printed
    assert "可用率报告" in printed
    assert not out.exists()


def test_netwatch_html_survives_broken_db(tmp_path, capsys):
    """库被写坏（不是 sqlite 格式）时给一行说明就行，退出码仍为 0。"""
    db = tmp_path / ".history.db"
    db.write_bytes(b"not a sqlite file at all")
    cfg = tmp_path / "config.yaml"
    cfg.write_text("devices: []\n", encoding="utf-8")
    out = tmp_path / "report.html"
    assert netwatch.main(["--config", str(cfg), "--report", "7d", "--html", str(out)]) == 0
    printed = capsys.readouterr().out
    assert "HTTP" not in printed
    assert not out.exists()

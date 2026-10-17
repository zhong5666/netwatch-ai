#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""巡检历史库：每轮探测结果落 SQLite，用来算可用率 / 中断时长 / 延迟趋势。

为什么是 SQLite：单文件、零依赖（标准库 sqlite3）、不占常驻内存 ——
巡检进程跑完即退，不开后台服务，不给用户的游戏帧率添麻烦。

用法（一般不直接调，走 netwatch.py --report）：
    python history.py --db .history.db --report 7d
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta

TS_FMT = "%Y-%m-%d %H:%M:%S"

SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT    NOT NULL,          -- 本轮巡检时间
    device TEXT    NOT NULL,
    ip     TEXT    NOT NULL,
    ok     INTEGER NOT NULL,          -- 1 在线 / 0 离线
    streak INTEGER NOT NULL,          -- 本轮连续离线次数
    ms     INTEGER,                   -- 本轮最慢单项探测耗时(毫秒)
    detail TEXT,                      -- 分层明细
    items  TEXT                       -- 每项探测的 JSON
);
CREATE INDEX IF NOT EXISTS idx_checks_device_ts ON checks (device, ts);
"""


# ---------------------------------------------------------------- 建库 / 写入

def connect(db_path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


@contextmanager
def open_db(db_path):
    """用完就关 —— Windows 上没关的连接会挡住临时目录清理。"""
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def record(conn: sqlite3.Connection, data: dict, ts: str) -> int:
    """把一轮巡检结果写库，返回写入行数。"""
    rows = []
    for r in data.get("results") or []:
        items = r.get("checks") or []
        ms = max([int(i.get("ms") or 0) for i in items], default=0) or None
        rows.append((
            ts, r["name"], r["ip"], 1 if r["ok"] else 0, int(r["streak"]),
            ms, r.get("detail"), json.dumps(items, ensure_ascii=False),
        ))
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO checks (ts, device, ip, ok, streak, ms, detail, items)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    return len(rows)


# ---------------------------------------------------------------- 时间范围

_PERIOD_RE = re.compile(r"^(\d+)\s*([dhm])$")
_PERIOD_UNIT = {"d": "days", "h": "hours", "m": "minutes"}


def parse_period(text: str) -> timedelta:
    """把 '7d' / '24h' / '30m' 解析成时间跨度（单测直接断言）。"""
    m = _PERIOD_RE.match(str(text).strip().lower())
    if not m:
        raise ValueError("时间范围写法：7d / 24h / 30m（d=天 h=小时 m=分钟）")
    n, unit = int(m.group(1)), m.group(2)
    return timedelta(**{_PERIOD_UNIT[unit]: n})


def period_bounds(text: str, now: datetime | None = None) -> tuple:
    """返回 (since, until) 两个 ts 字符串。"""
    now = now or datetime.now()
    since = now - parse_period(text)
    return since.strftime(TS_FMT), now.strftime(TS_FMT)


# ---------------------------------------------------------------- 统计

def _parse_ts(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, TS_FMT)
    except (TypeError, ValueError):
        return None


def availability(conn: sqlite3.Connection, since: str | None = None,
                 until: str | None = None) -> list:
    """按设备统计：可用率、最长连续中断、平均探测耗时。

    可用率 = 在线轮次 / 总轮次。连续中断按巡检轮次算（而不是分钟），
    因为巡检间隔由用户的定时任务决定，用轮次才不会误导。
    """
    sql = "SELECT * FROM checks WHERE 1 = 1"
    args: list = []
    if since:
        sql += " AND ts >= ?"
        args.append(since)
    if until:
        sql += " AND ts <= ?"
        args.append(until)
    sql += " ORDER BY device, ts, id"
    rows = conn.execute(sql, args).fetchall()

    stats: dict = {}
    for row in rows:
        st = stats.setdefault(row["device"], {
            "device": row["device"], "ip": row["ip"], "total": 0, "ok_count": 0,
            "down_run": 0, "run_start": None, "longest_down": 0, "longest_down_at": None,
            "ms_sum": 0, "ms_n": 0, "first_ts": row["ts"], "last_ts": None,
            "last_ok": None, "last_streak": 0,
        })
        st["ip"] = row["ip"]
        st["total"] += 1
        st["last_ts"] = row["ts"]
        st["last_ok"] = bool(row["ok"])
        st["last_streak"] = row["streak"]
        if row["ms"]:
            st["ms_sum"] += int(row["ms"])
            st["ms_n"] += 1
        if row["ok"]:
            st["ok_count"] += 1
            st["down_run"] = 0
            st["run_start"] = None
        else:
            # 记住这段连续离线是从哪一轮开始的（报告里显示起点，比显示结束点有用）
            if st["down_run"] == 0:
                st["run_start"] = row["ts"]
            st["down_run"] += 1
            if st["down_run"] > st["longest_down"]:
                st["longest_down"] = st["down_run"]
                st["longest_down_at"] = st["run_start"]

    out = []
    for st in stats.values():
        total = st["total"] or 1
        out.append({
            "device": st["device"], "ip": st["ip"],
            "total": st["total"], "ok_count": st["ok_count"],
            "availability": st["ok_count"] * 100.0 / total,
            "longest_down": st["longest_down"], "longest_down_at": st["longest_down_at"],
            "avg_ms": int(st["ms_sum"] / st["ms_n"]) if st["ms_n"] else None,
            "first_ts": st["first_ts"], "last_ts": st["last_ts"],
            "last_ok": st["last_ok"], "last_streak": st["last_streak"],
        })
    # 可用率低的排前面，一眼看到最该关注的设备
    out.sort(key=lambda s: (s["availability"], -s["longest_down"]))
    return out


def format_history_report(stats: list, since: str, until: str) -> str:
    head = "=== netwatch-ai 可用率报告 (%s ~ %s) ===" % (since, until)
    if not stats:
        return "\n".join([
            head, "",
            "库里没有这段区间的巡检记录。",
            "先跑一轮巡检写入数据：python netwatch.py --once",
        ])

    w_dev = max([len(s["device"]) for s in stats] + [4]) + 2
    w_ip = max([len(s["ip"]) for s in stats] + [4]) + 2
    lines = [head, ""]
    lines.append("%-*s %-*s %6s %8s %10s %14s" % (
        w_dev, "设备", w_ip, "地址", "轮次", "可用率", "最长中断", "平均探测"))
    lines.append("-" * (w_dev + w_ip + 44))
    for s in stats:
        longest = "%d 轮" % s["longest_down"]
        if s["longest_down_at"]:
            longest += " 起%s" % s["longest_down_at"][5:16]
        avg = "%dms" % s["avg_ms"] if s["avg_ms"] else "-"
        lines.append("%-*s %-*s %6d %7.1f%% %10s %14s" % (
            w_dev, s["device"], w_ip, s["ip"], s["total"],
            s["availability"], longest, avg))

    bad = [s for s in stats if s["availability"] < 99.0]
    lines.append("")
    if bad:
        lines.append("⚠️ 可用率低于 99%% 的设备 %d 台：%s" % (
            len(bad), ", ".join("%s(%.1f%%)" % (s["device"], s["availability"]) for s in bad)))
    else:
        lines.append("✅ 所有设备可用率 ≥ 99%")
    return "\n".join(lines)


# ---------------------------------------------------------------- 独立入口

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="netwatch-ai 历史库")
    parser.add_argument("--db", default=".history.db", help="SQLite 文件路径")
    parser.add_argument("--report", default="7d", help="统计范围：7d / 24h / 30m")
    parser.add_argument("--now", default=None,
                        help="覆盖当前时间（测试用，格式 %s）" % TS_FMT)
    args = parser.parse_args(argv)

    now = _parse_ts(args.now) if args.now else datetime.now()
    try:
        since, until = period_bounds(args.report, now)
    except ValueError as e:
        print("时间范围有误：%s" % e)
        return 0

    with open_db(args.db) as conn:
        stats = availability(conn, since, until)
    print(format_history_report(stats, since, until))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

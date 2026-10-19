#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把巡检历史库渲染成一个自包含的静态 HTML 报告（双击即看，零常驻、零依赖）。

为什么是「静态文件」而不是「Web 面板服务」：
    用户机器上打游戏在意帧率，任何常驻进程/端口都是负担。静态文件跑完即退，
    Python 只看这一次，浏览器打开时也不占本机资源；还能直接发给别人（面试/交接）。
    样式与图形全部内联（CSS + 方块条），不引任何 CDN —— 断网也能看。

用法（一般不直接调，走 netwatch.py --html report.html）：
    python report_html.py --db .history.db --report 7d --out report.html
"""
from __future__ import annotations

import argparse
from datetime import datetime
from html import escape
from pathlib import Path

import history

# 明细太长会把表格拉爆，截断到一行以内（省略号本身也说明「还有下文」）
DETAIL_MAX = 120
# 时序方块条最多画多少轮（185 轮全画会又长又糊，只画最近这些轮）
TIMELINE_MAX = 120
# 每台设备最多列几段中断（剩下的只报个数，别把页面变成日志海）
OUTAGE_MAX = 10


# ---------------------------------------------------------------- 取数

def outages(conn, since: str | None = None, until: str | None = None) -> list:
    """按设备切出**全部**连续离线段（不只是最长的那一段）。

    终端报告只给「最长中断」，排查时想知道的是「断过几次、每次从几点到几点」——
    这正是 HTML 报告相对终端报告的增量。
    """
    sql = "SELECT device, ip, ts, ok, streak, detail FROM checks WHERE ok = 0"
    args: list = []
    if since:
        sql += " AND ts >= ?"
        args.append(since)
    if until:
        sql += " AND ts <= ?"
        args.append(until)
    sql += " ORDER BY device, ts, id"

    segs: list = []
    cur = None
    for row in conn.execute(sql, args):
        # 中间夹着的「已恢复」轮次在 ok=0 的过滤结果里是看不见的，
        # 所以断点只能靠 streak 认：streak 归 1 = 这一段连续离线刚开始。
        fresh = int(row["streak"] or 0) <= 1
        if cur is None or cur["device"] != row["device"] or fresh:
            cur = {
                "device": row["device"], "ip": row["ip"],
                "start": row["ts"], "end": row["ts"], "rounds": 0, "streak": 0,
                "detail": _first_line(row["detail"]),
            }
            segs.append(cur)
        cur["end"] = row["ts"]
        cur["rounds"] += 1
        cur["streak"] = max(cur["streak"], int(row["streak"] or 0))
    return segs


def timeline(conn, since: str | None = None, until: str | None = None,
             limit: int = TIMELINE_MAX) -> dict:
    """每台设备最近 limit 轮的在线/离线序列，画成方块条（一眼看出「断得多碎」）。"""
    sql = "SELECT device, ok FROM checks WHERE 1 = 1"
    args: list = []
    if since:
        sql += " AND ts >= ?"
        args.append(since)
    if until:
        sql += " AND ts <= ?"
        args.append(until)
    sql += " ORDER BY device, ts, id"
    series: dict = {}
    for row in conn.execute(sql, args):
        series.setdefault(row["device"], []).append(bool(row["ok"]))
    return {dev: marks[-limit:] for dev, marks in series.items()}


def collect(db_path, since: str, until: str) -> tuple:
    """一次开库取回（可用率统计, 中断段, 时序条）三份数据 —— 用完就关。"""
    with history.open_db(db_path) as conn:
        stats = history.availability(conn, since, until)
        segs = outages(conn, since, until)
        series = timeline(conn, since, until)
    return stats, segs, series


def _first_line(detail) -> str:
    lines = str(detail or "").strip().splitlines()
    first = lines[0].strip() if lines else ""
    if len(first) > DETAIL_MAX:
        first = first[:DETAIL_MAX].rstrip() + "…"
    return first


# ---------------------------------------------------------------- 渲染

_CSS = """
:root { color-scheme: light dark; --fg:#1b1f24; --muted:#6b7280; --bg:#ffffff;
  --card:#f7f8fa; --line:#e5e7eb; --ok:#16a34a; --bad:#dc2626; --warn:#d97706; }
@media (prefers-color-scheme: dark) {
  :root { --fg:#e6e8eb; --muted:#9aa4b2; --bg:#14171a; --card:#1c2024;
    --line:#2c3137; --ok:#4ade80; --bad:#f87171; --warn:#fbbf24; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px; background:var(--bg); color:var(--fg);
  font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",Roboto,sans-serif; }
h1 { font-size:22px; margin:0 0 4px; }
h2 { font-size:16px; margin:0 0 10px; }
.sub { color:var(--muted); font-size:13px; margin-bottom:20px; }
.cards { display:flex; flex-wrap:wrap; gap:12px; margin-bottom:24px; }
.kpi { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:10px 16px; min-width:110px; }
.kpi b { display:block; font-size:22px; }
.kpi span { color:var(--muted); font-size:12px; }
section { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:16px 18px; margin-bottom:18px; }
table { width:100%; border-collapse:collapse; font-size:14px; }
th,td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; font-size:12.5px; }
tr:last-child td { border-bottom:none; }
td.num { font-variant-numeric:tabular-nums; white-space:nowrap; }
.badge { padding:1px 8px; border-radius:999px; font-size:12px; border:1px solid; }
.b-ok { color:var(--ok); border-color:var(--ok); }
.b-bad { color:var(--bad); border-color:var(--bad); }
.b-warn { color:var(--warn); border-color:var(--warn); }
.bar { background:var(--line); border-radius:4px; height:8px; width:130px; overflow:hidden; }
.bar i { display:block; height:100%; background:var(--ok); }
.bar i.low { background:var(--bad); }
.bar i.mid { background:var(--warn); }
.strip { display:flex; flex-wrap:wrap; gap:2px; margin:8px 0 6px; }
.strip i { width:6px; height:14px; border-radius:2px; background:var(--ok); }
.strip i.down { background:var(--bad); }
.dev-head { display:flex; align-items:baseline; gap:10px; margin-bottom:2px; }
.dev-head .ip { color:var(--muted); font-size:13px; }
.hint { color:var(--muted); font-size:13px; margin-top:6px; }
footer { color:var(--muted); font-size:12.5px; margin-top:22px; }
code { background:rgba(127,127,127,.14); padding:1px 5px; border-radius:4px; }
"""

_NUM = ' class="num"'          # 数字列右对齐口径一致
_TH_STYLE = ' style="width:170px"'


def _pct(value: float) -> str:
    return "%.1f%%" % value


def _badge(value: float) -> str:
    if value >= 99.99:
        return '<span class="badge b-ok">正常</span>'
    if value < 99.0:
        return '<span class="badge b-bad">异常</span>'
    return '<span class="badge b-warn">抖动</span>'


def _bar(value: float) -> str:
    cls = "low" if value < 99.0 else ("mid" if value < 99.99 else "")
    return '<div class="bar"><i class="%s" style="width:%.1f%%"></i></div>' % (
        cls, max(0.0, min(100.0, value)))


def _longest(s: dict) -> str:
    if not s["longest_down"]:
        return "-"
    text = "%d 轮" % s["longest_down"]
    if s["longest_down_at"]:
        text += " 起 %s" % s["longest_down_at"][5:16]
    return text


def _summary_table(stats: list) -> str:
    head = ('<tr><th>设备</th><th>地址</th><th>轮次</th><th>可用率</th><th></th>'
            '<th>最长中断</th><th>平均探测</th><th>状态</th></tr>')
    body = []
    for s in stats:
        avg = "%dms" % s["avg_ms"] if s["avg_ms"] else "-"
        body.append(
            "<tr><td>%s</td><td%s>%s</td><td%s>%d</td><td%s>%s</td><td>%s</td>"
            "<td%s>%s</td><td%s>%s</td><td>%s</td></tr>" % (
                escape(str(s["device"])), _NUM, escape(str(s["ip"])),
                _NUM, s["total"], _NUM, _pct(s["availability"]),
                _bar(s["availability"]), _NUM, escape(_longest(s)),
                _NUM, escape(avg), _badge(s["availability"])))
    return "<table>%s%s</table>" % (head, "".join(body))


def _timeline_html(marks: list) -> str:
    blocks = "".join('<i class="%s" title="%s"></i>' % (
        "" if ok else "down", "在线" if ok else "离线") for ok in marks)
    note = "（只画最近 %d 轮）" % TIMELINE_MAX if len(marks) >= TIMELINE_MAX else ""
    return ('<div class="strip">%s</div>'
            '<div class="hint">最近 %d 轮时序%s，红块 = 离线</div>' % (
                blocks, len(marks), note))


def _outage_html(segs: list) -> str:
    if not segs:
        return '<div class="hint">这段区间内没有中断记录 ✅</div>'
    rows = []
    for seg in segs[:OUTAGE_MAX]:
        detail = ('<br><span class="hint">%s</span>' % escape(seg["detail"])
                  if seg["detail"] else "")
        rows.append("<tr><td%s>%s</td><td%s>%s</td><td%s>%d 轮</td>"
                    "<td>streak=%d%s</td></tr>" % (
                        _NUM, escape(str(seg["start"])[5:16]),
                        _NUM, escape(str(seg["end"])[5:16]),
                        _NUM, seg["rounds"], seg["streak"], detail))
    more = ""
    if len(segs) > OUTAGE_MAX:
        more = '<div class="hint">另有 %d 段中断未列出。</div>' % (len(segs) - OUTAGE_MAX)
    return ('<table><tr><th>开始</th><th>结束</th><th>持续</th><th>首条明细</th></tr>'
            "%s</table>%s" % ("".join(rows), more))


def _device_card(s: dict, marks: list, segs: list) -> str:
    return (
        '<section><div class="dev-head"><h2>%s</h2><span class="ip">%s</span>%s</div>'
        '<div class="sub">可用率 %s（在线 %d / %d 轮）· 最长中断 %s</div>%s%s</section>' % (
            escape(str(s["device"])), escape(str(s["ip"])), _badge(s["availability"]),
            _pct(s["availability"]), s["ok_count"], s["total"], escape(_longest(s)),
            _timeline_html(marks) if marks else "",
            _outage_html(segs)))


def _page(title: str, subtitle: str, body: str) -> str:
    return ("<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
            "<title>%s</title>\n<style>%s</style>\n</head>\n<body>\n"
            "<h1>%s</h1>\n<div class=\"sub\">%s</div>\n%s\n"
            "<footer>由 netwatch-ai 生成：静态文件，<b>无服务、无外链、不联网</b>；"
            "跑完即退，不给本机添任何常驻开销。真实报告含内网地址，公开前先确认。</footer>\n"
            "</body>\n</html>\n" % (escape(title), _CSS, escape(title), subtitle, body))


def render(stats: list, segs: list, series: dict, since: str, until: str,
           generated: str, source: str = "") -> str:
    """拼出整页 HTML。库里来的文本一律过 escape()（明细里可能有 `<` 或引号）。"""
    head = "%s ~ %s · 生成于 %s" % (since, until, generated)
    if not stats:
        return _page("netwatch-ai 可用率报告",
                     escape(head),
                     "<section>库里没有这段区间的巡检记录。<br>"
                     "先跑一轮巡检写入数据：<code>python netwatch.py --once</code>"
                     "</section>")

    bad = [s for s in stats if s["availability"] < 99.0]
    kpis = [
        ("%d" % len(stats), "设备"),
        ("%d" % len(bad), "可用率 &lt;99%"),
        ("%d" % sum(1 for s in stats if s["availability"] >= 99.99), "全程在线"),
        ("%d" % len(segs), "中断段"),
    ]
    kpi_html = "".join('<div class="kpi"><b>%s</b><span>%s</span></div>' % (v, k)
                       for v, k in kpis)

    by_dev: dict = {}
    for seg in segs:
        by_dev.setdefault(seg["device"], []).append(seg)
    cards = "".join(_device_card(s, series.get(s["device"], []), by_dev.get(s["device"], []))
                    for s in stats)

    if bad:
        summary = "⚠️ 可用率低于 99%% 的设备 %d 台：%s" % (
            len(bad), escape(", ".join("%s(%s)" % (s["device"], _pct(s["availability"]))
                                       for s in bad)))
    else:
        summary = "✅ 所有设备可用率 ≥ 99%"

    src = "<br>数据源：<code>%s</code>" % escape(source) if source else ""
    body = ('<div class="cards">%s</div>\n'
            '<section><h2>概览</h2>%s<div class="hint">%s</div></section>\n%s' % (
                kpi_html, _summary_table(stats), summary, cards))
    return _page("netwatch-ai 可用率报告", escape(head) + src, body)


def build_html(db_path, period: str = "7d", generated: datetime | None = None) -> str:
    """读库 → 出整页 HTML 字符串（不写文件，方便单测与复用）。"""
    now = generated or datetime.now()
    since, until = history.period_bounds(period, now)
    stats, segs, series = collect(db_path, since, until)
    return render(stats, segs, series, since, until, now.strftime(history.TS_FMT),
                  source=Path(db_path).name)


# ---------------------------------------------------------------- 独立入口

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="netwatch-ai 静态 HTML 报告")
    parser.add_argument("--db", default=".history.db", help="SQLite 文件路径")
    parser.add_argument("--report", default="7d", help="统计范围：7d / 24h / 30m")
    parser.add_argument("--out", default="report.html", help="输出的 HTML 路径")
    args = parser.parse_args(argv)

    try:
        html_text = build_html(args.db, args.report)
    except ValueError as e:
        print("时间范围有误：%s" % e)
        return 0

    path = Path(args.out)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_text, encoding="utf-8", newline="\n")
    print("HTML 报告已写入 %s（%d 字符，双击即可看，无需服务）" % (path, len(html_text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

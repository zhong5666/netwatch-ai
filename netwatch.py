#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""netwatch-ai 巡检编排层：读配置 → 逐台探测 → 判定异常 → 变化告警 → 可选 AI 分析。

分层：
    probes.py    探测层（ICMP / TCP / HTTP，跨平台）
    netwatch.py  编排层（设备清单、连续离线计数、告警去重、报告渲染）
    analyzer.py  AI 层（把异常交给大模型判断根因，规则先行）
    notifiers.py 通知层（把结论推到 webhook 等渠道，插件化，失败不影响巡检）
    history.py   历史层（SQLite 落库，算可用率 / 中断时长 / 延迟趋势）

用法：
    python netwatch.py                                  # 跑一轮并打印报告
    python netwatch.py --config demo/config.demo.yaml   # 指定配置（演示）
    python netwatch.py --ai                             # 异常时调 AI 分析
    python netwatch.py --silent-ok                      # 无新变化只输出 [SILENT]（给定时任务用）
    python netwatch.py --alert-on all                   # 每次都告警（默认 change：只在变化时告警）
    python netwatch.py --report 7d                      # 不探测，只看最近 7 天可用率报告
    python netwatch.py --notify                         # 告警时按配置推送（需 notify.channels）
    python netwatch.py --test-notify                    # 发一条样例消息，自检通知渠道

退出码：始终为 0（是否异常写在输出里）；定时任务靠 --silent-ok 的 [SILENT] 约定抑制投递。
"""
from __future__ import annotations

import argparse
import time
import sqlite3
from datetime import datetime
from pathlib import Path

import yaml

import probes

try:
    from analyzer import analyze, rule_hint, parse_analysis, render_card
except ImportError:          # 没配 AI 也能靠纯规则跑巡检
    analyze = None
    rule_hint = None
    parse_analysis = None
    render_card = None

try:
    import history
except ImportError:          # 历史库缺失不影响巡检本身
    history = None

try:
    import notifiers
except ImportError:          # 通知层缺失不影响巡检本身（报告照常打印）
    notifiers = None

try:
    import report_html
except ImportError:          # HTML 报告缺失只是少一种输出形态，报告本身照常打印
    report_html = None

DEFAULT_CONFIG = "config.yaml"
REVIEW_DEFAULT_PERIOD = "7d"      # --html 单独用时（没给 --report）默认统计范围
TS_FMT = "%Y-%m-%d %H:%M:%S"


# ---------------------------------------------------------------- 配置与状态

def load_config(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def state_path_for(config_path) -> Path:
    """状态文件跟着配置文件走 —— 一份配置一套状态，演示配置不会污染真实巡检。"""
    return Path(config_path).resolve().parent / ".state.yaml"


def history_path_for(config_path, cfg: dict | None = None) -> Path:
    """历史库路径：可在配置里改，默认跟状态文件放一起。"""
    cfg = cfg or {}
    name = ((cfg.get("history") or {}).get("db")) or ".history.db"
    p = Path(name)
    return p if p.is_absolute() else Path(config_path).resolve().parent / p


def history_enabled(cfg: dict) -> bool:
    return bool((cfg.get("history") or {}).get("enabled", True))


def load_state(path) -> dict:
    """读历史状态（每台设备连续离线次数 + 告警去重标记）。"""
    p = Path(path)
    if p.exists():
        with open(p, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def save_state(path, state: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(state, f, allow_unicode=True)


# ---------------------------------------------------------------- 巡检

def run_check(cfg: dict, state_file, probe=None, alert_on: str = "change") -> dict:
    """跑一轮巡检，并算出「相比上一轮的变化」。

    probe 可注入（默认 probes.run_checks），单测里换成假探测函数即可离线验证全部逻辑。
    alert_on 决定 traceroute 什么时候补跑（见下面 want_trace 那段），和 CLI 的 --alert-on 同义。

    返回里的 new_alerts / recoveries 是告警去重的核心：
    故障没修好之前不会每轮都吵一遍，设备恢复时反而会主动报一次。
    """
    check = cfg.get("check") or {}
    ping_count = int(check.get("ping_count", probes.PING_COUNT_DEFAULT))
    ping_timeout = int(check.get("ping_timeout", probes.PING_TIMEOUT_DEFAULT))
    tcp_timeout = int(check.get("tcp_timeout", probes.TCP_TIMEOUT_DEFAULT))
    http_timeout = int(check.get("http_timeout", probes.HTTP_TIMEOUT_DEFAULT))
    dns_timeout = int(check.get("dns_timeout", probes.DNS_TIMEOUT_DEFAULT))
    # 设备判定异常后补跑 traceroute：正常设备零开销（traceroute_enabled 的默认值是开）
    traceroute_on = probes.traceroute_enabled(check.get("traceroute"))
    traceroute_hops = int(check.get("traceroute_hops", probes.TRACEROUTE_HOPS_DEFAULT))
    traceroute_timeout = float(check.get("traceroute_timeout", probes.TRACEROUTE_TIMEOUT_DEFAULT))
    threshold = int(check.get("down_threshold", 2))
    probe = probe or probes.run_checks

    state = load_state(state_file)
    results, new_alerts, recoveries = [], [], []

    for dev in cfg.get("devices") or []:
        name, host = dev["name"], dev["ip"]
        checks = dev.get("checks")

        ok, detail, items = probe(
            host, checks,
            ping_count=ping_count, ping_timeout=ping_timeout,
            tcp_timeout=tcp_timeout, http_timeout=http_timeout,
            dns_timeout=dns_timeout,
        )

        # 连续离线计数：通了立刻归零，离线就累加，达到阈值才算「异常」
        prev = state.get(name) or {}
        prev_streak = int(prev.get("streak", 0))
        if "alerted" in prev:
            prev_alerted = bool(prev["alerted"])
        else:
            # 老版本状态文件没这个字段：本来就一直离线的设备，别在升级后再吵一次
            prev_alerted = prev.get("last_ok") is False
        prev_down_since = prev.get("down_since")
        streak = 0 if ok else prev_streak + 1
        abnormal = (not ok) and streak >= threshold
        now = time.strftime(TS_FMT)

        # 中断起点 = 第一次探测失败的时刻（不是跨过阈值那一刻），中断时长更贴近真实
        if ok:
            down_since = None
        else:
            down_since = prev_down_since or now

        # 告警去重：只报「状态变化」，不重复报同一场故障
        event, down_minutes = None, None
        if abnormal and not prev_alerted:
            event = "down"
        elif ok and prev_alerted:
            event = "up"
            down_minutes = _minutes_between(prev_down_since, now)

        state[name] = {
            "streak": streak,
            "last_ok": bool(ok),
            "last_check": now,
            "alerted": abnormal,
            "down_since": down_since,
        }

        # 什么时候补跑 traceroute（回答「断在第几跳」）：
        #   * --alert-on change（cron 常态）：只在这台设备**新告警**这一轮跑 —— 和新消息推送
        #     同一时机，常年不通的设备不必每 10 分钟重跑一遍 tracert（一台 1~11 秒）；
        #   * --alert-on all（人工排查 / 演示）：异常设备一律补跑，看全量。
        # 它是补充诊断：不改 ok / 不改 abnormal，只往明细后面接一句。
        want_trace = traceroute_on and abnormal and (event == "down" or alert_on == "all")
        if want_trace:
            try:
                items = list(items) + [probes.probe_traceroute(host, traceroute_hops, traceroute_timeout)]
                detail = " | ".join(str(i) for i in items)
            except Exception as e:      # 护栏不能变故障源：诊断挂了只跳过它，本轮结论照旧
                print("(traceroute 诊断失败: %s)" % e)

        item = {
            "name": name,
            "ip": host,
            "ok": bool(ok),
            "streak": streak,
            "abnormal": abnormal,
            "status": "在线" if ok else "离线",
            "detail": detail,
            "checks": [vars(i) for i in items],
            "event": event,
            "down_since": down_since,
            "down_minutes": down_minutes,
        }
        results.append(item)
        if event == "down":
            new_alerts.append(item)
        elif event == "up":
            recoveries.append(item)

    save_state(state_file, state)
    return {
        "results": results,
        "threshold": threshold,
        "new_alerts": new_alerts,
        "recoveries": recoveries,
        "has_news": bool(new_alerts or recoveries),
    }


def _minutes_between(start: str | None, end: str) -> int | None:
    """两个时间戳相差几分钟（解析不了就返回 None，不猜）。"""
    if not start:
        return None
    try:
        delta = datetime.strptime(end, TS_FMT) - datetime.strptime(start, TS_FMT)
    except ValueError:
        return None
    return max(0, int(delta.total_seconds() // 60))


# ---------------------------------------------------------------- 报告

def format_report(data: dict, ts: str) -> str:
    lines = ["=== netwatch-ai 巡检报告 %s ===" % ts]
    results = data["results"]
    # 列宽按实际内容算，设备名长短不一时也能对齐
    w_name = max([len(r["name"]) for r in results] or [8]) + 2
    w_ip = max([len(r["ip"]) for r in results] or [8]) + 2
    for r in results:
        flag = "⚠️" if r["abnormal"] else ("✓" if r["ok"] else "·")
        lines.append("%s %-*s %-*s %s (连续离线 %d 次)" % (
            flag, w_name, r["name"], w_ip, r["ip"], r["status"], r["streak"]))
        lines.append("      └ %s" % r["detail"])

    abnormal = [r for r in data["results"] if r["abnormal"]]
    lines.append("")
    if abnormal:
        lines.append("⚠️ 发现 %d 台异常设备: %s" % (
            len(abnormal), ", ".join(r["name"] for r in abnormal)))
    else:
        lines.append("✅ 全部设备正常")

    lines.append("🔄 本次变化: %s" % _format_changes(data))
    return "\n".join(lines)


def _format_changes(data: dict) -> str:
    """相比上一轮的变化 —— 修复了你不重复吵，恢复了主动报一次。"""
    new_alerts = data.get("new_alerts") or []
    recoveries = data.get("recoveries") or []
    if not new_alerts and not recoveries:
        return "无（与上一轮一致，不重复告警）"
    parts = []
    for r in new_alerts:
        parts.append("⚠️ %s 新出现异常 (连续离线 %d 次)" % (r["name"], r["streak"]))
    for r in recoveries:
        mins = r.get("down_minutes")
        if mins is None:
            span = "已恢复"
        elif mins == 0:
            span = "中断不到 1 分钟"
        else:
            span = "中断约 %d 分钟" % mins
        parts.append("✅ %s 已恢复在线 (%s)" % (r["name"], span))
    return "\n      ".join(parts)


# ---------------------------------------------------------------- 通知

def _notify_lines(cfg: dict, data: dict, report_text: str, ts: str,
                  enabled: bool, news: bool) -> list:
    """把报告推到配置的渠道，返回要打印的结果行（永不抛异常）。

    两道闸门，都是刻意的：
      * ``enabled``（--notify）：配了渠道也不会自动发，防误推公司群/生产群；
      * ``news``（本轮有无新异常/恢复）：和告警去重保持同一套判断 ——
        每 10 分钟一轮的巡检只在真有事时才打扰人，否则渠道会被刷爆。
    """
    if notifiers is None:
        return []
    try:
        channels = notifiers.build_notifiers(cfg)
    except Exception as e:              # 配置写错也要看得见，不能默默不发
        return ["⚠️ 通知配置有误: %s" % e]
    if not channels:
        return []
    if not enabled:
        # 只在「本来就有事该通知」的轮次提醒忘了加 --notify，平时不刷屏
        return ["(已配置 %d 个通知渠道，未加 --notify，本次未推送)" % len(channels)] if news else []
    if not news:
        return []
    msg = notifiers.build_message(data, report_text, ts)
    return notifiers.send_all(channels, msg)


def _run_test_notify(cfg: dict) -> int:
    """--test-notify：发一条样例消息，验证渠道通不通（不探测、不写历史）。"""
    try:
        channels = notifiers.build_notifiers(cfg)
    except Exception as e:
        print("⚠️ 通知配置有误: %s" % e)
        return 0
    if not channels:
        print("配置里没有 notify.channels，先加一个渠道再自检，例如：")
        print("notify:\n  channels:\n    - type: webhook\n      url: https://example.com/hook")
        return 0
    print("自检 %d 个通知渠道：" % len(channels))
    for line in notifiers.send_all(channels, notifiers.sample_message(time.strftime(TS_FMT))):
        print(line)
    return 0


# ---------------------------------------------------------------- 入口

def _write_html_report(out_path, db_path, period: str) -> str:
    """把可用率报告落成一份静态 HTML，返回要打印的一行说明。

    失败只回一行 —— HTML 只是「另一种看法」，不能反过来把已经打好的报告带崩。
    """
    if report_html is None:
        return "report_html.py 不可用，跳过 HTML 报告。"
    try:
        text = report_html.build_html(db_path, period)
    except (OSError, sqlite3.Error) as e:      # 库被锁 / 损坏 / 没权限
        return "HTML 报告生成失败：%s" % e
    path = Path(out_path)
    try:
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as e:
        return "HTML 报告写入失败：%s" % e
    return "HTML 报告已写入 %s（静态文件，双击即看，无需服务）" % path


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="netwatch-ai 网络巡检")
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help="配置文件路径（默认 ./config.yaml）")
    parser.add_argument("--once", action="store_true",
                        help="只跑一轮（默认行为，保留以兼容旧命令）")
    parser.add_argument("--ai", action="store_true",
                        help="出现新异常时调用大模型分析根因")
    parser.add_argument("--silent-ok", action="store_true",
                        help="无新变化时只输出 [SILENT]（给定时任务抑制投递）")
    parser.add_argument("--alert-on", choices=["change", "all"], default="change",
                        help="change=只在状态变化时告警（默认，防刷屏）；all=每轮异常都告警")
    parser.add_argument("--report", default=None,
                        help="不探测，只看历史可用率报告，如 --report 7d")
    parser.add_argument("--html", default=None, metavar="PATH",
                        help="不探测，把可用率报告另存成自包含 HTML 静态页"
                             "（如 --html report.html；窗口用 --report 7d 指定，默认 7d）")
    parser.add_argument("--no-history", action="store_true",
                        help="本轮不写历史库")
    parser.add_argument("--notify", action="store_true",
                        help="告警时按 notify.channels 推送（安全默认：不加就不推）")
    parser.add_argument("--test-notify", action="store_true",
                        help="不探测，只发一条样例消息自检通知渠道")
    args = parser.parse_args(argv)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print("找不到配置文件 %s" % cfg_path)
        print("先复制示例配置再改：cp config.example.yaml config.yaml")
        return 0

    cfg = load_config(cfg_path)

    # ---- 通知自检：不探测，只发一条样例到配置里的渠道
    if args.test_notify:
        if notifiers is None:
            print("notifiers.py 不可用，无法自检通知渠道。")
            return 0
        return _run_test_notify(cfg)

    # ---- 只看历史报告，不探测（--html 顺带落一份静态 HTML，不常驻、不开端口）
    if args.report or args.html:
        if history is None:
            print("history.py 不可用，无法出可用率报告。")
            return 0
        period = args.report or REVIEW_DEFAULT_PERIOD
        try:
            since, until = history.period_bounds(period)
        except ValueError as e:
            print("时间范围有误：%s" % e)
            return 0
        db_path = history_path_for(cfg_path, cfg)
        try:
            with history.open_db(db_path) as conn:
                stats = history.availability(conn, since, until)
        except (OSError, sqlite3.Error) as e:      # 库被写坏 / 被别的进程锁住
            print("历史库读取失败：%s" % e)
            print("（库文件：%s —— 删掉它再跑一轮巡检就会重建）" % db_path)
            return 0
        print(history.format_history_report(stats, since, until))
        if args.html:
            print(_write_html_report(args.html, db_path, period))
        return 0

    if not (cfg.get("devices") or []):
        print("配置里没有任何设备，请先在 devices: 下加设备清单。")
        return 0

    data = run_check(cfg, state_path_for(cfg_path), alert_on=args.alert_on)
    ts = time.strftime(TS_FMT)

    # ---- 落历史库（失败不能影响巡检结论）
    if history is not None and history_enabled(cfg) and not args.no_history:
        try:
            with history.open_db(history_path_for(cfg_path, cfg)) as conn:
                history.record(conn, data, ts)
        except Exception as e:
            print("(历史库写入失败: %s)" % e)

    abnormal = [r for r in data["results"] if r["abnormal"]]
    targets = data["new_alerts"] if args.alert_on == "change" else abnormal

    # 定时任务模式：没有需要通知的变化就静默，不往手机推消息
    if args.silent_ok and not targets and not data["recoveries"]:
        print("[SILENT]")
        return 0

    # 先攒成一份完整报告（含影响面 + AI 卡片），再一次性打印 / 推送 ——
    # 推送出去的正文必须和你在终端看到的**完全一致**，否则出问题没法对账。
    out = [format_report(data, ts)]

    if targets:
        alerting = data["new_alerts"] if args.alert_on == "change" else abnormal
        # 影响面判断是纯规则计算的，免费且比大模型更确定 —— 先规则、后 AI
        # 影响面看的是「当前有多少台不通」（全量），AI 只分析本次新出现的故障（省 token）
        if rule_hint is not None:
            out.append("\n🧭 影响面判断:")
            out.append(rule_hint(abnormal, data["results"]))

        if args.ai:
            out.append("\n🤖 AI 分析:")
            if analyze is None:
                out.append("(analyzer 不可用：请确认 analyzer.py 存在)")
            else:
                try:
                    raw = analyze(alerting, data["results"], ts_text=ts)
                    # 结构化优先：模型按约定回 JSON 就渲染卡片；没按约定就退回原文（内容不丢）
                    if parse_analysis is not None and render_card is not None:
                        out.append(render_card(parse_analysis(raw)))
                    else:
                        out.append(raw)
                except Exception as e:      # AI 挂了不能影响巡检结果本身
                    out.append("(AI 分析失败: %s)" % e)
    elif abnormal:
        out.append("\n(异常设备上一轮已告警过，本次不重复分析。想看全量加 --alert-on all)")

    report_text = "\n".join(out)
    print(report_text)

    # ---- 推送：只在「本轮确实有新消息」时发（与告警去重同一套判断），
    #      失败只打印一行 —— 通知挂掉绝不影响巡检结论和退出码
    news = bool(data["has_news"] or (args.alert_on == "all" and abnormal))
    for line in _notify_lines(cfg, data, report_text, ts, args.notify, news):
        print(line)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

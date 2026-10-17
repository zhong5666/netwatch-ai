#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""netwatch-ai 巡检编排层：读配置 → 逐台探测 → 判定异常 → 可选 AI 分析。

分层：
    probes.py    探测层（ICMP / TCP / HTTP，跨平台）
    netwatch.py  编排层（设备清单、连续离线计数、报告渲染）
    analyzer.py  AI 层（把异常交给大模型判断根因）

用法：
    python netwatch.py                                  # 跑一轮并打印报告
    python netwatch.py --config demo/config.demo.yaml   # 指定配置（演示）
    python netwatch.py --ai                             # 异常时调 AI 分析
    python netwatch.py --silent-ok                      # 全部正常只输出 [SILENT]（给定时任务用）

退出码：始终为 0（是否异常写在输出里）；定时任务靠 --silent-ok 的 [SILENT] 约定抑制投递。
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

import yaml

import probes

try:
    from analyzer import analyze, rule_hint
except ImportError:          # 没配 AI 也能靠纯规则跑巡检
    analyze = None
    rule_hint = None

DEFAULT_CONFIG = "config.yaml"


# ---------------------------------------------------------------- 配置与状态

def load_config(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def state_path_for(config_path) -> Path:
    """状态文件跟着配置文件走 —— 一份配置一套状态，演示配置不会污染真实巡检。"""
    return Path(config_path).resolve().parent / ".state.yaml"


def load_state(path) -> dict:
    """读历史状态（每台设备连续离线次数）。"""
    p = Path(path)
    if p.exists():
        with open(p, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def save_state(path, state: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(state, f, allow_unicode=True)


# ---------------------------------------------------------------- 巡检

def run_check(cfg: dict, state_file, probe=None) -> dict:
    """跑一轮巡检。

    probe 可注入（默认 probes.run_checks），单测里换成假探测函数即可离线验证全部逻辑。
    """
    check = cfg.get("check") or {}
    ping_count = int(check.get("ping_count", probes.PING_COUNT_DEFAULT))
    ping_timeout = int(check.get("ping_timeout", probes.PING_TIMEOUT_DEFAULT))
    tcp_timeout = int(check.get("tcp_timeout", probes.TCP_TIMEOUT_DEFAULT))
    http_timeout = int(check.get("http_timeout", probes.HTTP_TIMEOUT_DEFAULT))
    threshold = int(check.get("down_threshold", 2))
    probe = probe or probes.run_checks

    state = load_state(state_file)
    results = []

    for dev in cfg.get("devices") or []:
        name, host = dev["name"], dev["ip"]
        checks = dev.get("checks")

        ok, detail, items = probe(
            host, checks,
            ping_count=ping_count, ping_timeout=ping_timeout,
            tcp_timeout=tcp_timeout, http_timeout=http_timeout,
        )

        # 连续离线计数：通了立刻归零，离线就累加，达到阈值才算「异常」
        prev_streak = int((state.get(name) or {}).get("streak", 0))
        streak = 0 if ok else prev_streak + 1
        state[name] = {
            "streak": streak,
            "last_ok": bool(ok),
            "last_check": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        results.append({
            "name": name,
            "ip": host,
            "ok": bool(ok),
            "streak": streak,
            "abnormal": (not ok) and streak >= threshold,
            "status": "在线" if ok else "离线",
            "detail": detail,
            "checks": [vars(item) for item in items],
        })

    save_state(state_file, state)
    return {"results": results, "threshold": threshold}


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
    return "\n".join(lines)


# ---------------------------------------------------------------- 入口

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="netwatch-ai 网络巡检")
    parser.add_argument("--config", default=DEFAULT_CONFIG,
                        help="配置文件路径（默认 ./config.yaml）")
    parser.add_argument("--once", action="store_true",
                        help="只跑一轮（默认行为，保留以兼容旧命令）")
    parser.add_argument("--ai", action="store_true",
                        help="异常时调用大模型分析根因")
    parser.add_argument("--silent-ok", action="store_true",
                        help="全部正常时只输出 [SILENT]（给定时任务抑制投递）")
    args = parser.parse_args(argv)

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print("找不到配置文件 %s" % cfg_path)
        print("先复制示例配置再改：cp config.example.yaml config.yaml")
        return 0

    cfg = load_config(cfg_path)
    if not (cfg.get("devices") or []):
        print("配置里没有任何设备，请先在 devices: 下加设备清单。")
        return 0

    data = run_check(cfg, state_path_for(cfg_path))
    abnormal = [r for r in data["results"] if r["abnormal"]]

    # 定时任务模式：一切正常就静默，不往手机推消息
    if args.silent_ok and not abnormal:
        print("[SILENT]")
        return 0

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(format_report(data, ts))

    if abnormal:
        # 影响面判断是纯规则计算的，免费且比大模型更确定 —— 先规则、后 AI
        if rule_hint is not None:
            print("\n🧭 影响面判断:")
            print(rule_hint(abnormal, data["results"]))

        if args.ai:
            print("\n🤖 AI 分析:")
            if analyze is None:
                print("(analyzer 不可用：请确认 analyzer.py 存在)")
            else:
                try:
                    print(analyze(abnormal, data["results"], ts_text=ts))
                except Exception as e:      # AI 挂了不能影响巡检结果本身
                    print("(AI 分析失败: %s)" % e)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

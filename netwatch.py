#!/usr/bin/env python3
"""netwatch-ai 网络巡检核心

功能:
1. 按 config.yaml 里的设备清单做 ping 巡检
2. 记录在线状态，检测异常（连续离线）
3. 可选的 AI 分析 + 微信告警（后续迭代实现）

用法:
    python netwatch.py            # 跑一轮巡检并输出报告
    python netwatch.py --once     # 同上（单次模式，用于测试）
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

import yaml

try:
    from analyzer import analyze
except ImportError:
    analyze = None

STATE_FILE = Path(__file__).parent / ".state.yaml"


def load_config() -> dict:
    cfg_path = Path(__file__).parent / "config.yaml"
    with open(cfg_path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_state() -> dict:
    """读取历史状态（记录每台设备连续离线次数）"""
    if STATE_FILE.exists():
        with open(STATE_FILE, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def save_state(state: dict) -> None:
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        yaml.safe_dump(state, f, allow_unicode=True)


def ping(ip: str, count: int, timeout: int) -> tuple[bool, str]:
    """返回 (是否在线, 详情字符串)"""
    try:
        result = subprocess.run(
            ["ping", "-n", str(count), "-w", str(timeout * 1000), ip],
            capture_output=True,
            encoding="gbk",      # Windows ping 输出是 GBK，不是 UTF-8
            errors="replace",
            timeout=count * timeout + 5,
        )
        # Windows ping 判定：returncode 0=通 1=不通（最可靠）
        # 注意文本里 "100% 丢失" 包含 "0%" 子串，不能拿它当全通标志
        if result.returncode == 0:
            return True, f"ping通 ({ip})"
        if "无法访问目标主机" in result.stdout or "请求超时" in result.stdout:
            return False, f"ping不通 ({ip})"
        return False, f"ping失败 rc={result.returncode} ({ip})"
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, f"ping执行失败: {e}"


def run_check(cfg: dict) -> dict:
    check = cfg.get("check", {})
    ping_count = int(check.get("ping_count", 5))
    ping_timeout = int(check.get("ping_timeout", 1))
    threshold = int(check.get("down_threshold", 1))

    state = load_state()
    devices = cfg.get("devices", [])
    results = []

    for dev in devices:
        name, ip = dev["name"], dev["ip"]
        ok, detail = ping(ip, ping_count, ping_timeout)

        # 维护离线计数
        prev = state.get(name, {"streak": 0})
        streak = 0 if ok else prev.get("streak", 0) + 1
        state[name] = {"streak": streak}

        status = "在线" if ok else "离线"
        abnormal = (not ok) and streak >= threshold
        results.append({
            "name": name,
            "ip": ip,
            "ok": ok,
            "streak": streak,
            "abnormal": abnormal,
            "detail": detail,
            "status": status,
        })

    save_state(state)
    return {"results": results}


def print_report(data: dict) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"=== netwatch-ai 巡检报告 {ts} ===")
    abnormal = [r for r in data["results"] if r["abnormal"]]
    for r in data["results"]:
        flag = "⚠️" if r["abnormal"] else ("✓" if r["ok"] else "·")
        print(f"{flag} {r['name']:10s} {r['ip']:18s} {r['status']} "
              f"(连续离线 {r['streak']} 次)")
    if abnormal:
        print(f"\n⚠️ 发现 {len(abnormal)} 台异常设备: "
              + ", ".join(r["name"] for r in abnormal))
    else:
        print("\n✅ 全部设备正常")


def main() -> None:
    parser = argparse.ArgumentParser(description="netwatch-ai 网络巡检")
    parser.add_argument("--once", action="store_true", help="只跑一轮")
    parser.add_argument("--ai", action="store_true",
                        help="异常时调用 AI 分析（供 cron 定时跑）")
    parser.add_argument("--silent-ok", action="store_true",
                        help="全部正常时输出 [SILENT]（Hermes cron 用，抑制投递）")
    args = parser.parse_args()

    cfg = load_config()
    data = run_check(cfg)
    abnormal = [r for r in data["results"] if r["abnormal"]]

    # cron 模式：正常就静默，异常才输出告警
    if args.silent_ok and not abnormal:
        print("[SILENT]")
        return

    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"=== netwatch-ai 巡检报告 {ts} ===")
    for r in data["results"]:
        flag = "⚠️" if r["abnormal"] else ("✓" if r["ok"] else "·")
        print(f"{flag} {r['name']:10s} {r['ip']:18s} {r['status']} "
              f"(连续离线 {r['streak']} 次)")

    if abnormal:
        print(f"\n⚠️ 发现 {len(abnormal)} 台异常设备: "
              + ", ".join(r["name"] for r in abnormal))
        # AI 分析（可选）
        if args.ai and analyze is not None:
            try:
                print("\n🤖 AI 分析:")
                print(analyze(abnormal, data["results"], ts_text=ts))
            except Exception as e:
                print(f"\n(AI 分析失败: {e})")
    else:
        print("\n✅ 全部设备正常")

    if args.once:
        return  # 单次模式，不循环

    print("\n(当前为单轮演示；接入 cron 后可定时执行)")


if __name__ == "__main__":
    main()
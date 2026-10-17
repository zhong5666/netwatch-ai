#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键复现 README 里的实测输出：起本地服务 → 巡检 → 打死服务 → 巡检 → 恢复 → 出可用率报告。

跑法：
    python demo/run_demo.py            # 纯规则（不花任何 token）
    python demo/run_demo.py --ai       # 额外展示 AI 分析段（需要 NETWATCH_API_KEY）

脚本会自己起 python -m http.server 8899 再打死它，全程只在本机 127.0.0.1 上折腾，
不碰任何真实设备。README 的 demo/sample_output.txt 就是用 `--ai` 跑出来的。
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "demo" / "config.demo.yaml"
PORT = 8899


def run(*args: str, env=None) -> str:
    proc = subprocess.run([sys.executable, str(ROOT / "netwatch.py"), "--config", str(CONFIG), *args],
                          cwd=str(ROOT), capture_output=True, encoding="utf-8",
                          errors="replace", env=env)
    return (proc.stdout or "").rstrip() + (("\n[stderr] " + proc.stderr.strip()) if proc.stderr.strip() else "")


def title(text: str) -> None:
    print("\n" + "=" * 68)
    print("# " + text)
    print("=" * 68)


def start_server() -> subprocess.Popen:
    proc = subprocess.Popen([sys.executable, "-m", "http.server", str(PORT), "--bind", "127.0.0.1"],
                            cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.5)
    return proc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="netwatch-ai 演示")
    parser.add_argument("--ai", action="store_true", help="展示 AI 分析段（需要 API key）")
    parser.add_argument("--keep-state", action="store_true", help="保留演示产生的状态/历史文件")
    args = parser.parse_args(argv)

    state = ROOT / "demo" / ".state.yaml"
    db = ROOT / "demo" / ".history.db"
    if not args.keep_state:
        for f in (state, db):
            if f.exists():
                f.unlink()

    env = dict(os.environ)
    env.setdefault("PYTHONIOENCODING", "utf-8")
    ai = ["--ai"] if args.ai else []

    title("场景一：本地 8899 服务正常 —— 全部在线")
    server = start_server()
    print("$ python -m http.server %d --bind 127.0.0.1 &" % PORT)
    print(run(*ai))

    title("场景二：kill 掉 8899 服务（主机还活着，只是服务挂了）")
    server.terminate()
    server.wait(timeout=10)
    print("$ kill <http.server>")
    print(run(*ai))

    title("场景三：服务仍未恢复 —— 状态没变化，不再重复告警")
    print("$ python netwatch.py --silent-ok   # 定时任务模式，无新变化")
    print(run("--silent-ok"))

    title("场景四：服务恢复 —— 主动报一次「已恢复」")
    server = start_server()
    print("$ python -m http.server %d --bind 127.0.0.1 &" % PORT)
    print(run(*ai))
    server.terminate()
    server.wait(timeout=10)

    title("场景五：可用率报告（历史库）")
    print("$ python netwatch.py --report 7d")
    print(run("--report", "7d"))

    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

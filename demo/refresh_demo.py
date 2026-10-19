# -*- coding: utf-8 -*-
"""一条命令重抓演示输出并同步 README。

    python demo/refresh_demo.py            # 只重建 sample_output.txt
    python demo/refresh_demo.py --ai       # 带真实模型跑（需要 NETWATCH_API_KEY）

为什么用脚本而不是手改：
1. run_demo.py 的输出是 CRLF，仓库里统一 LF；
2. README 里逐字引用 sample_output.txt，而 AI 卡片有 60 列宽的边框 —— 手抄必错列。
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NEW = ROOT / "demo" / "_new.txt"
SAMPLE = ROOT / "demo" / "sample_output.txt"
README = ROOT / "README.md"

HEADER = """# netwatch-ai 实测输出（真实终端输出，非示意）
#
# 环境：Windows 11 + Python 3.11
# 一键复现：python demo/run_demo.py --ai
# 配置：demo/config.demo.yaml
#   localhost        127.0.0.1   本机
#   local-web        127.0.0.1   多协议探测 ICMP + TCP:8899 + HTTP，服务由 `python -m http.server 8899` 提供
#   unreachable-demo 192.0.2.1   RFC 5737 保留测试段，永不响应
#
# 五个场景连着跑：正常 → 服务挂 → 状态未变化（不重复告警）→ 恢复 → 可用率报告
# 「AI 分析」段是真实模型返回的 JSON 渲染成的卡片。模型偶尔不按 JSON 回，
# 这时不会丢内容：退回原文渲染，并在卡片上标注「未按 JSON 返回」。
"""


def run_demo(with_ai: bool) -> str:
    cmd = [sys.executable, str(ROOT / "demo" / "run_demo.py")]
    if with_ai:
        cmd.append("--ai")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(cmd, cwd=str(ROOT), env=env, capture_output=True)
    out = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n")
    err = proc.stderr.decode("utf-8", "replace").strip()
    if err:
        print("[run_demo stderr] %s" % err, file=sys.stderr)
    if proc.returncode != 0:
        raise SystemExit("run_demo.py 退出码 %s，先把它跑通再同步" % proc.returncode)
    return out.strip("\n")


def write_sample(body: str) -> None:
    SAMPLE.write_text(HEADER + body + "\n", encoding="utf-8", newline="\n")
    print("sample_output.txt: %d 行" % (SAMPLE.read_text(encoding="utf-8").count("\n") + 1))


def pick_scenario(body: str) -> str:
    """取「服务挂了」那一场（第二次巡检报告）作 README 引用段。"""
    lines = body.split("\n")
    heads = [i for i, l in enumerate(lines)
             if l.startswith("=== netwatch-ai 巡检报告")]
    if len(heads) < 2:
        raise SystemExit("演示输出里没找到两份巡检报告，先检查 demo 是否完整跑完")
    start = heads[1]
    end = next(i for i in range(start, len(lines)) if lines[i].startswith("└"))
    return "\n".join(lines[start:end + 1])


def sync_readme(block: str) -> None:
    text = README.read_text(encoding="utf-8")
    marker = "=== netwatch-ai 巡检报告"
    # 只替换「效果」段里 fenced code block 中的那份报告
    fence = text.index("## 效果")
    start = text.index(marker, fence)
    end = text.index("```", start)
    if text[start:end].strip() == block.strip():
        print("README 效果段已是最新，跳过")
        return
    README.write_text(text[:start] + block + "\n" + text[end:], encoding="utf-8", newline="\n")
    print("README 效果段已同步（%d 行）" % (block.count("\n") + 1))


def main() -> int:
    with_ai = "--ai" in sys.argv[1:]
    if not with_ai:
        raise SystemExit(
            "demo/sample_output.txt 是带 AI 卡片的版本，重抓请加 --ai ——\n"
            "不带 --ai 会把卡片段清空，README 引用段跟着一起变。"
        )
    body = run_demo(with_ai)
    NEW.write_text(body + "\n", encoding="utf-8", newline="\n")   # 留档，便于 diff
    write_sample(body)
    sync_readme(pick_scenario(body))
    print("提示：README「效果」段引用的时间戳变了，顺手确认一下那几句说明还成立。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

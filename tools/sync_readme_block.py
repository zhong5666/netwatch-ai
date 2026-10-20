# -*- coding: utf-8 -*-
"""把 README 里「逐字引用」的段同步成源文件的原文（开发工具，运行时不需要它）。

    python tools/sync_readme_block.py            # 只比对（有漂移则退出码 1，可挂收工自检 / CI）
    python tools/sync_readme_block.py --write    # 真正写回 README
    python tools/sync_readme_block.py --root .   # 指定仓库根（默认按本文件位置推断，测试用）

为什么要有它：
1. README 有两段是**逐字**引用 `demo/sample_output.txt` 的（「效果」段里那一整份巡检报告、
   「可用率报告」段），而 AI 卡片是 60 列宽的边框 —— 手抄必错列，肉眼还看不出来；
2. 之前只有 `demo/refresh_demo.py` 会同步「效果」段，报告段每次靠临时脚本手搓，
   脚本还留在系统临时目录里迟早被清掉 —— 现在两段规则收在这一处，refresh_demo 也改调它（一份实现，不各自漂移）；
3. 默认模式只读不写，随时能回答一句「现在 README 还是原文吗」。

块的规则（源文件 → README 区段）：
- 源文件里按标记切出原文（切完去掉尾部空行，统一 LF）；
- README 里从锚点标题之后**第一个**标记行开始，到该 fenced block 的收尾 ``` 之前结束。
"""
import argparse
import sys
from pathlib import Path

EFFECT = "=== netwatch-ai 巡检报告"
REPORT = "=== netwatch-ai 可用率报告"
SEPARATOR = "=" * 10          # 演示输出里的场景分隔线，也就是「效果」段的结束位置


class Block(object):
    """一段逐字引用：README 锚点 + 源文件标记 + 从源文件切原文的函数。"""

    def __init__(self, name, anchor, marker, slicer):
        self.name = name
        self.anchor = anchor
        self.marker = marker
        self.slicer = slicer


def _read(path):
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _write(path, text):
    """显式写 LF。Path.write_text(newline=...) 是 3.10+ 的签名，本项目 floor 是 3.9。"""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _slice(lines, marker, nth):
    """取第 nth 个以 marker 开头的行，到下一次场景分隔线（或文件尾）为止。"""
    heads = [i for i, line in enumerate(lines) if line.startswith(marker)]
    if len(heads) < nth:
        raise SystemExit("源文件里没找够 `%s`（需要第 %d 个，只有 %d 个），先确认演示是否完整跑完"
                         % (marker, nth, len(heads)))
    start = heads[nth - 1]
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].startswith(SEPARATOR):
            end = i
            break
    block = lines[start:end]
    while block and not block[-1].strip():
        block.pop()
    return "\n".join(block)


def slice_effect(body):
    """「效果」段 = 第二份巡检报告（服务挂了那一场，带 AI 卡片）。

    结束位置必须是**下一场的分隔线**：明细行都带 6 个空格前缀，拿「第一行 └ 明细」当结束
    标记永远不成立（会直接崩），改成 strip 后再匹配又会把 AI 卡片截掉。
    """
    return _slice(body.split("\n"), EFFECT, 2)


def slice_report(body):
    """「可用率报告」段 = 源文件里最后那份报告，一直到文件尾。"""
    return _slice(body.split("\n"), REPORT, 1)


BLOCKS = (
    Block("效果", "## 效果", EFFECT, slice_effect),
    Block("可用率报告", "## 历史数据与可用率报告", REPORT, slice_report),
)


def region(readme_text, block):
    """README 里这段引用的字符区间 [start, end)：从标记行到收尾 ``` 之前。"""
    try:
        anchor = readme_text.index(block.anchor)
    except ValueError:
        raise SystemExit("README 里找不到锚点标题 `%s`" % block.anchor)
    try:
        start = readme_text.index(block.marker, anchor)
    except ValueError:
        raise SystemExit("README 的 `%s` 之后找不到标记行 `%s`" % (block.anchor, block.marker))
    try:
        end = readme_text.index("```", start)
    except ValueError:
        raise SystemExit("README 的 `%s` 段没有找到收尾的 ```" % block.name)
    return start, end


def _first_diff(want, got):
    a = want.split("\n")
    b = got.split("\n")
    for i in range(max(len(a), len(b))):
        x = a[i] if i < len(a) else "<缺这一行>"
        y = b[i] if i < len(b) else "<多这一行>"
        if x != y:
            return i + 1, x, y
    return None


def sync_block(root, block, write=False):
    """比对/同步一段引用。返回 {name, status, lines, detail}，status ∈ in-sync/synced/drift。"""
    src = root / "demo" / "sample_output.txt"
    readme_path = root / "README.md"
    want = block.slicer(_read(src))
    readme = _read(readme_path)
    start, end = region(readme, block)
    got = readme[start:end].rstrip("\n")
    lines = want.count("\n") + 1
    if got == want:
        return {"name": block.name, "status": "in-sync", "lines": lines, "detail": ""}
    if not write:
        i, x, y = _first_diff(want, got)
        return {"name": block.name, "status": "drift", "lines": lines,
                "detail": "第 %d 行起不一致：源文件 `%s` / README `%s`" % (i, x, y)}
    _write(readme_path, readme[:start] + want + "\n" + readme[end:])
    return {"name": block.name, "status": "synced", "lines": lines, "detail": ""}


def sync_all(root, write=False):
    return [sync_block(root, b, write=write) for b in BLOCKS]


def main(argv=None):
    ap = argparse.ArgumentParser(description="同步 README 里逐字引用的 demo 输出段")
    ap.add_argument("--write", action="store_true", help="写回 README（默认只比对）")
    ap.add_argument("--root", default=None, help="仓库根目录（默认按本文件位置推断）")
    args = ap.parse_args(argv)
    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    results = sync_all(root, write=args.write)
    for r in results:
        if r["status"] == "in-sync":
            print("README「%s」段与源文件逐字一致（%d 行）" % (r["name"], r["lines"]))
        elif r["status"] == "synced":
            print("README「%s」段已同步（%d 行）" % (r["name"], r["lines"]))
        else:
            print("⚠️ README「%s」段与源文件不一致：%s" % (r["name"], r["detail"]))
    drift = [r["name"] for r in results if r["status"] == "drift"]
    if drift:
        print("跑 `python tools/sync_readme_block.py --write` 同步（别手抄：对齐空格必错列）")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

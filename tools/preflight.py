# -*- coding: utf-8 -*-
"""收工自检：一条命令回答「现在能不能收工」（开发工具，运行时不需要它）。

    python tools/preflight.py            # 全套本地自检：README 逐字引用 + 双版本 pytest + 工作区干净
    python tools/preflight.py --fast     # 跳过测试（只查 README / 工作区，2 秒出结果）
    python tools/preflight.py --ci       # 额外核对「最新 CI 结论」和「远程 HEAD 是否就是本地 HEAD」
    python tools/preflight.py --allow-dirty   # 允许工作区有改动（改 PROGRESS.local.md 之外的场景）

为什么要有它：收工那几步是分散的、且每一步都能被骗过 ——
1. README 那两段是**逐字**引用 demo 输出，手抄必错列，改完 demo 常忘了同步（`tools/sync_readme_block.py` 只回答这一件事）；
2. 测试要跑两遍：本地 `.venv`（3.11）和 `uv run --python 3.9`（仓库 floor）。只跑前者就会重演「本地全绿、CI 九红」；
3. 工作区常残留 `commit_msg.tmp`、`*.bak-*`、临时 `.db`，`git add -A` 一把梭就带进仓库。
分散做的时候总有一项会漏，所以收成一条命令 + 一个退出码。

退出码：0 全通过；1 有失败项。跳过项（没装 uv / 没装 gh / 没有 .venv）不算失败，但会明说。
"""
import argparse
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:      # 直接 `python tools/preflight.py` 时本来就在，被别的脚本 import 时补上
    sys.path.insert(0, _HERE)

import sync_readme_block as srb  # noqa: E402  （比对规则只住在那里，这里不重写）


DEFAULT_TIMEOUT = 900


def _last_line(text):
    for line in reversed((text or "").strip().splitlines()):
        if line.strip():
            return line.strip()
    return ""


def _run(cmd, cwd, timeout):
    """跑一条外部命令，返回 (退出码, stdout, stderr)；超时/找不到程序都折成退出码 127。"""
    try:
        p = subprocess.Popen(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        return 124, (out or b"").decode("utf-8", "replace"), "超时（%ds）" % timeout
    dec = lambda b: (b or b"").decode("utf-8", "replace")  # noqa: E731
    return p.returncode, dec(out), dec(err)


def _row(name, ok, detail, skipped=False):
    return {"name": name, "ok": bool(ok), "skipped": bool(skipped), "detail": detail}


def check_readme(root):
    """README 两段逐字引用是否与 demo 输出一致（规则来自 sync_readme_block）。"""
    try:
        results = srb.sync_all(root)
    except SystemExit as exc:            # 锚点/标记缺失，srb 用 SystemExit 报错
        return _row("README 引用段", False, str(exc.code if exc.code not in (0, None) else "定位失败"))
    drift = [r for r in results if r["status"] == "drift"]
    if not drift:
        parts = ["%s %d 行" % (r["name"], r["lines"]) for r in results]
        return _row("README 引用段", True, "逐字一致（%s）" % " / ".join(parts))
    detail = "；".join("%s 段：%s" % (r["name"], r["detail"]) for r in drift)
    return _row("README 引用段", False, detail + "（跑 tools/sync_readme_block.py --write 同步，别手抄）")


def test_commands(root):
    """默认的两条测试命令；缺工具时返回 None 表示跳过。"""
    cmds = []
    venv = root / ".venv"
    venv_py = venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if venv_py.exists():
        cmds.append(("pytest（本地 .venv）", [str(venv_py), "-m", "pytest", "-q"], None))
    else:
        cmds.append(("pytest（本地 .venv）", None, "没找到 .venv（先 `python -m venv .venv`）"))
    if shutil.which("uv"):
        cmds.append(("pytest（py3.9 floor）",
                     ["uv", "run", "--python", "3.9", "--with", "pytest", "--with", "PyYAML",
                      "python", "-m", "pytest", "-q"], None))
    else:
        cmds.append(("pytest（py3.9 floor）", None, "没装 uv —— 跳过就等于没验 CI floor"))
    return cmds


def check_tests(root, timeout, override=None):
    """跑测试。override 非空时用它（测试注入用），名字统一叫「测试」。"""
    rows = []
    if override:
        pairs = [("测试", list(override), None)]
    else:
        pairs = test_commands(root)
    for name, cmd, skip in pairs:
        if cmd is None:
            rows.append(_row(name, True, skip, skipped=True))
            continue
        code, out, err = _run(cmd, root, timeout)
        tail = _last_line(out) or _last_line(err) or "无输出"
        if code == 0:
            rows.append(_row(name, True, tail))
        else:
            rows.append(_row(name, False, "退出码 %d：%s" % (code, tail)))
    return rows


def _git(root, *args):
    code, out, err = _run(["git", "-C", str(root)] + list(args), root, 120)
    return code, out.strip(), err.strip()


def check_worktree(root):
    """工作区是否干净；未跟踪文件单独点名（`git add -A` 前最该看的就是它们）。"""
    code, out, err = _git(root, "status", "--porcelain")
    if code != 0:
        return _row("工作区", True, "不是 git 仓库或 git 不可用（%s）" % (err or "无输出"), skipped=True)
    if not out:
        return _row("工作区", True, "干净")
    lines = [ln for ln in out.splitlines() if ln.strip()]
    untracked = [ln[3:] for ln in lines if ln.startswith("??")]
    changed = len(lines) - len(untracked)
    bits = []
    if changed:
        bits.append("%d 个文件有改动" % changed)
    if untracked:
        bits.append("未跟踪：%s" % "、".join(untracked[:5]) + ("…" if len(untracked) > 5 else ""))
    return _row("工作区", False, "；".join(bits))


def _github_slug(root):
    code, out, _ = _git(root, "remote", "get-url", "origin")
    if code != 0 or not out:
        return None
    url = out.strip()
    if url.startswith("git@"):                       # git@github.com:owner/repo.git
        url = url.split(":", 1)[1]
    elif "://" in url:                               # https://github.com/owner/repo.git
        url = url.split("://", 1)[1]
        url = url.split("/", 1)[1] if "/" in url else ""
    if url.endswith(".git"):
        url = url[:-4]
    parts = [p for p in url.split("/") if p]
    return "/".join(parts[-2:]) if len(parts) >= 2 else None


def check_ci(root, gh_cmd):
    """可选：最新 CI 结论 + 远程 HEAD 是否等于本地 HEAD（要 gh 和网络）。"""
    if not shutil.which(gh_cmd) and not Path(gh_cmd).exists():
        return _row("CI", True, "没装 gh —— 跳过（没验 CI 就别声称绿）", skipped=True)
    slug = _github_slug(root)
    if not slug:
        return _row("CI", True, "origin 不是 github 仓库（%s）" % slug, skipped=True)
    code, out, err = _run([gh_cmd, "run", "list", "--repo", slug, "--limit", "1",
                           "--json", "databaseId,headSha,status,conclusion"], root, 120)
    if code != 0:
        return _row("CI", False, "gh run list 失败：%s" % (_last_line(err) or _last_line(out)))
    try:
        import json
        runs = json.loads(out)
    except ValueError:
        return _row("CI", False, "gh 返回的不是 JSON：%s" % _last_line(out))
    if not runs:
        return _row("CI", False, "仓库没有任何 CI run")
    run = runs[0]
    code, local, _ = _git(root, "rev-parse", "HEAD")
    local = local[:7]
    detail = "run %s %s/%s，head=%s（本地 %s）" % (
        run.get("databaseId"), run.get("status"), run.get("conclusion"),
        str(run.get("headSha") or "")[:7], local)
    ok = run.get("conclusion") == "success" and str(run.get("headSha") or "")[:7] == local
    return _row("CI", ok, detail)


MARK = {True: "✓", False: "✗"}


def main(argv=None):
    ap = argparse.ArgumentParser(description="收工自检：README 同步 + 双版本测试 + 工作区")
    ap.add_argument("--root", default=None, help="仓库根目录（默认按本文件位置推断，测试用）")
    ap.add_argument("--fast", action="store_true", help="跳过测试")
    ap.add_argument("--ci", action="store_true", help="额外核对最新 CI 结论与远程 HEAD")
    ap.add_argument("--allow-dirty", action="store_true", help="工作区有改动不算失败")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="单条测试命令超时秒数")
    ap.add_argument("--test-cmd", default=None, help="用一条自定义命令代替测试（测试注入用，按空格切）")
    ap.add_argument("--gh-cmd", default="gh", help="gh 可执行文件（测试注入用）")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]

    rows = [check_readme(root)]
    if args.fast:
        rows.append(_row("测试", True, "--fast 跳过", skipped=True))
    else:
        rows.extend(check_tests(root, args.timeout, override=shlex.split(args.test_cmd, posix=(os.name != "nt")) if args.test_cmd else None))
    dirty = check_worktree(root)
    if not dirty["ok"] and args.allow_dirty:
        dirty = _row(dirty["name"], True, dirty["detail"] + "（--allow-dirty 放行）", skipped=True)
    rows.append(dirty)
    if args.ci:
        rows.append(check_ci(root, args.gh_cmd))

    print("netwatch-ai 收工自检")
    for r in rows:
        mark = "⚠" if r["skipped"] else MARK[r["ok"]]
        print("  %s %-18s %s" % (mark, r["name"], r["detail"]))
    failed = [r for r in rows if not r["ok"]]
    passed = [r for r in rows if r["ok"] and not r["skipped"]]
    skipped = [r for r in rows if r["skipped"]]
    tail = "结论：%d 项通过、%d 项失败" % (len(passed), len(failed))
    if skipped:
        tail += "、%d 项跳过" % len(skipped)
    print(tail)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

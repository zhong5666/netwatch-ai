#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/preflight.py 单测：收工自检的三类检查与汇总口径（不跑真测试、不碰网络）。

假仓库里造 demo 输出 + README（用 sync_readme_block --write 生成，保证初始就是一致的），
git 仓库用真的 `git init` 造 —— 这样「未跟踪文件会被点名」这件事是真的被 git 回答的。
"""
import subprocess
import sys
from pathlib import Path

import preflight
import sync_readme_block as srb

ROOT = Path(__file__).resolve().parents[1]

SRC = """# demo 输出（测试用假样本）
==========
# 场景一：正常
=== netwatch-ai 巡检报告 2026-01-01 10:00:00 ===
✓ a                  127.0.0.1   在线 (连续离线 0 次)

==========
# 场景二：服务挂了
=== netwatch-ai 巡检报告 2026-01-01 10:05:00 ===
✗ a                  127.0.0.1   异常 (连续离线 1 次)

  └ 明细: ICMP 不通 (rc=1)

==========
# 场景五：可用率报告
$ python netwatch.py --report 7d
=== netwatch-ai 可用率报告 (2025-12-25 10:00:00 ~ 2026-01-01 10:00:00) ===

设备                 轮次      可用率       探测耗时     平均RTT
a                        2     50.0%        1021ms        <1ms

⚠️ 可用率低于 99% 的设备 1 台：a(50.0%)
"""

README = """# netwatch-ai

## 效果

```
=== netwatch-ai 巡检报告 占位 ===
占位
```

## 历史数据与可用率报告

```
=== netwatch-ai 可用率报告 占位 ===
占位
```
"""


def _git(root, *args):
    subprocess.check_call(["git", "-C", str(root)] + list(args),
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def make_repo(tmp_path, committed=True):
    """造一个「README 已同步、干净」的假仓库；committed=False 时只 init 不提交。"""
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / "sample_output.txt").write_text(SRC, encoding="utf-8")
    (tmp_path / "README.md").write_text(README, encoding="utf-8")
    srb.sync_all(tmp_path, write=True)          # 用被测工具自己生成一致状态
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    if committed:
        _git(tmp_path, "add", "-A")
        _git(tmp_path, "commit", "-q", "-m", "init")
    return tmp_path


def fake_pytest(tmp_path, line="301 passed in 0.4s", exit_code=0):
    """造一个假 pytest 可执行脚本：命令行里只有路径，不会被空格/引号拆错。"""
    script = tmp_path.parent / ("_fake_pytest_%s.py" % tmp_path.name)   # 放在仓库外，别污染工作区
    script.write_text("import sys\nprint(%r)\nsys.exit(%d)\n" % (line, exit_code), encoding="utf-8")
    return [sys.executable, str(script)]


def ok_cmd(tmp_path):
    return fake_pytest(tmp_path)


def main(argv):
    return preflight.main(argv)


# ---------------------------------------------------------------- README 检查
def test_readme_in_sync(tmp_path):
    root = make_repo(tmp_path)
    row = preflight.check_readme(root)
    assert row["ok"] is True
    assert "效果 3 行" in row["detail"] or "逐字一致" in row["detail"]


def test_readme_drift_detected(tmp_path):
    root = make_repo(tmp_path)
    (root / "demo" / "sample_output.txt").write_text(SRC.replace("rc=1", "rc=2"), encoding="utf-8")
    row = preflight.check_readme(root)
    assert row["ok"] is False
    assert "不一致" in row["detail"]


def test_readme_missing_anchor_is_failure_not_crash(tmp_path):
    root = make_repo(tmp_path)
    (root / "README.md").write_text("# 什么都没有\n", encoding="utf-8")
    row = preflight.check_readme(root)      # 不能抛异常出来
    assert row["ok"] is False


def test_own_repo_readme_in_sync():
    """本仓库自己的 README 必须与 demo 输出一致 —— 这条挂了说明我提交时忘了同步。"""
    row = preflight.check_readme(ROOT)
    assert row["ok"] is True, row["detail"]


# ---------------------------------------------------------------- 测试命令
def test_tests_pass(tmp_path):
    root = make_repo(tmp_path)
    rows = preflight.check_tests(root, 60, override=ok_cmd(root))
    assert len(rows) == 1
    assert rows[0]["ok"] is True
    assert "301 passed" in rows[0]["detail"]


def test_tests_fail_carries_exit_code_and_tail(tmp_path):
    root = make_repo(tmp_path)
    rows = preflight.check_tests(root, 60, override=fake_pytest(root, "1 failed, 8 passed", 1))
    assert rows[0]["ok"] is False
    assert "退出码 1" in rows[0]["detail"]
    assert "1 failed" in rows[0]["detail"]


def test_test_commands_skip_when_venv_missing(tmp_path):
    """没有 .venv 时第一行必须是「跳过」，而不是假装跑过。"""
    tools = preflight.test_commands(tmp_path)
    assert tools[0][1] is None
    assert ".venv" in tools[0][2]


# ---------------------------------------------------------------- 工作区
def test_worktree_clean(tmp_path):
    root = make_repo(tmp_path)
    row = preflight.check_worktree(root)
    assert row["ok"] is True
    assert row["detail"] == "干净"


def test_worktree_names_untracked_file(tmp_path):
    root = make_repo(tmp_path)
    (root / "commit_msg.tmp").write_text("oops\n", encoding="utf-8")
    row = preflight.check_worktree(root)
    assert row["ok"] is False
    assert "commit_msg.tmp" in row["detail"]
    assert "未跟踪" in row["detail"]


def test_worktree_separates_modified_from_untracked(tmp_path):
    root = make_repo(tmp_path)
    (root / "README.md").write_text("# 改过了\n", encoding="utf-8")
    (root / "tmp.db").write_text("x\n", encoding="utf-8")
    row = preflight.check_worktree(root)
    assert "1 个文件有改动" in row["detail"]
    assert "tmp.db" in row["detail"]


def test_worktree_not_a_repo_is_skip(tmp_path):
    row = preflight.check_worktree(tmp_path)      # 空目录，不是 git 仓库
    assert row["ok"] is True and row["skipped"] is True


# ---------------------------------------------------------------- 汇总 / 退出码
def test_all_green_exit_zero_and_summary(tmp_path, capsys):
    root = make_repo(tmp_path)
    code = main(["--root", str(root), "--test-cmd", " ".join(ok_cmd(root))])
    out = capsys.readouterr().out
    assert code == 0, out
    assert "3 项通过、0 项失败" in out
    assert "netwatch-ai 收工自检" in out


def test_drift_makes_exit_one(tmp_path, capsys):
    root = make_repo(tmp_path)
    (root / "demo" / "sample_output.txt").write_text(SRC.replace("rc=1", "rc=2"), encoding="utf-8")
    code = main(["--root", str(root), "--test-cmd", " ".join(ok_cmd(root))])
    out = capsys.readouterr().out
    assert code == 1
    assert "2 项失败" in out          # README 漂移 + 源文件被改（也是工作区不干净）
    assert "✗ README 引用段" in out
    assert "sync_readme_block.py --write" in out


def test_fast_skips_tests_but_still_checks_readme(tmp_path, capsys):
    root = make_repo(tmp_path)
    code = main(["--root", str(root), "--fast"])
    out = capsys.readouterr().out
    assert code == 0
    assert "--fast 跳过" in out
    assert "2 项通过" in out          # README + 工作区，测试是跳过项


def test_dirty_fails_unless_allowed(tmp_path, capsys):
    root = make_repo(tmp_path)
    (root / "notes.txt").write_text("tmp\n", encoding="utf-8")
    assert main(["--root", str(root), "--fast"]) == 1
    capsys.readouterr()
    assert main(["--root", str(root), "--fast", "--allow-dirty"]) == 0
    out = capsys.readouterr().out
    assert "--allow-dirty 放行" in out


# ---------------------------------------------------------------- CI（可选，无网）
def test_ci_skipped_without_gh(tmp_path, capsys):
    root = make_repo(tmp_path)
    code = main(["--root", str(root), "--fast", "--ci", "--gh-cmd", "gh-不存在"])
    out = capsys.readouterr().out
    assert code == 0
    assert "没装 gh" in out
    assert "跳过" in out

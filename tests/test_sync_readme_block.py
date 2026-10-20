#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tools/sync_readme_block.py 单测：README 逐字引用段的比对与同步（纯文本，不碰网络/不写仓库）。

假仓库里造一段和 demo 输出同构的文本（两份巡检报告 + 一份可用率报告 + 场景分隔线），
这样「效果段取第二份、到分隔线为止、卡片不能丢」这些规则能被真实执行到。
"""
from pathlib import Path

import pytest

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

🤖 AI 分析:
  └ 影响面: 单台 —— 只有本机不通

==========
# 场景五：可用率报告
$ python netwatch.py --report 7d
=== netwatch-ai 可用率报告 (2025-12-25 10:00:00 ~ 2026-01-01 10:00:00) ===

设备                 轮次      可用率       探测耗时     平均RTT
a                        2     50.0%        1021ms        <1ms

⚠️ 可用率低于 99% 的设备 1 台：a(50.0%)
"""

README_TMPL = """# netwatch-ai

## 效果

```text
{effect}
```

## 历史数据与可用率报告

```bash
python netwatch.py --report 7d
```

```
{report}
```

## 尾巴
"""


def _write(path, text):
    """py3.9 floor：`Path.write_text(newline=)` 是 3.10+ 签名，CI 三个 py3.9 作业会直接 TypeError。"""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _make(tmp_path, effect=None, report=None):
    """铺一个假仓库：demo/sample_output.txt + README.md。默认两段都同步好，传参可造漂移。"""
    (tmp_path / "demo").mkdir(parents=True, exist_ok=True)
    _write(tmp_path / "demo" / "sample_output.txt", SRC)
    readme = tmp_path / "README.md"
    _write(readme, README_TMPL.format(
        effect=srb.slice_effect(SRC) if effect is None else effect,
        report=srb.slice_report(SRC) if report is None else report,
    ))
    return readme


# ---- 切原文的规则（历史上踩过：结束标记写成「第一行 └ 明细」，卡片会被截）----

def test_slice_effect_keeps_card_and_stops_at_scenario_separator():
    blk = srb.slice_effect(SRC)
    assert blk.startswith("=== netwatch-ai 巡检报告 2026-01-01 10:05:00")
    assert "影响面" in blk                      # 卡片必须留在里面
    assert "可用率报告" not in blk               # 不能越到下一场


def test_slice_report_takes_tail_without_trailing_blank_lines():
    blk = srb.slice_report(SRC)
    assert blk.startswith("=== netwatch-ai 可用率报告")
    assert blk.endswith("a(50.0%)")             # 尾部空行要切掉，不然每次同步都算漂移


def test_missing_second_report_raises_clearly():
    with pytest.raises(SystemExit):
        srb.slice_effect("=== netwatch-ai 巡检报告 只有一份\n")


# ---- 比对 / 同步 ----

def test_repo_readme_is_byte_identical_to_demo_output():
    """回归闸门：谁手改了 README 里那两段（或改了 demo 输出忘了同步），这里就红。"""
    results = srb.sync_all(ROOT, write=False)
    assert [r["status"] for r in results] == ["in-sync", "in-sync"], results


def test_check_detects_drift_and_leaves_files_untouched(tmp_path):
    # 漂移的真实形态：标记行还在，内容被手改过（标记行被删的话工具会直接报「找不到标记行」）
    readme = _make(tmp_path, effect=srb.slice_effect(SRC).replace("单台", "全网"))
    before = readme.read_text(encoding="utf-8")
    results = srb.sync_all(tmp_path, write=False)
    assert [r["status"] for r in results] == ["drift", "in-sync"]
    assert "第 7 行起不一致" in results[0]["detail"]        # 报出第一处差异的行号
    assert "全网" in results[0]["detail"]                   # 并给出两边原文，方便对
    assert readme.read_text(encoding="utf-8") == before      # 只读不写
    assert srb.main(["--root", str(tmp_path)]) == 1          # 退出码 1，可直接当收工自检


def test_write_syncs_drift_and_is_idempotent(tmp_path):
    readme = _make(tmp_path,
                   effect=srb.slice_effect(SRC).replace("影响面", "影响"),
                   report=srb.slice_report(SRC).replace("50.0%", "五成"))
    assert [r["status"] for r in srb.sync_all(tmp_path, write=True)] == ["synced", "synced"]
    text = readme.read_text(encoding="utf-8")
    assert srb.slice_effect(SRC) in text and srb.slice_report(SRC) in text
    assert "2026-01-01 10:05:00" in text and "五成" not in text
    assert srb.main(["--root", str(tmp_path)]) == 0          # 同步完就干净
    assert [r["status"] for r in srb.sync_all(tmp_path, write=False)] == ["in-sync", "in-sync"]


def test_refresh_demo_shares_this_tool_instead_of_duplicating_rules():
    """demo/refresh_demo.py 只负责重抓输出，切块/同步规则必须走这一份实现。"""
    import importlib.util
    spec = importlib.util.spec_from_file_location("refresh_demo", ROOT / "demo" / "refresh_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # demo/ 不是包，导入靠 refresh_demo 里插的 sys.path
    assert mod.srb.slice_effect is srb.slice_effect
    assert not hasattr(mod, "pick_scenario")   # 老的重复实现要删掉，别留两份

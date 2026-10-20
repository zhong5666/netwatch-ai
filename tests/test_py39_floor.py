#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""py3.9 floor 静态闸门。

CI 是 Win·macOS·Linux × py3.9/3.11/3.12 九个作业，本地 venv 是 3.11 —— 用了 3.10+ 的 API 时
本地照样全绿，只有推送后三个 py3.9 作业一起红（`Path.write_text(newline=)` 已经踩过两次：
v0.8 的 `report_html.py`、v0.10 的测试辅助函数）。这个测试把这类硬 API 提到本地就拦下来。

关键点：只扫**真代码**，注释和字符串里的反面例子不算（否则文档里写一句
「别用 Path.write_text(newline=)」就被自己的护栏误伤）。用 tokenize 把 STRING/COMMENT 抹成
等长空格，行号不漂。

只列「本地跑得通、3.9 直接报错」的硬 API；不做完整语法检查（那交给 CI 的 py3.9 作业）。
"""

import io
import re
import tokenize
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".venv", ".git", "__pycache__", ".pytest_cache", "venv", "env"}

# (名字, 正则, 最低版本, 替代写法)
BANNED = (
    (
        "Path.write_text/read_text(newline=)",
        r"\.(?:write|read)_text\([^)]*newline\s*=",
        "3.10",
        'open(path, "w", encoding="utf-8", newline="\\n")',
    ),
    ("zip(strict=)", r"\bzip\([^)]*strict\s*=", "3.10", "别传 strict，3.9 没这个参数"),
    ("datetime.UTC / tomllib", r"\bdatetime\.UTC\b|\btomllib\b", "3.11", "timezone.utc / 别用 tomllib"),
)


def _abs_offset(text, line, col):
    """(行, 列) → 字符下标（tokenize 给的是行列，正则要的是下标）。"""
    if line <= 1:
        return col
    lines = text.split("\n")
    return sum(len(part) + 1 for part in lines[: line - 1]) + col


def code_only(text):
    """抹掉注释与字符串字面量：长度和换行数不变，所以行号不漂。"""
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return text  # 拿不到 token 就退回原文：宁可多报，也别漏报
    chars = list(text)
    for tok in toks:
        if tok.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        start = _abs_offset(text, tok.start[0], tok.start[1])
        end = _abs_offset(text, tok.end[0], tok.end[1])
        for i in range(start, min(end, len(chars))):
            if chars[i] != "\n":
                chars[i] = " "
    return "".join(chars)


def _hits(text):
    """返回 [(行号, 名字, 最低版本, 替代写法), ...]，只认真代码里的命中。"""
    cleaned = code_only(text)
    out = []
    for name, pattern, ver, fix in BANNED:
        for match in re.finditer(pattern, cleaned):
            out.append((cleaned[: match.start()].count("\n") + 1, name, ver, fix))
    return out


def _py_files():
    for path in sorted(ROOT.rglob("*.py")):
        if SKIP_DIRS & set(path.parts):
            continue
        yield path


def test_code_only_ignores_comments_and_strings():
    """护栏自身要有效：注释/字符串里的反面例子不该算，真代码才算，行号要准。"""
    src = (
        'a = 1  # p.write_text(t, newline="\\n")\n'
        's = "p.write_text(t, newline=\\"\\\\n\\")"\n'
        'real = p.write_text(t, newline="\\n")\n'
        "multi = p.read_text(\n"
        '    encoding="utf-8",\n'
        '    newline="\\n",\n'
        ")\n"
    )
    cleaned = code_only(src)
    assert len(cleaned) == len(src)              # 长度不变 → 行号不漂
    assert cleaned.count("\n") == src.count("\n")
    assert [h[0] for h in _hits(src)] == [3, 4]  # 第 3 行真代码、第 4 行跨行调用


def test_repo_has_no_post_39_apis():
    offenders = [
        "%s:%d 用了 py%s+ 的 %s → 改成 %s" % (path.relative_to(ROOT), line, ver, name, fix)
        for path in _py_files()
        for line, name, ver, fix in _hits(path.read_text(encoding="utf-8", errors="replace"))
    ]
    assert not offenders, "CI 的 py3.9 作业会红：\n" + "\n".join(offenders)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

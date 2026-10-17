#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AI 告警分析：把异常巡检数据交给大模型，输出故障判断与建议。

设计原则
--------
1. **key 只走环境变量**，不写进代码、不进仓库：
       export NETWATCH_API_KEY=sk-xxxx
2. **接口用 OpenAI 兼容协议**，任何兼容端点都能用：
       export NETWATCH_API_BASE=https://api.deepseek.com/v1   # 默认
       export NETWATCH_MODEL=deepseek-chat                    # 默认
   自建网关 / 中转站同理（如 NETWATCH_API_BASE=https://your-gateway/v1）。
3. **AI 只做补充**：先由程序用规则判断「全网断还是单台断」，AI 负责讲清原因和第一步；
   所以 prompt 里要求它只在给定数据内推理，不许编造。
"""
import json
import os
import urllib.error
import urllib.request

BASE_URL = os.environ.get("NETWATCH_API_BASE", "https://api.deepseek.com/v1")
MODEL = os.environ.get("NETWATCH_MODEL", "deepseek-chat")


def _get_key() -> str:
    for name in ("NETWATCH_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        v = os.environ.get(name)
        if v:
            return v
    raise RuntimeError(
        "未找到 API key：请设置环境变量 NETWATCH_API_KEY（或 DEEPSEEK_API_KEY / OPENAI_API_KEY）"
    )


def rule_hint(abnormal_devices: list, all_results: list) -> str:
    """规则先行：先给出「影响面」的初步判断，再让 AI 补充原因。

    这个判断不需要大模型：全网断 vs 单台断，在运维里是两条完全不同的排查路线。
    """
    total = len(all_results)
    down = len(abnormal_devices)
    if total and down >= total:
        return "规则判断：**全部设备不可达** → 优先怀疑上游/网关/本机网络，而不是逐台查设备。"
    if down == 1:
        return "规则判断：**仅单台设备不可达** → 优先怀疑该设备自身（电源/网线/服务），网络整体是通的。"
    return "规则判断：**多台不可达**（共 %d 台）→ 优先怀疑共同上级（交换机/网关/VLAN）。" % down


def build_prompt(abnormal_devices: list, all_results: list, ts_text: str = "") -> str:
    return (
        "巡检时间：%s\n" % (ts_text or "未知")
        + "全部设备状态：\n"
        + "\n".join(
            "- %s (%s): %s，连续离线%d次" % (r["name"], r["ip"], r["status"], r["streak"])
            for r in all_results
        )
        + "\n\n其中异常设备（含每层探测明细）：\n"
        + "\n".join(
            "- %s (%s): %s" % (d["name"], d["ip"], d.get("detail", ""))
            for d in abnormal_devices
        )
        + "\n\n请判断：1) 故障类型（设备宕机/网络中断/端口或服务异常/其他）"
          " 2) 可能原因 3) 修复建议第一步。"
    )


def analyze(abnormal_devices: list, all_results: list, ts_text: str = "") -> str:
    """输入异常设备 + 全部巡检结果，返回 AI 分析文本。"""
    if not abnormal_devices:
        return "全部设备正常，无需分析。"

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "你是网络运维专家。根据巡检数据判断故障根因，给出修复建议。"
                    "要求：结论先行，用中文，简洁（100字内），不编造数据，"
                    "只基于给出的巡检信息推理。探测明细里的 ICMP/TCP/HTTP 分层结果"
                    "可以用来区分「设备完全失联」和「设备在线但服务挂了」。"
                ),
            },
            {"role": "user", "content": build_prompt(abnormal_devices, all_results, ts_text)},
        ],
        "max_tokens": 300,
        "temperature": 0.3,
    }

    req = urllib.request.Request(
        "%s/chat/completions" % BASE_URL.rstrip("/"),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % _get_key(),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError("AI 接口返回 HTTP %s：%s" % (e.code, e.read()[:200])) from e

    choices = data.get("choices") or []
    content = ""
    if choices:
        content = (choices[0].get("message") or {}).get("content") or ""
    content = content.strip()
    if not content:
        # 实测遇到过：接口被限流时返回 200 但内容为空，这种情况必须显式说明，别静默吞掉
        raise RuntimeError("AI 返回了空内容（可能被限流或模型不可用）")
    return content


def report(abnormal_devices: list, all_results: list, ts_text: str = "",
           use_ai: bool = True) -> str:
    """规则判断 + （可选）AI 分析，拼成最终告警正文。"""
    parts = [rule_hint(abnormal_devices, all_results)]
    if use_ai:
        parts.append(analyze(abnormal_devices, all_results, ts_text))
    return "\n\n".join(parts)


if __name__ == "__main__":
    # 自测：直接传一个模拟异常（需要 NETWATCH_API_KEY 环境变量）
    demo_all = [
        {"name": "server1", "ip": "192.168.136.11", "status": "在线", "streak": 0},
        {"name": "server2", "ip": "192.168.136.12", "status": "离线", "streak": 3},
        {"name": "server3", "ip": "192.168.136.13", "status": "在线", "streak": 0},
    ]
    demo_abnormal = [dict(demo_all[1], detail="ICMP 通 (12ms) | TCP 22 连不上 (timed out)")]
    print(report(demo_abnormal, demo_all, ts_text="2026-10-17 15:00"))

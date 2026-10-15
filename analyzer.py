#!/usr/bin/env python3
"""AI 告警分析：把异常巡检数据交给大模型，输出故障判断与建议。

复用 Hermes 的 siyu.site 中转配置（环境变量注入 key），不写死在代码里。
"""
import json
import os
import urllib.request

BASE_URL = os.environ.get("NETWATCH_API_BASE", "https://siyu.site/v1")
MODEL = os.environ.get("NETWATCH_MODEL", "deepseek-v4-flash")


def _get_key() -> str:
    # 优先项目专用变量，其次复用 Hermes 中转 key
    for name in ("NETWATCH_API_KEY", "HERMES_CUSTOM_SIYU_API_API_KEY"):
        v = os.environ.get(name)
        if v:
            return v
    raise RuntimeError("未找到 API key：请设置 NETWATCH_API_KEY 环境变量")


def analyze(abnormal_devices: list[dict], all_results: list[dict],
            ts_text: str = "") -> str:
    """输入异常设备+全部巡检结果，返回 AI 分析文本"""
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
                    "只基于给出的巡检信息推理。"
                ),
            },
            {
                "role": "user",
                "content": (
                    f"巡检时间：{ts_text or '未知'}\n"
                    "全部设备状态：\n"
                    + "\n".join(
                        f"- {r['name']} ({r['ip']}): {r['status']}，"
                        f"连续离线{r['streak']}次"
                        for r in all_results
                    )
                    + "\n\n其中异常设备：\n"
                    + "\n".join(
                        f"- {d['name']} ({d['ip']}): {d['detail']}"
                        for d in abnormal_devices
                    )
                    + "\n\n请判断：1) 故障类型（设备宕机/网络中断/其他）"
                      " 2) 可能原因 3) 修复建议第一步。"
                ),
            },
        ],
        "max_tokens": 300,
        "temperature": 0.3,
    }

    req = urllib.request.Request(
        f"{BASE_URL}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {_get_key()}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"].strip()


if __name__ == "__main__":
    # 自测：直接传一个模拟异常
    print(analyze(
        abnormal_devices=[{"name": "server2", "ip": "192.168.136.12",
                           "streak": 3, "detail": "ping 5次全丢包"}],
        all_results=[
            {"name": "server1", "ip": "192.168.136.11", "status": "在线",
             "streak": 0},
            {"name": "server2", "ip": "192.168.136.12", "status": "离线",
             "streak": 3},
            {"name": "server3", "ip": "192.168.136.13", "status": "在线",
             "streak": 0},
        ],
        ts_text="2026-10-15 14:20",
    ))
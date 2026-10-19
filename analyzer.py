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
4. **结构化输出**：要求模型只回一个 JSON（故障类型/置信度/影响面/原因/第一步），
   由 parse_analysis 解析成字段后渲染成告警卡片 —— 比一段散文好读，也方便以后接告警平台。
   解析失败**不丢内容**：退回原文渲染，只在卡片上标注「未按 JSON 返回」。
"""
import json
import os
import unicodedata
import urllib.error
import urllib.request

def _int_env(name: str, default: int) -> int:
    """环境变量读整数：写错了就退回默认值，别让 import 阶段直接崩。"""
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


BASE_URL = os.environ.get("NETWATCH_API_BASE", "https://api.deepseek.com/v1")
MODEL = os.environ.get("NETWATCH_MODEL", "deepseek-chat")
# 推理模型（deepseek-v4 这类）会先花一截预算在思考上：实测 max_tokens=300 时
# 300 个 token 全被 reasoning_tokens 吃掉，content 直接是空的；调到 800 时
# 同一 prompt 有时够、有时不够（思考长度会波动），所以默认给到 2000 留余量。
MAX_TOKENS = _int_env("NETWATCH_MAX_TOKENS", 2000)
# 推理模型思考 + 生成一起算，30 秒会读超时：默认给到 60 秒，慢线路可再调大。
TIMEOUT = _int_env("NETWATCH_TIMEOUT", 60)
def _bool_env(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# 实测（2026-10-18，siyu 中转 deepseek-v4-flash，真实巡检 prompt）：
#   裸调推理模型：2000 / 4000 预算全被 reasoning 吃光，content 永远为空；
#   + enable_thinking=false 仍然空想（reasoning 1941）；
#   + response_format=json_object 才收敛：finish=stop、14.8 秒、319 字符真 JSON。
# 所以用推理模型跑本项目，这两个开关缺一不可。
NO_THINKING = _bool_env("NETWATCH_NO_THINKING", False)
JSON_MODE = _bool_env("NETWATCH_JSON_MODE", True)


def _get_key() -> str:
    for name in ("NETWATCH_API_KEY", "DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        v = os.environ.get(name)
        if v:
            return v
    raise RuntimeError(
        "未找到 API key：请设置环境变量 NETWATCH_API_KEY（或 DEEPSEEK_API_KEY / OPENAI_API_KEY）"
    )


FAULT_TYPES = ("设备宕机", "网络中断", "端口或服务异常", "DNS 解析异常", "其他")

# 结构化字段：fault_type / confidence / impact / reason / first_step
ANALYSIS_FIELDS = ("fault_type", "confidence", "impact", "reason", "first_step")

JSON_INSTRUCTION = (
    "请只输出一个 JSON 对象（不要 markdown 代码块、不要多余解释），字段固定为：\n"
    '{"fault_type": "%s",\n' % "|".join(FAULT_TYPES)      # 枚举由 FAULT_TYPES 生成，避免两处写歪
    + ' "confidence": 0.0 到 1.0 之间的小数,\n'
    ' "impact": "影响面：哪些设备/业务受影响",\n'
    ' "reason": "最可能的原因，一句话",\n'
    ' "first_step": "第一步该做什么，给一个具体命令或动作"}\n'
    "只根据上面给出的巡检数据推理；信息不足就把 confidence 给低（如 0.3），"
    "不要编造设备名、IP 或端口。"
)


def dns_failures(devices: list) -> list:
    """挑出「栽在 DNS 解析上」的设备。

    只看结构化字段（``checks[].kind == "dns"`` 且该项不 ok），不做字符串匹配 ——
    改一句文案不该影响判定。结果里没有 checks（老数据/假探测）就当它不是 DNS 故障。
    """
    out = []
    for dev in devices or []:
        for chk in dev.get("checks") or []:
            if chk.get("kind") == "dns" and not chk.get("ok"):
                out.append(dev)
                break
    return out


def _names(devices: list, limit: int = 3) -> str:
    """设备名拼成一行，超过 limit 台就用「等 N 台」收尾（报告别被名字撑爆）。"""
    names = ", ".join(str(d.get("name", "?")) for d in devices[:limit])
    return names if len(devices) <= limit else "%s 等 %d 台" % (names, len(devices))


def rule_hint(abnormal_devices: list, all_results: list) -> str:
    """规则先行：先给出「影响面」的初步判断，再让 AI 补充原因。

    这个判断不需要大模型：全网断 vs 单台断，在运维里是两条完全不同的排查路线。
    优先级（依次判，先命中的说了算）：
    1. 全部设备异常 → 上游/本机网络（此时"部分设备 DNS 失败"只是表象，别被带偏）
    2. 异常设备里**多数是 DNS 解析失败** → DNS 服务器，不是交换机
    3. 单台异常 → 该设备自身（若它正是 DNS 失败，改成指向解析配置）
    4. 其余多台异常 → 共同上级
    """
    total = len(all_results)
    down = len(abnormal_devices)

    if total and down >= total:
        return "规则判断：**全部设备不可达** → 优先怀疑上游/网关/本机网络，而不是逐台查设备。"

    dns_down = dns_failures(abnormal_devices)
    if down >= 2 and len(dns_down) * 2 > down:      # DNS 失败占异常设备的一半以上才算「扎堆」
        return ("规则判断：**多台设备 DNS 解析失败**（%s）→ 线路本身多半是通的，"
                "优先查 DNS 服务器/上游 DNS/本机解析配置，而不是交换机和网线。" % _names(dns_down))

    if down == 1:
        if dns_down:
            return "规则判断：**这台设备是 DNS 解析失败** → 优先查 DNS 服务器与解析配置（网络其它部分是通的）。"
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
        + "\n\n" + JSON_INSTRUCTION
    )


class _Http400(RuntimeError):
    """400：多半是中转不认我们加的某个字段（已实测 reasoning_effort 会被拒）。"""


def _post(payload: dict) -> dict:
    req = urllib.request.Request(
        "%s/chat/completions" % BASE_URL.rstrip("/"),
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % _get_key(),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = "AI 接口返回 HTTP %s：%s" % (e.code, e.read()[:200])
        if e.code == 400:
            raise _Http400(detail) from e
        raise RuntimeError(detail) from e
    except (urllib.error.URLError, TimeoutError) as e:
        raise RuntimeError(
            "AI 接口超时或不可达（上限 %d 秒，可用 NETWATCH_TIMEOUT 调大）：%s" % (TIMEOUT, e)
        ) from e


def _post_with_fallback(payload: dict) -> dict:
    """护栏字段被接口拒时自动降级：宁可少一层约束，也不能让整个分析报错。"""
    try:
        return _post(payload)
    except _Http400 as e:
        if "response_format" not in payload:
            raise
        retry = dict(payload)
        retry.pop("response_format")
        try:
            return _post(retry)
        except RuntimeError:
            raise e


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
                    "要求：用中文，简洁，不编造数据，"
                    "只基于给出的巡检信息推理。探测明细里的 ICMP/TCP/HTTP 分层结果"
                    "可以用来区分「设备完全失联」和「设备在线但服务挂了」。"
                    "严格按用户给的字段返回一个 JSON 对象，不要任何额外文字。"
                ),
            },
            {"role": "user", "content": build_prompt(abnormal_devices, all_results, ts_text)},
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": 0.3,
    }
    if NO_THINKING:
        # 典型场景：deepseek-v4 这类推理模型只会输出思考过程，正式内容永远是空的
        payload["enable_thinking"] = False
    if JSON_MODE:
        # 光关思考不够：实测还得加上强制 JSON，模型才会停止空想、直接给结构化结果
        payload["response_format"] = {"type": "json_object"}

    data = _post_with_fallback(payload)

    choices = data.get("choices") or []
    content, finish = "", ""
    if choices:
        choice = choices[0]
        content = ((choice.get("message") or {}).get("content") or "").strip()
        finish = choice.get("finish_reason") or ""
    if not content:
        # 实测三种空返回要分开说，否则现场会误判成「没故障」或「代码坏了」：
        #   ① 被限流 / 模型不可用 → 200 但 content 空
        #   ② 推理模型把 max_tokens 全花在 reasoning → finish_reason=length
        if finish == "length":
            raise RuntimeError(
                "AI 输出被 max_tokens(%d) 截断：推理模型的思考会吃光预算。"
                "对 deepseek-v4 这类模型请设 NETWATCH_NO_THINKING=1（并保持 NETWATCH_JSON_MODE=1），"
                "或调大 NETWATCH_MAX_TOKENS" % MAX_TOKENS
            )
        raise RuntimeError("AI 返回了空内容（可能被限流或模型不可用）")
    return content


def report(abnormal_devices: list, all_results: list, ts_text: str = "",
           use_ai: bool = True) -> str:
    """规则判断 + （可选）AI 分析，拼成最终告警正文。"""
    parts = [rule_hint(abnormal_devices, all_results)]
    if use_ai:
        parts.append(analyze(abnormal_devices, all_results, ts_text))
    return "\n\n".join(parts)


# ---------------------------------------------------------------- 结构化解析 / 卡片

def _dwidth(s: str) -> int:
    """终端显示宽度：CJK/全角算 2 列、其余算 1 列 —— 画出来的卡片边框才对得齐。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in s)


def _extract_json_object(text: str):
    """从模型输出里抠出第一个 JSON 对象（纯函数）。

    兼容三种常见形态：纯 JSON、```json 围栏、前后夹了客套话。
    抠不出来返回 None，由调用方回退渲染原文。
    """
    if not text:
        return None
    s = text.strip()
    if "```" in s:
        # 取最长的一段，通常就是围栏里的正文（前后散文都更短）
        s = max(s.split("```"), key=len).strip()
        if s.lower().startswith("json"):
            s = s[4:].strip()
    try:
        obj = json.loads(s)
    except (ValueError, TypeError):
        start, end = s.find("{"), s.rfind("}")
        if start == -1 or end <= start:
            return None
        try:
            obj = json.loads(s[start:end + 1])
        except (ValueError, TypeError):
            return None
    return obj if isinstance(obj, dict) else None


def _norm_confidence(value):
    """置信度归一成 0.0~1.0。认不出来返回 None —— 不猜、不编。"""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, str):
        v = value.strip().rstrip("%").strip()
        if not v:
            return None
        try:
            value = float(v)
        except ValueError:
            return None
    if not isinstance(value, (int, float)):
        return None
    v = float(value)
    if v > 1:
        # 模型写 85 / "85%" 时按百分数理解；1~2 之间的值更像写错，直接截到 1.0（保留原文备查）
        v = v / 100.0 if v >= 2 else 1.0
    if v < 0:
        return None
    return round(min(v, 1.0), 2)


def _plain(value) -> str:
    """把字段值压成一行文本（模型偶尔会把列表/字典塞进字符串字段）。"""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "；".join(_plain(v) for v in value)
    if isinstance(value, dict):
        return "；".join("%s: %s" % (k, _plain(v)) for k, v in value.items())
    return str(value).strip()


def parse_analysis(text: str) -> dict:
    """把 AI 输出解析成结构化告警字段（纯函数，不联网，可离线单测）。

    **永远不抛异常**：解析不出来就 ok=False，调用方回退渲染原文 ——
    AI 的结论是花钱换来的，不能因为格式不合规就整段丢掉。
    """
    text = (text or "").strip()
    parsed = {
        "ok": False,
        "raw": text,
        "fault_type": "",
        "confidence": None,
        "confidence_raw": "",
        "impact": "",
        "reason": "",
        "first_step": "",
        "missing": list(ANALYSIS_FIELDS),
    }
    obj = _extract_json_object(text)
    if obj is None:
        return parsed

    parsed["fault_type"] = _plain(obj.get("fault_type"))
    parsed["confidence"] = _norm_confidence(obj.get("confidence"))
    parsed["confidence_raw"] = _plain(obj.get("confidence"))
    parsed["impact"] = _plain(obj.get("impact"))
    parsed["reason"] = _plain(obj.get("reason"))
    parsed["first_step"] = _plain(obj.get("first_step"))
    parsed["missing"] = [f for f in ANALYSIS_FIELDS if parsed.get(f) in (None, "")]
    # 至少要有结论、原因或第一步之一，才算这次解析有内容可用
    parsed["ok"] = any(parsed.get(f) for f in ("fault_type", "impact", "reason", "first_step"))
    return parsed


def render_card(parsed: dict, rule_text: str = "") -> str:
    """把解析结果渲染成告警卡片（纯函数）。

    解析失败时退回原文，标题上标出「未按 JSON 返回」——内容一个字都不删。
    """
    lines = []
    if rule_text:
        lines.append(rule_text)
    if not parsed.get("ok"):
        lines.append("🤖 AI 分析（未按 JSON 返回，原文如下）:")
        lines.append(parsed.get("raw") or "(AI 未返回内容)")
        return "\n".join(lines)

    conf, conf_raw = parsed.get("confidence"), parsed.get("confidence_raw")
    if isinstance(conf, (int, float)):
        conf_text = "%.0f%%" % (conf * 100)
    elif conf_raw:
        conf_text = "未识别(%s)" % conf_raw
    else:
        conf_text = "未给出"

    rows = [
        "类型  : %s" % (parsed.get("fault_type") or "未给出"),
        "置信度: %s" % conf_text,
        "影响面: %s" % (parsed.get("impact") or "未给出"),
        "原因  : %s" % (parsed.get("reason") or "未给出"),
        "第一步: %s" % (parsed.get("first_step") or "未给出"),
    ]
    if parsed.get("missing"):
        rows.append("缺失  : %s" % ", ".join(parsed["missing"]))

    inner = max(_dwidth(r) for r in rows)
    out = lines + ["🤖 AI 故障卡片", "┌" + "─" * (inner + 2) + "┐"]
    for r in rows:
        out.append("│ " + r + " " * (inner - _dwidth(r)) + " │")
    out.append("└" + "─" * (inner + 2) + "┘")
    return "\n".join(out)


if __name__ == "__main__":
    # 自测：直接传一个模拟异常（需要 NETWATCH_API_KEY 环境变量）
    demo_all = [
        {"name": "server1", "ip": "192.168.136.11", "status": "在线", "streak": 0},
        {"name": "server2", "ip": "192.168.136.12", "status": "离线", "streak": 3},
        {"name": "server3", "ip": "192.168.136.13", "status": "在线", "streak": 0},
    ]
    demo_abnormal = [dict(demo_all[1], detail="ICMP 通 (12ms) | TCP 22 连不上 (timed out)")]
    print(report(demo_abnormal, demo_all, ts_text="2026-10-17 15:00"))

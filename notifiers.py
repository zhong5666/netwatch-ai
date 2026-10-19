#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""netwatch-ai 通知层：把巡检结论推到外部渠道（插件化，webhook 先行）。

设计原则
--------
1. **安全默认**：配置里没有 ``notify.channels`` 就什么都不发；即使配了，
   也要命令行显式加 ``--notify`` 才会真发 —— 防止误推到公司群/生产群。
2. **失败隔离**：任何渠道发失败都只打印一行：(1) 不影响巡检结论与退出码，
   (2) 不影响其它渠道；单个渠道失败会重试一次（间隔 1 秒）。
3. **载荷固定**：webhook 统一 POST 一段 JSON（title/text/level/summary/devices/ts），
   任何能收 HTTP 的网关（自建中转、钉钉/企微的代理、IFTTT、n8n）都能接。
   官方钉钉/企业微信的签名与消息体结构不同，后续各作为一个插件加进来，
   不影响已有渠道。
4. **只在会告警的轮次发**：复用 netwatch 的告警去重结论（新异常 / 恢复），
   ``[SILENT]`` 轮不发送 —— 通知层不做第二套判断逻辑。

配置示例
--------
    notify:
      timeout: 5
      channels:
        - type: webhook
          url: https://example.com/netwatch-hook      # 本地自测: http://127.0.0.1:8898/hook

    python netwatch.py --notify                 # 真发
    python netwatch.py --test-notify            # 发一条样例，自检渠道是否通
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

NOTIFY_TIMEOUT_DEFAULT = 5      # 秒；通知卡住不能拖慢巡检
NOTIFY_RETRY = 1                # 失败重试次数（不含首次）


class NotifyConfigError(ValueError):
    """通知配置写错了 —— 当场报出来，别默默不发。"""


@dataclass
class Message:
    """要推送的内容：一段人类可读的正文 + 几个结构化字段。"""

    title: str
    text: str
    level: str = "info"                     # info / warn / recover
    summary: str = ""
    devices: list = field(default_factory=list)
    ts: str = ""

    def to_payload(self) -> dict:
        return {
            "source": "netwatch-ai",
            "title": self.title,
            "text": self.text,
            "level": self.level,
            "summary": self.summary or self.title,
            "devices": list(self.devices),
            "ts": self.ts,
        }


class Notifier:
    """通知渠道基类：子类只需实现 send()，并声明自己的 type。"""

    type = "base"

    def __init__(self, conf: dict | None = None):
        self.conf = conf or {}

    @property
    def timeout(self) -> int:
        try:
            return max(1, int(self.conf.get("timeout", NOTIFY_TIMEOUT_DEFAULT)))
        except (TypeError, ValueError):
            return NOTIFY_TIMEOUT_DEFAULT

    def send(self, msg: Message) -> str:        # pragma: no cover - 抽象
        raise NotImplementedError

    def describe(self) -> str:
        return self.type


class WebhookNotifier(Notifier):
    """把报告 POST 成 JSON 到任意 URL —— 最通用的一种，先做这个。"""

    type = "webhook"

    def __init__(self, conf: dict | None = None):
        super().__init__(conf)
        url = str((conf or {}).get("url") or "").strip()
        if not url:
            raise NotifyConfigError("webhook 渠道缺少 url（例：url: https://example.com/hook）")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise NotifyConfigError("webhook 的 url 必须以 http:// 或 https:// 开头: %r" % url)
        self.url = url

    def describe(self) -> str:
        return "webhook %s" % self.url

    def send(self, msg: Message) -> str:
        body = json.dumps(msg.to_payload(), ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json; charset=utf-8",
                     "User-Agent": "netwatch-ai"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return "HTTP %s" % int(getattr(resp, "status", 200) or 200)


# 渠道注册表：加一个新渠道 = 写一个子类 + 在这里登记一行
REGISTRY = {
    WebhookNotifier.type: WebhookNotifier,
}


def build_notifiers(cfg: dict | None = None) -> list:
    """把配置里的 ``notify.channels`` 实例化成渠道列表（纯函数，不发网络请求）。

    没配 notify（或 channels 为空）= 返回空列表 = 什么都不发（安全默认）。
    配置写错直接抛 NotifyConfigError，让问题当场暴露而不是「以为发了其实没发」。
    """
    notify = (cfg or {}).get("notify") or {}
    channels = notify.get("channels") or []
    if not channels:
        return []
    if not isinstance(channels, (list, tuple)):
        raise NotifyConfigError("notify.channels 必须是列表")

    out = []
    for raw in channels:
        if not isinstance(raw, dict):
            raise NotifyConfigError("每个通知渠道必须是映射，例如 - type: webhook / url: ...")
        kind = str(raw.get("type") or "").strip().lower()
        if not kind:
            raise NotifyConfigError("通知渠道缺少 type 字段")
        cls = REGISTRY.get(kind)
        if cls is None:
            raise NotifyConfigError("不认识的通知渠道 %r（已支持: %s）" % (
                kind, ", ".join(sorted(REGISTRY))))
        conf = {k: v for k, v in raw.items() if k != "type"}
        conf.setdefault("timeout", notify.get("timeout", NOTIFY_TIMEOUT_DEFAULT))
        out.append(cls(conf))
    return out


def send_all(channels, msg: Message, retry: int = NOTIFY_RETRY) -> list:
    """逐个渠道发送，返回每个渠道一行结果。

    约定：**永不抛异常** —— 通知失败是「少一条消息」，不能让巡检本身报错，
    也不能因为一个渠道挂了就不发其它渠道。
    """
    lines = []
    for ch in channels or []:
        label = ch.describe() if hasattr(ch, "describe") else str(ch)
        last_err = None
        for attempt in range(retry + 1):
            try:
                note = ch.send(msg)
                lines.append("✅ 已通知: %s%s" % (label, (" (%s)" % note) if note else ""))
                last_err = None
                break
            except Exception as e:              # noqa: BLE001 - 通知层兜住一切
                last_err = e
                if attempt < retry:
                    time.sleep(1)
        if last_err is not None:
            lines.append("⚠️ 通知失败: %s (%s)" % (label, _short(last_err)))
    return lines


def build_message(data: dict, text: str, ts: str = "") -> Message:
    """按巡检结果拼一条消息（纯函数）。

    level 只有三种，够用且好判断：有新异常 = warn，只有恢复 = recover，其余 = info。
    """
    new_alerts = data.get("new_alerts") or []
    recoveries = data.get("recoveries") or []
    if new_alerts:
        level = "warn"
    elif recoveries:
        level = "recover"
    else:
        level = "info"

    parts = ["⚠️ %s 新异常 (连续离线 %d 次)" % (r["name"], r.get("streak", 0)) for r in new_alerts]
    for r in recoveries:
        mins = r.get("down_minutes")
        if mins is None:
            span = "已恢复"
        elif mins == 0:
            span = "中断不到 1 分钟"
        else:
            span = "中断约 %d 分钟" % mins
        parts.append("✅ %s 已恢复 (%s)" % (r["name"], span))
    summary = "；".join(parts)
    devices = [r["name"] for r in new_alerts] + [r["name"] for r in recoveries]

    if level == "warn":
        # 标题带上设备名 —— 手机通知栏只显示标题，能一眼看出是哪台
        names = ", ".join(r["name"] for r in new_alerts)
        extra = "" if len(new_alerts) == 1 else " 等 %d 台" % len(new_alerts)
        title = "⚠️ netwatch-ai: %s%s 异常" % (names, extra)
    elif level == "recover":
        title = "✅ netwatch-ai: %s 已恢复" % (", ".join(devices) or "设备")
    else:
        title = "netwatch-ai 巡检报告"

    return Message(title=title, text=text, level=level, summary=summary,
                   devices=devices, ts=ts)


def sample_message(ts: str = "") -> Message:
    """自检用的样例消息（--test-notify）。"""
    return Message(
        title="🔔 netwatch-ai 通知自检",
        text="如果你看到这条消息，说明通知渠道配置成功。\n"
             "正式报告只会在「设备新异常」或「设备恢复」时推送。",
        level="info",
        summary="通知渠道自检",
        devices=[],
        ts=ts,
    )


def _short(exc: BaseException, limit: int = 90) -> str:
    text = str(exc).replace("\n", " ").strip()
    return text[:limit] + ("…" if len(text) > limit else "")


if __name__ == "__main__":      # 手动自测：python notifiers.py
    chans = build_notifiers({"notify": {"channels": [{"type": "webhook",
                                                     "url": "http://127.0.0.1:8898/hook"}]}})
    print("渠道:", [c.describe() for c in chans])
    for line in send_all(chans, sample_message(time.strftime("%Y-%m-%d %H:%M:%S"))):
        print(line)

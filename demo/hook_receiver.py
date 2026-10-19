#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""本地假 webhook 接收端：把收到的每条 POST 追加到日志，用来验证通知真的发出去了。

不需要钉钉/企业微信账号，也不用公网 —— 一条命令就能看到 netwatch 推过来的完整载荷：

    python demo/hook_receiver.py 8898 &                    # 日志默认写 hook.log
    python netwatch.py --config demo/config.demo.yaml --notify
    cat hook.log

只做两件事：收 POST、落盘、回 200。收到就说明链路是通的。
"""
from __future__ import annotations

import argparse
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


def make_handler(log_path: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "netwatch-fake-hook/1.0"

        def do_POST(self):                       # noqa: N802 (stdlib 命名)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n).decode("utf-8", "replace")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write("=== %s POST %s ===\n%s\n"
                        % (time.strftime("%Y-%m-%d %H:%M:%S"), self.path, body))
            print("← 收到 %d 字节 → %s" % (n, log_path), flush=True)
            payload = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):            # 访问日志别刷屏
            pass

    return Handler


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="假 webhook 接收端（验证通知用）")
    ap.add_argument("port", nargs="?", type=int, default=8898)
    ap.add_argument("--log", default="hook.log", help="收到的载荷追加到这个文件")
    args = ap.parse_args(argv)
    print("假接收端已启动： http://127.0.0.1:%d/hook  →  %s" % (args.port, args.log))
    try:
        HTTPServer(("127.0.0.1", args.port), make_handler(args.log)).serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

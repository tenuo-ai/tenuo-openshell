#!/usr/bin/env python3
"""Small MCP-shaped effect server used only by the OpenShell E2E demo."""

from __future__ import annotations

import argparse
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    server_version = "tenuo-demo-mcp/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {"ok": True})
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self._json(404, {"error": "not_found"})
            return
        try:
            size = int(self.headers.get("content-length", "0"))
            document = json.loads(self.rfile.read(size))
        except (ValueError, json.JSONDecodeError):
            self._json(400, {"error": "invalid_json"})
            return

        method = document.get("method")
        request_id = document.get("id")
        if method == "tools/call":
            params = document.get("params") or {}
            effect = {
                "tool": params.get("name"),
                "arguments": params.get("arguments") or {},
            }
            effect_log = Path(os.environ["TENUO_DEMO_EFFECT_LOG"])
            with effect_log.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(effect, sort_keys=True) + "\n")
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": "read payments logs in staging",
                            }
                        ]
                    },
                },
            )
            return
        if method == "initialize":
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "tenuo-demo", "version": "1"},
                    },
                },
            )
            return
        if method == "tools/list":
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {
                                "name": "read_logs",
                                "description": "Read service logs",
                                "inputSchema": {"type": "object"},
                            }
                        ]
                    },
                },
            )
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.end_headers()
            return
        self._json(400, {"error": "unsupported_method"})

    def log_message(self, message: str, *args: object) -> None:
        print(message % args, flush=True)

    def _json(self, status: int, body: object) -> None:
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

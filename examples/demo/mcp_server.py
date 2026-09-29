#!/usr/bin/env python3
"""MCP effect server that verifies `_meta.tenuo` before running a tool.

The MCP wire encoding is unpadded URL-safe base64. ``MCPVerifier`` decodes a
raw warrant stack from standard base64, so this server normalizes those fields
and then calls ``MCPVerifier``. A failed check returns JSON-RPC ``-32001`` or
``-32002`` and does not run the tool.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


def require_tenuo() -> None:
    try:
        import tenuo
    except ImportError as exc:
        raise SystemExit("the destination verifier requires the tenuo package") from exc
    parts = tuple(int(piece) for piece in tenuo.__version__.split(".")[:3])
    if parts < (0, 3, 1):
        raise SystemExit(
            f"the destination verifier requires tenuo>=0.3.1, found {tenuo.__version__}"
        )


def standard_b64(value: str) -> str:
    text = value.strip()
    padding = "=" * ((4 - len(text) % 4) % 4)
    raw = base64.urlsafe_b64decode(text + padding)
    return base64.b64encode(raw).decode("ascii")


def normalize_meta(meta: object) -> dict[str, Any] | None:
    """Return `_meta` with Tenuo fields in standard base64, or None when absent."""
    if not isinstance(meta, dict):
        return None
    tenuo = meta.get("tenuo")
    if not isinstance(tenuo, dict):
        return meta
    normalized = dict(tenuo)
    for field in ("warrant", "signature"):
        value = normalized.get(field)
        if isinstance(value, str):
            normalized[field] = standard_b64(value)
    approvals = normalized.get("approvals")
    if isinstance(approvals, list):
        normalized["approvals"] = [
            standard_b64(item) if isinstance(item, str) else item for item in approvals
        ]
    copied = dict(meta)
    copied["tenuo"] = normalized
    return copied


def load_roots(path: Path) -> list[Any]:
    from tenuo import PublicKey

    document = json.loads(path.read_text(encoding="utf-8"))
    sandboxes = document.get("sandboxes")
    if not isinstance(sandboxes, dict) or not sandboxes:
        raise SystemExit("policy has no sandboxes")
    roots: list[Any] = []
    seen: set[str] = set()
    for sandbox in sandboxes.values():
        if not isinstance(sandbox, dict):
            raise SystemExit("policy sandbox entry is not an object")
        entries = sandbox.get("trusted_roots")
        if not isinstance(entries, list) or not entries:
            raise SystemExit("policy sandbox has no trusted roots")
        for item in entries:
            if not isinstance(item, str) or item in seen:
                continue
            seen.add(item)
            try:
                raw = bytes.fromhex(item)
            except ValueError as exc:
                raise SystemExit("trusted root is not hex") from exc
            if len(raw) != 32:
                raise SystemExit("trusted root must be 32 bytes")
            roots.append(PublicKey.from_bytes(raw))
    if not roots:
        raise SystemExit("policy has no trusted roots")
    return roots


class Handler(BaseHTTPRequestHandler):
    server_version = "tenuo-demo-mcp/1"
    verifier: Any = None
    effect_log: Path | None = None

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
        if not isinstance(document, dict):
            self._json(400, {"error": "invalid_json"})
            return

        method = document.get("method")
        request_id = document.get("id")
        if method == "tools/call":
            self._tool_call(request_id, document.get("params"))
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
                            },
                            {
                                "name": "restart_service",
                                "description": "Restart a service",
                                "inputSchema": {"type": "object"},
                            },
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

    def _tool_call(self, request_id: object, params: object) -> None:
        if self.verifier is None or self.effect_log is None:
            self._denied(request_id, -32001)
            return
        if not isinstance(params, dict):
            self._denied(request_id, -32001)
            return
        name = params.get("name")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(name, str) or not name or not isinstance(arguments, dict):
            self._denied(request_id, -32001)
            return
        try:
            meta = normalize_meta(params.get("_meta"))
            result = self.verifier.verify(name, arguments, meta=meta)
        except Exception:
            print(f"destination verifier failed for {name}", flush=True)
            self._denied(request_id, -32001)
            return
        if not result.allowed:
            code = result.jsonrpc_error_code or -32001
            print(f"destination denied {name} code={code}", flush=True)
            self._denied(request_id, code)
            return

        effect = {"tool": name, "arguments": arguments}
        with self.effect_log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(effect, sort_keys=True) + "\n")
        text = (
            "restarted payments in staging"
            if name == "restart_service"
            else "read payments logs in staging"
        )
        self._json(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"content": [{"type": "text", "text": text}]},
            },
        )

    def _denied(self, request_id: object, code: int) -> None:
        self._json(
            200,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": code, "message": "Authorization denied"},
            },
        )

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
    require_tenuo()
    from tenuo import Authorizer
    from tenuo.mcp import MCPVerifier

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args()
    effect_log = os.environ.get("TENUO_DEMO_EFFECT_LOG")
    if not effect_log:
        raise SystemExit("TENUO_DEMO_EFFECT_LOG is required")
    Handler.verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=load_roots(args.policy)))
    Handler.effect_log = Path(effect_log)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)

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
import contextvars
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


SUPPORTED_PROTOCOL_VERSIONS = {"2025-03-26", "2025-06-18", "2025-11-25"}


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
    accept_all: bool = False
    runtime: Any = None
    receipt_log: Path | None = None
    request_ids: contextvars.ContextVar[str | None] = contextvars.ContextVar(
        "tenuo_demo_request_id", default=None
    )
    receipt_lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._json(200, {"ok": True})
        elif self.path == "/mcp":
            # No server-to-client event stream is offered. MCP clients treat
            # 405 as "not supported" and continue.
            self._json(405, {"error": "method_not_allowed"})
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
            params = document.get("params")
            requested = params.get("protocolVersion") if isinstance(params, dict) else None
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else "2025-11-25"
            self._json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": version,
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
        if self.effect_log is None or (self.verifier is None and not self.accept_all):
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
        if self.accept_all:
            self._execute(request_id, name, arguments)
            return
        token = None
        if request_id is not None:
            token = self.request_ids.set(str(request_id))
        try:
            with self.receipt_lock:
                try:
                    started = time.perf_counter()
                    meta = normalize_meta(params.get("_meta"))
                    result = self.verifier.verify(name, arguments, meta=meta)
                    decision_us = int((time.perf_counter() - started) * 1_000_000)
                    if result.allowed:
                        outcome = "allow"
                        reason = "-"
                    else:
                        outcome = "deny"
                        reason = result.error_type or "authorization_failed"
                    print(
                        f"tenuo_decision request_id={request_id} decision_us={decision_us} "
                        f"outcome={outcome} reason={reason}",
                        flush=True,
                    )
                except Exception:
                    print(f"destination verifier failed for {name}", flush=True)
                    self._denied(request_id, -32001)
                    return
                self._store_receipts()
        finally:
            if token is not None:
                self.request_ids.reset(token)
        if not result.allowed:
            code = result.jsonrpc_error_code or -32001
            print(f"destination denied {name} code={code}", flush=True)
            self._denied(request_id, code)
            return

        self._execute(request_id, name, arguments)

    def _execute(self, request_id: object, name: str, arguments: dict[str, Any]) -> None:
        if self.effect_log is None:
            self._denied(request_id, -32001)
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

    def _store_receipts(self) -> None:
        runtime = self.runtime
        path = self.receipt_log
        if runtime is None or path is None:
            return
        try:
            wires = runtime.drain_receipts()
        except Exception:
            print("receipt was not stored", flush=True)
            return
        if not wires:
            return
        try:
            with path.open("a", encoding="ascii") as handle:
                for wire in wires:
                    handle.write(str(wire).strip() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            runtime.acknowledge_receipts(len(wires))
        except OSError:
            print("receipt was not stored", flush=True)

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


def install_destination_receipts(directory: Path, roots: list[Any]) -> Any:
    """Collect destination receipts with this process's own signing key."""
    import tenuo.receipts as receipts
    from tenuo.identity import HolderIdentity
    from tenuo.runtime import Runtime

    identity = HolderIdentity.generate()
    runtime = Runtime(identity, roots, receipts="collect")
    directory.mkdir(parents=True, exist_ok=True)
    public = identity.public_key.to_bytes().hex()
    (directory / "destination.pub").write_text(public + "\n", encoding="ascii")
    original = receipts.collect_enforcement_receipt

    def collect(result: object, chain_result: object = None, runtime: object = None) -> None:
        request_id = Handler.request_ids.get()
        if request_id:
            try:
                setattr(result, "request_id", request_id)
            except Exception:
                pass
        return original(result, chain_result, runtime=runtime)

    receipts.collect_enforcement_receipt = collect
    Handler.runtime = runtime
    Handler.receipt_log = directory / "destination.jsonl"
    return runtime


def main() -> None:
    require_tenuo()
    from tenuo import Authorizer
    from tenuo.mcp import MCPVerifier

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--accept-all",
        action="store_true",
        help="Run every tools/call. Used only for the OpenShell-only comparison.",
    )
    args = parser.parse_args()
    effect_log = os.environ.get("TENUO_DEMO_EFFECT_LOG")
    if not effect_log:
        raise SystemExit("TENUO_DEMO_EFFECT_LOG is required")
    if args.accept_all:
        Handler.accept_all = True
        Handler.effect_log = Path(effect_log)
        print("accept-all: warrant checks are off", flush=True)
        ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
        return
    roots = load_roots(args.policy)
    runtime = None
    receipt_dir = os.environ.get("TENUO_DEMO_RECEIPT_DIR")
    if receipt_dir:
        runtime = install_destination_receipts(Path(receipt_dir), roots)
    Handler.verifier = MCPVerifier(
        authorizer=Authorizer(trusted_roots=roots),
        runtime=runtime,
    )
    Handler.effect_log = Path(effect_log)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)

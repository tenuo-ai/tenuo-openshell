#!/usr/bin/env python3
"""Deny one restart inside the Agent Toolkit middleware and store the receipt.

The protected function is not called. The receipt signer stays in this process.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from types import NoneType

from nat.middleware.middleware import FunctionMiddlewareContext
from nat.plugins.tenuo import AuthorizationDenied
from nat.plugins.tenuo import TenuoFunctionMiddleware
from nat.plugins.tenuo import authority
from pydantic import BaseModel
from tenuo import PublicKey
from tenuo import SigningKey
from tenuo import Warrant


class Restart(BaseModel):
    service: str
    environment: str
    replicas: int


def load_roots(path: Path) -> list[PublicKey]:
    document = json.loads(path.read_text(encoding="utf-8"))
    sandboxes = document.get("sandboxes")
    if not isinstance(sandboxes, dict) or not sandboxes:
        raise SystemExit("policy has no sandboxes")
    roots: list[PublicKey] = []
    seen: set[str] = set()
    for sandbox in sandboxes.values():
        if not isinstance(sandbox, dict):
            raise SystemExit("policy sandbox entry is not an object")
        entries = sandbox.get("trusted_roots")
        if not isinstance(entries, list):
            raise SystemExit("policy sandbox has no trusted roots")
        for item in entries:
            if not isinstance(item, str) or item in seen:
                continue
            seen.add(item)
            raw = bytes.fromhex(item)
            if len(raw) != 32:
                raise SystemExit("trusted root must be 32 bytes")
            roots.append(PublicKey.from_bytes(raw))
    if not roots:
        raise SystemExit("policy has no trusted roots")
    return roots


def install_receipts(directory: Path, roots: list[PublicKey], request_id: str):
    import tenuo.receipts as receipts
    from tenuo.identity import HolderIdentity
    from tenuo.runtime import Runtime

    identity = HolderIdentity.generate()
    runtime = Runtime(identity, roots, receipts="collect")
    runtime.install()
    directory.mkdir(parents=True, exist_ok=True)
    public = identity.public_key.to_bytes().hex()
    (directory / "agent-toolkit.pub").write_text(public + "\n", encoding="ascii")
    original = receipts.collect_enforcement_receipt

    def collect(result: object, chain_result: object = None, runtime: object = None) -> None:
        try:
            setattr(result, "request_id", request_id)
        except Exception:
            pass
        return original(result, chain_result, runtime=runtime)

    receipts.collect_enforcement_receipt = collect
    return runtime


async def deny_restart(middleware: TenuoFunctionMiddleware, bound) -> None:
    async def call_next(*_args, **_kwargs):
        raise SystemExit("the function ran")

    arguments = {"service": "payments", "environment": "staging", "replicas": 3}
    context = FunctionMiddlewareContext(
        name="restart_service",
        config=None,
        description=None,
        input_schema=Restart,
        single_output_schema=NoneType,
        stream_output_schema=NoneType,
    )
    with authority(bound):
        try:
            await middleware.function_middleware_invoke(
                arguments,
                call_next=call_next,
                context=context,
            )
        except AuthorizationDenied as exc:
            if exc.category != "tool_denied":
                raise SystemExit(f"unexpected denial category {exc.category}") from exc
            return
    raise SystemExit("the restart was allowed")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--warrant", type=Path, required=True)
    parser.add_argument("--holder-key", type=Path, required=True)
    parser.add_argument("--receipt-dir", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    args = parser.parse_args()

    roots = load_roots(args.policy)
    secret = args.holder_key.read_bytes()
    if len(secret) != 32:
        raise SystemExit("holder key must be 32 bytes")
    holder = SigningKey.from_bytes(secret)
    warrant = Warrant.from_bytes(args.warrant.read_bytes())
    runtime = install_receipts(args.receipt_dir, roots, args.request_id)
    middleware = TenuoFunctionMiddleware(trusted_roots=roots)
    asyncio.run(deny_restart(middleware, warrant.bind(holder)))
    wires = runtime.drain_receipts()
    if not wires:
        raise SystemExit("in-process denial produced no receipt")
    path = args.receipt_dir / "agent-toolkit.jsonl"
    with path.open("a", encoding="ascii") as handle:
        for wire in wires:
            handle.write(str(wire).strip() + "\n")
    runtime.acknowledge_receipts(len(wires))
    print("PASS in-process restart was denied before the function ran")


if __name__ == "__main__":
    main()

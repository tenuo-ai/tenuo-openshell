#!/usr/bin/env python3
"""A minimal per-request warrant issuance service.

An orchestrator calls this service once per task. The service authenticates
the caller, looks up what that principal may do for the named task, and mints
a short-lived root warrant for the holder public key the task's sandbox
generated. The orchestrator installs the result with
`tenuo-openshell-agent install-warrant`.

This is a reference, not a product:

- Callers authenticate with static bearer tokens. Replace `Authenticator`
  with your identity provider (OIDC, mTLS, workload identity).
- The issuer key is read from a file. `load_issuer` is the one place a
  KMS- or HSM-backed signer would go once Tenuo core can mint with one; see
  docs/production-issuance.md.
- It uses only the standard library and the public `tenuo` package.

Run it:

    python3 issuer_service.py --issuer-key issuer.key \
        --grants grants.json --callers callers.json --audit-log issued.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tenuo import (
    Exact,
    OneOf,
    Pattern,
    PublicKey,
    Range,
    SigningKey,
    Warrant,
    Wildcard,
    encode_warrant_stack,
)

HOLDER = re.compile(r"^[0-9a-f]{64}$")
MAX_BODY = 4096


class IssuanceError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code


def load_issuer(path: Path) -> SigningKey:
    """Read a 32-byte issuer key, raw or hex, as `tenuo-openshell` does."""
    raw = path.read_bytes()
    if len(raw) != 32:
        raw = bytes.fromhex(raw.decode().strip())
    if len(raw) != 32:
        raise ValueError(f"{path}: issuer key must be 32 bytes")
    return SigningKey.from_bytes(raw)


class Authenticator:
    """Map a bearer token to a principal.

    `callers.json` maps the SHA-256 of each token (hex) to a principal name,
    so the file holds no usable secret.
    """

    def __init__(self, callers: dict[str, str]):
        self._callers = {digest.lower(): name for digest, name in callers.items()}

    def principal(self, header: str | None) -> str:
        if not header or not header.startswith("Bearer "):
            raise IssuanceError(401, "unauthenticated", "missing bearer token")
        digest = hashlib.sha256(header[len("Bearer ") :].strip().encode()).hexdigest()
        for known, name in self._callers.items():
            if hmac.compare_digest(known, digest):
                return name
        raise IssuanceError(401, "unauthenticated", "unknown bearer token")


def constraint(spec: Any) -> Any:
    """Convert one argument spec, in the `--capabilities` format, to a constraint.

    tenuo 0.3.2's Python `Exact` and `OneOf` take strings only.
    """
    if not isinstance(spec, dict):
        return Exact(str(spec))
    if len(spec) != 1:
        raise ValueError("use one of exact, one_of, pattern, range, wildcard")
    kind, value = next(iter(spec.items()))
    if kind == "exact":
        return Exact(str(value))
    if kind == "one_of":
        return OneOf([str(item) for item in value])
    if kind == "pattern":
        return Pattern(value)
    if kind == "range":
        return Range(min=value.get("min"), max=value.get("max"))
    if kind == "wildcard" and value is True:
        return Wildcard()
    raise ValueError(f"unknown constraint {kind}")


class Grants:
    """What each principal may receive for each task.

    `grants.json`:

        {"max_ttl_secs": 900,
         "principals": {"alice": {"triage": {"read_logs": {...}}}}}

    Each task maps tools to argument constraints in the same format as
    `tenuo-openshell warrant issue --capabilities`. A principal gets exactly
    what is listed for that task, and nothing for an unlisted task.
    """

    def __init__(self, document: dict[str, Any]):
        self.max_ttl = int(document.get("max_ttl_secs", 900))
        self._principals = document["principals"]
        for tasks in self._principals.values():
            for tools in tasks.values():
                self._compile(tools)

    @staticmethod
    def _compile(tools: dict[str, Any]) -> dict[str, dict[str, Any]]:
        if not tools:
            raise ValueError("a task must grant at least one tool")
        return {
            tool: {field: constraint(spec) for field, spec in arguments.items()}
            for tool, arguments in tools.items()
        }

    def capabilities(self, principal: str, task: str) -> dict[str, dict[str, Any]]:
        tools = self._principals.get(principal, {}).get(task)
        if tools is None:
            raise IssuanceError(403, "not_granted", f"{principal} may not run {task}")
        return self._compile(tools)


class Issuer:
    def __init__(self, key: SigningKey, grants: Grants, audit_log: Path):
        self._key = key
        self._grants = grants
        self._audit_log = audit_log
        self._lock = threading.Lock()

    @property
    def public_key(self) -> str:
        return bytes(self._key.public_key.to_bytes()).hex()

    def issue(self, principal: str, request: dict[str, Any]) -> dict[str, Any]:
        holder_hex = str(request.get("holder", "")).lower()
        if not HOLDER.match(holder_hex):
            raise IssuanceError(400, "bad_request", "holder must be 64 hex characters")
        if holder_hex == self.public_key:
            raise IssuanceError(400, "bad_request", "holder must not be the issuer")
        task = request.get("task")
        if not isinstance(task, str):
            raise IssuanceError(400, "bad_request", "task is required")
        ttl = request.get("ttl", self._grants.max_ttl)
        if not isinstance(ttl, int) or ttl < 1:
            raise IssuanceError(400, "bad_request", "ttl must be a positive integer")
        ttl = min(ttl, self._grants.max_ttl)

        capabilities = self._grants.capabilities(principal, task)
        holder = PublicKey.from_bytes(bytes.fromhex(holder_hex))
        request_id = str(uuid.uuid4())
        builder = Warrant.mint_builder().holder(holder).ttl(ttl)
        for tool, constraints in capabilities.items():
            builder = builder.capability(tool, constraints)
        # session_id is signed into the warrant, so the principal travels with
        # it and appears in every receipt's warrant chain.
        warrant = builder.session_id(f"{principal}/{request_id}").mint(self._key)

        issued_at = int(time.time())
        record = {
            "time": issued_at,
            "request_id": request_id,
            "principal": principal,
            "task": task,
            "holder": holder_hex,
            "warrant_id": warrant.id,
            "tools": sorted(capabilities),
            "expires_at": issued_at + ttl,
        }
        with self._lock, self._audit_log.open("a") as log:
            log.write(json.dumps(record, sort_keys=True) + "\n")
        return {
            **record,
            "session_id": warrant.session_id,
            "warrant": encode_warrant_stack([warrant]),
        }


def handler(issuer: Issuer, authenticator: Authenticator) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "tenuo-issuance-example"

        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/v1/issuer":
                self._send(200, {"public_key": issuer.public_key})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                if self.path != "/v1/warrants":
                    raise IssuanceError(404, "not_found", "unknown path")
                principal = authenticator.principal(self.headers.get("Authorization"))
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0 or length > MAX_BODY:
                    raise IssuanceError(400, "bad_request", "body required, at most 4 KiB")
                try:
                    request = json.loads(self.rfile.read(length))
                except json.JSONDecodeError as error:
                    raise IssuanceError(400, "bad_request", "body is not JSON") from error
                if not isinstance(request, dict):
                    raise IssuanceError(400, "bad_request", "body must be an object")
                self._send(201, issuer.issue(principal, request))
            except IssuanceError as error:
                self._send(error.status, {"error": error.code, "message": str(error)})

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            pass  # The audit log is the record; do not log tokens or bodies.

    return Handler


def serve(issuer: Issuer, authenticator: Authenticator, host: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), handler(issuer, authenticator))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--issuer-key", type=Path, required=True)
    parser.add_argument("--grants", type=Path, required=True)
    parser.add_argument("--callers", type=Path, required=True)
    parser.add_argument("--audit-log", type=Path, default=Path("issued.jsonl"))
    parser.add_argument("--listen", default="127.0.0.1:8471")
    args = parser.parse_args()

    issuer = Issuer(
        load_issuer(args.issuer_key),
        Grants(json.loads(args.grants.read_text())),
        args.audit_log,
    )
    authenticator = Authenticator(json.loads(args.callers.read_text()))
    host, port = args.listen.rsplit(":", 1)
    server = serve(issuer, authenticator, host, int(port))
    print(f"issuer {issuer.public_key}", flush=True)
    print(f"listening on http://{args.listen}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

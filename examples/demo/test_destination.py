#!/usr/bin/env python3
"""The effect server checks a warrant even when OpenShell is not on the path."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def post(port: int, document: dict) -> dict:
    payload = json.dumps(document).encode()
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        data=payload,
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        body = json.loads(response.read().decode())
    return body


def assert_denied(body: dict) -> None:
    error = body["error"]
    if error["code"] != -32001 or error["message"] != "Authorization denied":
        raise SystemExit(f"unexpected denial: {body}")
    if set(error) != {"code", "message"}:
        raise SystemExit(f"denial carries extra fields: {error}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()
    fixture = args.fixture
    effect_log = fixture / "effects.jsonl"
    effect_log.write_text("", encoding="utf-8")
    port = free_port()
    server = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).with_name("mcp_server.py")),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--policy",
            str(fixture / "policy.json"),
        ],
        env={**os.environ, "TENUO_DEMO_EFFECT_LOG": str(effect_log)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            if server.poll() is not None:
                raise SystemExit(server.stdout.read() if server.stdout else "server exited")
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
                    if response.status == 200:
                        break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("destination server did not start")

        allowed = json.loads((fixture / "task-a-read.json").read_text(encoding="utf-8"))
        body = post(port, allowed)
        if body.get("result", {}).get("content", [{}])[0].get("text") != "read payments logs in staging":
            raise SystemExit(f"allowed call was not executed: {body}")

        denied = json.loads((fixture / "task-b-restart.json").read_text(encoding="utf-8"))
        assert_denied(post(port, denied))
        missing = json.loads((fixture / "missing-warrant.json").read_text(encoding="utf-8"))
        assert_denied(post(port, missing))

        lines = [line for line in effect_log.read_text(encoding="utf-8").splitlines() if line]
        if len(lines) != 1:
            raise SystemExit(f"effect log should contain only the allowed call: {lines}")
        recorded = json.loads(lines[0])
        if recorded["tool"] != "read_logs" or recorded["arguments"]["service"] != "payments":
            raise SystemExit(f"unexpected effect: {recorded}")
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
    print("destination verifier ok")


if __name__ == "__main__":
    main()

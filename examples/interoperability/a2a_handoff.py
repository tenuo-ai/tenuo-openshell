#!/usr/bin/env python3
"""Exercise a real Tenuo A2A interoperability handoff with an attenuated warrant."""

from __future__ import annotations

import argparse
import asyncio
import base64
import io
import json
import time
import uuid

import httpx
import uvicorn

from tenuo import SigningKey, Warrant, encode_warrant_stack
from tenuo.a2a import A2AServer


async def run(port: int) -> dict:
    root = SigningKey.generate()
    parent = SigningKey.generate()
    worker = SigningKey.generate()

    server = A2AServer(
        name="OpenShell delegated worker",
        url=f"http://127.0.0.1:{port}",
        public_key=worker.public_key,
        trusted_issuers=[root.public_key],
        require_warrant=True,
        require_audience=False,
        require_pop=True,
        check_replay=True,
        audit_log=io.StringIO(),
    )
    effects: list[str] = []

    @server.skill("read_logs")
    async def read_logs(service: str, environment: str) -> str:
        effects.append(f"read:{service}:{environment}")
        return f"read {service} logs in {environment}"

    @server.skill("restart_service")
    async def restart_service(service: str, environment: str, replicas: int) -> str:
        effects.append(f"restart:{service}:{environment}:{replicas}")
        return "restarted"

    parent_warrant = (
        Warrant.mint_builder()
        .capability("read_logs")
        .capability("restart_service")
        .holder(parent.public_key)
        .ttl(300)
        .mint(root)
    )
    child_warrant = parent_warrant.attenuate(
        signing_key=parent,
        holder=worker.public_key,
        capabilities={"read_logs": {}},
        ttl_seconds=120,
    )
    denied_warrant = parent_warrant.attenuate(
        signing_key=parent,
        holder=worker.public_key,
        capabilities={"read_logs": {}},
        ttl_seconds=120,
    )

    uvicorn_server = uvicorn.Server(
        uvicorn.Config(server.app, host="127.0.0.1", port=port, log_level="error", lifespan="off")
    )
    task = asyncio.create_task(uvicorn_server.serve())
    try:
        for _ in range(100):
            if uvicorn_server.started:
                break
            await asyncio.sleep(0.05)
        else:
            raise RuntimeError("A2A server did not start")

        async def send(warrant: Warrant, skill: str, arguments: dict, message: str) -> dict:
            stack = encode_warrant_stack([parent_warrant, warrant])
            signature = warrant.sign(worker, skill, arguments, int(time.time()))
            task_id = str(uuid.uuid4())
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"http://127.0.0.1:{port}/a2a",
                    headers={
                        "X-Tenuo-Warrant": stack,
                        "X-Tenuo-PoP": base64.urlsafe_b64encode(bytes(signature)).decode("ascii"),
                    },
                    json={
                        "jsonrpc": "2.0",
                        "method": "task/send",
                        "params": {
                            "task": {
                                "id": task_id,
                                "message": {
                                    "role": "user",
                                    "parts": [{"type": "text", "text": message}],
                                },
                                "skill": skill,
                                "arguments": arguments,
                            }
                        },
                        "id": 1,
                    },
                )
            response.raise_for_status()
            return response.json()

        read = await send(
            child_warrant,
            "read_logs",
            {"service": "payments", "environment": "staging"},
            "Read the staging payments log",
        )
        restart = await send(
            denied_warrant,
            "restart_service",
            {"service": "payments", "environment": "staging", "replicas": 3},
            "Restart the staging payments service",
        )
        error_text = json.dumps(restart.get("error", {})).lower()
        if "skill_not_granted" not in error_text and "not granted" not in error_text:
            raise RuntimeError("attenuated A2A warrant did not deny restart_service")
        if effects != ["read:payments:staging"]:
            raise RuntimeError(f"unexpected A2A effects: {effects}")
        return {
            "transport": "a2a-jsonrpc-http",
            "proof_of_possession": True,
            "chain_depth": child_warrant.depth,
            "read_output": read["result"]["output"],
            "restart_outcome": "denied-before-skill",
            "effects": effects,
        }
    finally:
        uvicorn_server.should_exit = True
        await task


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    result = asyncio.run(run(args.port))
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        from pathlib import Path

        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")


if __name__ == "__main__":
    main()

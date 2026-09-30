#!/usr/bin/env python3
"""An unmodified MCP client for the demo sandbox.

This is ordinary MCP Python SDK code with no Tenuo imports. It points at the
`tenuo-openshell-agent proxy` on loopback, which signs each tools/call with the
sandbox's holder key. It prints one JSON object with each call's outcome.
"""

from __future__ import annotations

import asyncio
import json
import sys

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError

CALLS = [
    ("read_logs", {"service": "payments", "environment": "staging"}),
    ("restart_service", {"service": "payments", "environment": "staging", "replicas": 3}),
]


async def main(url: str) -> dict:
    results: dict = {}
    async with streamablehttp_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            results["tools"] = sorted(tool.name for tool in listed.tools)
            for name, arguments in CALLS:
                try:
                    result = await session.call_tool(name, arguments)
                except McpError as error:
                    data = error.error.data if isinstance(error.error.data, dict) else {}
                    tenuo = data.get("tenuo", {}) if isinstance(data, dict) else {}
                    results[name] = {
                        "outcome": "deny",
                        "code": error.error.code,
                        "reason": tenuo.get("code", ""),
                        "source": tenuo.get("source", ""),
                    }
                    continue
                text = " ".join(
                    part.text for part in result.content if getattr(part, "type", "") == "text"
                )
                results[name] = {
                    "outcome": "error" if result.isError else "allow",
                    "text": text,
                }
    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: mcp_client.py <mcp url>")
    print(json.dumps(asyncio.run(main(sys.argv[1])), sort_keys=True))

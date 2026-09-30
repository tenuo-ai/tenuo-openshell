#!/usr/bin/env python3
"""OpenAI-compatible chat endpoint that replays a fixed ReAct script.

It lets the example run without a model or an API key. NAT's standard
`openai` LLM client talks to it exactly as it would to a hosted model.
Each workflow run replays the script from the start.
"""

from __future__ import annotations

import argparse
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT = [
    "Thought: I should read the staging payments logs first.\n"
    "Action: ops__read_logs\n"
    'Action Input: {"service": "payments", "environment": "staging"}',
    "Thought: The logs show errors, so I will restart the service.\n"
    "Action: ops__restart_service\n"
    'Action Input: {"service": "payments", "environment": "staging", "replicas": 3}',
    "Thought: I now know the final answer\n"
    "Final Answer: Read the staging payments logs and requested a restart.",
]


class Handler(BaseHTTPRequestHandler):
    turn = 0

    def log_message(self, *_args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        messages = request.get("messages", [])
        # A new run starts with no prior assistant turns in the transcript.
        if not any(message.get("role") == "assistant" for message in messages) and not any(
            "Observation" in str(message.get("content", "")) for message in messages[1:]
        ):
            Handler.turn = 0
        text = SCRIPT[min(Handler.turn, len(SCRIPT) - 1)]
        Handler.turn += 1
        created = int(time.time())
        if request.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for delta, finish in (({"role": "assistant", "content": text}, None), ({}, "stop")):
                chunk = {
                    "id": "scripted",
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": request.get("model", "scripted"),
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
                }
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
        body = {
            "id": "scripted",
            "object": "chat.completion",
            "created": created,
            "model": request.get("model", "scripted"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()

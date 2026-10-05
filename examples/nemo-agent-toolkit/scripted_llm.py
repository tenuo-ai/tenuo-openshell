#!/usr/bin/env python3
"""OpenAI-compatible chat endpoint that plays a scripted ReAct model.

It lets the examples run without a model or an API key. NAT's standard
`openai` LLM client talks to it exactly as it would to a hosted model.

The script follows the question, the way a model would:

- "logs" or "investigate" reads the logs of the service and environment the
  question names;
- "restart" or "fix" restarts that service, with the replica count the
  question names (3 by default);
- both do both, in that order; and
- after the last tool call, the answer reports each tool's result.

The service is the first of payments or identity in the question, payments by
default; the environment the first of staging, production, or dev, staging by
default. It keeps no state between requests: each one carries the transcript
so far.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SERVICES = ("payments", "identity")
ENVIRONMENTS = ("staging", "production", "dev")


def first_of(text: str, words: tuple[str, ...]) -> str:
    found = [(text.find(word), word) for word in words if word in text]
    return min(found)[1] if found else words[0]


def plan(question: str) -> list[tuple[str, dict]]:
    """The tool calls the question asks for, in order."""
    text = question.lower()
    target = {"service": first_of(text, SERVICES), "environment": first_of(text, ENVIRONMENTS)}
    calls = []
    if "log" in text or "investigate" in text:
        calls.append(("read_logs", dict(target)))
    if "restart" in text or "fix" in text:
        # Bounded: the prompt is untrusted, and an unbounded digit run makes
        # this search polynomial.
        replicas = re.search(r"\b(\d{1,4}) {0,3}replicas?\b", text[:4096])
        calls.append(("restart_service", {**target, "replicas": int(replicas.group(1)) if replicas else 3}))
    return calls or [("read_logs", dict(target))]


def question_of(messages: list[dict]) -> str:
    for message in messages:
        if message.get("role") == "user":
            found = re.search(r"Question:\s*(.*)", str(message.get("content", "")))
            if found:
                return found.group(1).strip()
    return ""


def observations_of(messages: list[dict]) -> list[str]:
    """Tool results so far: the turns after the question that the model did not write."""
    seen_question = False
    results = []
    for message in messages:
        content = str(message.get("content") or "")
        if not seen_question:
            seen_question = message.get("role") == "user" and "Question:" in content
            continue
        if message.get("role") != "assistant":
            results.append(re.sub(r"^\s*Observation:\s*", "", content).strip())
    return results


def summary(calls: list[tuple[str, dict]], results: list[str]) -> str:
    lines = []
    for (tool, _arguments), result in zip(calls, results):
        failed = re.search(r"(?:tool call failed:|Last error:)\s*(.*)", result, re.I | re.S)
        if failed:
            # The first clause, with any request hash shortened.
            reason = re.split(r" \(`|;", failed.group(1).strip(), maxsplit=1)[0]
            reason = re.sub(r"\b([0-9a-f]{12})[0-9a-f]{52}\b", r"\1", reason)
            lines.append(f"{tool} did not run: {reason}.")
        else:
            lines.append(f"{tool} ran: {result}")
    return " ".join(lines)


def next_turn(messages: list[dict]) -> str:
    calls = plan(question_of(messages))
    results = observations_of(messages)
    if len(results) < len(calls):
        tool, arguments = calls[len(results)]
        return (
            f"Thought: I will call {tool}.\n"
            f"Action: ops__{tool}\n"
            f"Action Input: {json.dumps(arguments)}"
        )
    return f"Thought: I now know the final answer\nFinal Answer: {summary(calls, results)}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        size = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(size) or b"{}")
        text = next_turn(request.get("messages", []))
        created = int(time.time())
        model = request.get("model", "scripted")
        if request.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for delta, finish in (({"role": "assistant", "content": text}, None), ({}, "stop")):
                chunk = {
                    "id": "scripted",
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
                }
                self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.write(b"data: [DONE]\n\n")
            return
        body = {
            "id": "scripted",
            "object": "chat.completion",
            "created": created,
            "model": model,
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

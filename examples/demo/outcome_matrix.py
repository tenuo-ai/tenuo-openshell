#!/usr/bin/env python3
"""Compare one live OpenShell run with one live OpenShell + Tenuo run.

The rows come from the observation log. This file checks those rows and adds
the destination and Agent Toolkit timing samples.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import time
from pathlib import Path
from types import NoneType

from nat.middleware.middleware import FunctionMiddlewareContext
from nat.plugins.tenuo import AuthorizationDenied
from nat.plugins.tenuo import TenuoFunctionMiddleware
from nat.plugins.tenuo import authority
from pydantic import BaseModel
from tenuo import Authorizer
from tenuo import PublicKey
from tenuo import SigningKey
from tenuo import Warrant
from tenuo.mcp import MCPVerifier


class Restart(BaseModel):
    service: str
    environment: str
    replicas: int


# Outcome with Tenuo, outcome with OpenShell alone, enforcement point, reason.
# Scenario names match the observations written by scripts/openshell-e2e.sh.
EXPECTED = {
    "task A read": ("allow", "allow", "openshell", ""),
    "task B read": ("allow", "allow", "openshell", ""),
    "approved restart": ("allow", "allow", "openshell", ""),
    "repeated approved restart": ("allow", "allow", "openshell", ""),
    "restart without approval": ("deny", "allow", "openshell", "tenuo_approval_required"),
    "approval does not cover replicas 5": (
        "deny",
        "allow",
        "openshell",
        "tenuo_invalid_authority",
    ),
    "task B restart": ("deny", "allow", "openshell", "tenuo_tool_denied"),
    "copied warrant": ("deny", "allow", "openshell", "tenuo_invalid_authority"),
    "production read": ("deny", "allow", "openshell", "tenuo_constraint_denied"),
    "replicas 8": ("deny", "allow", "openshell", "tenuo_constraint_denied"),
    "missing warrant": ("deny", "allow", "openshell", "tenuo_missing_warrant"),
    "narrowed read": ("allow", "allow", "openshell", ""),
    "narrowed restart": ("deny", "allow", "openshell", "tenuo_tool_denied"),
    "wider child": ("refused", "not checked", "attenuation", "attenuation-refused"),
    "direct task B restart": ("deny", "allow", "destination", ""),
    "direct missing warrant": ("deny", "allow", "destination", ""),
    "direct narrowed restart": ("deny", "allow", "destination", ""),
    "in-process task B restart": ("deny", "function ran", "agent-toolkit", "tool_denied"),
}

BASELINE_REASON = {
    "task A read": "tool admission and the warrant agree",
    "task B read": "tool admission and the warrant agree",
    "approved restart": "tool admission and the signed approval agree",
    "repeated approved restart": "the same approval is checked again and there is no replay store",
    "narrowed read": "the child warrant still admits this read",
}


def percentile(samples: list[int], quantile: float) -> int:
    ordered = sorted(samples)
    index = round((len(ordered) - 1) * quantile)
    return ordered[index]


def load_roots(path: Path) -> list[PublicKey]:
    document = json.loads(path.read_text(encoding="utf-8"))
    sandboxes = document.get("sandboxes")
    if not isinstance(sandboxes, dict) or not sandboxes:
        raise SystemExit("policy has no sandboxes")
    roots: list[PublicKey] = []
    seen: set[str] = set()
    for sandbox in sandboxes.values():
        entries = sandbox.get("trusted_roots") if isinstance(sandbox, dict) else None
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


def load_observations(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def pair_rows(rows: list[dict]) -> dict[str, dict[str, dict]]:
    paired: dict[str, dict[str, dict]] = {}
    for row in rows:
        scenario = row["scenario"]
        run = row["run"]
        paired.setdefault(scenario, {})
        if run in paired[scenario]:
            raise SystemExit(f"duplicate observation for {scenario} {run}")
        paired[scenario][run] = row
    return paired


def check_pairs(paired: dict[str, dict[str, dict]]) -> list[dict]:
    if set(paired) != set(EXPECTED):
        missing = sorted(set(EXPECTED) - set(paired))
        extra = sorted(set(paired) - set(EXPECTED))
        raise SystemExit(f"observation scenarios missing={missing} extra={extra}")
    checked = []
    for scenario, (tenuo_outcome, only_outcome, point, reason) in EXPECTED.items():
        runs = paired[scenario]
        tenuo = runs.get("openshell+tenuo")
        only = runs.get("openshell-only")
        if tenuo is None or only is None:
            raise SystemExit(f"{scenario} is missing one run")
        if tenuo["outcome"] != tenuo_outcome or only["outcome"] != only_outcome:
            raise SystemExit(
                f"{scenario} outcomes tenuo={tenuo['outcome']} only={only['outcome']}"
            )
        if tenuo["point"] != point or only["point"] != point:
            raise SystemExit(f"{scenario} enforcement point is {tenuo['point']}")
        if reason and tenuo["reason"] != reason:
            raise SystemExit(f"{scenario} reason is {tenuo['reason']}")
        same = tenuo["outcome"] == only["outcome"]
        checked.append(
            {
                "scenario": scenario,
                "openshell_only": only["outcome"],
                "openshell_tenuo": tenuo["outcome"],
                "classification": "baseline" if same else "different",
                "baseline_reason": BASELINE_REASON.get(scenario, "") if same else "",
                "point": point,
                "reason": tenuo["reason"],
                "verify_us": tenuo["verify_us"],
            }
        )
    return checked


def destination_samples(policy: Path, request_dir: Path, iterations: int) -> list[int]:
    from mcp_server import normalize_meta

    roots = load_roots(policy)
    verifier = MCPVerifier(authorizer=Authorizer(trusted_roots=roots))
    body = json.loads((request_dir / "task-a-read.json").read_text(encoding="utf-8"))
    params = body["params"]
    meta = normalize_meta(params.get("_meta"))
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        verifier.verify(params["name"], params.get("arguments") or {}, meta=meta)
        samples.append(int((time.perf_counter() - started) * 1_000_000))
    return samples


async def toolkit_samples(policy: Path, warrant_path: Path, holder_key: Path, iterations: int) -> list[int]:
    roots = load_roots(policy)
    secret = holder_key.read_bytes()
    if len(secret) != 32:
        raise SystemExit("holder key must be 32 bytes")
    warrant = Warrant.from_bytes(warrant_path.read_bytes())
    bound = warrant.bind(SigningKey.from_bytes(secret))
    middleware = TenuoFunctionMiddleware(trusted_roots=roots)
    context = FunctionMiddlewareContext(
        name="restart_service",
        config=None,
        description=None,
        input_schema=Restart,
        single_output_schema=NoneType,
        stream_output_schema=NoneType,
    )
    arguments = {"service": "payments", "environment": "staging", "replicas": 3}

    async def call_next(*_args, **_kwargs):
        raise SystemExit("the function ran during the timing sample")

    samples = []
    for _ in range(iterations):
        with authority(bound):
            started = time.perf_counter()
            try:
                await middleware.function_middleware_invoke(
                    arguments,
                    call_next=call_next,
                    context=context,
                )
            except AuthorizationDenied as exc:
                if exc.category != "tool_denied":
                    raise SystemExit(f"unexpected denial category {exc.category}") from exc
            else:
                raise SystemExit("timing sample was allowed")
            samples.append(int((time.perf_counter() - started) * 1_000_000))
    return samples


async def unguarded_restart() -> None:
    arguments = {"service": "payments", "environment": "staging", "replicas": 3}

    async def call_next(value, **_kwargs):
        if value != arguments:
            raise SystemExit("unguarded function saw different arguments")
        return "ran"

    result = await call_next(arguments)
    if result != "ran":
        raise SystemExit("unguarded function did not run")


def median_e2e(rows: list[dict]) -> int:
    samples = [
        int(row["e2e_us"])
        for row in rows
        if row["run"] == "openshell+tenuo" and row["point"] == "openshell" and int(row["e2e_us"]) > 0
    ]
    if not samples:
        raise SystemExit("no end-to-end sandbox timings")
    return int(statistics.median(samples))


def render(checked: list[dict], latency: list[dict], timeout_ms: int, median_us: int) -> str:
    lines = [
        "# Outcome matrix",
        "",
        f"OpenShell middleware timeout: {timeout_ms} ms.",
        f"Median end-to-end sandbox call with Tenuo: {median_us} us.",
        "",
        "| Scenario | OpenShell only | OpenShell + Tenuo | Class | Enforcement point | Reason | Verification us |",
        "| --- | --- | --- | --- | --- | --- | ---: |",
    ]
    for row in checked:
        reason = row["reason"] or "—"
        if row["classification"] == "baseline":
            reason = row["baseline_reason"]
        verify = str(row["verify_us"])
        lines.append(
            "| {scenario} | {openshell_only} | {openshell_tenuo} | {classification} | {point} | {why} | {verify} |".format(
                scenario=row["scenario"],
                openshell_only=row["openshell_only"],
                openshell_tenuo=row["openshell_tenuo"],
                classification=row["classification"],
                point=row["point"],
                why=reason,
                verify=verify,
            )
        )
    lines.extend(
        [
            "",
            "| Enforcement point | Samples | p50 us | p99 us | Middleware timeout | Median end-to-end us |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in latency:
        lines.append(
            f"| {row['point']} | {row['samples']} | {row['p50_us']} | {row['p99_us']} | {timeout_ms} ms | {median_us} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--requests", type=Path, required=True)
    parser.add_argument("--warrant", type=Path, required=True)
    parser.add_argument("--holder-key", type=Path, required=True)
    parser.add_argument("--openshell-bench", type=Path, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    asyncio.run(unguarded_restart())
    with args.observations.open("a", encoding="utf-8") as handle:
        handle.write(
            json.dumps(
                {
                    "scenario": "in-process task B restart",
                    "run": "openshell-only",
                    "outcome": "function ran",
                    "point": "agent-toolkit",
                    "reason": "",
                    "verify_us": 0,
                    "e2e_us": 0,
                }
            )
            + "\n"
        )
    rows = load_observations(args.observations)
    checked = check_pairs(pair_rows(rows))
    openshell = json.loads(args.openshell_bench.read_text(encoding="utf-8"))
    if int(openshell["samples"]) < args.iterations:
        raise SystemExit("OpenShell timing sample is short")
    destination = destination_samples(args.policy, args.requests, args.iterations)
    toolkit = asyncio.run(
        toolkit_samples(args.policy, args.warrant, args.holder_key, args.iterations)
    )
    latency = [
        {
            "point": "openshell",
            "samples": int(openshell["samples"]),
            "p50_us": int(openshell["p50_us"]),
            "p99_us": int(openshell["p99_us"]),
        },
        {
            "point": "destination",
            "samples": len(destination),
            "p50_us": percentile(destination, 0.50),
            "p99_us": percentile(destination, 0.99),
        },
        {
            "point": "agent-toolkit",
            "samples": len(toolkit),
            "p50_us": percentile(toolkit, 0.50),
            "p99_us": percentile(toolkit, 0.99),
        },
    ]
    median_us = median_e2e(rows)
    document = {
        "middleware_timeout_ms": args.timeout_ms,
        "median_e2e_us": median_us,
        "rows": checked,
        "latency": latency,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "outcome-matrix.json").write_text(
        json.dumps(document, indent=2) + "\n",
        encoding="utf-8",
    )
    markdown = render(checked, latency, args.timeout_ms, median_us)
    (args.output_dir / "outcome-matrix.md").write_text(markdown, encoding="utf-8")
    print(markdown, end="")


if __name__ == "__main__":
    main()

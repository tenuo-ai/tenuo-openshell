#!/usr/bin/env python3
"""Verify authorization and result receipts with public keys only.

A receipt records the authorization decision. It does not show that a tool ran.
A result receipt records the bytes OpenShell returned for an allowed call.

Result logs (``*.results.jsonl``) are verified by the middleware's own
``receipts export`` command, then linked here to the allow receipt they name.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

RESULT_SUFFIX = ".results.jsonl"


def load_roots(path: Path) -> list[str]:
    document = json.loads(path.read_text(encoding="utf-8"))
    sandboxes = document.get("sandboxes")
    if not isinstance(sandboxes, dict):
        raise SystemExit("policy has no sandboxes")
    roots: list[str] = []
    for sandbox in sandboxes.values():
        if not isinstance(sandbox, dict):
            continue
        entries = sandbox.get("trusted_roots")
        if not isinstance(entries, list):
            continue
        for item in entries:
            if isinstance(item, str) and item not in roots:
                roots.append(item.strip().lower())
    if not roots:
        raise SystemExit("policy has no trusted roots")
    return roots


def load_signers(directory: Path) -> dict[str, str]:
    signers: dict[str, str] = {}
    for path in sorted(directory.glob("*.pub")):
        text = path.read_text(encoding="ascii").strip().lower().removeprefix("0x")
        if len(text) != 64:
            raise SystemExit(f"{path.name} is not a 32-byte public key")
        signers[text] = path.stem
    if not signers:
        raise SystemExit(f"no public keys in {directory}")
    return signers


def load_wires(directory: Path) -> list[str]:
    wires: list[str] = []
    for path in sorted(directory.glob("*.jsonl")):
        if path.name.endswith(RESULT_SUFFIX):
            continue
        for line in path.read_text(encoding="ascii").splitlines():
            text = line.strip()
            if not text:
                continue
            if text.startswith("{"):
                text = str(json.loads(text)["receipt"])
            wires.append(text)
    return wires


def call(obj: object, name: str) -> object:
    value = getattr(obj, name)
    return value() if callable(value) else value


def chain_label(payload: object) -> str:
    import tenuo_core

    stack = list(tenuo_core.decode_warrant_stack_base64(call(payload, "warrant_chain")))
    labels = []
    for warrant in stack:
        issuer = call(warrant, "issuer")
        issuer_bytes = issuer.to_bytes() if hasattr(issuer, "to_bytes") else bytes(issuer)
        labels.append(f"{issuer_bytes.hex()[:16]}:{call(warrant, 'id')}")
    return " -> ".join(labels)


def chain_verifies(payload: object, roots: list[str]) -> bool:
    import tenuo_core

    stack = list(tenuo_core.decode_warrant_stack_base64(call(payload, "warrant_chain")))
    keys = [tenuo_core.PublicKey.from_bytes(bytes.fromhex(root)) for root in roots]
    authorizer = tenuo_core.Authorizer(trusted_roots=keys)
    authorizer.verify_chain(stack, as_of=call(payload, "timestamp"))
    return True


def verify_all(directory: Path, roots: list[str]) -> list[dict[str, object]]:
    import tenuo_core

    signers = load_signers(directory)
    records = []
    for wire in load_wires(directory):
        try:
            payload = tenuo_core.verify_receipt(wire)
        except Exception as exc:  # noqa: BLE001 — the verifier owns the message
            raise SystemExit(f"receipt does not verify: {exc}") from exc
        signer = str(call(payload, "signer_key")).lower()
        point = signers.get(signer)
        if point is None:
            raise SystemExit(f"receipt signer {signer[:16]} is not a published public key")
        outcome = str(call(payload, "outcome"))
        if outcome == "allow":
            try:
                chain_verifies(payload, roots)
            except Exception as exc:  # noqa: BLE001
                raise SystemExit(f"allow receipt chain does not verify: {exc}") from exc
        records.append(
            {
                "request_id": str(call(payload, "request_id")),
                "point": point,
                "outcome": outcome,
                "decision_code": call(payload, "decision_code"),
                "action": str(call(payload, "action")),
                "signer": signer,
                "chain": chain_label(payload),
                "receipt_hash": wire_hash(wire),
            }
        )
    return records


def wire_hash(wire: str) -> str | None:
    """SHA-256 of a hex receipt line, the value a result receipt links to."""
    try:
        return hashlib.sha256(bytes.fromhex(wire)).hexdigest()
    except ValueError:
        return None


def verify_results(
    directory: Path, exporter: Path | None, records: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Verify each result log and link every result to its allow receipt."""
    paths = sorted(directory.glob(f"*{RESULT_SUFFIX}"))
    if not paths:
        return []
    if exporter is None:
        raise SystemExit("result receipts need --exporter to verify their signatures")
    by_hash = {record["receipt_hash"]: record for record in records if record["receipt_hash"]}
    results = []
    for path in paths:
        point = path.name.removesuffix(RESULT_SUFFIX)
        key = directory / f"{point}.pub"
        exported = subprocess.run(
            [str(exporter), "receipts", "export", "--log", str(path), "--verify-with", str(key)],
            capture_output=True,
            text=True,
            check=False,
        )
        if exported.returncode != 0:
            raise SystemExit(f"{path.name} does not verify: {exported.stderr.strip()}")
        for line in exported.stdout.splitlines():
            row = json.loads(line)
            linked = by_hash.get(row["request_receipt_hash"])
            if linked is None or linked["point"] != point or linked["outcome"] != "allow":
                raise SystemExit(f"result for request {row['request_id']} names no allow receipt")
            if linked["request_id"] != row["request_id"] or linked["action"] != f"tool:{row['tool']}":
                raise SystemExit(f"result for request {row['request_id']} does not match its allow receipt")
            results.append(
                {
                    "request_id": row["request_id"],
                    "point": point,
                    "outcome": row["outcome"],
                    "decision_code": row["decision_code"],
                    "bytes": row["result_bytes"],
                    "sha256": row["result_sha256"],
                }
            )
    return results


def print_results(results: list[dict[str, object]]) -> None:
    if not results:
        return
    print("A result receipt records the bytes returned for an allowed call.")
    for row in sorted(results, key=lambda item: (len(str(item["request_id"])), str(item["request_id"]))):
        detail = f"sha256={str(row['sha256'])[:16]}" if row["sha256"] else str(row["decision_code"] or "")
        print(
            f"result {row['request_id']} {row['point']} {row['outcome']} "
            f"{row['bytes']} bytes {detail}".rstrip()
        )


def require_demo_results(results: list[dict[str, object]]) -> None:
    # JSON-RPC id 2 appears twice: the approved restart and the MCP client's
    # read. Each result links to its own allow receipt by hash.
    outcomes = sorted(
        (str(row["request_id"]), str(row["outcome"]), str(row["decision_code"])) for row in results
    )
    expected = sorted(
        [(request_id, "delivered", "None") for request_id in ("1", "2", "2", "5", "9")]
        + [("17", "blocked", "tenuo_result_too_large")]
    )
    if outcomes != expected:
        raise SystemExit("result receipts do not match the demo calls")


def print_report(records: list[dict[str, object]]) -> None:
    print("A receipt records the authorization decision. It does not show that a tool ran.")
    grouped: dict[str, list[dict[str, object]]] = {}
    for record in records:
        grouped.setdefault(str(record["request_id"]), []).append(record)
    for request_id in sorted(grouped, key=lambda item: (len(item), item)):
        print(f"request {request_id}")
        rows = sorted(grouped[request_id], key=lambda row: (str(row["point"]), str(row["outcome"]), str(row["action"])))
        for row in rows:
            reason = f" {row['decision_code']}" if row["decision_code"] else ""
            print(
                f"  {row['point']} {row['outcome']}{reason} {row['action']} "
                f"signer={str(row['signer'])[:16]} chain {row['chain']}"
            )


def require_demo(records: list[dict[str, object]]) -> None:
    by_request: dict[str, list[dict[str, object]]] = {}
    for record in records:
        by_request.setdefault(str(record["request_id"]), []).append(record)

    def has(request_id: str, point: str, outcome: str, code: str | None = None) -> bool:
        for record in by_request.get(request_id, []):
            if record["point"] == point and record["outcome"] == outcome:
                if code is None or record["decision_code"] == code:
                    return True
        return False

    def absent(request_id: str, point: str) -> bool:
        return not any(record["point"] == point for record in by_request.get(request_id, []))

    def shows_parent(request_id: str) -> bool:
        records = by_request.get(request_id, [])
        return bool(records) and all("->" in record["chain"] for record in records)

    checks = [
        has("1", "openshell", "allow") and has("1", "destination", "allow"),
        has("2", "openshell", "allow") and has("2", "destination", "allow"),
        has("5", "openshell", "allow") and has("5", "destination", "allow"),
        has("6", "openshell", "deny", "tool-not-authorized")
        and has("6", "destination", "deny", "tool-not-authorized"),
        has("3", "openshell", "deny", "constraint-violation") and absent("3", "destination"),
        has("4", "openshell", "deny", "constraint-violation") and absent("4", "destination"),
        has("7", "openshell", "deny", "signature-invalid") and absent("7", "destination"),
        "8" not in by_request,
        has("9", "openshell", "allow") and has("9", "destination", "allow"),
        has("10", "openshell", "deny", "tool-not-authorized")
        and has("10", "destination", "deny", "tool-not-authorized"),
        shows_parent("9") and shows_parent("10"),
        has("2", "openshell", "allow") and "13" not in by_request,
        has("11", "openshell", "deny", "approval-required") and absent("11", "destination"),
        has("12", "openshell", "deny", "approval-invalid") and absent("12", "destination"),
        has("15", "openshell", "deny", "constraint-violation") and absent("15", "destination"),
        has("14", "agent-toolkit", "deny", "tool-not-authorized")
        and absent("14", "openshell")
        and absent("14", "destination"),
    ]
    if not all(checks):
        raise SystemExit("receipt report does not match the demo decisions")
    request_one = [record for record in by_request["1"] if record["outcome"] == "allow"]
    signers = {record["signer"] for record in request_one}
    if len(signers) < 2:
        raise SystemExit("the two enforcement points signed request 1 with one key")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--exporter",
        type=Path,
        help="tenuo-openshell-middleware binary, used to verify result logs",
    )
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    records = verify_all(args.dir, load_roots(args.policy))
    if not records:
        raise SystemExit("no receipts")
    results = verify_results(args.dir, args.exporter, records)
    print_report(records)
    print_results(results)
    if args.demo:
        require_demo(records)
        require_demo_results(results)
    print(f"PASS {len(records)} receipts and {len(results)} result receipts verified offline")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)

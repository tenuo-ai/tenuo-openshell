#!/usr/bin/env python3
"""Verify authorization receipts with public keys only.

A receipt records the authorization decision. It does not show that a tool ran.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


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
            }
        )
    return records


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
        has("15", "openshell", "allow") and has("15", "destination", "allow"),
        shows_parent("15"),
        has("2", "openshell", "allow") and "13" not in by_request,
        has("11", "openshell", "deny", "approval-required") and absent("11", "destination"),
        has("12", "openshell", "deny", "approval-invalid") and absent("12", "destination"),
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
    parser.add_argument("--demo", action="store_true")
    args = parser.parse_args()
    records = verify_all(args.dir, load_roots(args.policy))
    if not records:
        raise SystemExit("no receipts")
    print_report(records)
    if args.demo:
        require_demo(records)
    print(f"PASS {len(records)} receipts verified offline")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        sys.exit(0)

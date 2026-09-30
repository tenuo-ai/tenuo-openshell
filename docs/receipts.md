# Receipts

The middleware signs one receipt per authorization decision and, when result
evaluation is enabled, one result receipt per result of an allowed call. Both
are stored locally and verify offline with the receipt public key.

## Files

`--receipt-log /var/lib/tenuo/receipts.jsonl` produces:

| File | Contents |
| --- | --- |
| `receipts.jsonl` | Tenuo authorization receipts, one hex-encoded CBOR receipt per line. |
| `receipts.results.jsonl` | Result receipts, same line format. Written only with `--evaluate-results`. |
| `receipts.pub` | Receipt signer public key, 64 hex characters. |

Each file is its own hash chain. A receipt's `prev_receipt_hash` is the
SHA-256 of the previous line's decoded bytes, so a deleted, inserted, or
reordered line breaks every later link. The chain continues across restarts
and key rotation.

## Authorization receipts

These are Tenuo v1 receipts (`tenuo::Receipt`). A receipt records the
decision, the presented warrant chain, the holder's proof of possession, the
request hash, and the trusted-root and revocation state in force. It does not
show that a tool ran. See [architecture](architecture.md#failure-behavior) for
when a receipt is required.

## Result receipts

A Tenuo receipt payload is a closed map: an unknown key fails verification.
It has no field for a result, so results use a separate, smaller artifact
signed by the same key. It links to the authorization receipt by hash rather
than repeating it.

The envelope is a CBOR map:

| Key | Type | Meaning |
| --- | --- | --- |
| `kind` | text | `tenuo-openshell-result-v1` |
| `payload` | bytes | Deterministic CBOR of the payload below. |
| `signer_key` | public key | Same encoding as Tenuo receipts. |
| `signature` | signature | Ed25519 over Tenuo's signing context, then `tenuo-openshell-result-v1`, then `payload`. |

The context string keeps a result signature from verifying as a Tenuo
receipt, and the reverse.

The payload is a CBOR map with text keys. Absent optional fields are omitted.
Unknown keys are rejected.

| Key | Type | Meaning |
| --- | --- | --- |
| `version` | uint | `1`. |
| `authorizer_id` | text | `openshell`. |
| `timestamp` | int | Unix seconds when evaluation finished. |
| `sandbox_id` | text | OpenShell `sandbox_id`. |
| `openshell_request_id` | text | OpenShell `RequestContext.request_id`, shared by the request and its response. |
| `request_id` | text | JSON-RPC id. Equals `request_id` on the authorization receipt. |
| `tool` | text | Tool name. |
| `warrant_id` | text | Leaf warrant id. |
| `request_receipt_hash` | bytes(32), optional | SHA-256 of the authorization receipt line. Absent when no receipt was stored. |
| `status_code` | uint | Upstream HTTP status. |
| `body_mode` | text | `whole_body`, `stream`, or `headers` (blocked before any body). |
| `outcome` | text | `delivered`, `blocked`, or `incomplete`. |
| `decision_code` | text, optional | Reason for `blocked`, such as `tenuo_result_too_large`. |
| `result_bytes` | uint | Body bytes read. For a block at the response head, the declared length. |
| `result_sha256` | bytes(32), optional | SHA-256 of the complete body. Present only for `delivered`. |
| `prev_receipt_hash` | bytes(32), optional | Chain link within the result log. |

The digest covers the body bytes OpenShell gave this stage: without transfer
framing, after earlier middleware stages in policy order, and before later
ones. For a Server-Sent Events response it covers the event stream.

`incomplete` means body inspection ended before the final unit, for example
because the sandbox or upstream disconnected. In `stream` mode, earlier units
may already have reached the sandbox.

A result receipt records what was returned for an allowed call. Like an
authorization receipt, it does not prove what the tool did.

## Export for log pipelines

```bash
tenuo-openshell-middleware receipts export \
  --log /var/lib/tenuo/receipts.jsonl \
  --verify-with /var/lib/tenuo/receipts.pub \
  --format json > receipts.ndjson
```

Export reads the whole file, verifies every signature and chain link, then
writes one JSON object per line. When `--verify-with` is set, every receipt
must be signed by that key; without it, signatures are checked against the key
each receipt carries, which proves integrity but not whose key it is. Nothing
is written unless the whole file verifies. The command exits `1` on an
unreadable file, a bad signature, a broken chain, a foreign signer, or a file
that mixes authorization and result receipts, and `2` on a usage error.

Export does not re-verify warrant chains against trusted roots. Use
`examples/demo/audit_receipts.py` or `tenuo_core.verify_receipt` for that.

The first line of a file is its anchor: its `prev_receipt_hash` is reported
but not checked, so a rotated segment exports on its own. To join segments,
check that a segment's first `prev_receipt_hash` equals the previous
segment's last `receipt_hash`.

Point the same command at `receipts.results.jsonl` to export result receipts.
Join the two on `request_receipt_hash` = `receipt_hash`.

### Fields

Every object:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `tenuo.openshell.receipt.v1`. Changes only for incompatible changes. |
| `kind` | string | `authorization` or `result`. |
| `line` | integer | 1-based line in the source file. |
| `receipt_hash` | hex | SHA-256 of this line's bytes. Use it as the idempotency key. |
| `prev_receipt_hash` | hex or null | Chain link. |
| `signer_key` | hex | Receipt signer public key. |
| `timestamp` | integer | Unix seconds. |
| `time` | string | `timestamp` as RFC 3339 UTC, for index time fields. |
| `authorizer_id` | string or null | `openshell`. |
| `request_id` | string | JSON-RPC id. |
| `tool` | string or null | Tool name. |
| `outcome` | string | See below. |
| `decision_code` | string or null | Denial or block reason. |
| `warrant_id` | string or null | Leaf warrant id. |

`authorization` objects add:

| Field | Type | Meaning |
| --- | --- | --- |
| `action` | string | `tool:<name>`. |
| `outcome` | string | `allow` or `deny`. |
| `decision_code` | string or null | Canonical Tenuo error name, such as `constraint-violation`. |
| `chain_depth` | integer or null | Warrants in the presented chain. |
| `root_principal` | hex or null | Root issuer public key. |
| `request_hash` | hex or null | Commitment to the tool and arguments. |
| `pop_signature_present` | boolean | False only for denials before proof of possession verified. |
| `trusted_roots_hash` | hex or null | Commitment to the sandbox's trusted roots. |
| `srl_version` | integer or null | Revocation list version. |
| `srl_hash` | hex or null | Revocation list commitment. |
| `policy_definition_hash` | hex or null | Not set by this middleware. |

`result` objects add:

| Field | Type | Meaning |
| --- | --- | --- |
| `outcome` | string | `delivered`, `blocked`, or `incomplete`. |
| `decision_code` | string or null | OpenShell reason code for `blocked`. |
| `sandbox_id` | string | OpenShell `sandbox_id`. |
| `openshell_request_id` | string | Correlates with OpenShell logs. |
| `request_receipt_hash` | hex or null | `receipt_hash` of the authorization receipt. |
| `status_code` | integer | Upstream HTTP status. |
| `body_mode` | string | `whole_body`, `stream`, or `headers`. |
| `result_bytes` | integer | See the payload table. |
| `result_sha256` | hex or null | Present only for `delivered`. |

No field carries tool arguments, result content, warrant bodies, approvals,
or keys other than the public signer key.

### Ingestion

Run export from a checkpointing shipper, not against a file that is still
being written: copy or rotate the log first, export the copy, then ship the
lines. For Splunk, use `time` as the timestamp field and `receipt_hash` as a
dedup key. For Elastic, use `receipt_hash` as the document `_id` so a replay
of the same segment is idempotent.

# Interoperability proofs

These examples show Tenuo authority crossing boundaries beyond the core
OpenShell supervisor integration. They are executable evidence, not separately
distributed products or stable public APIs.

`a2a_handoff.py` starts a local Tenuo A2A server, sends a parent/child warrant
stack and child-holder proof over JSON-RPC HTTP, allows `read_logs`, and denies
`restart_service` before the skill runs.

The proof posts the JSON-RPC request itself instead of using
`tenuo.a2a.A2AClient`. The client does send a full stack:
`send_task(..., warrant_chain=[parent], signing_key=...)` packs the parent and
leaf into one `X-Tenuo-Warrant` stack. The problem is proof of possession. In
Tenuo 0.3.1 and 0.3.2, `send_task` converts the arguments with
`tenuo_core.ConstraintValue` before signing. `tenuo_core` does not export that
name, so a call with `signing_key` raises `ImportError` before any request is
sent. The server requires proof of possession, and the client has no way to
add a header, so there is no partial use of the client to fall back on.

The example therefore builds the request from public pieces:
`tenuo.encode_warrant_stack` for the `X-Tenuo-Warrant` header and
`Warrant.sign` for the `X-Tenuo-PoP` header. `Warrant.sign` takes the
arguments as plain values. The server does all of the authorization. With
`send_task` changed to pass the arguments straight to `Warrant.sign`, the
client version of this example gives the same evidence. Switch to
`A2AClient` once a Tenuo release ships that fix.

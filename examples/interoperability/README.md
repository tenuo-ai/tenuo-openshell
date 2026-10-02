# Interoperability proofs

These examples show Tenuo authority crossing boundaries beyond the core
OpenShell supervisor integration. They are executable evidence, not separately
distributed products or stable public APIs.

`a2a_handoff.py` starts a local Tenuo A2A server, sends a parent/child warrant
stack and child-holder proof over JSON-RPC HTTP, allows `read_logs`, and denies
`restart_service` before the skill runs.

The Tenuo 0.3.1 A2A client does not send a full warrant stack, so this proof
encodes the stack with the public `tenuo.encode_warrant_stack` and posts the
JSON-RPC request itself. Switch to the A2A client once a release sends stacks.

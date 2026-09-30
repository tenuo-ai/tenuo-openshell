# Interoperability proofs

These examples show Tenuo authority crossing boundaries beyond the core
OpenShell supervisor integration. They are executable evidence, not separately
distributed products or stable public APIs.

`a2a_handoff.py` starts a local Tenuo A2A server, sends a parent/child warrant
stack and child-holder proof over JSON-RPC HTTP, allows `read_logs`, and denies
`restart_service` before the skill runs.

The pinned Tenuo 0.3.1 client surface does not yet expose the required full
warrant-stack encoding, so this proof imports `tenuo_core.encode_warrant_stack`
as a documented compatibility bridge. Replace it with the public Tenuo A2A
client before declaring this example a standalone supported integration.

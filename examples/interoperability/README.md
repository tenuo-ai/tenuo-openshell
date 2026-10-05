# Interoperability proofs

These examples show Tenuo authority crossing boundaries beyond the core
OpenShell supervisor integration. They are executable evidence, not separately
distributed products or stable public APIs.

`a2a_handoff.py` starts a local Tenuo A2A server, sends a parent/child warrant
stack and child-holder proof over JSON-RPC HTTP, allows `read_logs`, and denies
`restart_service` before the skill runs.

The proof uses Tenuo's public A2A client and server. `A2AClient.send_task`
sends the parent and child warrants as one `X-Tenuo-Warrant` stack and signs
the `X-Tenuo-PoP` proof with the worker's key. The server does all of the
authorization. It needs Tenuo 0.3.3 or later; earlier clients failed to sign
the proof ([tenuo-ai/tenuo#779](https://github.com/tenuo-ai/tenuo/issues/779)).

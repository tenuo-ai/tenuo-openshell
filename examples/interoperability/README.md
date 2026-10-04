# Interoperability proofs

These examples show Tenuo authority crossing boundaries beyond the core
OpenShell supervisor integration. They are executable evidence, not separately
distributed products or stable public APIs.

`a2a_handoff.py` starts a local Tenuo A2A server, sends a parent/child warrant
stack and child-holder proof over JSON-RPC HTTP, allows `read_logs`, and denies
`restart_service` before the skill runs.

The proof builds the request from Tenuo's public pieces:

- `tenuo.encode_warrant_stack` produces the `X-Tenuo-Warrant` header;
- `Warrant.sign` produces the `X-Tenuo-PoP` header; and
- the server performs all of the authorization.

It does not use `tenuo.a2a.A2AClient`, because the client's proof-of-possession
signing fails in Tenuo 0.3.2
([tenuo-ai/tenuo#779](https://github.com/tenuo-ai/tenuo/issues/779)). Once
that fix ships, the client sends the same request.

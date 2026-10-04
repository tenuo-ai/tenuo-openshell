# What OpenShell's MCP policy can match

Date: 2026-09-28  
Pin: OpenShell v0.1.2 (`6648bd0c290efbc41ba131ee9831ee45cd431f94`)

OpenShell layer-7 MCP matchers accept `params.name` only. Tool arguments are not a policy input. The policy is selected per sandbox.

Sources, at that tag:

- `proto/sandbox.proto`, `L7Allow.params` and `L7DenyRule.params`: "Currently only params.name is supported for tools/call filtering."
- `crates/openshell-supervisor-network/src/l7/jsonrpc.rs`: policy-visible MCP params expose only `params.name`. The test `mcp_mode_ignores_tool_arguments_when_extracting_policy_params` asserts that a `tools/call` with nested `arguments` yields a one-entry params map whose only key is `name`.
- `McpOptions.strict_tool_names` checks tool-name syntax `^[A-Za-z0-9_.-]{1,128}$`. It does not constrain argument values.

So a sandbox policy decides whether a sandbox may call `restart_service`. It does not decide which service, which environment, or how many replicas, and it applies the same answer to every task in the sandbox.

The Tenuo middleware makes that decision per call. It evaluates the warrant, the holder's proof of possession, and the argument object on each covered `tools/call`, at `PRE_CREDENTIALS`, after OpenShell's tool-name admission. The two checks compose: OpenShell decides what the sandbox can reach, and the warrant decides what this task may do there.

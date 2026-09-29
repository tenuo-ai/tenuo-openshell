# OpenShell capability gap

Date: 2026-09-28  
Pin: OpenShell v0.1.2 (`6648bd0c290efbc41ba131ee9831ee45cd431f94`)  
Question: for each reference scenario, can the strongest static OpenShell policy produce the same outcome with the Tenuo middleware removed?

The strongest static policy for the reference sandbox admits both `read_logs` and `restart_service` on the operations MCP host. That is the envelope in section 5.5 of the local specification. Narrowing that policy until it matches one task would make the control run answer a different question. A second sandbox used for attenuation is judged the same way: its static policy is the union of tools the parent sandbox admits, not a hand-narrowed read-only policy that hides the delegation story.

Sources:

- `proto/sandbox.proto` at v0.1.2, `L7Allow.params` and `L7DenyRule.params`: only `params.name` is supported for `tools/call` filtering.
- `crates/openshell-supervisor-network/src/l7/jsonrpc.rs` at v0.1.2: MCP policy params are only the tool name. `mcp_mode_ignores_tool_arguments_when_extracting_policy_params` locks that in.
- OpenShell policy is selected per sandbox. It does not vary per task inside one sandbox.

"Same outcome" means the allow or deny result, not the reason string.

| ID | OpenShell alone | Why | Label |
|---|---|---|---|
| H1 | Allows `restart_service` | The sandbox policy admits that tool name. A missing warrant and W_B are invisible to MCP policy. | Headline. Outcome differs. |
| H2 | Allows both restarts | Both calls are `tools/call` with `params.name=restart_service` in the same sandbox. Task identity is not a policy input. | Headline. Outcome differs. |
| H3(a) | Allows `read_logs` | Tool name is admitted. | Shared allow. Not the Tenuo claim. |
| H3(b) | Allows `restart_service` | Under the union policy above. A read-only policy on sandbox 2 would deny this without Tenuo, and the control run must not use that policy. | Headline for the union-policy setup. |
| H3(c) | Allows if the presented tool name is admitted | Chain shape and attenuation are not policy inputs. | Headline. |
| H3(d) | No OpenShell decision | The client is outside any sandbox. Destination verification is the Tenuo claim. | Headline. |
| H4 | Allows if the tool name is admitted | A copied warrant is not an OpenShell input. Proof-of-possession is not evaluated. | Headline. Outcome differs. |
| H5 | Allows `replicas=3` and `replicas=5`, including the replay | Arguments are ignored. OpenShell has no request-hash approval and no Tenuo replay decision. | Headline. Outcome differs. |
| H6 | No Tenuo receipt chain | OCSF middleware logs are not a warrant chain a third party can verify from issuer and receipt public keys. | Headline. |
| B1 | Allows | `read_logs` is admitted. | Baseline. Same outcome. |
| B2 | Allows | `restart_service` is admitted. The approval artifact is ignored, so the allow matches Tenuo only because the Tenuo case also allows. | Baseline. Same outcome. Say that OpenShell did not check the approval. |
| B3 | Allows | `environment=production` is an argument. Policy sees `restart_service` only. | Baseline for demo order. Outcome differs. Do not label this OpenShell-enforceable. |
| B4 | Allows | `replicas=8` is an argument. Policy sees `restart_service` only. | Baseline for demo order. Outcome differs. Do not label this OpenShell-enforceable. |

B3 and B4 stay in the baseline section of the demo so the two-minute run can lead with H2 and H1. The outcome matrix must show OpenShell-only allowing both. They are argument-constraint evidence, not proof that Tenuo is redundant with MCP policy.

No headline row above has the same outcome under OpenShell alone. None are demoted.

Signer isolation for H2 and H4 is a deployment requirement, not an OpenShell policy feature. The gap analysis does not claim OpenShell prevents one task from reading another task's holder key.

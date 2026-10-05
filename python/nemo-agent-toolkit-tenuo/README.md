# Tenuo for NVIDIA NeMo Agent Toolkit

Provider-owned Agent Toolkit middleware that checks a Tenuo warrant before a
function runs. Unauthorized calls stop before `call_next`, so protected
function code never receives them.

This package is the in-process Agent Toolkit integration. The OpenShell
supervisor middleware at the repository root is the independent enforcement
point for MCP traffic that leaves the sandbox. Use both: the plugin catches
calls early, with readable errors, and the middleware enforces at the network
boundary.

## Install

Install the published plugin into the same environment as Agent Toolkit. PyPI
is the recommended installation path:

```bash
pip install nemo-agent-toolkit-tenuo
nat info components
```

The package metadata selects a compatible Agent Toolkit range. Current source
is tested with Agent Toolkit 1.8 and 1.9. Use the checkout path below only when
testing support that has not reached the latest PyPI release.

To install from a checkout instead, run this from the repository root:

```bash
uv sync --locked --project python/nemo-agent-toolkit-tenuo --extra test
uv run --locked --project python/nemo-agent-toolkit-tenuo nat info components
```

For an existing environment, an editable or regular local install also works:

```bash
python -m pip install ./python/nemo-agent-toolkit-tenuo
```

The package uses NVIDIA's third-party plugin convention:

| Surface | Value |
| --- | --- |
| Distribution | `nemo-agent-toolkit-tenuo` |
| Import | `nat.plugins.tenuo` |
| Entry point | `nat_tenuo` |
| Middleware `_type` | `tenuo` |

For a runnable ReAct workflow with an approval step, see the
[Agent Toolkit example](../../examples/nemo-agent-toolkit/README.md). That
example protects MCP calls with the signing proxy. This plugin is the path for
native Agent Toolkit functions; the [integration guide](../../docs/agent-toolkit.md)
explains how the two compose.

## Bind task authority

Bind authority in application-controlled task scope. Do not accept a warrant
or holder key from model-generated function arguments.

```python
from nat.plugins.tenuo import authority

with authority(warrant.bind(holder)):
    result = await workflow.ainvoke(input)
```

`holder` is the task's signing key and must match the leaf holder named by the
warrant. For a local-only smoke test, application code can mint both with the
public Tenuo API:

```python
from tenuo import SigningKey, Warrant

holder = SigningKey.generate()
warrant = Warrant.mint_builder().tool("read_logs").ttl(300).mint(holder)
```

In production, bind the short-lived warrant issued for the authenticated task
or end user. Do not mint broad authority inside the agent process. See
[Production issuance](../../docs/production-issuance.md).

The binding follows Python context propagation, including async tasks created
inside the block. The middleware does not write MCP `_meta.tenuo`; use Tenuo's
`SecureMCPClient` when the same authority must cross an MCP boundary.

That authority is not tied to Agent Toolkit. The same warrant can be verified
again by the OpenShell middleware, an MCP server, an A2A worker, or another
supported agent runtime, so delegation does not require translating authority
into a new framework-specific policy.

## Configure middleware

```yaml
middleware:
  task_authorization:
    _type: tenuo
    trusted_roots:
      - "<64 hex characters of a 32-byte issuer public key>"

functions:
  read_logs:
    _type: read_logs
    middleware: [task_authorization]
```

`trusted_roots` selects accepted issuers and cannot be empty. A denied call
raises `AuthorizationDenied`; a call needing a signed approval raises
`ApprovalRequired`, which subclasses it. The middleware is not final, so later
middleware continues after an allow.

### With `nat run` and MCP tools

`nat run` and other front ends run no application code around the workflow,
so nothing binds a task's warrant. In an OpenShell sandbox with the Tenuo
agent, the middleware can read the warrant and holder key that
`tenuo-openshell provision` installed:

```yaml
middleware:
  task_authorization:
    _type: tenuo
    trusted_roots: ["${TENUO_TRUSTED_ROOT}"]
    warrant_file: ${HOME}/.tenuo/warrant
    holder_key_file: ${HOME}/.tenuo/holder.key
    strip_function_group: true
    approval_required: defer

function_groups:
  ops:
    _type: mcp_client
    server:
      transport: streamable-http
      url: http://127.0.0.1:7415/mcp
    middleware: [task_authorization]
```

| Option | Default | Effect |
| --- | --- | --- |
| `warrant_file`, `holder_key_file` | unset | Read on every call when no `authority()` binding is active. A binding takes precedence. Both or neither. |
| `strip_function_group` | `false` | Check a function group's function by its name in the group (`read_logs`), not NAT's qualified name (`ops__read_logs`), so a warrant that names MCP tools applies. |
| `approval_required` | `raise` | `defer` hands a call that needs an approval to the next stage instead of raising `ApprovalRequired`. Use it only when that stage enforces approvals itself, as `tenuo-openshell-agent proxy` and the OpenShell middleware do: the proxy records the request for an approver. Calls the warrant does not allow still stop here. |

[A NeMo Agent Toolkit agent in an OpenShell sandbox](../../docs/nat-agent.md)
runs this configuration.

## Compatibility and verification

Tested with Python 3.11–3.13, `nvidia-nat-core` 1.8.x and 1.9.x, and
Tenuo 0.3.x. The locked environment uses Agent Toolkit 1.9. Run its tests and
distribution build with:

```bash
uv run --locked --project python/nemo-agent-toolkit-tenuo --extra test \
  pytest python/nemo-agent-toolkit-tenuo/tests -q
uv build --project python/nemo-agent-toolkit-tenuo
```

To run the same tests and `nat info components` discovery against Agent
Toolkit 1.8 in a fresh environment:

```bash
ci/nat-compat.sh 1.8
```

See the repository [security policy](../../SECURITY.md) before reporting a
vulnerability and [release guide](../../docs/releasing.md) for the publication
gate.

## License

Apache-2.0.

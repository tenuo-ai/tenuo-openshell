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

Install it into the same environment as Agent Toolkit 1.8 or 1.9:

```bash
pip install nemo-agent-toolkit-tenuo
nat info components
```

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

## Bind task authority

Bind authority in application-controlled task scope. Do not accept a warrant
or holder key from model-generated function arguments.

```python
from nat.plugins.tenuo import authority

with authority(warrant.bind(holder)):
    result = await workflow.ainvoke(input)
```

The binding follows Python context propagation, including async tasks created
inside the block. The middleware does not write MCP `_meta.tenuo`; use Tenuo's
`SecureMCPClient` when the same authority must cross an MCP boundary.

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

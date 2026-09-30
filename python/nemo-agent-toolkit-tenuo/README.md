# NVIDIA NeMo Agent Toolkit — Tenuo

Provider-owned Agent Toolkit middleware that checks a Tenuo warrant before a
function runs. Unauthorized calls stop before `call_next`, so protected
function code never receives them.

> [!IMPORTANT]
> `nemo-agent-toolkit-tenuo` is currently a source preview and is not published
> on PyPI. Install it from a pinned repository revision until the first release.

This package is the in-process Agent Toolkit integration. The independent
OpenShell supervisor middleware is implemented at the repository root.

## Install from source

From the repository root, use the same environment as Agent Toolkit 1.8:

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

This preview is tested with Python 3.11–3.13, `nvidia-nat-core` 1.8.x, and
Tenuo 0.3.x. Run its tests and distribution build with:

```bash
uv run --locked --project python/nemo-agent-toolkit-tenuo --extra test \
  pytest python/nemo-agent-toolkit-tenuo/tests -q
uv build --project python/nemo-agent-toolkit-tenuo
```

See the repository [security policy](../../SECURITY.md) before reporting a
vulnerability and [release guide](../../docs/releasing.md) for the publication
gate.

## License

Apache-2.0.

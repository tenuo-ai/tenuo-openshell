# tenuo-nat

NeMo Agent Toolkit middleware that authorizes a function call with a Tenuo warrant before the function runs.

The warrant is bound to the current task with `authority()`. The middleware does not read a warrant from function arguments. On denial it raises `AuthorizationDenied` and does not call the next stage. A call that still needs a signed approval raises `ApprovalRequired`, a subclass of `AuthorizationDenied`.

This package is the Agent Toolkit plugin. It does not implement the OpenShell supervisor service in the repository root.

## Install

Use the same environment as `nvidia-nat-core` 1.8.

```bash
pip install -e ".[test]"
```

The `tenuo` package must be installed as well. This package was checked against `nvidia-nat-core` 1.8.0.

## Bind a warrant

```python
from nat.plugins.tenuo import authority

with authority(warrant.bind(holder)):
    ...
```

`holder` is the signing key for that warrant's holder. The binding lasts for the `with` block and for async tasks started inside it.

To attach the same warrant to an MCP `tools/call`, pass it through `SecureMCPClient` from the `tenuo` package. This middleware does not write `_meta.tenuo`.

## Configuration

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

`trusted_roots` selects which issuers are accepted. An empty list is rejected when the configuration is loaded. The middleware is not final, so later middleware still runs after an allow.

## Test

```bash
pytest
```

## License

Apache-2.0.

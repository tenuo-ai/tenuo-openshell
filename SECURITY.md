# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately to
[security@tenuo.ai](mailto:security@tenuo.ai). Do not open a public issue with
exploit details or credentials.

Include the affected commit or version, deployment mode, reproduction steps,
expected impact, and any suggested mitigation. Remove secrets and personal
data. We acknowledge each report, coordinate validation and remediation, and agree
on disclosure timing with the reporter.

## Supported versions

Before the first release, only the current `main` branch is supported. After
publication, the latest released minor version and `main` will receive security
fixes unless a release note states otherwise.

## Security boundary

The supervisor middleware authorizes only traffic delivered to its configured
OpenShell binding. The current implementation covers MCP Streamable HTTP
`HTTP_REQUEST / PRE_CREDENTIALS`; it does not cover `tls: skip`, raw TCP,
binary WebSocket frames, or server-to-client WebSocket messages. Network policy
must close alternate paths. See [Architecture](docs/architecture.md) for the
trust boundaries and the [threat model](docs/threat-model.md) for attackers,
controls, and known residual risks.

A report of a documented residual risk is still welcome when it shows a
practical exploit or a cheaper mitigation. A report that a control listed in
the threat model does not hold as described is a vulnerability.

Never include issuer, holder, approval, JWT, TLS, or receipt-signing private
keys in a report, fixture, log, or CI artifact.

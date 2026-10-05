# Per-request issuance example

`issuer_service.py` is a minimal issuance service for platforms that run
agents for many users. An orchestrator sends the task's holder public key and
a task name. The service authenticates the caller, looks up that principal's
grant for the task in `grants.json`, mints a root warrant with a capped
lifetime, writes one audit line, and returns the warrant for
`tenuo-openshell-agent install-warrant`.

See [Issuing warrants in production](../../docs/production-issuance.md) for
the design. This example is a reference, not a product:

- Callers authenticate with static bearer tokens. `callers.json` maps the
  SHA-256 of each token to a principal. In production, verify the
  orchestrator over mTLS and the user's OIDC or token-exchange token instead.
- The issuer key is a file. Tenuo core 0.3.2 cannot mint a root warrant with
  a KMS or HSM key yet; `load_issuer` is where one would go.
- It serves plain HTTP on loopback. Put it behind TLS.
- With tenuo 0.3.2, Python `exact` and `one_of` constraints take strings.

## Run the test

```bash
python3 -m pip install 'tenuo==0.3.2'
cargo build --locked --bin tenuo-openshell-agent
python3 examples/issuance/test_issuer_service.py --agent target/debug/tenuo-openshell-agent
```

The test starts the service on a loopback port and issues the same `triage`
task to `alice` and `bob`. It checks that:

- each warrant names the service's issuer key and that user's holder key;
- the lifetime is capped at `max_ttl_secs`;
- `session_id` names the user;
- Alice's warrant allows `payments` logs and not `auth`, and Bob's the
  reverse;
- unauthenticated, ungranted, and malformed requests are refused;
- the audit log maps each warrant id to its principal.

With `--agent`, it generates each holder key with the real agent's `keygen`.
It installs each warrant with `install-warrant`, and checks that Alice's
warrant does not install under Bob's key. Without `--agent`, it generates the
holder keys in Python and skips the install step.

## Run the service

```bash
python3 -c 'import os; open("issuer.key","wb").write(os.urandom(32))'
chmod 0400 issuer.key
token="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
printf '{"%s": "alice"}\n' "$(printf %s "$token" | shasum -a 256 | cut -d" " -f1)" > callers.json
python3 examples/issuance/issuer_service.py --issuer-key issuer.key \
  --grants examples/issuance/grants.json --callers callers.json
```

Put the printed issuer key in each sandbox's `trusted_roots` with
`tenuo-openshell policy add --trusted-root`. Then provision a sandbox:

```bash
holder="$(openshell sandbox exec --name my-sandbox --no-tty -- tenuo-openshell-agent keygen)"
warrant="$(curl -sf -H "Authorization: Bearer $token" \
  -d "{\"holder\":\"$holder\",\"task\":\"triage\",\"ttl\":600}" \
  http://127.0.0.1:8471/v1/warrants | jq -r .warrant)"
openshell sandbox exec --name my-sandbox --no-tty -- tenuo-openshell-agent install-warrant "$warrant"
```

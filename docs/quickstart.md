# Quickstart

This guide takes you from nothing to one allowed and two denied MCP tool calls
in an OpenShell sandbox, in about 10 minutes. It uses only released artifacts:
the OpenShell v0.1.2 binaries, the Tenuo v0.1.2 images, and the
`tenuo-openshell` v0.1.2 CLI. Nothing is built from source.

It starts its own OpenShell gateway on port 18670, so a gateway you already
run is not touched. Run every command in one shell, in order.

| You end with | Where |
| --- | --- |
| An OpenShell v0.1.2 gateway with Tenuo registered over TLS and JWT | Host process |
| The Tenuo middleware | Docker container `tenuo-quickstart-middleware` |
| An MCP server with `read_logs` and `restart_service` | Host process |
| A sandbox whose task may read `payments` logs in `staging` or `dev` | Sandbox `tenuo-quickstart` |

## Requirements

- macOS on Apple silicon, or Linux on x86_64 or arm64.
- Docker Desktop, or Docker Engine 28.0 or later.
- `curl`, `jq`, and `python3`.
- About 400 MB of downloads.

The gateway listens on your LAN address without authentication, because the
sandbox supervisors must reach it from Docker. Run this on a trusted network
and clean up when you are done.

## 1. Settings and binaries

```bash
mkdir tenuo-quickstart && cd tenuo-quickstart
export PATH="$PWD/bin:$PATH"
GATEWAY_PORT=18670 HEALTH_PORT=18671 MIDDLEWARE_PORT=18651 MCP_PORT=18680

if [ "$(uname -s)" = Darwin ]; then
  HOST_IP="$(ipconfig getifaddr "$(route -n get default | awk '/interface:/ {print $2}')")"
else
  HOST_IP="$(ip -4 route get 1.1.1.1 | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
fi
export OPENSHELL_GATEWAY_ENDPOINT="http://$HOST_IP:$GATEWAY_PORT"
echo "host address: $HOST_IP"
```

`HOST_IP` must be a non-loopback IPv4 address. The gateway, the sandbox
supervisors, and the middleware all reach each other through it.

Download the OpenShell CLI and gateway, and the Tenuo operator CLI:

```bash
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) cli=aarch64-apple-darwin gateway=aarch64-apple-darwin ;;
  Linux/x86_64) cli=x86_64-unknown-linux-musl gateway=x86_64-unknown-linux-gnu ;;
  Linux/aarch64) cli=aarch64-unknown-linux-musl gateway=aarch64-unknown-linux-gnu ;;
  *) echo "unsupported platform" >&2; false ;;
esac
mkdir -p bin
curl -fsSL "https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/openshell-$cli.tar.gz" \
  | tar -xz -C bin
curl -fsSL "https://github.com/NVIDIA/OpenShell/releases/download/v0.1.2/openshell-gateway-$gateway.tar.gz" \
  | tar -xz -C bin
curl -fsSL "https://github.com/tenuo-ai/tenuo-openshell/releases/download/v0.1.2/tenuo-openshell-v0.1.2-$cli.tar.gz" \
  | tar -xz -C bin tenuo-openshell
openshell --version && openshell-gateway --version && tenuo-openshell --version
```

To verify the Tenuo binary's signature first, see
[Verifying a release binary](releasing.md#verifying-a-release-binary).

## 2. Keys

The gateway signs a short-lived JWT for every call it makes to the middleware.
`generate-certs` creates that signing key, a CA, and a server certificate for
`HOST_IP`. The quickstart gateway runs without TLS on its own listener, so the
middleware uses that server certificate.

```bash
openshell-gateway generate-certs --output-dir pki --server-san "$HOST_IP"
```

The issuer key signs warrants, and the middleware trusts its public key. The
policy signing key signs each version of the trust policy, and the middleware
gets only its public key. `keygen` writes each secret key with mode 0600,
never overwrites a file, and prints the public key:

```bash
tenuo-openshell keygen --out issuer.key --public-out issuer.pub
tenuo-openshell keygen --out policy-signing.key --public-out policy-signing.pub
```

## 3. Middleware

The sandbox ID does not exist until step 6, so start from a policy that
trusts no sandboxes. `--sign-with` writes `tenuo/policy.json.sig` next to it:

```bash
mkdir -p tenuo
tenuo-openshell policy init --policy tenuo/policy.json --sign-with policy-signing.key
```

Start the middleware with TLS, the gateway's JWT public key, and the policy
signing public key. It denies every request until a sandbox is added:

```bash
docker run -d --name tenuo-quickstart-middleware \
  --user "$(id -u):$(id -g)" \
  -e TENUO_DECISION_LOG=1 \
  -p "$MIDDLEWARE_PORT:50051" \
  -v "$PWD/tenuo:/etc/tenuo:ro" \
  -v "$PWD/pki/server:/tls:ro" \
  -v "$PWD/pki/jwt/public.pem:/jwt/public.pem:ro" \
  ghcr.io/tenuo-ai/tenuo-openshell:v0.1.2 \
  --policy /etc/tenuo/policy.json \
  --policy-signing-key "$(cat policy-signing.pub)" \
  --listen 0.0.0.0:50051 \
  --tls-cert /tls/tls.crt \
  --tls-key /tls/tls.key \
  --openshell-jwt-public-key /jwt/public.pem \
  --openshell-gateway-id tenuo-quickstart \
  --allow-in-memory-replay
until docker logs tenuo-quickstart-middleware 2>&1 | grep -q listening; do sleep 1; done
```

The middleware refuses a policy whose signature does not verify.
`--allow-in-memory-replay` keeps single-use state for proofs and approvals in
the process, which suits one local instance. Production uses Redis over
`rediss://`; see [Deployment](deployment.md).

## 4. MCP server

A minimal MCP server that runs every call it receives and logs it to
`mcp.log`. It has no Tenuo code.

```bash
cat > mcp_server.py <<'EOF'
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARGS = {"type": "object", "properties": {
    "service": {"type": "string"}, "environment": {"type": "string"}}}
TOOLS = [{"name": "read_logs", "inputSchema": ARGS},
         {"name": "restart_service", "inputSchema": ARGS}]


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        message = json.loads(self.rfile.read(int(self.headers["content-length"])))
        method, params = message.get("method"), message.get("params") or {}
        if "id" not in message:
            self.send_response(202)
            self.end_headers()
            return
        if method == "initialize":
            result = {"protocolVersion": params.get("protocolVersion", "2025-11-25"),
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "quickstart", "version": "1"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            args = params.get("arguments", {})
            print(f"RAN {params['name']} {json.dumps(args)}", flush=True)
            text = f"{params['name']} ran for {args.get('service')} in {args.get('environment')}"
            result = {"content": [{"type": "text", "text": text}]}
        else:
            result = {}
        body = json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", int(sys.argv[1])), Handler).serve_forever()
EOF
python3 mcp_server.py "$MCP_PORT" > mcp.log 2>&1 &
echo $! > mcp.pid
```

## 5. Gateway

Write the gateway configuration. `tenuo-openshell register --only gateway`
prints the middleware registration block for it.

```bash
cat > gateway.toml <<EOF
[openshell]
version = 2

[openshell.gateway.auth]
allow_unauthenticated_users = true

[openshell.gateway.gateway_jwt]
signing_key_path = "$PWD/pki/jwt/signing.pem"
public_key_path = "$PWD/pki/jwt/public.pem"
kid_path = "$PWD/pki/jwt/kid"
gateway_id = "tenuo-quickstart"

[openshell.drivers.docker]
grpc_endpoint = "http://$HOST_IP:$GATEWAY_PORT"

EOF
tenuo-openshell register --only gateway \
  --middleware-endpoint "https://$HOST_IP:$MIDDLEWARE_PORT" \
  --ca "$PWD/pki/ca.crt" \
  --mcp-host host.openshell.internal >> gateway.toml
openshell-gateway config preflight --path gateway.toml
```

`gateway_id` must match the middleware's `--openshell-gateway-id`. The
middleware rejects any call whose JWT has another issuer or audience.

Start the gateway. It contacts the middleware before it accepts requests:

```bash
openshell-gateway \
  --config gateway.toml \
  --compute-driver docker \
  --bind-address "$HOST_IP" \
  --port "$GATEWAY_PORT" \
  --health-port "$HEALTH_PORT" \
  --disable-tls \
  --db-url "sqlite://$PWD/gateway.db" > gateway.log 2>&1 &
echo $! > gateway.pid
until curl -fs -o /dev/null "http://$HOST_IP:$HEALTH_PORT/healthz"; do sleep 1; done
```

## 6. Sandbox

Build a sandbox image with the agent. The `COPY --from` line is the only Tenuo
addition:

```bash
cat > Dockerfile <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/tenuo-ai/tenuo-openshell-agent:v0.1.2 \
  /usr/local/bin/tenuo-openshell-agent /usr/local/bin/
EOF
docker build -q -t tenuo-quickstart-sandbox:latest .
```

The sandbox policy admits both tools on the MCP server and attaches the Tenuo
middleware to it:

```bash
cat > sandbox-policy.yaml <<EOF
version: 1

network_middlewares:
  tenuo:
    middleware: tenuo/authorization
    on_error: fail_closed
    endpoints:
      include:
        - host.openshell.internal

network_policies:
  quickstart-mcp:
    name: Quickstart MCP server
    endpoints:
      - host: host.openshell.internal
        port: $MCP_PORT
        path: /mcp
        protocol: mcp
        enforcement: enforce
        rules:
          - allow: {method: initialize}
          - allow: {method: notifications/initialized}
          - allow: {method: tools/list}
          - allow: {method: tools/call, tool: read_logs}
          - allow: {method: tools/call, tool: restart_service}
    binaries:
      - path: /usr/local/bin/tenuo-openshell-agent
      - path: /usr/bin/curl
EOF
openshell sandbox create --name tenuo-quickstart \
  --from tenuo-quickstart-sandbox:latest \
  --policy sandbox-policy.yaml \
  --no-tty --detach -- sleep infinity
```

`curl` is listed only so step 8 can show what the middleware does with an
unsigned call. In your own policy, list only the agent.

## 7. Trust the sandbox and issue a warrant

Add the sandbox's ID to the trust policy, and sign the new version. Every tool
accepts a signed call once unless it is listed with `--idempotent`, so list
the read-only `read_logs` there; `restart_service` stays single-use. The
middleware reloads the policy within five seconds:

```bash
SANDBOX_ID="$(openshell sandbox get tenuo-quickstart -o json | jq -er .id)"
tenuo-openshell policy add \
  --policy tenuo/policy.json \
  --sandbox-id "$SANDBOX_ID" \
  --trusted-root issuer.pub \
  --mcp "http://host.openshell.internal:$MCP_PORT/mcp" \
  --tools read_logs,restart_service \
  --idempotent read_logs \
  --sign-with policy-signing.key
sleep 6
```

Provision the task. The holder key is generated inside the sandbox and never
leaves it. The warrant allows `read_logs` for `payments` in `staging` or
`dev`, and nothing else:

```bash
tenuo-openshell provision \
  --sandbox tenuo-quickstart \
  --issuer-key issuer.key \
  --capabilities '{"read_logs": {"service": "payments", "environment": {"one_of": ["staging", "dev"]}}}' \
  --ttl 3600
```

Your key and warrant IDs differ:

```text
sandbox tenuo-quickstart
holder  38f75994816fe14f4c4179865277018dd76d1e52e398734f3ef48ce2a5e34f8f
warrant tnu_wrt_01a10a65811476b291459ac46e9fff56
tools   read_logs
```

## 8. Make calls

Start the signing proxy in the sandbox. An agent's MCP client points at it
instead of the MCP server:

```bash
openshell sandbox exec --name tenuo-quickstart --no-tty -- sh -c "
  nohup tenuo-openshell-agent proxy \
    --upstream http://host.openshell.internal:$MCP_PORT/mcp > /tmp/proxy.log 2>&1 &
  until grep -q listening /tmp/proxy.log; do sleep 0.2; done"
```

`call <url> <tool> <arguments>` sends one MCP `tools/call` from inside the
sandbox:

```bash
call() {
  openshell sandbox exec --name tenuo-quickstart --no-tty -- \
    curl -sS "$1" \
      -H 'content-type: application/json' \
      -H 'accept: application/json, text/event-stream' \
      -H 'mcp-protocol-version: 2025-11-25' \
      -d "{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"tools/call\",
           \"params\": {\"name\": \"$2\", \"arguments\": $3}}"
  echo
}
```

**Allowed.** The proxy signs the call, the middleware checks the warrant, and
the MCP server runs it:

```bash
call http://127.0.0.1:7415/mcp read_logs '{"service": "payments", "environment": "staging"}'
```

```text
{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "read_logs ran for payments in staging"}]}}
```

**Denied by the warrant.** `production` is outside the warrant. The proxy
refuses to sign it, so the call never leaves the sandbox:

```bash
call http://127.0.0.1:7415/mcp read_logs '{"service": "payments", "environment": "production"}'
```

```text
{"error":{"code":-32001,"data":{"tenuo":{"code":"constraint-violation","message":"Constraint not satisfied","source":"agent"}},"message":"Authorization denied: Constraint not satisfied"},"id":1,"jsonrpc":"2.0"}
```

**Denied by the middleware.** The proxy's check is there for clear errors. The
middleware is the enforcement point. A call that skips the proxy reaches
OpenShell with no warrant, and the middleware denies it before it reaches the
MCP server:

```bash
call "http://host.openshell.internal:$MCP_PORT/mcp" read_logs '{"service": "payments", "environment": "staging"}'
```

```text
{"binary":"/usr/bin/curl","detail":"Request rejected by configured middleware","error":"middleware_denied","host":"host.openshell.internal","layer":"l7","method":"POST","middleware":"tenuo","path":"/mcp","policy":"quickstart-mcp","port":18680,"reason_code":"tenuo_missing_warrant"}
```

A denial whose code does not start with `tenuo_`, such as `policy_denied`,
comes from OpenShell's own sandbox policy, not from Tenuo.

Check both sides. The middleware logged one allow and one deny with its reason
code, and the MCP server ran one call:

```bash
docker logs tenuo-quickstart-middleware 2>&1 | grep tenuo_decision
cat mcp.log
```

```text
tenuo_decision request_id=1 decision_us=415 outcome=allow reason=-
tenuo_decision request_id=1 decision_us=9 outcome=deny reason=tenuo_missing_warrant
RAN read_logs {"environment": "staging", "service": "payments"}
```

The middleware reason codes are defined in [`src/reason.rs`](../src/reason.rs).
The agent's codes, such as
`constraint-violation` and `tool-not-authorized`, are described in
[Running an agent under Tenuo](sandbox-agent.md#denials-the-agent-sees).

## 9. Try a change

Narrow or widen the task without restarting anything. The proxy re-reads the
warrant on every call:

```bash
tenuo-openshell provision \
  --sandbox tenuo-quickstart \
  --issuer-key issuer.key \
  --capabilities '{"read_logs": {"service": "payments", "environment": {"one_of": ["staging", "dev"]}}, "restart_service": {"service": "payments", "environment": "staging"}}' \
  --ttl 600
call http://127.0.0.1:7415/mcp restart_service '{"service": "payments", "environment": "staging"}'
call http://127.0.0.1:7415/mcp restart_service '{"service": "auth", "environment": "staging"}'
```

The first restart runs. The second is denied `constraint-violation`.

## 10. Clean up

```bash
openshell sandbox delete tenuo-quickstart
while openshell sandbox get tenuo-quickstart > /dev/null 2>&1; do sleep 1; done
kill "$(cat gateway.pid)" "$(cat mcp.pid)"
docker rm -f tenuo-quickstart-middleware
docker rmi tenuo-quickstart-sandbox:latest
cd .. && rm -rf tenuo-quickstart
```

## Next steps

| Goal | Guide |
| --- | --- |
| Put your own agent under Tenuo | [Running an agent under Tenuo](sandbox-agent.md) |
| Add approvals, delegation, and sub-agents | [Running an agent under Tenuo](sandbox-agent.md#approvals) |
| Run the middleware in production | [Deployment](deployment.md) and the [Helm chart](../deploy/helm/tenuo-openshell/README.md) |
| See every scenario with and without Tenuo | [Demo](../examples/demo/README.md) (`make demo`, builds from source) |

To add Tenuo to a gateway you already run, put the `register` block in its
`gateway.toml`, start the middleware with that gateway's JWT public key and
`gateway_id`, and restart the gateway. The package-managed gateway's
configuration path is in the
[OpenShell installation guide](https://docs.nvidia.com/openshell/latest/about/installation).

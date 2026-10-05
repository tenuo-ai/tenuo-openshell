//! Loopback MCP proxy for an unmodified agent.
//!
//! The agent's MCP client points at this proxy instead of the MCP server. The
//! proxy signs each `tools/call` with the sandbox's holder key and forwards
//! everything else unchanged, including Streamable HTTP event streams. Only
//! the proxy needs network access to the MCP server, so the OpenShell policy
//! can list this binary alone for that endpoint.

use crate::authority::Holder;
use crate::sign::{error_response_with, sign_body, Signed};
use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderName, Request, Response, StatusCode};
use futures_util::TryStreamExt;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// Largest request body the proxy buffers for signing.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// Largest OpenShell denial body the proxy reads to recover the reason code.
const MAX_DENIAL_BYTES: usize = 64 * 1024;

pub struct Proxy {
    holder: Holder,
    upstream: reqwest::Url,
    client: reqwest::Client,
}

impl Proxy {
    pub fn new(holder: Holder, upstream: reqwest::Url) -> Result<Self, reqwest::Error> {
        // Redirects are not followed: a redirect would move a signed call to a
        // destination the operator did not configure.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .build()?;
        Ok(Self {
            holder,
            upstream,
            client,
        })
    }

    pub fn router(self) -> axum::Router {
        axum::Router::new()
            .fallback(handle)
            .with_state(Arc::new(self))
    }
}

async fn handle(State(proxy): State<Arc<Proxy>>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = match to_bytes(body, MAX_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(_) => return plain(StatusCode::PAYLOAD_TOO_LARGE, "request body is too large"),
    };
    let mut tool_call_id = None;
    let body = if parts.method == axum::http::Method::POST {
        match sign_body(&proxy.holder, &body) {
            Signed::Unchanged => body.to_vec(),
            Signed::Body(signed) => {
                tool_call_id = Some(jsonrpc_id(&body));
                signed
            }
            Signed::Denied(error) => return json(StatusCode::OK, error),
        }
    } else {
        body.to_vec()
    };

    let mut url = proxy.upstream.clone();
    url.set_query(parts.uri.query());
    let method = match reqwest::Method::from_bytes(parts.method.as_str().as_bytes()) {
        Ok(method) => method,
        Err(_) => return plain(StatusCode::METHOD_NOT_ALLOWED, "unsupported method"),
    };
    let mut forward = proxy.client.request(method, url);
    for (name, value) in parts.headers.iter() {
        if forwardable(name) {
            forward = forward.header(name.as_str(), value.as_bytes());
        }
    }
    let upstream = match forward.body(body).send().await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("tenuo_agent_proxy upstream_error={error}");
            return plain(StatusCode::BAD_GATEWAY, "MCP server is unreachable");
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if status == StatusCode::FORBIDDEN {
        if let Some(id) = tool_call_id {
            return openshell_denial(upstream, &id).await;
        }
    }
    let mut response = Response::builder().status(status);
    if let Some(headers) = response.headers_mut() {
        copy_headers(upstream.headers(), headers);
    }
    let stream = upstream.bytes_stream().map_err(std::io::Error::other);
    response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| plain(StatusCode::BAD_GATEWAY, "invalid upstream response"))
}

/// OpenShell answers a denied request with HTTP 403 and a JSON body. An MCP
/// client would surface that as a transport failure; the agent gets a
/// JSON-RPC error carrying the reason instead.
///
/// Two kinds of denial arrive this way. The Tenuo middleware's codes start
/// with `tenuo_` and come in `reason_code`. Anything else is OpenShell's own:
/// its L7 policy (`policy_denied`), an MCP protocol check such as
/// `mcp_protocol_version_not_allowed`, a middleware that failed
/// (`middleware_failed`), or another middleware's `reason_code`. For those the
/// agent sees OpenShell's code and detail, so the denial is not mistaken for a
/// Tenuo one.
async fn openshell_denial(upstream: reqwest::Response, id: &Value) -> Response<Body> {
    let bytes = upstream.bytes().await.unwrap_or_default();
    let body = (bytes.len() <= MAX_DENIAL_BYTES)
        .then(|| serde_json::from_slice::<Value>(&bytes).ok())
        .flatten()
        .unwrap_or(Value::Null);
    let denial = Denial::parse(&body);
    let reason = denial.code();
    let approval = reason == "tenuo_approval_required";
    // A result block comes after the call: the tool ran, only its result was
    // withheld. Say so, so the agent does not retry a non-idempotent call.
    let message = if reason.starts_with("tenuo_result_") {
        "OpenShell withheld the result; the call already ran on the MCP server".to_string()
    } else if reason == "tenuo_pop_replayed" {
        // Proofs sign a 30-second window, so an identical call inside it
        // carries the same proof. The first one was accepted.
        "OpenShell denied a duplicate: an identical call was already accepted in this 30-second window; wait and retry, or ask the operator to list the tool in idempotent_tools".to_string()
    } else if reason.starts_with("tenuo_") {
        "OpenShell denied this call before it reached the MCP server".to_string()
    } else {
        match &denial.detail {
            Some(detail) => format!("OpenShell denied this call ({reason}): {detail}"),
            None => {
                format!("OpenShell denied this call ({reason}) before it reached the MCP server")
            }
        }
    };
    let extra = (!denial.fields.is_empty()).then(|| {
        let mut extra = serde_json::Map::new();
        extra.insert("openshell".into(), Value::Object(denial.fields.clone()));
        extra
    });
    json(
        StatusCode::OK,
        error_response_with(id, &reason, &message, approval, "openshell", extra),
    )
}

/// Longest OpenShell code passed to the agent. OpenShell's own reason codes
/// are at most 64 bytes.
const MAX_CODE_BYTES: usize = 64;
/// Longest OpenShell detail or field value passed to the agent.
const MAX_FIELD_BYTES: usize = 256;
/// OpenShell denial fields copied into `data.tenuo.openshell`. Host, port,
/// path, and binary are left out: the agent already knows them.
const DENIAL_FIELDS: [&str; 8] = [
    "error",
    "reason_code",
    "detail",
    "layer",
    "protocol",
    "policy",
    "middleware",
    "rule",
];

/// The parts of an OpenShell 403 body the agent is shown, bounded.
struct Denial {
    reason_code: Option<String>,
    error: Option<String>,
    detail: Option<String>,
    fields: serde_json::Map<String, Value>,
}

impl Denial {
    /// OpenShell writes `{"error": "<code>", "detail": ..., ...}` for policy
    /// and middleware denials, and `{"error": {"code", "reason", "message"}}`
    /// for a few relay checks. Anything else yields no fields.
    fn parse(body: &Value) -> Self {
        let text = |value: Option<&Value>| value.and_then(Value::as_str).map(bounded);
        let nested = body.get("error").filter(|error| error.is_object());
        let error = match nested {
            Some(error) => text(error.get("code")),
            None => text(body.get("error")),
        }
        .filter(|code| is_code(code));
        let reason_code = text(body.get("reason_code")).filter(|code| is_code(code));
        let detail = text(body.get("detail"))
            .or_else(|| text(body.get("message")))
            .or_else(|| nested.and_then(|error| text(error.get("message"))))
            .filter(|detail| !detail.is_empty());
        let mut fields = serde_json::Map::new();
        for name in DENIAL_FIELDS {
            let value = match name {
                "error" => error.clone(),
                "reason_code" => reason_code.clone(),
                "detail" => detail.clone(),
                _ => text(body.get(name)),
            };
            if let Some(value) = value {
                fields.insert(name.to_string(), Value::String(value));
            }
        }
        Self {
            reason_code,
            error,
            detail,
            fields,
        }
    }

    /// A middleware `reason_code` names the denial most precisely; OpenShell's
    /// `error` names it otherwise.
    fn code(&self) -> String {
        self.reason_code
            .clone()
            .or_else(|| self.error.clone())
            .unwrap_or_else(|| "forbidden".to_string())
    }
}

fn is_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= MAX_CODE_BYTES
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-.:/".contains(&byte))
}

/// At most `MAX_FIELD_BYTES`, on a character boundary, with control
/// characters replaced.
fn bounded(value: &str) -> String {
    let mut end = value.len().min(MAX_FIELD_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end]
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

fn jsonrpc_id(body: &[u8]) -> Value {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(Value::Null)
}

fn forwardable(name: &HeaderName) -> bool {
    !matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn copy_headers(from: &reqwest::header::HeaderMap, to: &mut HeaderMap) {
    for (name, value) in from.iter() {
        let Ok(name) = HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        if !forwardable(&name) {
            continue;
        }
        if let Ok(value) = header::HeaderValue::from_bytes(value.as_bytes()) {
            to.append(name, value);
        }
    }
}

fn json(status: StatusCode, body: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap_or_default()
}

fn plain(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(message))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::{encode_chain, WarrantSource};
    use axum::http::HeaderValue;
    use serde_json::json;
    use std::sync::Mutex;
    use tenuo::{ConstraintSet, SigningKey, Warrant};

    #[derive(Default)]
    struct Seen {
        bodies: Mutex<Vec<Value>>,
        session: Mutex<Option<String>>,
    }

    /// Stands in for OpenShell plus the MCP server.
    async fn upstream(State(seen): State<Arc<Seen>>, request: Request<Body>) -> Response<Body> {
        let session = request
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        *seen.session.lock().unwrap() = session;
        let body = to_bytes(request.into_body(), 1 << 20).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        seen.bodies.lock().unwrap().push(value.clone());
        let denial = value["params"]["name"]
            .as_str()
            .and_then(|name| DENIALS.iter().find(|(tool, _)| *tool == name))
            .map(|(_, body)| body.to_string());
        let denial = denial.or_else(|| {
            (value["params"]["name"] == "long_upstream").then(|| {
                json!({"error": "policy_denied", "detail": "é".repeat(4096),
                       "policy": "p".repeat(4096)})
                .to_string()
            })
        });
        if let Some(denial) = denial {
            return Response::builder()
                .status(403)
                .header("content-type", "application/json")
                .body(Body::from(denial))
                .unwrap();
        }
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .header("mcp-session-id", "s-1")
            .body(Body::from(
                "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
            ))
            .unwrap()
    }

    /// OpenShell 403 bodies, by the tool whose call receives them.
    const DENIALS: [(&str, &str); 8] = [
        (
            "denied_upstream",
            r#"{"error":"middleware_denied","reason_code":"tenuo_constraint_denied"}"#,
        ),
        (
            "withheld_upstream",
            r#"{"error":"middleware_denied","reason_code":"tenuo_result_too_large"}"#,
        ),
        // The quickstart's second identical call, as OpenShell v0.1.2 sent it.
        (
            "replayed_upstream",
            r#"{"binary":"/usr/bin/curl","detail":"Request rejected by configured middleware","error":"middleware_denied","host":"host.openshell.internal","layer":"l7","method":"POST","middleware":"tenuo-task-authority","path":"/mcp","policy":"demo-mcp","port":1,"reason_code":"tenuo_pop_replayed"}"#,
        ),
        // OpenShell's own L7 policy denial (`deny_response_body`).
        (
            "policy_upstream",
            r#"{"error":"policy_denied","policy":"demo-mcp","rule":"POST /mcp","detail":"tools/call read_secrets is not allowed by endpoint rules","layer":"l7","protocol":"rest","method":"POST","path":"/mcp","host":"mcp.internal","port":443,"binary":"/usr/local/bin/tenuo-openshell-agent","rule_missing":{"type":"rest_allow"},"next_steps":[]}"#,
        ),
        // An MCP protocol check, which has no reason_code.
        (
            "version_upstream",
            r#"{"error":"mcp_protocol_version_not_allowed","detail":"MCP protocol version 2024-11-05 is not allowed by endpoint policy","policy":"demo-mcp","layer":"l7","protocol":"mcp","method":"POST","path":"/mcp"}"#,
        ),
        // Another middleware on the same endpoint.
        (
            "guard_upstream",
            r#"{"error":"middleware_denied","detail":"Request rejected by configured middleware","middleware":"content-guard","reason_code":"content_match","policy":"demo-mcp","layer":"l7"}"#,
        ),
        // A relay check with a nested error object.
        (
            "nested_upstream",
            r#"{"error":{"code":"credential_placeholder_in_request_body","reason":"placeholder","message":"A credential placeholder in the request body cannot be forwarded."}}"#,
        ),
        (
            "garbled_upstream",
            r#"{"error":"bad code
with a newline","detail":"x"}"#,
        ),
    ];

    async fn start() -> (String, Arc<Seen>) {
        let seen = Arc::new(Seen::default());
        let app = axum::Router::new()
            .fallback(upstream)
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}/mcp", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let key = SigningKey::generate();
        let mut builder = Warrant::builder().capability("read_logs", ConstraintSet::new());
        for (tool, _) in DENIALS {
            builder = builder.capability(tool, ConstraintSet::new());
        }
        builder = builder.capability("long_upstream", ConstraintSet::new());
        let warrant = builder
            .holder(key.public_key())
            .ttl(Duration::from_secs(300))
            .build(&SigningKey::generate())
            .unwrap();
        let holder = Holder::new(
            key,
            WarrantSource::Inline(encode_chain(&[warrant]).unwrap()),
        );
        let proxy = Proxy::new(holder, upstream_url.parse().unwrap()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}/mcp", listener.local_addr().unwrap());
        let router = proxy.router();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (proxy_url, seen)
    }

    fn call(name: &str) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": name, "arguments": {}}})
    }

    #[tokio::test]
    async fn tool_calls_are_signed_and_streams_pass_through() {
        let (url, seen) = start().await;
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("mcp-session-id", HeaderValue::from_static("s-1"))
            .json(&call("read_logs"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.headers()["mcp-session-id"], "s-1");
        assert!(response.text().await.unwrap().starts_with("event: message"));
        assert_eq!(seen.session.lock().unwrap().as_deref(), Some("s-1"));
        let forwarded = seen.bodies.lock().unwrap()[0].clone();
        assert!(forwarded["params"]["_meta"]["tenuo"]["signature"].is_string());

        client
            .post(&url)
            .json(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
            .send()
            .await
            .unwrap();
        let listed = seen.bodies.lock().unwrap()[1].clone();
        assert!(listed.get("params").is_none());
    }

    #[tokio::test]
    async fn denials_become_jsonrpc_errors() {
        let (url, seen) = start().await;
        let client = reqwest::Client::new();

        let local: Value = client
            .post(&url)
            .json(&call("restart_service"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(local["error"]["code"], -32001);
        assert_eq!(local["error"]["data"]["tenuo"]["source"], "agent");
        assert!(
            seen.bodies.lock().unwrap().is_empty(),
            "local denial was forwarded"
        );

        let response = client
            .post(&url)
            .json(&call("denied_upstream"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let remote: Value = response.json().await.unwrap();
        assert_eq!(remote["id"], 1);
        assert_eq!(remote["error"]["data"]["tenuo"]["source"], "openshell");
        assert_eq!(
            remote["error"]["data"]["tenuo"]["code"],
            "tenuo_constraint_denied"
        );
        assert!(remote["error"]["data"]["tenuo"]["message"]
            .as_str()
            .unwrap()
            .contains("before it reached"));

        let withheld: Value = client
            .post(&url)
            .json(&call("withheld_upstream"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            withheld["error"]["data"]["tenuo"]["code"],
            "tenuo_result_too_large"
        );
        assert!(withheld["error"]["data"]["tenuo"]["message"]
            .as_str()
            .unwrap()
            .contains("already ran"));
    }

    async fn denial_for(url: &str, tool: &str) -> Value {
        let response = reqwest::Client::new()
            .post(url)
            .json(&call(tool))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["id"], 1);
        assert_eq!(body["error"]["code"], -32001);
        assert_eq!(body["error"]["data"]["tenuo"]["source"], "openshell");
        body["error"].clone()
    }

    #[tokio::test]
    async fn tenuo_codes_keep_their_messages() {
        let (url, _) = start().await;
        let error = denial_for(&url, "replayed_upstream").await;
        let tenuo = &error["data"]["tenuo"];
        assert_eq!(tenuo["code"], "tenuo_pop_replayed");
        assert!(tenuo["message"]
            .as_str()
            .unwrap()
            .starts_with("OpenShell denied a duplicate"));
        assert_eq!(
            error["message"],
            format!(
                "Authorization denied: {}",
                tenuo["message"].as_str().unwrap()
            )
        );
        assert_eq!(tenuo["openshell"]["error"], "middleware_denied");
        assert_eq!(tenuo["openshell"]["middleware"], "tenuo-task-authority");
        assert_eq!(tenuo["openshell"]["policy"], "demo-mcp");
        assert!(tenuo["openshell"].get("binary").is_none());
    }

    #[tokio::test]
    async fn openshell_denials_carry_openshell_reasons() {
        let (url, _) = start().await;

        let error = denial_for(&url, "policy_upstream").await;
        let tenuo = &error["data"]["tenuo"];
        assert_eq!(tenuo["code"], "policy_denied");
        assert_eq!(
            tenuo["message"],
            "OpenShell denied this call (policy_denied): tools/call read_secrets is not allowed by endpoint rules"
        );
        assert_eq!(tenuo["openshell"]["rule"], "POST /mcp");
        assert_eq!(tenuo["openshell"]["layer"], "l7");
        assert!(tenuo["openshell"].get("next_steps").is_none());
        assert!(error["message"]
            .as_str()
            .unwrap()
            .contains("not allowed by endpoint rules"));

        let tenuo = denial_for(&url, "version_upstream").await["data"]["tenuo"].clone();
        assert_eq!(tenuo["code"], "mcp_protocol_version_not_allowed");
        assert_eq!(tenuo["openshell"]["protocol"], "mcp");
        assert!(tenuo["message"].as_str().unwrap().contains("2024-11-05"));

        // Another middleware's reason code is shown, and is not a Tenuo code.
        let tenuo = denial_for(&url, "guard_upstream").await["data"]["tenuo"].clone();
        assert_eq!(tenuo["code"], "content_match");
        assert_eq!(tenuo["openshell"]["middleware"], "content-guard");
        assert_eq!(tenuo["openshell"]["error"], "middleware_denied");

        let tenuo = denial_for(&url, "nested_upstream").await["data"]["tenuo"].clone();
        assert_eq!(tenuo["code"], "credential_placeholder_in_request_body");
        assert!(tenuo["message"]
            .as_str()
            .unwrap()
            .contains("cannot be forwarded"));

        // A code OpenShell would never send is not passed on as one.
        let tenuo = denial_for(&url, "garbled_upstream").await["data"]["tenuo"].clone();
        assert_eq!(tenuo["code"], "forbidden");
        assert!(tenuo["openshell"].get("error").is_none());

        let tenuo = denial_for(&url, "long_upstream").await["data"]["tenuo"].clone();
        assert_eq!(tenuo["code"], "policy_denied");
        let detail = tenuo["openshell"]["detail"].as_str().unwrap();
        assert!(detail.len() <= MAX_FIELD_BYTES && detail.starts_with('é'));
        assert!(tenuo["openshell"]["policy"].as_str().unwrap().len() <= MAX_FIELD_BYTES);
        assert!(tenuo["message"].as_str().unwrap().len() < 2 * MAX_FIELD_BYTES);
    }
}

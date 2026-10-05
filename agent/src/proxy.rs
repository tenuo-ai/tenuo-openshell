//! Loopback MCP proxy for an unmodified agent.
//!
//! The agent's MCP client points at this proxy instead of the MCP server. The
//! proxy signs each `tools/call` with the sandbox's holder key and forwards
//! everything else unchanged, including Streamable HTTP event streams. Only
//! the proxy needs network access to the MCP server, so the OpenShell policy
//! can list this binary alone for that endpoint.

use crate::authority::Holder;
use crate::sign::{error_response, sign_body, Signed};
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

/// OpenShell answers a middleware denial with HTTP 403 and a `reason_code`.
/// An MCP client would surface that as a transport failure; the agent gets a
/// JSON-RPC error carrying the code instead.
async fn openshell_denial(upstream: reqwest::Response, id: &Value) -> Response<Body> {
    let bytes = upstream.bytes().await.unwrap_or_default();
    let reason = (bytes.len() <= MAX_DENIAL_BYTES)
        .then(|| serde_json::from_slice::<Value>(&bytes).ok())
        .flatten()
        .and_then(|value| {
            value
                .get("reason_code")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "forbidden".to_string());
    let approval = reason == "tenuo_approval_required";
    // A result block comes after the call: the tool ran, only its result was
    // withheld. Say so, so the agent does not retry a non-idempotent call.
    let message = if reason.starts_with("tenuo_result_") {
        "OpenShell withheld the result; the call already ran on the MCP server"
    } else if reason == "tenuo_pop_replayed" {
        // Proofs sign a 30-second window, so an identical call inside it
        // carries the same proof. The first one was accepted.
        "OpenShell denied a duplicate: an identical call was already accepted in this 30-second window; wait and retry, or ask the operator to list the tool in idempotent_tools"
    } else {
        "OpenShell denied this call before it reached the MCP server"
    };
    json(
        StatusCode::OK,
        error_response(id, &reason, message, approval, "openshell"),
    )
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
        let reason = match value["params"]["name"].as_str() {
            Some("denied_upstream") => Some("tenuo_constraint_denied"),
            Some("withheld_upstream") => Some("tenuo_result_too_large"),
            _ => None,
        };
        if let Some(reason) = reason {
            return Response::builder()
                .status(403)
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"error":"middleware_denied","reason_code":"{reason}"}}"#
                )))
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

    async fn start() -> (String, Arc<Seen>) {
        let seen = Arc::new(Seen::default());
        let app = axum::Router::new()
            .fallback(upstream)
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}/mcp", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let key = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read_logs", ConstraintSet::new())
            .capability("denied_upstream", ConstraintSet::new())
            .capability("withheld_upstream", ConstraintSet::new())
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
}

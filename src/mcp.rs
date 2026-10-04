//! MCP `tools/call` extraction from an HTTP body.
//!
//! JSON objects with a repeated key are rejected. `serde_json::Value` would
//! otherwise keep the last occurrence.

use crate::policy::McpOptions;
use serde_json::Value;

const PASS_THROUGH_METHODS: &[&str] = &[
    "initialize",
    "notifications/initialized",
    "notifications/cancelled",
    "ping",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "prompts/list",
];

#[derive(Debug)]
pub enum McpRequest {
    /// A listed lifecycle method, or a method the sandbox policy adds. No
    /// warrant is required.
    PassThrough,
    /// A JSON-RPC response the client returns for a server-initiated request.
    /// It is forwarded only when the sandbox policy allows client responses.
    ClientResponse,
    ToolCall {
        name: String,
        arguments: Value,
        /// JSON-RPC id, used as the receipt request id when it is present.
        request_id: String,
        /// `params._meta.tenuo` when present.
        tenuo: Option<Value>,
        /// Full JSON-RPC object, used when `_meta.tenuo` is removed on allow.
        document: Value,
    },
}

#[derive(Debug)]
pub enum McpError {
    NotJson,
    DuplicateKey,
    Batch,
    NotAnObject,
    UnsupportedMethod,
    InvalidToolCall,
}

pub fn parse_body(body: &[u8], options: &McpOptions) -> Result<McpRequest, McpError> {
    if body.is_empty() {
        return Err(McpError::NotJson);
    }
    let document = parse_json(body)?;
    if document.is_array() {
        return Err(McpError::Batch);
    }
    let object = document.as_object().ok_or(McpError::NotAnObject)?;
    let Some(method) = object.get("method") else {
        return if is_response(object) && options.allow_client_responses {
            Ok(McpRequest::ClientResponse)
        } else {
            Err(McpError::UnsupportedMethod)
        };
    };
    let method = method.as_str().ok_or(McpError::NotAnObject)?;
    if method == "tools/call" {
        return parse_tool_call(document);
    }
    if PASS_THROUGH_METHODS.contains(&method) || options.passthrough_methods.contains(method) {
        return Ok(McpRequest::PassThrough);
    }
    Err(McpError::UnsupportedMethod)
}

/// A JSON-RPC response: an `id` and exactly one of `result` or `error`.
fn is_response(object: &serde_json::Map<String, Value>) -> bool {
    object.contains_key("id") && (object.contains_key("result") != object.contains_key("error"))
}

fn parse_tool_call(document: Value) -> Result<McpRequest, McpError> {
    let params = document
        .get("params")
        .and_then(Value::as_object)
        .ok_or(McpError::InvalidToolCall)?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or(McpError::InvalidToolCall)?
        .to_string();
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Value::Object(serde_json::Map::new()),
        Some(value @ Value::Object(_)) => value.clone(),
        Some(_) => return Err(McpError::InvalidToolCall),
    };
    let tenuo = params
        .get("_meta")
        .and_then(Value::as_object)
        .and_then(|meta| meta.get("tenuo"))
        .cloned();
    Ok(McpRequest::ToolCall {
        name,
        arguments,
        request_id: jsonrpc_id(&document),
        tenuo,
        document,
    })
}

fn jsonrpc_id(document: &Value) -> String {
    match document.get("id") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        _ => String::new(),
    }
}

/// JSON encoding of `document` with `params._meta.tenuo` removed.
pub fn strip_tenuo(document: &Value) -> Result<Vec<u8>, McpError> {
    let mut document = document.clone();
    let params = document
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .ok_or(McpError::InvalidToolCall)?;
    if let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) {
        meta.remove("tenuo");
        if meta.is_empty() {
            params.remove("_meta");
        }
    }
    serde_json::to_vec(&document).map_err(|_| McpError::NotJson)
}

/// Parse with Tenuo core's strict parser: a repeated object key is an error
/// rather than letting the last occurrence win, so the proof covers the
/// arguments the tool receives.
fn parse_json(body: &[u8]) -> Result<Value, McpError> {
    let text = std::str::from_utf8(body).map_err(|_| McpError::NotJson)?;
    tenuo::parse_json_strict(text).map_err(|error| match error {
        tenuo::StrictJsonError::DuplicateKey => McpError::DuplicateKey,
        _ => McpError::NotJson,
    })
}

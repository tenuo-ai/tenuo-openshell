//! MCP body parsing with the default and a permissive sandbox configuration.
//!
//! Beyond "does not panic", every accepted body is checked against serde_json:
//! the classification must agree with the method serde_json sees, and
//! stripping `_meta.tenuo` must leave no `tenuo` entry in the forwarded body.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::OnceLock;
use tenuo_openshell_middleware::mcp::{self, McpRequest};
use tenuo_openshell_middleware::policy::McpOptions;

fn permissive() -> &'static McpOptions {
    static OPTIONS: OnceLock<McpOptions> = OnceLock::new();
    OPTIONS.get_or_init(|| McpOptions {
        passthrough_methods: HashSet::from(["resources/read".to_string()]),
        allow_client_responses: true,
    })
}

fuzz_target!(|body: &[u8]| {
    let default = McpOptions::default();
    for options in [&default, permissive()] {
        let Ok(request) = mcp::parse_body(body, options) else {
            continue;
        };
        // An accepted body is one JSON object without repeated keys, so
        // serde_json must parse it to the same value.
        let document: Value = serde_json::from_slice(body).expect("accepted body is JSON");
        let object = document.as_object().expect("accepted body is an object");
        let method = object.get("method").and_then(Value::as_str);
        match request {
            McpRequest::ToolCall {
                name,
                document: parsed,
                tenuo,
                ..
            } => {
                assert_eq!(method, Some("tools/call"));
                assert!(!name.is_empty());
                assert_eq!(parsed, document);
                assert_eq!(tenuo.as_ref(), document.pointer("/params/_meta/tenuo"));
                let stripped = mcp::strip_tenuo(&parsed).expect("strip");
                let stripped: Value = serde_json::from_slice(&stripped).expect("stripped JSON");
                assert!(stripped.pointer("/params/_meta/tenuo").is_none());
            }
            McpRequest::PassThrough => {
                let method = method.expect("pass-through has a method");
                assert!(
                    lifecycle(method) || options.passthrough_methods.contains(method),
                    "{method}"
                );
            }
            McpRequest::ClientResponse => {
                assert!(options.allow_client_responses);
                assert!(!object.contains_key("method"));
                assert!(object.contains_key("id"));
            }
        }
    }
});

fn lifecycle(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "notifications/initialized"
            | "notifications/cancelled"
            | "ping"
            | "tools/list"
            | "resources/list"
            | "resources/templates/list"
            | "prompts/list"
    )
}

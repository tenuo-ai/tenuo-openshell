//! Attach `params._meta.tenuo` to MCP `tools/call` requests.

use crate::authority::{AuthorityError, Holder};
use serde_json::{json, Map, Value};
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::encode_meta_from_authorized;

/// JSON-RPC error codes Tenuo's MCP integrations use for denials.
pub const AUTHORIZATION_DENIED: i64 = -32001;
pub const APPROVAL_REQUIRED: i64 = -32002;

pub enum Signed {
    /// Not a `tools/call`; forward the original bytes.
    Unchanged,
    /// Signed body to forward.
    Body(Vec<u8>),
    /// JSON-RPC error to return to the agent. Nothing is forwarded.
    Denied(Vec<u8>),
}

/// Sign one JSON-RPC message if it is a `tools/call`.
pub fn sign_body(holder: &Holder, body: &[u8]) -> Signed {
    let Ok(mut document) = serde_json::from_slice::<Value>(body) else {
        return Signed::Unchanged;
    };
    if document.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Signed::Unchanged;
    }
    let id = document.get("id").cloned().unwrap_or(Value::Null);
    let Some(params) = document.get_mut("params").and_then(Value::as_object_mut) else {
        return Signed::Denied(denial(
            &id,
            "invalid-request",
            "tools/call has no params",
            false,
        ));
    };
    let Some(name) = params
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Signed::Denied(denial(
            &id,
            "invalid-request",
            "tools/call has no tool name",
            false,
        ));
    };
    let arguments = match params.get("arguments") {
        None | Some(Value::Null) => Value::Object(Map::new()),
        Some(value @ Value::Object(_)) => value.clone(),
        Some(_) => {
            return Signed::Denied(denial(
                &id,
                "invalid-request",
                "tools/call arguments must be an object",
                false,
            ))
        }
    };
    let meta = match authorize(holder, &name, &arguments) {
        Ok(meta) => meta,
        Err(error) => return Signed::Denied(error.into_response(&id)),
    };
    let slot = params
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(slot) = slot.as_object_mut() else {
        return Signed::Denied(denial(
            &id,
            "invalid-request",
            "params._meta must be an object",
            false,
        ));
    };
    slot.insert("tenuo".to_string(), meta);
    match serde_json::to_vec(&document) {
        Ok(body) => Signed::Body(body),
        Err(_) => Signed::Denied(denial(
            &id,
            "invalid-request",
            "could not encode request",
            false,
        )),
    }
}

enum SignError {
    Authority(AuthorityError),
    Denied(tenuo::sdk::Denial),
    Arguments,
    Encoding,
}

impl SignError {
    fn into_response(self, id: &Value) -> Vec<u8> {
        match self {
            Self::Authority(AuthorityError::NoWarrant) => denial(
                id,
                "authority-missing",
                "no warrant is installed in this sandbox",
                false,
            ),
            Self::Authority(error) => denial(id, "authority-malformed", &error.to_string(), false),
            Self::Denied(denied) => {
                denial(id, denied.code(), denied.message(), denied.needs_approval())
            }
            Self::Arguments => denial(
                id,
                "arguments-rejected",
                "tool arguments cannot be signed",
                false,
            ),
            Self::Encoding => denial(id, "authority-malformed", "could not encode proof", false),
        }
    }
}

fn authorize(holder: &Holder, name: &str, arguments: &Value) -> Result<Value, SignError> {
    let presented = holder.present().map_err(SignError::Authority)?;
    let call = Call::try_from_json(name, arguments).map_err(|_| SignError::Arguments)?;
    match presented
        .guard
        .guard(&presented.authority, &call, encode_meta_from_authorized)
    {
        Ok(guarded) => Ok(guarded.into_inner()),
        Err(tenuo::sdk::GuardError::Denied(denied)) => Err(SignError::Denied(denied)),
        Err(_) => Err(SignError::Encoding),
    }
}

/// JSON-RPC error for a call that did not leave the sandbox, or that the
/// OpenShell middleware denied. `source` tells the agent which one.
pub fn denial(id: &Value, code: &str, message: &str, needs_approval: bool) -> Vec<u8> {
    error_response(id, code, message, needs_approval, "agent")
}

pub fn error_response(
    id: &Value,
    code: &str,
    message: &str,
    needs_approval: bool,
    source: &str,
) -> Vec<u8> {
    let (number, title) = if needs_approval {
        (APPROVAL_REQUIRED, "Approval required")
    } else {
        (AUTHORIZATION_DENIED, "Authorization denied")
    };
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": number,
            "message": title,
            "data": {"tenuo": {"code": code, "message": message, "source": source}}
        }
    }))
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::WarrantSource;
    use std::time::Duration;
    use tenuo::{ConstraintSet, Exact, SigningKey, Warrant};

    fn holder_with(tool: &str) -> (Holder, SigningKey) {
        let issuer = SigningKey::generate();
        let key = SigningKey::generate();
        let mut constraints = ConstraintSet::new();
        constraints.insert("service", Exact::new("payments"));
        let warrant = Warrant::builder()
            .capability(tool, constraints)
            .holder(key.public_key())
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let encoded = crate::authority::encode_chain(&[warrant]).unwrap();
        (Holder::new(key, WarrantSource::Inline(encoded)), issuer)
    }

    fn call(name: &str, arguments: Value, meta: Option<Value>) -> Vec<u8> {
        let mut params = json!({"name": name, "arguments": arguments});
        if let Some(meta) = meta {
            params["_meta"] = meta;
        }
        serde_json::to_vec(
            &json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params}),
        )
        .unwrap()
    }

    fn error_code(body: &[u8]) -> (i64, String) {
        let value: Value = serde_json::from_slice(body).unwrap();
        (
            value["error"]["code"].as_i64().unwrap(),
            value["error"]["data"]["tenuo"]["code"]
                .as_str()
                .unwrap()
                .to_string(),
        )
    }

    #[test]
    fn a_permitted_call_is_signed_and_keeps_other_meta() {
        let (holder, _) = holder_with("read_logs");
        let body = call(
            "read_logs",
            json!({"service": "payments"}),
            Some(json!({"progressToken": 3})),
        );
        let Signed::Body(signed) = sign_body(&holder, &body) else {
            panic!("call was not signed");
        };
        let value: Value = serde_json::from_slice(&signed).unwrap();
        assert_eq!(value["params"]["_meta"]["progressToken"], 3);
        let meta = &value["params"]["_meta"]["tenuo"];
        assert!(meta["warrant"].is_string() && meta["signature"].is_string());
        let decoded = tenuo::sdk::transport::mcp_meta::decode_meta(meta).unwrap();
        assert_eq!(decoded.chain().len(), 1);
    }

    #[test]
    fn denials_are_returned_locally_with_the_tenuo_code() {
        let (holder, _) = holder_with("read_logs");
        let Signed::Denied(body) = sign_body(&holder, &call("restart_service", json!({}), None))
        else {
            panic!("call outside the warrant was forwarded");
        };
        assert_eq!(
            error_code(&body),
            (AUTHORIZATION_DENIED, "tool-not-authorized".into())
        );

        let Signed::Denied(body) = sign_body(
            &holder,
            &call("read_logs", json!({"service": "identity"}), None),
        ) else {
            panic!("constraint violation was forwarded");
        };
        assert_eq!(error_code(&body).1, "constraint-violation");
    }

    #[test]
    fn other_messages_pass_through() {
        let (holder, _) = holder_with("read_logs");
        for body in [
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#.to_vec(),
            b"not json".to_vec(),
        ] {
            assert!(matches!(sign_body(&holder, &body), Signed::Unchanged));
        }
    }

    #[test]
    fn missing_warrant_is_reported_to_the_agent() {
        let directory = tempfile::tempdir().unwrap();
        let holder = Holder::new(
            SigningKey::generate(),
            WarrantSource::File(directory.path().join("warrant")),
        );
        let Signed::Denied(body) = sign_body(&holder, &call("read_logs", json!({}), None)) else {
            panic!("unsigned call was forwarded");
        };
        assert_eq!(error_code(&body).1, "authority-missing");
    }
}

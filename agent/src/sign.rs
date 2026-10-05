//! Attach `params._meta.tenuo` to MCP `tools/call` requests.

use crate::approvals;
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
    /// Approval is required and none is installed; the request was recorded.
    ApprovalPending([u8; 32]),
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
            Self::ApprovalPending(hash) => {
                let hash = hex::encode(hash);
                let message = format!(
                    "request {hash} is waiting for an approver (`tenuo-openshell approve --request {hash}`); retry the same call once it is approved"
                );
                let mut body: Value =
                    serde_json::from_slice(&denial(id, "approval-required", &message, true))
                        .unwrap_or_default();
                body["error"]["data"]["tenuo"]["request_hash"] = Value::String(hash);
                serde_json::to_vec(&body).unwrap_or_default()
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
    let store = holder.approvals();
    let leaf = presented.authority.leaf();
    let hash = approvals::request_hash(leaf, &call);
    let installed = store.map(|store| store.load(&hash)).unwrap_or_default();
    let signed: Vec<_> = installed
        .iter()
        .map(|(_, approval)| approval.clone())
        .collect();
    let attempt = if signed.is_empty() {
        AuthorizationAttempt::new(&call)
    } else {
        AuthorizationAttempt::with_approvals(&call, &signed)
    };
    match presented
        .guard
        .guard_attempt(&presented.authority, attempt, encode_meta_from_authorized)
    {
        Ok(guarded) => {
            if let Some(store) = store {
                let paths: Vec<_> = installed.into_iter().map(|(path, _)| path).collect();
                store.consume(&hash, &paths);
            }
            Ok(guarded.into_inner())
        }
        Err(tenuo::sdk::GuardError::Denied(denied)) if denied.needs_approval() => {
            let recorded = match (store, denied.approval_request()) {
                (Some(store), Some(request)) => store
                    .record_pending(request, presented.authority.chain(), arguments)
                    .is_ok(),
                _ => false,
            };
            if recorded {
                Err(SignError::ApprovalPending(hash))
            } else {
                Err(SignError::Denied(denied))
            }
        }
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
    error_response_with(id, code, message, needs_approval, source, None)
}

/// `error_response` with `extra` fields merged into `data.tenuo`.
pub fn error_response_with(
    id: &Value,
    code: &str,
    message: &str,
    needs_approval: bool,
    source: &str,
    extra: Option<serde_json::Map<String, Value>>,
) -> Vec<u8> {
    let mut tenuo = serde_json::Map::new();
    tenuo.insert("code".into(), json!(code));
    tenuo.insert("message".into(), json!(message));
    tenuo.insert("source".into(), json!(source));
    for (key, value) in extra.into_iter().flatten() {
        tenuo.entry(key).or_insert(value);
    }
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
            // Many MCP clients surface only `message`, so it names the reason.
            "message": format!("{title}: {message}"),
            "data": {"tenuo": tenuo}
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

    #[test]
    fn a_gated_call_waits_for_an_approval_then_uses_it_once() {
        use crate::approvals::ApprovalStore;
        let directory = tempfile::tempdir().unwrap();
        let issuer = SigningKey::generate();
        let key = SigningKey::generate();
        let approver = SigningKey::generate();
        let mut gates = tenuo::ApprovalGateMap::new();
        gates.insert(
            "restart_service".to_string(),
            tenuo::ToolApprovalGate::whole_tool(),
        );
        let warrant = Warrant::builder()
            .capability("restart_service", ConstraintSet::new())
            .holder(key.public_key())
            .required_approvers(vec![approver.public_key()])
            .min_approvals(1)
            .extension(
                tenuo::APPROVAL_GATE_EXTENSION_KEY,
                tenuo::encode_approval_gate_map(&gates).unwrap(),
            )
            .ttl(Duration::from_secs(300))
            .build(&issuer)
            .unwrap();
        let store = ApprovalStore::new(directory.path());
        let holder = Holder::new(
            key,
            WarrantSource::Inline(crate::authority::encode_chain(&[warrant]).unwrap()),
        )
        .with_approvals(store.clone());
        let body = call("restart_service", json!({"service": "payments"}), None);

        let Signed::Denied(first) = sign_body(&holder, &body) else {
            panic!("gated call was signed without an approval");
        };
        let first: Value = serde_json::from_slice(&first).unwrap();
        assert_eq!(first["error"]["code"], APPROVAL_REQUIRED);
        let hash = first["error"]["data"]["tenuo"]["request_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let pending = store.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["request_hash"], hash);
        assert_eq!(pending[0]["arguments"], json!({"service": "payments"}));
        let recorded: tenuo::approval::ApprovalRequest =
            serde_json::from_value(pending[0]["request"].clone()).unwrap();
        assert_eq!(hex::encode(recorded.request_hash), hash);
        let chain =
            tenuo::meta_envelope::decode_warrant_chain(pending[0]["warrant"].as_str().unwrap())
                .unwrap();
        assert!(recorded.matches_warrant(chain.last().unwrap()).unwrap());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed = tenuo::approval::SignedApproval::create(
            tenuo::approval::ApprovalPayload {
                version: 1,
                request_hash: hex::decode(&hash).unwrap().try_into().unwrap(),
                nonce: [3; 16],
                external_id: "test".to_string(),
                approved_at: now,
                expires_at: now + 300,
                extensions: None,
            },
            &approver,
        );
        let mut encoded = Vec::new();
        ciborium::into_writer(&signed, &mut encoded).unwrap();
        store.install(&encoded).unwrap();

        let Signed::Body(forwarded) = sign_body(&holder, &body) else {
            panic!("approved call was not signed");
        };
        let forwarded: Value = serde_json::from_slice(&forwarded).unwrap();
        let meta =
            tenuo::sdk::transport::mcp_meta::decode_meta(&forwarded["params"]["_meta"]["tenuo"])
                .unwrap();
        assert_eq!(meta.approvals().len(), 1);
        assert!(store.list_pending().is_empty());

        assert!(matches!(sign_body(&holder, &body), Signed::Denied(_)));
    }
}

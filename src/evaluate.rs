//! One HTTP middleware decision. No network.
//!
//! Receipt export is optional and does not change the decision.

use crate::mcp::{self, McpError, McpRequest};
use crate::policy::{MetaMode, PolicySet};
use crate::reason;
use crate::receipt::{DecisionReceipt, ReceiptLog};
use serde_json::Value;
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::decode_meta;

pub struct Outcome {
    pub allow: bool,
    pub reason_code: &'static str,
    /// Set when the forwarded body must replace the admitted body.
    pub replacement: Option<Vec<u8>>,
}

pub fn evaluate(
    policy: &PolicySet,
    sandbox_id: &str,
    pre_credentials: bool,
    body: &[u8],
    meta_mode: MetaMode,
    receipts: Option<&ReceiptLog>,
) -> Outcome {
    if !pre_credentials {
        return deny(reason::INVALID_REQUEST);
    }
    let guard = match policy.guard(sandbox_id) {
        Ok(guard) => guard,
        Err(code) => return deny(code),
    };
    let trusted_roots_hash = policy.trusted_roots_hash(sandbox_id).ok();
    let request = match mcp::parse_body(body) {
        Ok(request) => request,
        Err(
            McpError::Batch
            | McpError::DuplicateKey
            | McpError::UnsupportedMethod
            | McpError::InvalidToolCall
            | McpError::NotAnObject
            | McpError::NotJson
            | McpError::TrailingData,
        ) => {
            return deny(reason::INVALID_REQUEST);
        }
    };
    match request {
        McpRequest::PassThrough => allow_unchanged(),
        McpRequest::ToolCall {
            name,
            arguments,
            request_id,
            tenuo,
            document,
        } => authorize_tool(
            guard,
            meta_mode,
            &name,
            &arguments,
            tenuo.as_ref(),
            &document,
            ReceiptContext {
                log: receipts,
                request_id: &request_id,
                trusted_roots_hash,
            },
        ),
    }
}

struct ReceiptContext<'a> {
    log: Option<&'a ReceiptLog>,
    request_id: &'a str,
    trusted_roots_hash: Option<[u8; 32]>,
}

fn authorize_tool(
    guard: &Guard,
    meta_mode: MetaMode,
    name: &str,
    arguments: &Value,
    tenuo: Option<&Value>,
    document: &Value,
    receipts: ReceiptContext<'_>,
) -> Outcome {
    let Some(tenuo) = tenuo else {
        return deny(reason::MISSING_WARRANT);
    };
    let owned = match decode_meta(tenuo) {
        Ok(owned) => owned,
        Err(_) => return deny(reason::INVALID_REQUEST),
    };
    let received = match owned.as_received() {
        Ok(received) => received,
        Err(_) => return deny(reason::MISSING_WARRANT),
    };
    let call = match Call::try_from_json(name, arguments) {
        Ok(call) => call,
        Err(_) => return deny(reason::INVALID_REQUEST),
    };
    if let Err(denial) = guard.check_received(&received, &call) {
        record(
            &receipts,
            DecisionReceipt {
                request_id: receipts.request_id,
                tool: name,
                chain: received.chain(),
                pop: received.signature().to_bytes(),
                pop_args: call.pop_args(),
                trusted_roots_hash: [0; 32],
                denial: Some(&denial),
            },
        );
        return deny(reason::from_denial_code(denial.code()));
    }
    let allowed = DecisionReceipt {
        request_id: receipts.request_id,
        tool: name,
        chain: received.chain(),
        pop: received.signature().to_bytes(),
        pop_args: call.pop_args(),
        trusted_roots_hash: [0; 32],
        denial: None,
    };
    match meta_mode {
        MetaMode::Preserve => {
            record(&receipts, allowed);
            allow_unchanged()
        }
        MetaMode::Strip => match mcp::strip_tenuo(document) {
            Ok(body) => {
                record(&receipts, allowed);
                Outcome {
                    allow: true,
                    reason_code: "",
                    replacement: Some(body),
                }
            }
            Err(_) => deny(reason::VERIFIER_FAILED),
        },
    }
}

fn record(receipts: &ReceiptContext<'_>, mut decision: DecisionReceipt<'_>) {
    let (Some(log), Some(trusted_roots_hash)) = (receipts.log, receipts.trusted_roots_hash) else {
        return;
    };
    decision.trusted_roots_hash = trusted_roots_hash;
    log.record(decision);
}

fn allow_unchanged() -> Outcome {
    Outcome {
        allow: true,
        reason_code: "",
        replacement: None,
    }
}

fn deny(reason_code: &'static str) -> Outcome {
    Outcome {
        allow: false,
        reason_code,
        replacement: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::ReceiptLog;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tenuo::sdk::transport::mcp_meta::encode_meta;
    use tenuo::{ConstraintSet, Exact, Range, SigningKey, Warrant, SIGNATURE_CONTEXT};

    fn policy_for(root: &SigningKey) -> PolicySet {
        let document = json!({
            "max_warrant_lifetime_secs": 3600,
            "sandboxes": {
                "sbx": { "trusted_roots": [hex::encode(root.public_key().to_bytes())] }
            }
        });
        PolicySet::from_json(document.to_string().as_bytes()).expect("policy")
    }

    fn sign(warrant: &Warrant, holder: &SigningKey, name: &str, arguments: &Value) -> Value {
        let call = Call::try_from_json(name, arguments).expect("call");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs() as i64;
        let preimage = warrant
            .pop_preimage(call.capability(), call.pop_args(), now, 30)
            .expect("preimage");
        let mut message = SIGNATURE_CONTEXT.to_vec();
        message.extend(preimage);
        let signature = holder.sign_raw(&message);
        encode_meta(std::slice::from_ref(warrant), &signature, &[]).expect("meta")
    }

    fn tools_call(name: &str, arguments: Value, tenuo: Option<Value>) -> Vec<u8> {
        let mut params = serde_json::Map::new();
        params.insert("name".into(), Value::String(name.to_string()));
        params.insert("arguments".into(), arguments);
        if let Some(tenuo) = tenuo {
            params.insert("_meta".into(), json!({ "tenuo": tenuo }));
        }
        serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": Value::Object(params)
        }))
        .expect("body")
    }

    fn warrant(issuer: &SigningKey, holder: &SigningKey, tool: &str) -> Warrant {
        Warrant::builder()
            .capability(tool, ConstraintSet::new())
            .holder(holder.public_key())
            .ttl(std::time::Duration::from_secs(300))
            .build(issuer)
            .expect("warrant")
    }

    #[test]
    fn missing_meta_denies_before_credential_injection() {
        let issuer = SigningKey::generate();
        let policy = policy_for(&issuer);
        let body = tools_call("restart_service", json!({"service": "payments"}), None);
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, None);
        assert!(!outcome.allow);
        assert_eq!(outcome.reason_code, reason::MISSING_WARRANT);
        assert!(outcome.replacement.is_none());
    }

    #[test]
    fn read_only_warrant_denies_restart() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_for(&issuer);
        let issued = warrant(&issuer, &holder, "read_logs");
        let arguments = json!({"service": "payments", "environment": "staging"});
        let meta = sign(&issued, &holder, "restart_service", &arguments);
        let body = tools_call("restart_service", arguments, Some(meta));
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, None);
        assert!(!outcome.allow);
        assert_eq!(outcome.reason_code, reason::TOOL_DENIED);
    }

    #[test]
    fn matching_tool_is_allowed_and_can_strip_meta() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_for(&issuer);
        let issued = warrant(&issuer, &holder, "read_logs");
        let arguments = json!({"service": "payments"});
        let meta = sign(&issued, &holder, "read_logs", &arguments);
        let body = tools_call("read_logs", arguments, Some(meta));
        let preserved = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, None);
        assert!(preserved.allow);
        assert!(preserved.replacement.is_none());

        let stripped = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None);
        assert!(stripped.allow);
        let replacement = stripped.replacement.expect("replacement");
        let document: Value = serde_json::from_slice(&replacement).expect("json");
        assert!(document["params"].get("_meta").is_none());
        assert_eq!(document["params"]["name"], "read_logs");
    }

    #[test]
    fn lifecycle_methods_pass_and_unknown_shapes_deny() {
        let issuer = SigningKey::generate();
        let policy = policy_for(&issuer);
        let init = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
        assert!(evaluate(&policy, "sbx", true, &init, MetaMode::Preserve, None).allow);

        let batch = serde_json::to_vec(&json!([])).unwrap();
        let outcome = evaluate(&policy, "sbx", true, &batch, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::INVALID_REQUEST);

        let duplicate = br#"{"jsonrpc":"2.0","method":"ping","method":"ping"}"#;
        let outcome = evaluate(&policy, "sbx", true, duplicate, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::INVALID_REQUEST);

        let outcome = evaluate(&policy, "other", true, &init, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::VERIFIER_FAILED);
    }

    fn scoped_warrant(issuer: &SigningKey, holder: &SigningKey, restart: bool) -> Warrant {
        let mut read = ConstraintSet::new();
        read.insert("service", Exact::new("payments"));
        read.insert("environment", Exact::new("staging"));
        let mut builder = Warrant::builder().capability("read_logs", read);
        if restart {
            let mut restart_constraints = ConstraintSet::new();
            restart_constraints.insert("service", Exact::new("payments"));
            restart_constraints.insert("environment", Exact::new("staging"));
            restart_constraints.insert("replicas", Range::max(5.0).expect("range"));
            builder = builder.capability("restart_service", restart_constraints);
        }
        builder
            .holder(holder.public_key())
            .ttl(std::time::Duration::from_secs(300))
            .build(issuer)
            .expect("warrant")
    }

    #[test]
    fn two_holders_do_not_authorize_each_other() {
        let issuer = SigningKey::generate();
        let task_a = SigningKey::generate();
        let task_b = SigningKey::generate();
        let policy = policy_for(&issuer);
        let warrant_a = scoped_warrant(&issuer, &task_a, true);
        let warrant_b = scoped_warrant(&issuer, &task_b, false);
        let restart = json!({"service": "payments", "environment": "staging", "replicas": 3});

        let allowed = tools_call(
            "restart_service",
            restart.clone(),
            Some(sign(&warrant_a, &task_a, "restart_service", &restart)),
        );
        let outcome = evaluate(&policy, "sbx", true, &allowed, MetaMode::Preserve, None);
        assert!(outcome.allow);

        let other_task = tools_call(
            "restart_service",
            restart.clone(),
            Some(sign(&warrant_b, &task_b, "restart_service", &restart)),
        );
        let outcome = evaluate(&policy, "sbx", true, &other_task, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::TOOL_DENIED);

        let copied = tools_call(
            "restart_service",
            restart.clone(),
            Some(sign(&warrant_a, &task_b, "restart_service", &restart)),
        );
        let outcome = evaluate(&policy, "sbx", true, &copied, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::INVALID_AUTHORITY);

        let too_many = json!({"service": "payments", "environment": "staging", "replicas": 8});
        let over_limit = tools_call(
            "restart_service",
            too_many.clone(),
            Some(sign(&warrant_a, &task_a, "restart_service", &too_many)),
        );
        let outcome = evaluate(&policy, "sbx", true, &over_limit, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::CONSTRAINT_DENIED);
    }

    #[test]
    fn receipts_follow_the_decision_and_a_failed_write_does_not_change_it() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_for(&issuer);
        let issued = warrant(&issuer, &holder, "read_logs");
        let arguments = json!({"service": "payments"});
        let meta = sign(&issued, &holder, "read_logs", &arguments);
        let body = tools_call("read_logs", arguments, Some(meta));

        let directory = tempfile::tempdir().expect("tempdir");
        let log = ReceiptLog::open(
            &directory.path().join("receipt.key"),
            &directory.path().join("openshell.jsonl"),
        )
        .expect("receipt log");
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, Some(&log));
        assert!(outcome.allow);
        let line = std::fs::read_to_string(directory.path().join("openshell.jsonl")).expect("log");
        let bytes = hex::decode(line.trim()).expect("hex");
        let receipt: tenuo::Receipt =
            ciborium::from_reader(bytes.as_slice()).expect("receipt cbor");
        let payload = receipt.verify_signature().expect("signature");
        assert_eq!(payload.request_id, "1");
        assert_eq!(payload.action, "tool:read_logs");
        assert_eq!(payload.outcome.as_str(), "allow");
        assert!(payload.pop_signature.is_some());
        assert_eq!(payload.authorizer_id.as_deref(), Some("openshell"));
        assert!(payload.request_hash.is_some());
        assert!(payload.trusted_roots_hash.is_some());

        let blocked = tempfile::tempdir().expect("tempdir");
        let blocked_log = blocked.path().join("openshell.jsonl");
        std::fs::create_dir(&blocked_log).expect("directory blocks the log");
        let log = ReceiptLog::open(&blocked.path().join("receipt.key"), &blocked_log)
            .expect("receipt log opens before the first write");
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, Some(&log));
        assert!(outcome.allow);
    }
}

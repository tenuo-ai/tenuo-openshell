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
    pub request_id: String,
    /// Time inside this check, excluding network transit.
    pub verify_us: u64,
}

/// Check one admitted MCP body.
///
/// `verify_us` is the time spent in this check. When `TENUO_DECISION_LOG` is
/// set and the JSON-RPC id is present, one `tenuo_decision` line is written
/// to stderr. The line carries the request id, duration, outcome, and reason
/// code.
pub fn evaluate(
    policy: &PolicySet,
    sandbox_id: &str,
    pre_credentials: bool,
    body: &[u8],
    meta_mode: MetaMode,
    receipts: Option<&ReceiptLog>,
) -> Outcome {
    let started = std::time::Instant::now();
    let mut outcome = decide(
        policy,
        sandbox_id,
        pre_credentials,
        body,
        meta_mode,
        receipts,
    );
    outcome.verify_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if std::env::var_os("TENUO_DECISION_LOG").is_some() && !outcome.request_id.is_empty() {
        let name = if outcome.allow { "allow" } else { "deny" };
        let reason = if outcome.reason_code.is_empty() {
            "-"
        } else {
            outcome.reason_code
        };
        eprintln!(
            "tenuo_decision request_id={} verify_us={} outcome={} reason={}",
            outcome.request_id, outcome.verify_us, name, reason
        );
    }
    outcome
}

fn decide(
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
        return identified(deny(reason::MISSING_WARRANT), receipts.request_id);
    };
    let owned = match decode_meta(tenuo) {
        Ok(owned) => owned,
        Err(_) => return identified(deny(reason::INVALID_REQUEST), receipts.request_id),
    };
    let received = match owned.as_received() {
        Ok(received) => received,
        Err(_) => return identified(deny(reason::MISSING_WARRANT), receipts.request_id),
    };
    let call = match Call::try_from_json(name, arguments) {
        Ok(call) => call,
        Err(_) => return identified(deny(reason::INVALID_REQUEST), receipts.request_id),
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
        return identified(
            deny(reason::from_denial_code(denial.code())),
            receipts.request_id,
        );
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
            identified(allow_unchanged(), receipts.request_id)
        }
        MetaMode::Strip => match mcp::strip_tenuo(document) {
            Ok(body) => {
                record(&receipts, allowed);
                identified(
                    Outcome {
                        allow: true,
                        reason_code: "",
                        replacement: Some(body),
                        request_id: String::new(),
                        verify_us: 0,
                    },
                    receipts.request_id,
                )
            }
            Err(_) => identified(deny(reason::VERIFIER_FAILED), receipts.request_id),
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
        request_id: String::new(),
        verify_us: 0,
    }
}

fn deny(reason_code: &'static str) -> Outcome {
    Outcome {
        allow: false,
        reason_code,
        replacement: None,
        request_id: String::new(),
        verify_us: 0,
    }
}

fn identified(mut outcome: Outcome, request_id: &str) -> Outcome {
    outcome.request_id = request_id.to_string();
    outcome
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

    fn sign_chain(chain: &[Warrant], holder: &SigningKey, name: &str, arguments: &Value) -> Value {
        let warrant = chain.last().expect("leaf");
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
        encode_meta(chain, &signature, &[]).expect("meta")
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
    fn a_narrowed_child_can_read_but_cannot_restart_or_widen() {
        let issuer = SigningKey::generate();
        let parent_holder = SigningKey::generate();
        let child_holder = SigningKey::generate();
        let policy = policy_for(&issuer);
        let parent = scoped_warrant(&issuer, &parent_holder, true);
        let mut read = ConstraintSet::new();
        read.insert("service", Exact::new("payments"));
        read.insert("environment", Exact::new("staging"));
        let child = parent
            .attenuate()
            .holder(child_holder.public_key())
            .tool("read_logs", read.clone())
            .ttl(std::time::Duration::from_secs(120))
            .build(&parent_holder)
            .expect("narrowed child");
        let chain = [parent, child.clone()];
        let arguments = json!({"service": "payments", "environment": "staging"});
        let read_body = tools_call(
            "read_logs",
            arguments.clone(),
            Some(sign_chain(&chain, &child_holder, "read_logs", &arguments)),
        );
        let outcome = evaluate(&policy, "sbx", true, &read_body, MetaMode::Preserve, None);
        assert!(outcome.allow);

        let restart = json!({"service": "payments", "environment": "staging", "replicas": 3});
        let restart_body = tools_call(
            "restart_service",
            restart.clone(),
            Some(sign_chain(
                &chain,
                &child_holder,
                "restart_service",
                &restart,
            )),
        );
        let outcome = evaluate(
            &policy,
            "sbx",
            true,
            &restart_body,
            MetaMode::Preserve,
            None,
        );
        assert_eq!(outcome.reason_code, reason::TOOL_DENIED);

        let mut restart_constraints = read;
        restart_constraints.insert("replicas", Range::max(5.0).expect("range"));
        let widened = child
            .attenuate()
            .holder(SigningKey::generate().public_key())
            .tool("read_logs", {
                let mut allowed = ConstraintSet::new();
                allowed.insert("service", Exact::new("payments"));
                allowed.insert("environment", Exact::new("staging"));
                allowed
            })
            .tool("restart_service", restart_constraints)
            .ttl(std::time::Duration::from_secs(60))
            .build(&child_holder);
        match widened {
            Err(tenuo::Error::MonotonicityViolation(message)) => {
                assert!(message.contains("restart_service"), "{message}");
            }
            other => panic!("wider child was not refused: {other:?}"),
        }
    }

    fn approved_restart(issuer: &SigningKey) -> (SigningKey, SigningKey, Warrant, Value) {
        let holder = SigningKey::generate();
        let approver = SigningKey::generate();
        let mut read = ConstraintSet::new();
        read.insert("service", Exact::new("payments"));
        read.insert("environment", Exact::new("staging"));
        let mut restart = read.clone();
        restart.insert("replicas", Range::max(5.0).expect("range"));
        let mut gates = tenuo::ApprovalGateMap::new();
        gates.insert(
            "restart_service".to_string(),
            tenuo::ToolApprovalGate::whole_tool(),
        );
        let warrant = Warrant::builder()
            .capability("read_logs", read)
            .capability("restart_service", restart)
            .holder(holder.public_key())
            .required_approvers(vec![approver.public_key()])
            .min_approvals(1)
            .extension(
                tenuo::APPROVAL_GATE_EXTENSION_KEY,
                tenuo::encode_approval_gate_map(&gates).expect("gates"),
            )
            .ttl(std::time::Duration::from_secs(300))
            .build(issuer)
            .expect("warrant");
        let arguments = json!({"service": "payments", "environment": "staging", "replicas": 3});
        (holder, approver, warrant, arguments)
    }

    fn approval_for(
        approver: &SigningKey,
        warrant: &Warrant,
        tool: &str,
        arguments: &Value,
    ) -> tenuo::approval::SignedApproval {
        let call = Call::try_from_json(tool, arguments).expect("call");
        let request_hash = tenuo::approval::compute_request_hash(
            &warrant.id().to_string(),
            tool,
            call.pop_args(),
            Some(warrant.authorized_holder()),
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        tenuo::approval::SignedApproval::create(
            tenuo::approval::ApprovalPayload {
                version: 1,
                request_hash,
                nonce: [9u8; 16],
                external_id: "local-fixture-approver".to_string(),
                approved_at: now,
                expires_at: now + 300,
                extensions: None,
            },
            approver,
        )
    }

    fn body_with_approval(
        warrant: &Warrant,
        holder: &SigningKey,
        tool: &str,
        arguments: &Value,
        approval: Option<&tenuo::approval::SignedApproval>,
    ) -> Vec<u8> {
        let call = Call::try_from_json(tool, arguments).expect("call");
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
        let approvals = approval.into_iter().cloned().collect::<Vec<_>>();
        let meta =
            encode_meta(std::slice::from_ref(warrant), &signature, &approvals).expect("meta");
        tools_call(tool, arguments.clone(), Some(meta))
    }

    #[test]
    fn an_approval_covers_one_argument_set_and_a_repeat_stays_allowed() {
        let issuer = SigningKey::generate();
        let policy = policy_for(&issuer);
        let (holder, approver, warrant, arguments) = approved_restart(&issuer);
        let approval = approval_for(&approver, &warrant, "restart_service", &arguments);
        let allowed = body_with_approval(
            &warrant,
            &holder,
            "restart_service",
            &arguments,
            Some(&approval),
        );
        assert!(evaluate(&policy, "sbx", true, &allowed, MetaMode::Preserve, None).allow);
        assert!(evaluate(&policy, "sbx", true, &allowed, MetaMode::Preserve, None).allow);

        let missing = body_with_approval(&warrant, &holder, "restart_service", &arguments, None);
        let outcome = evaluate(&policy, "sbx", true, &missing, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::APPROVAL_REQUIRED);

        let other = json!({"service": "payments", "environment": "staging", "replicas": 5});
        let mismatch = body_with_approval(
            &warrant,
            &holder,
            "restart_service",
            &other,
            Some(&approval),
        );
        let outcome = evaluate(&policy, "sbx", true, &mismatch, MetaMode::Preserve, None);
        assert_eq!(outcome.reason_code, reason::INVALID_AUTHORITY);

        let over = json!({"service": "payments", "environment": "staging", "replicas": 8});
        let constrained = body_with_approval(&warrant, &holder, "restart_service", &over, None);
        let outcome = evaluate(&policy, "sbx", true, &constrained, MetaMode::Preserve, None);
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

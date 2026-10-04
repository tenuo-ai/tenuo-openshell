//! One HTTP middleware decision. No control-plane network request.
//!
//! Best-effort receipt persistence does not change the decision. Required
//! receipt persistence fails closed before an effect is allowed.

use crate::mcp::{self, McpError, McpRequest};
use crate::policy::{MetaMode, PolicySet, RequestTarget};
use crate::reason;
use crate::receipt::{DecisionReceipt, ReceiptLog};
use serde_json::Value;
use std::borrow::Cow;
use std::sync::OnceLock;
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::decode_meta;

#[derive(Default)]
pub struct Outcome {
    pub allow: bool,
    pub reason_code: &'static str,
    /// Set when the forwarded body must replace the admitted body.
    pub replacement: Option<Vec<u8>>,
    pub request_id: String,
    /// End-to-end time inside this enforcement decision. This includes local
    /// parsing and verification plus configured replay and receipt I/O.
    pub decision_us: u64,
    /// `tools/call` name, when the request was a tool call.
    pub tool: Option<String>,
    /// Leaf warrant id, when the request carried a decodable warrant.
    pub warrant_id: Option<String>,
    /// SHA-256 of the stored allow receipt.
    pub receipt_hash: Option<[u8; 32]>,
}

/// Check one admitted MCP request.
///
/// `decision_us` is the time spent in this check. When `TENUO_DECISION_LOG` is
/// set at startup and the JSON-RPC id is present, one `tenuo_decision` line is
/// written to stderr. The line carries the request id, duration, outcome, and
/// reason code.
pub async fn evaluate(
    policy: &PolicySet,
    sandbox_id: &str,
    pre_credentials: bool,
    target: &RequestTarget<'_>,
    body: &[u8],
    meta_mode: MetaMode,
    receipts: Option<&ReceiptLog>,
) -> Outcome {
    let started = std::time::Instant::now();
    let mut outcome = decide(
        policy,
        sandbox_id,
        pre_credentials,
        target,
        body,
        meta_mode,
        receipts,
    )
    .await;
    outcome.decision_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX);
    if decision_log_enabled() && !outcome.request_id.is_empty() {
        let name = if outcome.allow { "allow" } else { "deny" };
        let reason = if outcome.reason_code.is_empty() {
            "-"
        } else {
            outcome.reason_code
        };
        eprintln!(
            "tenuo_decision request_id={} decision_us={} outcome={} reason={}",
            log_safe_id(&outcome.request_id),
            outcome.decision_us,
            name,
            reason
        );
    }
    outcome
}

/// The JSON-RPC id as written in a `key=value` log line.
///
/// The id is chosen by the sandbox. An id outside a small token alphabet is
/// written as `hex:` and its UTF-8 bytes, so it cannot add a line or a field
/// such as `outcome=allow`.
pub(crate) fn log_safe_id(request_id: &str) -> Cow<'_, str> {
    let plain = request_id.len() <= 128
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.:/+@".contains(&byte));
    if plain {
        Cow::Borrowed(request_id)
    } else {
        Cow::Owned(format!("hex:{}", hex::encode(request_id.as_bytes())))
    }
}

pub(crate) fn decision_log_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("TENUO_DECISION_LOG").is_some())
}

async fn decide(
    policy: &PolicySet,
    sandbox_id: &str,
    pre_credentials: bool,
    target: &RequestTarget<'_>,
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
    let trusted_roots_hash = match policy.trusted_roots_hash(sandbox_id) {
        Ok(hash) => hash,
        Err(code) => return deny(code),
    };
    let revocation = policy.revocation_commitment(sandbox_id).ok().flatten();
    if let Err(code) = policy.admit_destination(sandbox_id, target, None) {
        return deny(code);
    }
    // Streamable HTTP opens the server-to-client stream with GET and ends the
    // session with DELETE. Neither carries a JSON-RPC message.
    match target.method {
        "POST" => {}
        "GET" | "DELETE" if body.is_empty() => return allow_unchanged(),
        _ => return deny(reason::INVALID_REQUEST),
    }
    let options = match policy.mcp_options(sandbox_id) {
        Ok(options) => options,
        Err(code) => return deny(code),
    };
    let request = match mcp::parse_body(body, options) {
        Ok(request) => request,
        Err(
            McpError::Batch
            | McpError::DuplicateKey
            | McpError::UnsupportedMethod
            | McpError::InvalidToolCall
            | McpError::NotAnObject
            | McpError::NotJson,
        ) => {
            return deny(reason::INVALID_REQUEST);
        }
    };
    match request {
        McpRequest::PassThrough | McpRequest::ClientResponse => allow_unchanged(),
        McpRequest::ToolCall {
            name,
            arguments,
            request_id,
            tenuo,
            document,
        } => {
            if let Err(code) = policy.admit_destination(sandbox_id, target, Some(&name)) {
                let mut outcome = identified(deny(code), &request_id);
                outcome.tool = Some(name);
                return outcome;
            }
            let mut outcome = authorize_tool(
                AuthorizationContext {
                    policy,
                    sandbox_id,
                    guard,
                    meta_mode,
                },
                &name,
                &arguments,
                tenuo.as_ref(),
                &document,
                ReceiptContext {
                    log: receipts,
                    request_id: &request_id,
                    trusted_roots_hash,
                    revocation,
                },
            )
            .await;
            outcome.tool = Some(name);
            outcome
        }
    }
}

struct ReceiptContext<'a> {
    log: Option<&'a ReceiptLog>,
    request_id: &'a str,
    trusted_roots_hash: [u8; 32],
    revocation: Option<(u64, [u8; 32])>,
}

struct AuthorizationContext<'a> {
    policy: &'a PolicySet,
    sandbox_id: &'a str,
    guard: &'a Guard,
    meta_mode: MetaMode,
}

async fn authorize_tool(
    authorization: AuthorizationContext<'_>,
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
    let mut outcome = match Call::try_from_json(name, arguments) {
        Ok(call) => {
            authorize_received(authorization, name, &received, &call, document, &receipts).await
        }
        Err(_) => identified(deny(reason::INVALID_REQUEST), receipts.request_id),
    };
    outcome.warrant_id = received.chain().last().map(|leaf| leaf.id().to_string());
    outcome
}

async fn authorize_received(
    authorization: AuthorizationContext<'_>,
    name: &str,
    received: &ReceivedAuthorization<'_>,
    call: &Call<'_>,
    document: &Value,
    receipts: &ReceiptContext<'_>,
) -> Outcome {
    if let Err(denial) = authorization.guard.check_received(received, call) {
        let _ = record(
            receipts,
            DecisionReceipt {
                request_id: receipts.request_id,
                tool: name,
                chain: received.chain(),
                pop: received.signature().to_bytes(),
                pop_args: call.pop_args(),
                trusted_roots_hash: receipts.trusted_roots_hash,
                srl_version: receipts.revocation.map(|value| value.0),
                srl_hash: receipts.revocation.map(|value| value.1),
                denial: Some(&denial),
            },
        );
        return identified(
            deny(reason::from_denial_code(denial.code())),
            receipts.request_id,
        );
    }
    let replacement = match authorization.meta_mode {
        MetaMode::Preserve => None,
        MetaMode::Strip => match mcp::strip_tenuo(document) {
            Ok(body) => Some(body),
            Err(_) => return identified(deny(reason::VERIFIER_FAILED), receipts.request_id),
        },
    };
    let reservation = match authorization
        .policy
        .reserve_claims(
            authorization.sandbox_id,
            name,
            &received.signature().to_bytes(),
            received.approvals(),
        )
        .await
    {
        Ok(reservation) => reservation,
        Err(code) => return identified(deny(code), receipts.request_id),
    };
    let allowed = DecisionReceipt {
        request_id: receipts.request_id,
        tool: name,
        chain: received.chain(),
        pop: received.signature().to_bytes(),
        pop_args: call.pop_args(),
        trusted_roots_hash: receipts.trusted_roots_hash,
        srl_version: receipts.revocation.map(|value| value.0),
        srl_hash: receipts.revocation.map(|value| value.1),
        denial: None,
    };
    if receipt_is_required(receipts) && !receipt_log_ready(receipts) {
        release_reservation(reservation, receipts.request_id).await;
        return identified(deny(reason::VERIFIER_FAILED), receipts.request_id);
    }
    let reservation = match reservation {
        Some(reservation) => match reservation.commit().await {
            Ok(()) => Some(reservation),
            Err(_) => {
                release_reservation(Some(reservation), receipts.request_id).await;
                return identified(deny(reason::VERIFIER_FAILED), receipts.request_id);
            }
        },
        None => None,
    };
    let receipt_hash = match record_allow(receipts, allowed) {
        Ok(hash) => hash,
        Err(NotStored) if receipt_is_required(receipts) => {
            release_reservation(reservation, receipts.request_id).await;
            return identified(deny(reason::VERIFIER_FAILED), receipts.request_id);
        }
        Err(NotStored) => None,
    };
    identified(
        Outcome {
            allow: true,
            replacement,
            receipt_hash,
            ..Outcome::default()
        },
        receipts.request_id,
    )
}

struct NotStored;

fn record(receipts: &ReceiptContext<'_>, decision: DecisionReceipt<'_>) -> bool {
    receipts.log.is_none_or(|log| log.record(decision))
}

/// `Ok(None)` when receipts are not configured.
fn record_allow(
    receipts: &ReceiptContext<'_>,
    decision: DecisionReceipt<'_>,
) -> Result<Option<[u8; 32]>, NotStored> {
    match receipts.log {
        None => Ok(None),
        Some(log) => log.record_digest(decision).map(Some).ok_or(NotStored),
    }
}

fn receipt_is_required(receipts: &ReceiptContext<'_>) -> bool {
    receipts.log.is_some_and(ReceiptLog::is_required)
}

fn receipt_log_ready(receipts: &ReceiptContext<'_>) -> bool {
    receipts.log.is_some_and(ReceiptLog::can_append)
}

async fn release_reservation(
    reservation: Option<crate::policy::ClaimReservation>,
    request_id: &str,
) {
    if let Some(reservation) = reservation {
        if reservation.release().await.is_err() {
            eprintln!(
                "tenuo_replay_cleanup request_id={} outcome=failed",
                log_safe_id(request_id)
            );
        }
    }
}

fn allow_unchanged() -> Outcome {
    Outcome {
        allow: true,
        ..Outcome::default()
    }
}

pub(crate) fn deny(reason_code: &'static str) -> Outcome {
    Outcome {
        allow: false,
        reason_code,
        ..Outcome::default()
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
    use crate::replay::{
        InMemoryReplayStore, ReplayError, ReplayReservation, ReplayStore, ReserveResult,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tenuo::sdk::transport::mcp_meta::encode_meta;
    use tenuo::{ConstraintSet, Exact, Range, SigningKey, Warrant, SIGNATURE_CONTEXT};

    const MCP: RequestTarget<'static> = RequestTarget {
        method: "POST",
        host: "mcp.test",
        port: 443,
        path: "/mcp",
    };

    fn evaluate(
        policy: &PolicySet,
        sandbox_id: &str,
        pre_credentials: bool,
        body: &[u8],
        meta_mode: MetaMode,
        receipts: Option<&ReceiptLog>,
    ) -> Outcome {
        evaluate_at(
            policy,
            sandbox_id,
            &MCP,
            pre_credentials,
            body,
            meta_mode,
            receipts,
        )
    }

    fn evaluate_at(
        policy: &PolicySet,
        sandbox_id: &str,
        target: &RequestTarget<'_>,
        pre_credentials: bool,
        body: &[u8],
        meta_mode: MetaMode,
        receipts: Option<&ReceiptLog>,
    ) -> Outcome {
        futures::executor::block_on(super::evaluate(
            policy,
            sandbox_id,
            pre_credentials,
            target,
            body,
            meta_mode,
            receipts,
        ))
    }

    fn destinations() -> Value {
        json!([{"host": "mcp.test", "port": 443, "path": "/mcp", "tools": ["*"]}])
    }

    fn policy_for(root: &SigningKey) -> PolicySet {
        let document = json!({
            "max_warrant_lifetime_secs": 3600,
            "approval_replay_protection": true,
            "sandboxes": {
                "sbx": {
                    "trusted_roots": [hex::encode(root.public_key().to_bytes())],
                    "destinations": destinations()
                },
                "sbx-other": {
                    "trusted_roots": [hex::encode(root.public_key().to_bytes())],
                    "destinations": destinations()
                }
            }
        });
        PolicySet::from_json(document.to_string().as_bytes()).expect("policy")
    }

    #[derive(Default)]
    struct CommitFailingStore {
        inner: InMemoryReplayStore,
    }

    #[async_trait]
    impl ReplayStore for CommitFailingStore {
        async fn reserve(
            &self,
            claims: &[crate::replay::ReplayClaim],
        ) -> Result<ReserveResult, ReplayError> {
            self.inner.reserve(claims).await
        }

        async fn commit(&self, _reservation: &ReplayReservation) -> Result<(), ReplayError> {
            Err(ReplayError)
        }

        async fn release(&self, reservation: &ReplayReservation) -> Result<(), ReplayError> {
            self.inner.release(reservation).await
        }

        async fn healthy(&self) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct ReleaseFailingStore {
        inner: InMemoryReplayStore,
    }

    #[async_trait]
    impl ReplayStore for ReleaseFailingStore {
        async fn reserve(
            &self,
            claims: &[crate::replay::ReplayClaim],
        ) -> Result<ReserveResult, ReplayError> {
            self.inner.reserve(claims).await
        }

        async fn commit(&self, reservation: &ReplayReservation) -> Result<(), ReplayError> {
            self.inner.commit(reservation).await
        }

        async fn release(&self, _reservation: &ReplayReservation) -> Result<(), ReplayError> {
            Err(ReplayError)
        }

        async fn healthy(&self) -> bool {
            true
        }
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
    fn signed_revocation_denies_and_is_committed_to_receipts() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let issued = warrant(&issuer, &holder, "read_logs");
        let srl = tenuo::SignedRevocationList::builder()
            .revoke(issued.id().to_string())
            .version(7)
            .build(&issuer)
            .expect("srl");
        let directory = tempfile::tempdir().expect("tempdir");
        let document = json!({
            "version": 1,
            "max_warrant_lifetime_secs": 3600,
            "sandboxes": {
                "sbx": {
                    "trusted_roots": [hex::encode(issuer.public_key().to_bytes())],
                    "destinations": destinations(),
                    "revocation": {
                        "signed_list_base64": srl.to_base64().expect("encoded srl"),
                        "max_staleness_secs": 300,
                        "clock_tolerance_secs": 30,
                        "rollback_floor_path": directory.path().join("floor.json")
                    }
                }
            }
        });
        let policy = PolicySet::from_json(document.to_string().as_bytes()).expect("policy");
        assert_eq!(policy.revocation_commitment("sbx").unwrap().unwrap().0, 7);
        let arguments = json!({"service": "payments"});
        let body = tools_call(
            "read_logs",
            arguments.clone(),
            Some(sign(&issued, &holder, "read_logs", &arguments)),
        );
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, None);
        assert!(!outcome.allow);
        assert_eq!(outcome.reason_code, reason::REVOKED);
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
    fn sandbox_chosen_request_ids_cannot_forge_log_fields() {
        assert_eq!(log_safe_id("14"), "14");
        assert_eq!(log_safe_id("task-a:read/1"), "task-a:read/1");
        for forged in [
            "1 outcome=allow",
            "1\ntenuo_decision request_id=2 decision_us=0 outcome=allow reason=-",
            "a=b",
            "\u{202e}",
        ] {
            let logged = log_safe_id(forged);
            assert!(logged.starts_with("hex:"), "{forged:?}");
            assert!(!logged.contains([' ', '\n', '=']), "{forged:?}");
        }
        assert!(log_safe_id(&"a".repeat(129)).starts_with("hex:"));
    }

    #[test]
    fn outcomes_name_the_tool_warrant_and_allow_receipt() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_for(&issuer);
        let issued = warrant(&issuer, &holder, "read_logs");
        let directory = tempfile::tempdir().expect("tempdir");
        let log_path = directory.path().join("receipts.jsonl");
        let log = ReceiptLog::open(&directory.path().join("key"), &log_path).expect("log");

        let arguments = json!({"service": "payments"});
        let meta = sign(&issued, &holder, "read_logs", &arguments);
        let body = tools_call("read_logs", arguments, Some(meta));
        let allowed = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, Some(&log));
        assert!(allowed.allow);
        assert_eq!(allowed.tool.as_deref(), Some("read_logs"));
        assert_eq!(allowed.warrant_id, Some(issued.id().to_string()));
        let line = std::fs::read_to_string(&log_path).expect("log");
        let bytes = hex::decode(line.trim()).expect("hex");
        assert_eq!(
            allowed.receipt_hash,
            Some(crate::result_receipt::line_digest(&bytes))
        );

        let arguments = json!({"service": "payments"});
        let meta = sign(&issued, &holder, "restart_service", &arguments);
        let body = tools_call("restart_service", arguments, Some(meta));
        let denied = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, Some(&log));
        assert!(!denied.allow);
        assert_eq!(denied.tool.as_deref(), Some("restart_service"));
        assert_eq!(denied.warrant_id, Some(issued.id().to_string()));
        assert_eq!(denied.receipt_hash, None);

        let body = tools_call("read_logs", json!({}), None);
        let missing = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None);
        assert_eq!(missing.tool.as_deref(), Some("read_logs"));
        assert_eq!(missing.warrant_id, None);

        // Without a receipt log, an allow has no receipt to link.
        let arguments = json!({"service": "payments"});
        let meta = sign(&issued, &holder, "read_logs", &arguments);
        let body = tools_call("read_logs", arguments, Some(meta));
        let unrecorded = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None);
        assert!(unrecorded.allow && unrecorded.receipt_hash.is_none());
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
    fn an_approval_covers_one_argument_set_and_cannot_be_replayed() {
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
        let replay = evaluate(
            &policy,
            "sbx-other",
            true,
            &allowed,
            MetaMode::Preserve,
            None,
        );
        assert!(!replay.allow);
        assert_eq!(replay.reason_code, reason::APPROVAL_REPLAYED);
        let replay = evaluate(&policy, "sbx", true, &allowed, MetaMode::Preserve, None);
        assert_eq!(replay.reason_code, reason::APPROVAL_REPLAYED);

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
    fn required_receipt_failure_releases_the_approval_reservation() {
        let issuer = SigningKey::generate();
        let policy = policy_for(&issuer);
        let (holder, approver, warrant, arguments) = approved_restart(&issuer);
        let approval = approval_for(&approver, &warrant, "restart_service", &arguments);
        let body = body_with_approval(
            &warrant,
            &holder,
            "restart_service",
            &arguments,
            Some(&approval),
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("required.jsonl");
        let required = ReceiptLog::open(&directory.path().join("receipt.key"), &path)
            .expect("required receipt log")
            .require_delivery();
        std::fs::create_dir(&path).expect("directory blocks required log");

        let denied = evaluate(
            &policy,
            "sbx",
            true,
            &body,
            MetaMode::Preserve,
            Some(&required),
        );
        assert!(!denied.allow);
        assert_eq!(denied.reason_code, reason::VERIFIER_FAILED);

        std::fs::remove_dir(&path).expect("restore receipt path");
        assert!(
            evaluate(
                &policy,
                "sbx-other",
                true,
                &body,
                MetaMode::Preserve,
                Some(&required),
            )
            .allow
        );
        let replay = evaluate(
            &policy,
            "sbx",
            true,
            &body,
            MetaMode::Preserve,
            Some(&required),
        );
        assert_eq!(replay.reason_code, reason::APPROVAL_REPLAYED);
    }

    #[test]
    fn failed_reservation_cleanup_is_not_reported_as_replay() {
        let issuer = SigningKey::generate();
        let policy =
            policy_for(&issuer).with_replay_store(Arc::new(ReleaseFailingStore::default()));
        let (holder, approver, warrant, arguments) = approved_restart(&issuer);
        let approval = approval_for(&approver, &warrant, "restart_service", &arguments);
        let body = body_with_approval(
            &warrant,
            &holder,
            "restart_service",
            &arguments,
            Some(&approval),
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("required.jsonl");
        let required = ReceiptLog::open(&directory.path().join("receipt.key"), &path)
            .expect("required receipt log")
            .require_delivery();
        std::fs::create_dir(&path).expect("directory blocks required log");

        let first = evaluate(
            &policy,
            "sbx",
            true,
            &body,
            MetaMode::Preserve,
            Some(&required),
        );
        assert_eq!(first.reason_code, reason::VERIFIER_FAILED);

        std::fs::remove_dir(&path).expect("restore receipt path");
        let retry = evaluate(
            &policy,
            "sbx-other",
            true,
            &body,
            MetaMode::Preserve,
            Some(&required),
        );
        assert_eq!(retry.reason_code, reason::VERIFIER_FAILED);
        assert_ne!(retry.reason_code, reason::APPROVAL_REPLAYED);
    }

    #[test]
    fn failed_nonce_commit_does_not_store_an_allow_receipt() {
        let issuer = SigningKey::generate();
        let policy = policy_for(&issuer).with_replay_store(Arc::new(CommitFailingStore::default()));
        let (holder, approver, warrant, arguments) = approved_restart(&issuer);
        let approval = approval_for(&approver, &warrant, "restart_service", &arguments);
        let body = body_with_approval(
            &warrant,
            &holder,
            "restart_service",
            &arguments,
            Some(&approval),
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("required.jsonl");
        let required = ReceiptLog::open(&directory.path().join("receipt.key"), &path)
            .expect("required receipt log")
            .require_delivery();

        let denied = evaluate(
            &policy,
            "sbx",
            true,
            &body,
            MetaMode::Preserve,
            Some(&required),
        );
        assert_eq!(denied.reason_code, reason::VERIFIER_FAILED);
        let stored = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(stored.trim().is_empty());
    }

    #[test]
    fn receipts_are_chained_best_effort_or_required() {
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

        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, Some(&log));
        assert!(outcome.allow);
        let lines =
            std::fs::read_to_string(directory.path().join("openshell.jsonl")).expect("chained log");
        let second = lines.lines().nth(1).expect("second receipt");
        let bytes = hex::decode(second).expect("second receipt hex");
        let receipt: tenuo::Receipt = ciborium::from_reader(bytes.as_slice()).expect("receipt");
        let payload = receipt.verify_signature().expect("signature");
        assert!(payload.prev_receipt_hash.is_some());

        let blocked = tempfile::tempdir().expect("tempdir");
        let blocked_log = blocked.path().join("best-effort.jsonl");
        let log = ReceiptLog::open(&blocked.path().join("receipt.key"), &blocked_log)
            .expect("receipt log");
        std::fs::create_dir(&blocked_log).expect("directory blocks the log");
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Preserve, Some(&log));
        assert!(outcome.allow);

        let required_log = blocked.path().join("required.jsonl");
        let required = ReceiptLog::open(&blocked.path().join("required.key"), &required_log)
            .expect("required receipt log")
            .require_delivery();
        std::fs::create_dir(&required_log).expect("directory blocks required log");
        let outcome = evaluate(
            &policy,
            "sbx",
            true,
            &body,
            MetaMode::Preserve,
            Some(&required),
        );
        assert!(!outcome.allow);
        assert_eq!(outcome.reason_code, reason::VERIFIER_FAILED);
    }

    fn policy_with(root: &SigningKey, sandbox: Value) -> PolicySet {
        let mut sandbox = sandbox;
        sandbox["trusted_roots"] = json!([hex::encode(root.public_key().to_bytes())]);
        let document = json!({
            "max_warrant_lifetime_secs": 3600,
            "approval_replay_protection": true,
            "sandboxes": { "sbx": sandbox }
        });
        PolicySet::from_json(document.to_string().as_bytes()).expect("policy")
    }

    #[test]
    fn a_warrant_is_spent_only_at_a_destination_that_serves_the_tool() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_with(
            &issuer,
            json!({"destinations": [
                {"host": "logs.test", "port": 443, "path": "/mcp", "tools": ["read_logs"]},
                {"host": "ops.test", "port": 443, "path": "/mcp", "tools": ["restart_service"]}
            ]}),
        );
        let issued = warrant(&issuer, &holder, "read_logs");
        let arguments = json!({"service": "payments"});
        let body = tools_call(
            "read_logs",
            arguments.clone(),
            Some(sign(&issued, &holder, "read_logs", &arguments)),
        );
        let at = |host, port, path| RequestTarget {
            method: "POST",
            host,
            port,
            path,
        };
        let run = |target: RequestTarget<'_>| {
            evaluate_at(&policy, "sbx", &target, true, &body, MetaMode::Strip, None)
        };
        assert!(run(at("LOGS.test", 443, "/mcp")).allow);
        let outcome = run(at("ops.test", 443, "/mcp"));
        assert_eq!(outcome.reason_code, reason::DESTINATION_DENIED);
        assert_eq!(outcome.request_id, "1");
        let outcome = run(at("logs.test", 8443, "/mcp"));
        assert_eq!(outcome.reason_code, reason::DESTINATION_DENIED);
        let outcome = run(at("logs.test", 443, "/other"));
        assert_eq!(outcome.reason_code, reason::DESTINATION_DENIED);
        let outcome = run(at("unknown.test", 443, "/mcp"));
        assert_eq!(outcome.reason_code, reason::DESTINATION_DENIED);
    }

    #[test]
    fn streamable_http_stream_and_session_requests_pass_without_a_body() {
        let issuer = SigningKey::generate();
        let policy = policy_for(&issuer);
        let with = |method| RequestTarget { method, ..MCP };
        for method in ["GET", "DELETE"] {
            let outcome = evaluate_at(
                &policy,
                "sbx",
                &with(method),
                true,
                b"",
                MetaMode::Strip,
                None,
            );
            assert!(outcome.allow, "{method}");
        }
        let body = tools_call("read_logs", json!({}), None);
        let outcome = evaluate_at(
            &policy,
            "sbx",
            &with("GET"),
            true,
            &body,
            MetaMode::Strip,
            None,
        );
        assert_eq!(outcome.reason_code, reason::INVALID_REQUEST);
        let outcome = evaluate_at(
            &policy,
            "sbx",
            &with("PUT"),
            true,
            b"",
            MetaMode::Strip,
            None,
        );
        assert_eq!(outcome.reason_code, reason::INVALID_REQUEST);
        let elsewhere = RequestTarget {
            method: "GET",
            host: "other.test",
            ..MCP
        };
        let outcome = evaluate_at(&policy, "sbx", &elsewhere, true, b"", MetaMode::Strip, None);
        assert_eq!(outcome.reason_code, reason::DESTINATION_DENIED);
    }

    #[test]
    fn extra_methods_and_client_responses_are_opt_in_per_sandbox() {
        let issuer = SigningKey::generate();
        let read = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": 2, "method": "resources/read", "params": {"uri": "file:///a"}
        }))
        .unwrap();
        let response = serde_json::to_vec(&json!({
            "jsonrpc": "2.0", "id": "s-1", "result": {"roots": []}
        }))
        .unwrap();

        let strict = policy_for(&issuer);
        for body in [&read, &response] {
            let outcome = evaluate(&strict, "sbx", true, body, MetaMode::Strip, None);
            assert_eq!(outcome.reason_code, reason::INVALID_REQUEST);
        }

        let open = policy_with(
            &issuer,
            json!({
                "destinations": destinations(),
                "mcp": {
                    "passthrough_methods": ["resources/read"],
                    "allow_client_responses": true
                }
            }),
        );
        for body in [&read, &response] {
            assert!(evaluate(&open, "sbx", true, body, MetaMode::Strip, None).allow);
        }
        let ambiguous = br#"{"jsonrpc":"2.0","id":3,"result":{},"error":{}}"#;
        let outcome = evaluate(&open, "sbx", true, ambiguous, MetaMode::Strip, None);
        assert_eq!(outcome.reason_code, reason::INVALID_REQUEST);
    }

    #[test]
    fn a_single_use_tool_accepts_one_copy_of_a_signed_call() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_with(
            &issuer,
            json!({
                "destinations": destinations(),
                "single_use_tools": ["restart_service"]
            }),
        );
        let restart = scoped_warrant(&issuer, &holder, true);
        let arguments = json!({"service": "payments", "environment": "staging", "replicas": 3});
        let body = tools_call(
            "restart_service",
            arguments.clone(),
            Some(sign(&restart, &holder, "restart_service", &arguments)),
        );
        assert!(evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None).allow);
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None);
        assert_eq!(outcome.reason_code, reason::POP_REPLAYED);

        let read = json!({"service": "payments", "environment": "staging"});
        let body = tools_call(
            "read_logs",
            read.clone(),
            Some(sign(&restart, &holder, "read_logs", &read)),
        );
        assert!(evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None).allow);
        assert!(evaluate(&policy, "sbx", true, &body, MetaMode::Strip, None).allow);
    }

    #[test]
    fn denial_receipts_commit_to_the_trusted_roots() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let policy = policy_for(&issuer);
        let issued = warrant(&issuer, &holder, "read_logs");
        let arguments = json!({"service": "payments"});
        let body = tools_call(
            "restart_service",
            arguments.clone(),
            Some(sign(&issued, &holder, "restart_service", &arguments)),
        );
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("receipts.jsonl");
        let log = ReceiptLog::open(&directory.path().join("receipt.key"), &path).expect("log");
        let outcome = evaluate(&policy, "sbx", true, &body, MetaMode::Strip, Some(&log));
        assert_eq!(outcome.reason_code, reason::TOOL_DENIED);
        let line = std::fs::read_to_string(&path).expect("receipt");
        let bytes = hex::decode(line.trim()).expect("hex");
        let receipt: tenuo::Receipt = ciborium::from_reader(bytes.as_slice()).expect("cbor");
        let payload = receipt.verify_signature().expect("signature");
        assert_eq!(payload.outcome.as_str(), "deny");
        assert_eq!(
            payload.trusted_roots_hash,
            Some(policy.trusted_roots_hash("sbx").unwrap())
        );
    }
}

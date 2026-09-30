//! The full `evaluate` decision on arbitrary bodies against a fixed policy.
//!
//! In-memory replay, no receipts. The only authority the harness issues is a
//! `read_logs` warrant from a fixed issuer to a fixed holder, so an allowed
//! `tools/call` must be exactly that call with a decodable `_meta.tenuo`.
//!
//! Input layout: byte 0 selects the mode, the sandbox, and the meta mode.
//! In raw mode the rest is the body. In splice mode the rest edits a freshly
//! signed `read_logs` call: a 16-bit offset, a deletion length, and the bytes
//! to insert. Splice mode reaches the allow path, which raw mode cannot,
//! because the fuzzer cannot forge a proof of possession.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::{decode_meta, encode_meta};
use tenuo::{ConstraintSet, SigningKey, Warrant, SIGNATURE_CONTEXT};
use tenuo_openshell_middleware::policy::{MetaMode, PolicySet, RequestTarget};

const TARGET: RequestTarget<'static> = RequestTarget {
    method: "POST",
    host: "mcp.test",
    port: 443,
    path: "/mcp",
};
const SANDBOXES: [&str; 2] = ["sbx", "sbx-permissive"];
const TEMPLATE_TTL: Duration = Duration::from_secs(20);

struct Fixture {
    issuer: SigningKey,
    holder: SigningKey,
    policy: PolicySet,
    template: Mutex<(Instant, Vec<u8>)>,
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let issuer = SigningKey::from_bytes(&[7; 32]);
        let holder = SigningKey::from_bytes(&[11; 32]);
        let root = hex_encode(&issuer.public_key().to_bytes());
        let destinations = json!([{
            "host": "mcp.test",
            "port": 443,
            "path": "/mcp",
            "tools": ["read_logs", "restart_service"]
        }]);
        let document = json!({
            "version": 1,
            "max_warrant_lifetime_secs": 3600,
            "approval_replay_protection": true,
            "sandboxes": {
                "sbx": {
                    "trusted_roots": [root],
                    "destinations": destinations,
                    "single_use_tools": ["restart_service"]
                },
                "sbx-permissive": {
                    "trusted_roots": [root],
                    "destinations": destinations,
                    "mcp": {
                        "passthrough_methods": ["resources/read"],
                        "allow_client_responses": true
                    }
                }
            }
        });
        let policy = PolicySet::from_json(document.to_string().as_bytes()).expect("policy");
        let template = signed_read(&issuer, &holder);
        Fixture {
            issuer,
            holder,
            policy,
            template: Mutex::new((Instant::now(), template)),
        }
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn read_arguments() -> Value {
    json!({"service": "payments"})
}

/// A `read_logs` call signed now. Proofs are valid for a bounded window, so
/// the template is re-signed every `TEMPLATE_TTL`.
fn signed_read(issuer: &SigningKey, holder: &SigningKey) -> Vec<u8> {
    let warrant = Warrant::builder()
        .capability("read_logs", ConstraintSet::new())
        .holder(holder.public_key())
        .ttl(Duration::from_secs(600))
        .build(issuer)
        .expect("warrant");
    let arguments = read_arguments();
    let call = Call::try_from_json("read_logs", &arguments).expect("call");
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
    let meta = encode_meta(std::slice::from_ref(&warrant), &signature, &[]).expect("meta");
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "read_logs", "arguments": arguments, "_meta": {"tenuo": meta}}
    }))
    .expect("body")
}

fn template(fixture: &Fixture) -> Vec<u8> {
    let mut template = fixture
        .template
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if template.0.elapsed() > TEMPLATE_TTL {
        *template = (
            Instant::now(),
            signed_read(&fixture.issuer, &fixture.holder),
        );
    }
    template.1.clone()
}

fn splice(mut body: Vec<u8>, edit: &[u8]) -> Vec<u8> {
    let [high, low, delete, insert @ ..] = edit else {
        return body;
    };
    let offset = usize::from(u16::from_be_bytes([*high, *low])) % (body.len() + 1);
    let end = (offset + usize::from(*delete)).min(body.len());
    body.splice(offset..end, insert.iter().copied());
    body
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    let fixture = fixture();
    let signed = (control & 1 == 1).then(|| template(fixture));
    let body = match &signed {
        None => rest.to_vec(),
        Some(signed) => splice(signed.clone(), rest),
    };
    let sandbox_id = SANDBOXES[usize::from(control >> 1 & 1)];
    let meta_mode = if control & 4 == 0 {
        MetaMode::Strip
    } else {
        MetaMode::Preserve
    };
    let outcome = futures::executor::block_on(tenuo_openshell_middleware::evaluate(
        &fixture.policy,
        sandbox_id,
        true,
        &TARGET,
        &body,
        meta_mode,
        None,
    ));
    // The harness's own signed call is inside the warrant, and `read_logs` is
    // not single-use, so it must be allowed every time. This keeps the allow
    // path under test.
    if signed.as_ref() == Some(&body) {
        assert!(outcome.allow, "signed call denied: {}", outcome.reason_code);
    }
    if !outcome.allow {
        assert!(!outcome.reason_code.is_empty());
        assert!(outcome.replacement.is_none());
        return;
    }
    check_allowed(fixture, sandbox_id, meta_mode, &body, outcome.replacement);
});

/// Independent checks on an allowed body. They use serde_json and the Tenuo
/// wire decoder, not the middleware parser.
fn check_allowed(
    fixture: &Fixture,
    sandbox_id: &str,
    meta_mode: MetaMode,
    body: &[u8],
    replacement: Option<Vec<u8>>,
) {
    let document: Value = serde_json::from_slice(body).expect("allowed body is JSON");
    let object = document.as_object().expect("allowed body is an object");
    let permissive = sandbox_id == "sbx-permissive";
    let Some(method) = object.get("method") else {
        assert!(permissive, "client response allowed in the default sandbox");
        assert!(object.contains_key("id"));
        assert!(replacement.is_none());
        return;
    };
    let method = method.as_str().expect("method is a string");
    if method != "tools/call" {
        assert!(
            lifecycle(method) || (permissive && method == "resources/read"),
            "{method} allowed without a warrant"
        );
        assert!(replacement.is_none());
        return;
    }
    assert_eq!(document["params"]["name"], "read_logs");
    assert_eq!(document["params"]["arguments"], read_arguments());
    let meta = document
        .pointer("/params/_meta/tenuo")
        .expect("allowed tools/call has _meta.tenuo");
    let owned = decode_meta(meta).expect("allowed _meta.tenuo decodes");
    let received = owned.as_received().expect("allowed authority is complete");
    let root = received.chain().first().expect("chain root");
    assert_eq!(root.issuer(), &fixture.issuer.public_key());
    let leaf = received.chain().last().expect("chain leaf");
    assert_eq!(leaf.authorized_holder(), &fixture.holder.public_key());
    match meta_mode {
        MetaMode::Preserve => assert!(replacement.is_none()),
        MetaMode::Strip => {
            let forwarded = replacement.expect("stripped body");
            let forwarded: Value = serde_json::from_slice(&forwarded).expect("forwarded JSON");
            assert!(forwarded.pointer("/params/_meta/tenuo").is_none());
            assert_eq!(forwarded["params"]["name"], "read_logs");
            assert_eq!(forwarded["params"]["arguments"], read_arguments());
        }
    }
}

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

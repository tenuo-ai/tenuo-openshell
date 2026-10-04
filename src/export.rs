//! Offline receipt export for log pipelines.
//!
//! Reads one hex-CBOR receipt log, checks every signature and the hash chain,
//! then writes one JSON object per receipt. Nothing is written unless the whole
//! file verifies. The field names are documented in `docs/receipts.md`.
//!
//! Export proves the log is intact and signed by the receipt key. It does not
//! re-verify warrant chains against trusted roots; the offline auditor does.

use crate::result_receipt::{line_digest, ResultPayload, ResultReceipt, RESULT_RECEIPT_KIND};
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::path::Path;
use tenuo::{PublicKey, Receipt, ReceiptPayload};

/// `schema` on every exported object. Bumped only for incompatible changes.
pub const EXPORT_SCHEMA: &str = "tenuo.openshell.receipt.v1";

enum Record {
    Authorization(Box<ReceiptPayload>, PublicKey),
    Result(Box<ResultPayload>, PublicKey),
}

impl Record {
    fn kind(&self) -> &'static str {
        match self {
            Self::Authorization(..) => "authorization",
            Self::Result(..) => "result",
        }
    }

    fn prev_receipt_hash(&self) -> Option<[u8; 32]> {
        match self {
            Self::Authorization(payload, _) => payload.prev_receipt_hash,
            Self::Result(payload, _) => payload.prev_receipt_hash,
        }
    }

    fn signer(&self) -> &PublicKey {
        match self {
            Self::Authorization(_, signer) | Self::Result(_, signer) => signer,
        }
    }
}

/// Parse a `--verify-with` value: 64 hex characters, or a file holding them,
/// such as the `.pub` file written next to the log.
pub fn load_public_key(value: &str) -> Result<PublicKey, String> {
    let text = if is_hex_key(value.trim()) {
        value.trim().to_string()
    } else {
        fs::read_to_string(value)
            .map_err(|error| format!("read {value}: {error}"))?
            .trim()
            .to_string()
    };
    if !is_hex_key(&text) {
        return Err(format!("{value} is not a 32-byte hex public key"));
    }
    let bytes: [u8; 32] = hex::decode(&text)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    PublicKey::from_bytes(&bytes).map_err(|error| error.to_string())
}

fn is_hex_key(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Verify the whole log, then write it as JSON lines. Returns the count.
pub fn export(
    log: &Path,
    verify_with: Option<&PublicKey>,
    out: &mut impl Write,
) -> Result<usize, String> {
    let text =
        fs::read_to_string(log).map_err(|error| format!("read {}: {error}", log.display()))?;
    let mut objects = Vec::new();
    let mut previous: Option<[u8; 32]> = None;
    let mut kind = None;
    let mut authorizations = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let bytes = hex::decode(line).map_err(|_| format!("line {number}: not hex"))?;
        let (record, receipt) =
            decode(&bytes).map_err(|error| format!("line {number}: {error}"))?;
        if *kind.get_or_insert(record.kind()) != record.kind() {
            return Err(format!(
                "line {number}: a {} receipt in a log of {} receipts",
                record.kind(),
                kind.unwrap_or_default()
            ));
        }
        if let Some(receipt) = receipt {
            authorizations.push((number, receipt));
        }
        if let Some(expected) = verify_with {
            if record.signer() != expected {
                return Err(format!(
                    "line {number}: signed by {}, not the expected receipt key",
                    hex::encode(record.signer().to_bytes())
                ));
            }
        }
        // The first line anchors the file. Its link is reported, not checked,
        // so a rotated segment still exports. Authorization receipts are
        // checked by Tenuo core below.
        if let (Some(previous), Record::Result(..)) = (previous, &record) {
            if record.prev_receipt_hash() != Some(previous) {
                return Err(format!("line {number}: hash chain is broken"));
            }
        }
        let digest = line_digest(&bytes);
        objects.push(to_json(number, &record, &digest));
        previous = Some(digest);
    }
    if !authorizations.is_empty() {
        let receipts: Vec<Receipt> = authorizations
            .iter()
            .map(|(_, receipt)| receipt.clone())
            .collect();
        tenuo::receipt::verify_chain(&receipts, verify_with).map_err(|error| {
            let first = authorizations[0].0;
            format!("authorization receipt hash chain does not verify (from line {first}): {error}")
        })?;
    }
    for object in &objects {
        serde_json::to_writer(&mut *out, object).map_err(|error| error.to_string())?;
        out.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    Ok(objects.len())
}

/// Decode one line. Authorization receipts are returned too, for the chain
/// check in core.
fn decode(bytes: &[u8]) -> Result<(Record, Option<Receipt>), String> {
    let value: ciborium::Value =
        ciborium::from_reader(bytes).map_err(|_| "not CBOR".to_string())?;
    let is_result = value.as_map().is_some_and(|entries| {
        entries.iter().any(|(key, value)| {
            key.as_text() == Some("kind") && value.as_text() == Some(RESULT_RECEIPT_KIND)
        })
    });
    if is_result {
        let receipt = ResultReceipt::from_bytes(bytes)?;
        let payload = receipt.verify()?;
        return Ok((Record::Result(Box::new(payload), receipt.signer_key), None));
    }
    let receipt: Receipt =
        ciborium::from_reader(bytes).map_err(|_| "not a Tenuo receipt".to_string())?;
    let payload = receipt
        .verify_signature()
        .map_err(|error| format!("receipt does not verify: {error}"))?;
    let signer = receipt.signer_key.clone();
    Ok((
        Record::Authorization(Box::new(payload), signer),
        Some(receipt),
    ))
}

fn to_json(line: usize, record: &Record, digest: &[u8; 32]) -> Value {
    let mut object = json!({
        "schema": EXPORT_SCHEMA,
        "kind": record.kind(),
        "line": line,
        "receipt_hash": hex::encode(digest),
        "prev_receipt_hash": record.prev_receipt_hash().map(hex::encode),
        "signer_key": hex::encode(record.signer().to_bytes()),
    });
    let fields = match record {
        Record::Authorization(payload, _) => {
            let stack = tenuo::wire::decode_stack(&payload.warrant_chain).ok();
            let leaf = stack.as_ref().and_then(|stack| stack.leaf());
            json!({
                "timestamp": payload.timestamp,
                "time": rfc3339(payload.timestamp),
                "authorizer_id": payload.authorizer_id,
                "request_id": payload.request_id,
                "action": payload.action,
                "tool": payload.action.strip_prefix("tool:"),
                "outcome": payload.outcome.as_str(),
                "decision_code": payload.decision_code,
                "warrant_id": leaf.map(|warrant| warrant.id().to_string()),
                "chain_depth": stack.as_ref().map(|stack| stack.0.len()),
                "root_principal": payload.root_principal,
                "request_hash": payload.request_hash.map(hex::encode),
                "pop_signature_present": payload.pop_signature.is_some(),
                "trusted_roots_hash": payload.trusted_roots_hash.map(hex::encode),
                "srl_version": payload.srl_version,
                "srl_hash": payload.srl_hash.map(hex::encode),
                "policy_definition_hash": payload.policy_definition_hash.map(hex::encode),
            })
        }
        Record::Result(payload, _) => json!({
            "timestamp": payload.timestamp,
            "time": rfc3339(payload.timestamp),
            "authorizer_id": payload.authorizer_id,
            "request_id": payload.request_id,
            "tool": payload.tool,
            "outcome": payload.outcome,
            "decision_code": payload.decision_code,
            "warrant_id": payload.warrant_id,
            "sandbox_id": payload.sandbox_id,
            "openshell_request_id": payload.openshell_request_id,
            "request_receipt_hash": payload.request_receipt_hash.map(hex::encode),
            "status_code": payload.status_code,
            "body_mode": payload.body_mode,
            "result_bytes": payload.result_bytes,
            "result_sha256": payload.result_sha256.map(hex::encode),
        }),
    };
    if let (Some(object), Value::Object(fields)) = (object.as_object_mut(), fields) {
        object.extend(fields);
    }
    object
}

fn rfc3339(timestamp: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(timestamp, 0)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{DecisionReceipt, ReceiptLog};
    use crate::result_receipt::{DELIVERED, MODE_WHOLE_BODY, RESULT_PAYLOAD_VERSION};
    use std::collections::HashMap;
    use tenuo::{SigningKey, Warrant};

    struct Logs {
        dir: tempfile::TempDir,
        log: ReceiptLog,
    }

    fn logs() -> Logs {
        let dir = tempfile::tempdir().unwrap();
        let log = ReceiptLog::open(&dir.path().join("key"), &dir.path().join("r.jsonl")).unwrap();
        Logs { dir, log }
    }

    fn allow(log: &ReceiptLog, request_id: &str) -> [u8; 32] {
        let root = SigningKey::generate();
        let warrant = Warrant::builder()
            .capability("read_logs", tenuo::ConstraintSet::new())
            .ttl(std::time::Duration::from_secs(60))
            .holder(root.public_key())
            .build(&root)
            .unwrap();
        log.record_digest(DecisionReceipt {
            request_id,
            tool: "read_logs",
            chain: &[warrant],
            pop: [7; 64],
            pop_args: &HashMap::new(),
            trusted_roots_hash: [3; 32],
            srl_version: None,
            srl_hash: None,
            denial: None,
        })
        .unwrap()
    }

    fn result(request_receipt_hash: [u8; 32]) -> ResultPayload {
        ResultPayload {
            version: RESULT_PAYLOAD_VERSION,
            authorizer_id: String::new(),
            timestamp: 1_700_000_000,
            sandbox_id: "sbx".to_string(),
            openshell_request_id: "exchange".to_string(),
            request_id: "1".to_string(),
            tool: "read_logs".to_string(),
            warrant_id: "tnu_wrt_x".to_string(),
            request_receipt_hash: Some(request_receipt_hash),
            status_code: 200,
            body_mode: MODE_WHOLE_BODY.to_string(),
            outcome: DELIVERED.to_string(),
            decision_code: None,
            result_bytes: 5,
            result_sha256: Some([4; 32]),
            prev_receipt_hash: None,
        }
    }

    fn lines(path: &Path, key: Option<&PublicKey>) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        export(path, key, &mut out)?;
        Ok(String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect())
    }

    #[test]
    fn both_logs_export_with_stable_linked_fields() {
        let logs = logs();
        let first = allow(&logs.log, "1");
        allow(&logs.log, "2");
        assert!(logs.log.record_result(result(first)));
        assert!(logs.log.record_result(result(first)));
        let key = load_public_key(logs.dir.path().join("r.pub").to_str().unwrap()).unwrap();

        let authorizations = lines(&logs.dir.path().join("r.jsonl"), Some(&key)).unwrap();
        assert_eq!(authorizations.len(), 2);
        let row = &authorizations[0];
        assert_eq!(row["schema"], EXPORT_SCHEMA);
        assert_eq!(row["kind"], "authorization");
        assert_eq!(row["receipt_hash"], hex::encode(first));
        assert_eq!(row["prev_receipt_hash"], Value::Null);
        assert_eq!(row["tool"], "read_logs");
        assert_eq!(row["outcome"], "allow");
        assert_eq!(row["authorizer_id"], "openshell");
        assert!(row["warrant_id"].as_str().unwrap().starts_with("tnu_wrt_"));
        assert_eq!(
            row["time"],
            rfc3339(row["timestamp"].as_i64().unwrap()).unwrap()
        );
        assert_eq!(authorizations[1]["prev_receipt_hash"], hex::encode(first));

        let results = lines(logs.log.results_path(), Some(&key)).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["kind"], "result");
        assert_eq!(results[0]["request_receipt_hash"], hex::encode(first));
        assert_eq!(results[0]["result_bytes"], 5);
        assert_eq!(results[0]["outcome"], "delivered");
        assert_eq!(results[1]["prev_receipt_hash"], results[0]["receipt_hash"]);
    }

    #[test]
    fn a_deleted_or_reordered_line_breaks_the_chain() {
        let logs = logs();
        for id in ["1", "2", "3"] {
            allow(&logs.log, id);
        }
        let path = logs.dir.path().join("r.jsonl");
        let text = fs::read_to_string(&path).unwrap();
        let rows: Vec<_> = text.lines().collect();
        fs::write(&path, format!("{}\n{}\n", rows[0], rows[2])).unwrap();
        let mut out = Vec::new();
        assert!(export(&path, None, &mut out).unwrap_err().contains("chain"));
        assert!(out.is_empty(), "nothing is written for a broken log");

        // A later segment exports: its first line is the anchor.
        fs::write(&path, format!("{}\n{}\n", rows[1], rows[2])).unwrap();
        assert_eq!(lines(&path, None).unwrap().len(), 2);
    }

    #[test]
    fn a_bad_signature_or_foreign_signer_fails() {
        let logs = logs();
        allow(&logs.log, "1");
        let path = logs.dir.path().join("r.jsonl");
        let other = SigningKey::generate().public_key();
        assert!(lines(&path, Some(&other))
            .unwrap_err()
            .contains("expected receipt key"));

        let text = fs::read_to_string(&path).unwrap();
        let mut bytes = hex::decode(text.trim()).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, format!("{}\n", hex::encode(bytes))).unwrap();
        assert!(lines(&path, None).is_err());
    }

    #[test]
    fn a_mixed_log_and_bad_input_fail() {
        let logs = logs();
        let first = allow(&logs.log, "1");
        assert!(logs.log.record_result(result(first)));
        let path = logs.dir.path().join("r.jsonl");
        let result_line = fs::read_to_string(logs.log.results_path()).unwrap();
        let mut text = fs::read_to_string(&path).unwrap();
        text.push_str(&result_line);
        fs::write(&path, text).unwrap();
        assert!(lines(&path, None)
            .unwrap_err()
            .contains("log of authorization receipts"));
        fs::write(&path, "zz\n").unwrap();
        assert!(lines(&path, None).is_err());
        assert!(load_public_key("abc").is_err());
    }
}

//! Signed result receipts.
//!
//! A Tenuo receipt records an authorization decision; its payload map is
//! closed, so it cannot carry a result digest. A result receipt is a separate,
//! smaller artifact signed by the same receipt key. It commits to the bytes
//! OpenShell returned for one allowed `tools/call` and links to that call's
//! authorization receipt by hash.
//!
//! The payload is deterministic CBOR with text keys. The signature covers
//! `RESULT_CONTEXT || payload` under Tenuo's Ed25519 signing context, so a
//! result signature cannot be replayed as a Tenuo receipt or the reverse.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenuo::{PublicKey, Signature, SigningKey};

/// Envelope `kind`. Readers use it to tell result receipts from Tenuo receipts.
pub const RESULT_RECEIPT_KIND: &str = "tenuo-openshell-result-v1";
/// Domain separation for the signature preimage.
pub const RESULT_CONTEXT: &[u8] = b"tenuo-openshell-result-v1";
pub const RESULT_PAYLOAD_VERSION: u8 = 1;

/// Body mode the middleware used to read the result.
pub const MODE_WHOLE_BODY: &str = "whole_body";
pub const MODE_STREAM: &str = "stream";
pub const MODE_HEADERS: &str = "headers";

/// The result reached the sandbox in full.
pub const DELIVERED: &str = "delivered";
/// The middleware blocked delivery. `decision_code` says why.
pub const BLOCKED: &str = "blocked";
/// Streaming ended before the final body unit. Part of the result may have
/// reached the sandbox.
pub const INCOMPLETE: &str = "incomplete";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultPayload {
    pub version: u8,
    pub authorizer_id: String,
    /// Unix seconds when the result evaluation finished.
    pub timestamp: i64,
    pub sandbox_id: String,
    /// OpenShell `RequestContext.request_id`, shared by request and response.
    pub openshell_request_id: String,
    /// JSON-RPC id. Equals `request_id` on the authorization receipt.
    pub request_id: String,
    pub tool: String,
    /// Leaf warrant id of the authorized call.
    pub warrant_id: String,
    /// SHA-256 of the authorization receipt, when one was stored.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub request_receipt_hash: Option<[u8; 32]>,
    pub status_code: u32,
    pub body_mode: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_code: Option<String>,
    /// Bytes read, or for a block before any body, the declared length.
    pub result_bytes: u64,
    /// SHA-256 of the complete result body. Present only when delivered.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub result_sha256: Option<[u8; 32]>,
    /// SHA-256 of the previous line in this result log.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_bytes")]
    pub prev_receipt_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultReceipt {
    pub kind: String,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
    pub signer_key: PublicKey,
    pub signature: Signature,
}

impl ResultReceipt {
    pub fn create(payload: &ResultPayload, signer: &SigningKey) -> Result<Self, String> {
        let mut bytes = Vec::new();
        ciborium::into_writer(payload, &mut bytes).map_err(|error| error.to_string())?;
        let signature = signer.sign(&preimage(&bytes));
        Ok(Self {
            kind: RESULT_RECEIPT_KIND.to_string(),
            payload: bytes,
            signer_key: signer.public_key(),
            signature,
        })
    }

    /// Verify the signature, then parse and check the payload.
    pub fn verify(&self) -> Result<ResultPayload, String> {
        if self.kind != RESULT_RECEIPT_KIND {
            return Err("not a result receipt".to_string());
        }
        self.signer_key
            .verify(&preimage(&self.payload), &self.signature)
            .map_err(|_| "result receipt signature does not verify".to_string())?;
        let payload: ResultPayload = ciborium::from_reader(self.payload.as_slice())
            .map_err(|error| format!("result receipt payload: {error}"))?;
        if payload.version != RESULT_PAYLOAD_VERSION {
            return Err(format!(
                "unsupported result receipt version {}",
                payload.version
            ));
        }
        if ![MODE_WHOLE_BODY, MODE_STREAM, MODE_HEADERS].contains(&payload.body_mode.as_str()) {
            return Err("unknown result body mode".to_string());
        }
        match payload.outcome.as_str() {
            DELIVERED if payload.result_sha256.is_some() && payload.decision_code.is_none() => {}
            BLOCKED if payload.result_sha256.is_none() && payload.decision_code.is_some() => {}
            INCOMPLETE if payload.result_sha256.is_none() => {}
            _ => return Err("inconsistent result receipt outcome".to_string()),
        }
        Ok(payload)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes).map_err(|error| error.to_string())?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        ciborium::from_reader(bytes).map_err(|error| format!("result receipt: {error}"))
    }
}

/// SHA-256 over one encoded log line, the chain link for the next line.
pub fn line_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn preimage(payload: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(RESULT_CONTEXT.len() + payload.len());
    preimage.extend_from_slice(RESULT_CONTEXT);
    preimage.extend_from_slice(payload);
    preimage
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(outcome: &str) -> ResultPayload {
        ResultPayload {
            version: RESULT_PAYLOAD_VERSION,
            authorizer_id: "openshell".to_string(),
            timestamp: 1_700_000_000,
            sandbox_id: "sbx".to_string(),
            openshell_request_id: "exchange-1".to_string(),
            request_id: "7".to_string(),
            tool: "read_logs".to_string(),
            warrant_id: "tnu_wrt_00".to_string(),
            request_receipt_hash: Some([1; 32]),
            status_code: 200,
            body_mode: MODE_WHOLE_BODY.to_string(),
            outcome: outcome.to_string(),
            decision_code: None,
            result_bytes: 12,
            result_sha256: Some([2; 32]),
            prev_receipt_hash: None,
        }
    }

    #[test]
    fn a_result_receipt_round_trips_and_verifies() {
        let signer = SigningKey::generate();
        let receipt = ResultReceipt::create(&payload(DELIVERED), &signer).unwrap();
        let decoded = ResultReceipt::from_bytes(&receipt.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded.verify().unwrap(), payload(DELIVERED));
    }

    #[test]
    fn tampering_or_a_foreign_context_fails_verification() {
        let signer = SigningKey::generate();
        let mut receipt = ResultReceipt::create(&payload(DELIVERED), &signer).unwrap();
        let mut altered = payload(DELIVERED);
        altered.result_bytes = 13;
        receipt.payload.clear();
        ciborium::into_writer(&altered, &mut receipt.payload).unwrap();
        assert!(receipt.verify().is_err());

        // The same key signing the bare payload, as a Tenuo receipt would,
        // does not produce a valid result receipt.
        let mut bytes = Vec::new();
        ciborium::into_writer(&payload(DELIVERED), &mut bytes).unwrap();
        let forged = ResultReceipt {
            kind: RESULT_RECEIPT_KIND.to_string(),
            signature: signer.sign(&bytes),
            payload: bytes,
            signer_key: signer.public_key(),
        };
        assert!(forged.verify().is_err());
    }

    #[test]
    fn outcomes_must_match_their_evidence() {
        let signer = SigningKey::generate();
        let mut blocked = payload(BLOCKED);
        assert!(ResultReceipt::create(&blocked, &signer)
            .unwrap()
            .verify()
            .is_err());
        blocked.result_sha256 = None;
        blocked.decision_code = Some("tenuo_result_too_large".to_string());
        assert!(ResultReceipt::create(&blocked, &signer)
            .unwrap()
            .verify()
            .is_ok());
        let mut delivered = payload(DELIVERED);
        delivered.result_sha256 = None;
        assert!(ResultReceipt::create(&delivered, &signer)
            .unwrap()
            .verify()
            .is_err());
    }
}

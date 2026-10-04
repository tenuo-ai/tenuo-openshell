//! Signed approvals for gated tools.
//!
//! When a call needs approval the agent records a pending request. An
//! approver reviews the tool and arguments with `tenuo-openshell approve`,
//! which recomputes the request hash from them before signing, and installs
//! the signed approval here. The next identical call attaches it. An approval
//! is removed once attached: the middleware accepts each approval nonce once.

use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tenuo::approval::{ApprovalRequest, SignedApproval};
use tenuo::sdk::prelude::*;
use tenuo::Warrant;

#[derive(Clone, Debug)]
pub struct ApprovalStore {
    root: PathBuf,
}

/// Request hash an approval must carry for this call.
pub fn request_hash(leaf: &Warrant, call: &Call<'_>) -> [u8; 32] {
    tenuo::approval::compute_request_hash(
        &leaf.id().to_string(),
        call.capability(),
        call.pop_args(),
        Some(leaf.authorized_holder()),
    )
}

/// Decode a signed approval: the `_meta.tenuo` approval encoding (base64 in
/// either alphabet, decoded by Tenuo core) or raw CBOR bytes.
pub fn decode(bytes: &[u8]) -> Result<SignedApproval, String> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(approval) = tenuo::meta_envelope::decode_approval(text) {
            return Ok(approval);
        }
    }
    ciborium::from_reader(bytes).map_err(|_| "not a signed approval".to_string())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

impl ApprovalStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn approved(&self) -> PathBuf {
        self.root.join("approved")
    }

    fn pending(&self) -> PathBuf {
        self.root.join("pending")
    }

    /// Verify and store one signed approval. Returns its request hash.
    pub fn install(&self, bytes: &[u8]) -> Result<[u8; 32], String> {
        let approval = decode(bytes)?;
        let payload = approval
            .verify()
            .map_err(|error| format!("approval signature: {error}"))?;
        if payload.expires_at <= now() {
            return Err("approval has expired".to_string());
        }
        let directory = self.approved();
        fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
        let name = format!(
            "{}.{}.cbor",
            hex::encode(payload.request_hash),
            hex::encode(payload.nonce)
        );
        let mut encoded = Vec::new();
        ciborium::into_writer(&approval, &mut encoded).map_err(|error| error.to_string())?;
        let path = directory.join(name);
        let staging = path.with_extension("tmp");
        fs::write(&staging, encoded)
            .and_then(|()| fs::rename(&staging, &path))
            .map_err(|error| error.to_string())?;
        Ok(payload.request_hash)
    }

    /// Unexpired, verified approvals for one request.
    pub fn load(&self, hash: &[u8; 32]) -> Vec<(PathBuf, SignedApproval)> {
        let prefix = format!("{}.", hex::encode(hash));
        let Ok(entries) = fs::read_dir(self.approved()) else {
            return Vec::new();
        };
        let now = now();
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let named = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".cbor"));
            if !named {
                continue;
            }
            let Ok(approval) = fs::read(&path).map_err(|_| ()).and_then(|bytes| {
                ciborium::from_reader::<SignedApproval, _>(bytes.as_slice()).map_err(|_| ())
            }) else {
                continue;
            };
            match approval.verify() {
                Ok(payload) if payload.request_hash == *hash && payload.expires_at > now => {
                    found.push((path, approval));
                }
                Ok(_) => {
                    let _ = fs::remove_file(&path);
                }
                Err(_) => {}
            }
        }
        found.sort_by(|left, right| left.0.cmp(&right.0));
        found
    }

    /// Remove approvals that were attached to a signed call, and the request.
    pub fn consume(&self, hash: &[u8; 32], paths: &[PathBuf]) {
        for path in paths {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(self.pending_path(hash));
    }

    fn pending_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.pending().join(format!("{}.json", hex::encode(hash)))
    }

    /// Record what an approver needs to review this call: the request as
    /// core produced it and the warrant chain it was checked against. The
    /// approver verifies the chain and the request before showing either;
    /// `tool` and `arguments` are for listing only.
    pub fn record_pending(
        &self,
        request: &ApprovalRequest,
        chain: &[Warrant],
        arguments: &Value,
    ) -> Result<(), String> {
        let warrant =
            tenuo::meta_envelope::encode_warrant_chain(chain).map_err(|error| error.to_string())?;
        let record = json!({
            "request_hash": hex::encode(request.request_hash),
            "tool": request.tool,
            "arguments": arguments,
            "requested_at": now(),
            "request": request,
            "warrant": warrant,
        });
        fs::create_dir_all(self.pending()).map_err(|error| error.to_string())?;
        let path = self.pending_path(&request.request_hash);
        let staging = path.with_extension("tmp");
        fs::write(
            &staging,
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        )
        .and_then(|()| fs::rename(&staging, &path))
        .map_err(|error| error.to_string())
    }

    /// Pending requests, oldest first.
    pub fn list_pending(&self) -> Vec<Value> {
        let Ok(entries) = fs::read_dir(self.pending()) else {
            return Vec::new();
        };
        let mut requests: Vec<Value> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .filter_map(|path| fs::read(path).ok())
            .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
            .collect();
        requests.sort_by_key(|request| request["requested_at"].as_u64().unwrap_or(0));
        requests
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenuo::approval::{ApprovalPayload, SignedApproval};
    use tenuo::SigningKey;

    fn approval(approver: &SigningKey, hash: [u8; 32], nonce: u8, ttl: i64) -> SignedApproval {
        let issued = now();
        SignedApproval::create(
            ApprovalPayload {
                version: 1,
                request_hash: hash,
                nonce: [nonce; 16],
                external_id: "test".to_string(),
                approved_at: issued,
                expires_at: (issued as i64 + ttl) as u64,
                extensions: None,
            },
            approver,
        )
    }

    fn encoded(approval: &SignedApproval) -> Vec<u8> {
        let mut bytes = Vec::new();
        ciborium::into_writer(approval, &mut bytes).unwrap();
        bytes
    }

    #[test]
    fn installed_approvals_load_by_hash_and_are_consumed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ApprovalStore::new(directory.path());
        let approver = SigningKey::generate();
        let hash = [7u8; 32];
        use base64::Engine;
        let text = base64::engine::general_purpose::STANDARD
            .encode(encoded(&approval(&approver, hash, 1, 300)));
        assert_eq!(store.install(text.as_bytes()).unwrap(), hash);
        store
            .install(&encoded(&approval(&approver, [8; 32], 2, 300)))
            .unwrap();

        let found = store.load(&hash);
        assert_eq!(found.len(), 1);
        store.consume(
            &hash,
            &found
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>(),
        );
        assert!(store.load(&hash).is_empty());
        assert_eq!(store.load(&[8; 32]).len(), 1);
    }

    #[test]
    fn expired_or_forged_approvals_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let store = ApprovalStore::new(directory.path());
        let approver = SigningKey::generate();
        assert!(store
            .install(&encoded(&approval(&approver, [1; 32], 1, -1)))
            .is_err());

        let mut forged = approval(&approver, [1; 32], 1, 300);
        forged.signature = SigningKey::generate().sign(b"other");
        assert!(store.install(&encoded(&forged)).is_err());
        assert!(store.install(b"not cbor").is_err());
    }
}

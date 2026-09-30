//! Signed authorization receipts.
//!
//! A receipt records the decision. It does not record that a tool ran.
//! Persistence may be best-effort or required before an allowed decision.
//!
//! Result receipts go to a second chained log next to the first, named
//! `<log stem>.results.jsonl`. They are always best-effort: see
//! `crate::result`.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::result_receipt::{line_digest, ResultPayload, ResultReceipt};
use tenuo::sdk::prelude::Denial;
use tenuo::wire::{encode_stack, WarrantStack};
use tenuo::{ConstraintValue, ErrorCode, Receipt, ReceiptPayload, SigningKey, Warrant};

pub const AUTHORIZER_ID: &str = "openshell";

pub struct ReceiptLog {
    signer: SigningKey,
    path: PathBuf,
    previous_hash: Mutex<Option<[u8; 32]>>,
    results_path: PathBuf,
    previous_result_hash: Mutex<Option<[u8; 32]>>,
    required: bool,
}

pub struct DecisionReceipt<'a> {
    pub request_id: &'a str,
    pub tool: &'a str,
    pub chain: &'a [Warrant],
    pub pop: [u8; 64],
    pub pop_args: &'a HashMap<String, ConstraintValue>,
    pub trusted_roots_hash: [u8; 32],
    pub srl_version: Option<u64>,
    pub srl_hash: Option<[u8; 32]>,
    pub denial: Option<&'a Denial>,
}

impl ReceiptLog {
    pub fn open(key_path: &Path, log_path: &Path) -> Result<Self, String> {
        Self::open_inner(key_path, log_path, true)
    }

    pub fn open_existing(key_path: &Path, log_path: &Path) -> Result<Self, String> {
        Self::open_inner(key_path, log_path, false)
    }

    fn open_inner(key_path: &Path, log_path: &Path, create_key: bool) -> Result<Self, String> {
        let signer = if create_key {
            load_or_create_key(key_path)?
        } else {
            load_key(key_path)?
        };
        if let Some(parent) = log_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
        }
        let public_path = log_path.with_extension("pub");
        fs::write(
            public_path,
            format!("{}\n", hex::encode(signer.public_key().to_bytes())),
        )
        .map_err(|error| error.to_string())?;
        let previous_hash = previous_receipt_hash(log_path)?;
        let results_path = result_log_path(log_path);
        let previous_result_hash = previous_result_hash(&results_path)?;
        Ok(Self {
            signer,
            path: log_path.to_path_buf(),
            previous_hash: Mutex::new(previous_hash),
            results_path,
            previous_result_hash: Mutex::new(previous_result_hash),
            required: false,
        })
    }

    pub fn results_path(&self) -> &Path {
        &self.results_path
    }

    pub fn require_delivery(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn is_required(&self) -> bool {
        self.required
    }

    /// The log path can be opened for append. This does not write a receipt.
    pub fn can_append(&self) -> bool {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .is_ok()
    }

    pub fn record(&self, decision: DecisionReceipt<'_>) -> bool {
        self.record_digest(decision).is_some()
    }

    /// Store one receipt and return the SHA-256 of its encoded bytes, the
    /// value the next receipt carries as `prev_receipt_hash`.
    pub fn record_digest(&self, decision: DecisionReceipt<'_>) -> Option<[u8; 32]> {
        if decision.request_id.is_empty() || decision.chain.is_empty() {
            eprintln!("receipt was not stored");
            return None;
        }
        let leaf = decision.chain.last()?;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        let action = format!("tool:{}", decision.tool);
        let stack = match encode_stack(&WarrantStack::new(decision.chain.to_vec())) {
            Ok(stack) => stack,
            Err(_) => {
                eprintln!("receipt was not stored");
                return None;
            }
        };
        let mut payload = match decision.denial {
            None => {
                ReceiptPayload::allow(stack, action, timestamp, decision.request_id, decision.pop)
            }
            Some(denial) if pop_was_verified(denial) => ReceiptPayload::deny(
                stack,
                action,
                timestamp,
                decision.request_id,
                denial.code(),
                decision.pop,
            ),
            Some(denial) => ReceiptPayload::deny_before_pop(
                stack,
                action,
                timestamp,
                decision.request_id,
                denial.code(),
            ),
        };
        if decision.denial.is_none() || decision.denial.is_some_and(pop_was_verified) {
            payload.request_hash = Some(tenuo::approval::compute_request_hash(
                &leaf.id().to_string(),
                decision.tool,
                decision.pop_args,
                Some(leaf.authorized_holder()),
            ));
        }
        payload.authorizer_id = Some(AUTHORIZER_ID.to_string());
        payload.root_principal = decision
            .chain
            .first()
            .map(|warrant| hex::encode(warrant.issuer().to_bytes()));
        payload.trusted_roots_hash = Some(decision.trusted_roots_hash);
        payload.srl_version = decision.srl_version;
        payload.srl_hash = decision.srl_hash;
        let mut previous_hash = self
            .previous_hash
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        payload.prev_receipt_hash = *previous_hash;
        let receipt = match Receipt::create(&payload, &self.signer) {
            Ok(receipt) => receipt,
            Err(_) => {
                eprintln!("receipt was not stored");
                return None;
            }
        };
        let mut bytes = Vec::new();
        if ciborium::into_writer(&receipt, &mut bytes).is_err() {
            eprintln!("receipt was not stored");
            return None;
        }
        if !append_line(&self.path, &bytes) {
            eprintln!("receipt was not stored");
            return None;
        }
        let digest = line_digest(&bytes);
        *previous_hash = Some(digest);
        Some(digest)
    }

    /// Store one result receipt. The caller fills every field except the
    /// chain link, authorizer, and version.
    pub fn record_result(&self, mut payload: ResultPayload) -> bool {
        let mut previous_hash = self
            .previous_result_hash
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        payload.version = crate::result_receipt::RESULT_PAYLOAD_VERSION;
        payload.authorizer_id = AUTHORIZER_ID.to_string();
        payload.prev_receipt_hash = *previous_hash;
        let bytes = match ResultReceipt::create(&payload, &self.signer)
            .and_then(|receipt| receipt.to_bytes())
        {
            Ok(bytes) => bytes,
            Err(_) => {
                eprintln!("result receipt was not stored");
                return false;
            }
        };
        if !append_line(&self.results_path, &bytes) {
            eprintln!("result receipt was not stored");
            return false;
        }
        *previous_hash = Some(line_digest(&bytes));
        true
    }
}

/// `receipts.jsonl` becomes `receipts.results.jsonl`.
pub fn result_log_path(log_path: &Path) -> PathBuf {
    log_path.with_extension("results.jsonl")
}

fn append_line(path: &Path, bytes: &[u8]) -> bool {
    let line = format!("{}\n", hex::encode(bytes));
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) else {
        return false;
    };
    file.write_all(line.as_bytes()).is_ok()
}

fn previous_result_hash(path: &Path) -> Result<Option<[u8; 32]>, String> {
    let Some(bytes) = last_line(path)? else {
        return Ok(None);
    };
    ResultReceipt::from_bytes(&bytes)?;
    Ok(Some(line_digest(&bytes)))
}

fn last_line(path: &Path) -> Result<Option<Vec<u8>>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let Some(last) = contents.lines().rev().find(|line| !line.trim().is_empty()) else {
        return Ok(None);
    };
    hex::decode(last.trim())
        .map(Some)
        .map_err(|error| error.to_string())
}

fn previous_receipt_hash(path: &Path) -> Result<Option<[u8; 32]>, String> {
    let Some(bytes) = last_line(path)? else {
        return Ok(None);
    };
    let _: Receipt = ciborium::from_reader(bytes.as_slice()).map_err(|error| error.to_string())?;
    Ok(Some(line_digest(&bytes)))
}

fn load_key(path: &Path) -> Result<SigningKey, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{} is not a 32-byte receipt key", path.display()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn pop_was_verified(denial: &Denial) -> bool {
    matches!(
        denial.protocol_code(),
        Some(
            ErrorCode::ConstraintViolation
                | ErrorCode::ApprovalRequired
                | ErrorCode::InsufficientApprovals
                | ErrorCode::ApprovalInvalid
                | ErrorCode::ApproverNotAuthorized
                | ErrorCode::ApprovalExpired
                | ErrorCode::UnsupportedApprovalVersion
                | ErrorCode::ApprovalPayloadInvalid
                | ErrorCode::ApprovalRequestHashMismatch
        )
    )
}

fn load_or_create_key(path: &Path) -> Result<SigningKey, String> {
    if path.exists() {
        return load_key(path);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
    }
    let signer = SigningKey::generate();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| error.to_string())?;
    file.write_all(&signer.secret_key_bytes())
        .map_err(|error| error.to_string())?;
    Ok(signer)
}

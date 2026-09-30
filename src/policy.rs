//! Static sandbox-to-trust-root map. A missing sandbox denies.

use crate::reason;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tenuo::sdk::prelude::*;
use tenuo::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaMode {
    /// Leave `params._meta.tenuo` on the forwarded body.
    Preserve,
    /// Remove `params._meta.tenuo` before OpenShell forwards the body.
    Strip,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidMiddlewareConfig;

struct Sandbox {
    guard: Guard,
    trusted_roots_hash: [u8; 32],
}

pub struct PolicySet {
    sandboxes: HashMap<String, Sandbox>,
}

#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Json,
    Invalid,
    Empty,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Json => formatter.write_str("policy file is not JSON"),
            Self::Invalid => formatter.write_str("policy file is missing roots or a lifetime"),
            Self::Empty => formatter.write_str("policy file has no sandboxes"),
        }
    }
}

impl PolicySet {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let bytes = fs::read(path).map_err(PolicyError::Io)?;
        Self::from_json(&bytes)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, PolicyError> {
        let document: Value = serde_json::from_slice(bytes).map_err(|_| PolicyError::Json)?;
        let object = document.as_object().ok_or(PolicyError::Invalid)?;
        let lifetime = object
            .get("max_warrant_lifetime_secs")
            .and_then(Value::as_u64)
            .filter(|secs| *secs > 0)
            .ok_or(PolicyError::Invalid)?;
        let sandboxes = object
            .get("sandboxes")
            .and_then(Value::as_object)
            .ok_or(PolicyError::Invalid)?;
        if sandboxes.is_empty() {
            return Err(PolicyError::Empty);
        }
        let mut loaded = HashMap::new();
        for (sandbox_id, entry) in sandboxes {
            if sandbox_id.is_empty() {
                return Err(PolicyError::Invalid);
            }
            let roots = entry
                .get("trusted_roots")
                .and_then(Value::as_array)
                .ok_or(PolicyError::Invalid)?;
            let mut keys = Vec::with_capacity(roots.len());
            for root in roots {
                let text = root.as_str().ok_or(PolicyError::Invalid)?;
                keys.push(parse_root(text)?);
            }
            let Some(first) = keys.first() else {
                return Err(PolicyError::Invalid);
            };
            let trusted_roots_hash = tenuo::trusted_roots_digest(
                &keys.iter().map(PublicKey::to_bytes).collect::<Vec<_>>(),
            );
            let mut builder = Tenuo::enforcement().trusted_root(first.clone());
            for key in keys.into_iter().skip(1) {
                builder = builder.trusted_root(key);
            }
            let guard = builder
                .revocation(RevocationMode::TtlOnly {
                    max_lifetime: Duration::from_secs(lifetime),
                })
                .build()
                .map_err(|_| PolicyError::Invalid)?;
            loaded.insert(
                sandbox_id.clone(),
                Sandbox {
                    guard,
                    trusted_roots_hash,
                },
            );
        }
        Ok(Self { sandboxes: loaded })
    }

    pub fn guard(&self, sandbox_id: &str) -> Result<&Guard, &'static str> {
        Ok(&self.sandbox(sandbox_id)?.guard)
    }

    pub fn trusted_roots_hash(&self, sandbox_id: &str) -> Result<[u8; 32], &'static str> {
        Ok(self.sandbox(sandbox_id)?.trusted_roots_hash)
    }

    fn sandbox(&self, sandbox_id: &str) -> Result<&Sandbox, &'static str> {
        if sandbox_id.is_empty() {
            return Err(reason::VERIFIER_FAILED);
        }
        self.sandboxes
            .get(sandbox_id)
            .ok_or(reason::VERIFIER_FAILED)
    }
}

fn parse_root(text: &str) -> Result<PublicKey, PolicyError> {
    let bytes = hex::decode(text.trim()).map_err(|_| PolicyError::Invalid)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| PolicyError::Invalid)?;
    PublicKey::from_bytes(&bytes).map_err(|_| PolicyError::Invalid)
}

pub fn meta_mode(config: &prost_types::Struct) -> Result<MetaMode, InvalidMiddlewareConfig> {
    if config.fields.is_empty() {
        return Ok(MetaMode::Preserve);
    }
    if config.fields.len() != 1 {
        return Err(InvalidMiddlewareConfig);
    }
    let value = config
        .fields
        .get("tenuo_meta")
        .ok_or(InvalidMiddlewareConfig)?;
    let text = match &value.kind {
        Some(prost_types::value::Kind::StringValue(text)) => text.as_str(),
        _ => return Err(InvalidMiddlewareConfig),
    };
    match text {
        "preserve" => Ok(MetaMode::Preserve),
        "strip" => Ok(MetaMode::Strip),
        _ => Err(InvalidMiddlewareConfig),
    }
}

//! Static sandbox-to-trust-root map. A missing sandbox denies.

use crate::reason;
use crate::replay::{claims, InMemoryReplayStore, ReplayReservation, ReplayStore, ReserveResult};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tenuo::approval::SignedApproval;
use tenuo::revocation::SignedRevocationList;
use tenuo::revocation_tracker::{FileFloorStore, RevocationTracker, RevocationUpdate};
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
    revocation: Option<RevocationState>,
}

struct RevocationState {
    tracker: Arc<RevocationTracker>,
    version: u64,
    hash: [u8; 32],
}

pub struct PolicySet {
    version: u64,
    valid_until: Option<u64>,
    sandboxes: HashMap<String, Sandbox>,
    approval_replay_enabled: bool,
    replay_store: Arc<dyn ReplayStore>,
}

/// Claims reserved after approval verification and before an effect is allowed.
/// Dropping a reservation commits it as consumed. Release it only when a
/// required pre-effect step, such as durable receipt persistence, fails.
pub struct ApprovalReservation {
    store: Arc<dyn ReplayStore>,
    reservation: ReplayReservation,
}

impl ApprovalReservation {
    pub async fn commit(&self) -> Result<(), &'static str> {
        for _ in 0..3 {
            if self.store.commit(&self.reservation).await.is_ok() {
                return Ok(());
            }
        }
        Err(reason::VERIFIER_FAILED)
    }

    pub async fn release(self) -> Result<(), &'static str> {
        for _ in 0..3 {
            if self.store.release(&self.reservation).await.is_ok() {
                return Ok(());
            }
        }
        Err(reason::VERIFIER_FAILED)
    }
}

#[derive(Debug)]
pub enum PolicyError {
    Io(std::io::Error),
    Json,
    Invalid,
    Empty,
}

/// Supplies complete policy snapshots outside the authorization hot path.
///
/// Implementations may read a local file, a verified local cache, or another
/// operator-selected source. They must return the complete document only after
/// any source-specific authentication and integrity checks have succeeded.
/// `PolicyManager` performs schema, monotonic-version, revocation, and atomic
/// activation checks before a returned document becomes authoritative.
#[async_trait]
pub trait PolicyProvider: Send + Sync {
    async fn load(&self) -> Result<Vec<u8>, PolicyError>;

    /// A bounded, non-secret label suitable for diagnostics and metrics.
    fn kind(&self) -> &'static str;
}

/// Built-in standalone provider. No network activity is performed.
pub struct FilePolicyProvider {
    path: std::path::PathBuf,
}

impl FilePolicyProvider {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl PolicyProvider for FilePolicyProvider {
    async fn load(&self) -> Result<Vec<u8>, PolicyError> {
        tokio::fs::read(&self.path).await.map_err(PolicyError::Io)
    }

    fn kind(&self) -> &'static str {
        "file"
    }
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
        let version = match object.get("version") {
            Some(value) => value
                .as_u64()
                .filter(|version| *version > 0)
                .ok_or(PolicyError::Invalid)?,
            None => 1,
        };
        let valid_until = match object.get("valid_until") {
            Some(value) => Some(
                value
                    .as_u64()
                    .filter(|timestamp| *timestamp > 0)
                    .ok_or(PolicyError::Invalid)?,
            ),
            None => None,
        };
        let lifetime = object
            .get("max_warrant_lifetime_secs")
            .and_then(Value::as_u64)
            .filter(|secs| *secs > 0)
            .ok_or(PolicyError::Invalid)?;
        let approval_replay = match object.get("approval_replay_protection") {
            Some(value) => value.as_bool().ok_or(PolicyError::Invalid)?,
            None => false,
        };
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
            if keys.is_empty() {
                return Err(PolicyError::Invalid);
            }
            let trusted_roots_hash = tenuo::trusted_roots_digest(
                &keys.iter().map(PublicKey::to_bytes).collect::<Vec<_>>(),
            );
            let mut authorizer = tenuo::Authorizer::new();
            for key in &keys {
                authorizer.add_trusted_root(key.clone());
            }
            let (guard, revocation) = match entry.get("revocation") {
                None => {
                    let guard = Guard::builder()
                        .authorizer(authorizer)
                        .revocation(RevocationMode::TtlOnly {
                            max_lifetime: Duration::from_secs(lifetime),
                        })
                        .build()
                        .map_err(|_| PolicyError::Invalid)?;
                    (guard, None)
                }
                Some(value) => {
                    let value = value.as_object().ok_or(PolicyError::Invalid)?;
                    let encoded = value
                        .get("signed_list_base64")
                        .and_then(Value::as_str)
                        .ok_or(PolicyError::Invalid)?;
                    let max_staleness = value
                        .get("max_staleness_secs")
                        .and_then(Value::as_u64)
                        .filter(|seconds| *seconds > 0)
                        .ok_or(PolicyError::Invalid)?;
                    let tolerance = value
                        .get("clock_tolerance_secs")
                        .and_then(Value::as_u64)
                        .unwrap_or(30);
                    let floor_path = value
                        .get("rollback_floor_path")
                        .and_then(Value::as_str)
                        .filter(|path| !path.is_empty())
                        .ok_or(PolicyError::Invalid)?;
                    let srl = SignedRevocationList::from_base64(encoded)
                        .map_err(|_| PolicyError::Invalid)?;
                    let bytes = srl.to_bytes().map_err(|_| PolicyError::Invalid)?;
                    let version = srl.version();
                    let hash: [u8; 32] = Sha256::digest(&bytes).into();
                    let floors = Arc::new(
                        FileFloorStore::open(floor_path).map_err(|_| PolicyError::Invalid)?,
                    );
                    let tracker = Arc::new(
                        RevocationTracker::new(
                            keys,
                            Duration::from_secs(max_staleness),
                            Duration::from_secs(tolerance),
                            floors,
                        )
                        .map_err(|_| PolicyError::Invalid)?,
                    );
                    tracker
                        .accept(
                            RevocationUpdate {
                                srl,
                                fetched_at: Utc::now(),
                            },
                            Utc::now(),
                        )
                        .map_err(|_| PolicyError::Invalid)?;
                    let guard = Guard::builder()
                        .authorizer(authorizer)
                        .revocation(RevocationMode::SignedSrl)
                        .revocation_tracker(tracker.clone())
                        .build()
                        .map_err(|_| PolicyError::Invalid)?;
                    (
                        guard,
                        Some(RevocationState {
                            tracker,
                            version,
                            hash,
                        }),
                    )
                }
            };
            loaded.insert(
                sandbox_id.clone(),
                Sandbox {
                    guard,
                    trusted_roots_hash,
                    revocation,
                },
            );
        }
        Ok(Self {
            version,
            valid_until,
            sandboxes: loaded,
            approval_replay_enabled: approval_replay,
            replay_store: Arc::new(InMemoryReplayStore::default()),
        })
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn with_replay_store(mut self, store: Arc<dyn ReplayStore>) -> Self {
        self.replay_store = store;
        self
    }

    pub fn replay_store(&self) -> Option<&Arc<dyn ReplayStore>> {
        self.approval_replay_enabled.then_some(&self.replay_store)
    }

    fn replay_store_handle(&self) -> Arc<dyn ReplayStore> {
        self.replay_store.clone()
    }

    pub fn guard(&self, sandbox_id: &str) -> Result<&Guard, &'static str> {
        Ok(&self.sandbox(sandbox_id)?.guard)
    }

    pub fn trusted_roots_hash(&self, sandbox_id: &str) -> Result<[u8; 32], &'static str> {
        Ok(self.sandbox(sandbox_id)?.trusted_roots_hash)
    }

    pub fn revocation_commitment(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<(u64, [u8; 32])>, &'static str> {
        Ok(self
            .sandbox(sandbox_id)?
            .revocation
            .as_ref()
            .map(|state| (state.version, state.hash)))
    }

    pub fn revocation_ready(&self) -> bool {
        self.snapshot_fresh()
            && self.sandboxes.values().all(|sandbox| {
                sandbox
                    .revocation
                    .as_ref()
                    .is_none_or(|state| state.tracker.latest(Utc::now()).is_ok())
            })
    }

    /// Atomically reserve the nonces of approvals that already passed Guard validation.
    ///
    /// The store is deliberately integration-owned: Tenuo signs a unique nonce into every
    /// approval but leaves replay persistence to the enforcing application.
    pub async fn reserve_approvals(
        &self,
        sandbox_id: &str,
        approvals: &[SignedApproval],
    ) -> Result<Option<ApprovalReservation>, &'static str> {
        self.sandbox(sandbox_id)?;
        if !self.approval_replay_enabled {
            return Ok(None);
        }
        if approvals.is_empty() {
            return Ok(None);
        }
        let claims = claims(approvals).map_err(|_| reason::INVALID_AUTHORITY)?;
        match self.replay_store.reserve(&claims).await {
            Ok(ReserveResult::Reserved(reservation)) => Ok(Some(ApprovalReservation {
                store: self.replay_store.clone(),
                reservation,
            })),
            Ok(ReserveResult::Replayed) => Err(reason::APPROVAL_REPLAYED),
            Ok(ReserveResult::Pending) => Err(reason::VERIFIER_FAILED),
            Err(_) => Err(reason::VERIFIER_FAILED),
        }
    }

    fn sandbox(&self, sandbox_id: &str) -> Result<&Sandbox, &'static str> {
        if sandbox_id.is_empty() || !self.snapshot_fresh() {
            return Err(reason::VERIFIER_FAILED);
        }
        self.sandboxes
            .get(sandbox_id)
            .ok_or(reason::VERIFIER_FAILED)
    }

    fn snapshot_fresh(&self) -> bool {
        self.valid_until
            .is_none_or(|valid_until| unix_time() < valid_until)
    }
}

/// Atomically reloads a versioned policy while retaining the last valid state.
pub struct PolicyManager {
    provider: Option<Arc<dyn PolicyProvider>>,
    current: ArcSwap<PolicySet>,
    replay_store: Arc<dyn ReplayStore>,
    last_document: Mutex<Vec<u8>>,
    last_success: AtomicU64,
    reload_failures: AtomicU64,
}

impl PolicyManager {
    pub fn fixed(initial: PolicySet) -> Self {
        let replay_store = initial.replay_store_handle();
        Self {
            provider: None,
            current: ArcSwap::from_pointee(initial),
            replay_store,
            last_document: Mutex::new(Vec::new()),
            last_success: AtomicU64::new(unix_time()),
            reload_failures: AtomicU64::new(0),
        }
    }

    pub fn new(path: std::path::PathBuf, initial: PolicySet, document: Vec<u8>) -> Self {
        Self::with_provider(Arc::new(FilePolicyProvider::new(path)), initial, document)
    }

    /// Construct a manager around an operator-selected snapshot provider.
    ///
    /// The initial snapshot is explicit so startup never silently proceeds with
    /// an empty or remotely unavailable policy.
    pub fn with_provider(
        provider: Arc<dyn PolicyProvider>,
        initial: PolicySet,
        document: Vec<u8>,
    ) -> Self {
        let replay_store = initial.replay_store_handle();
        Self {
            provider: Some(provider),
            current: ArcSwap::from_pointee(initial),
            replay_store,
            last_document: Mutex::new(document),
            last_success: AtomicU64::new(unix_time()),
            reload_failures: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> Arc<PolicySet> {
        self.current.load_full()
    }

    pub fn reload_failures(&self) -> u64 {
        self.reload_failures.load(Ordering::Relaxed)
    }

    pub fn provider_kind(&self) -> &'static str {
        self.provider
            .as_ref()
            .map_or("fixed", |provider| provider.kind())
    }

    pub async fn reload_once(&self) -> Result<bool, PolicyError> {
        let provider = self.provider.as_ref().ok_or(PolicyError::Invalid)?;
        let document = provider.load().await?;
        let unchanged = self
            .last_document
            .lock()
            .map(|current| *current == document)
            .unwrap_or(false);
        if unchanged {
            self.last_success.store(unix_time(), Ordering::Relaxed);
            return Ok(false);
        }
        let mut next = PolicySet::from_json(&document)?;
        let current_version = self.current.load().version();
        if next.version() <= current_version {
            return Err(PolicyError::Invalid);
        }
        next = next.with_replay_store(self.replay_store.clone());
        self.current.store(Arc::new(next));
        if let Ok(mut current) = self.last_document.lock() {
            *current = document;
        }
        self.last_success.store(unix_time(), Ordering::Relaxed);
        Ok(true)
    }

    pub async fn ready(&self, max_stale: Duration) -> bool {
        if unix_time().saturating_sub(self.last_success.load(Ordering::Relaxed))
            > max_stale.as_secs()
        {
            return false;
        }
        let snapshot = self.snapshot();
        if !snapshot.revocation_ready() {
            return false;
        }
        match snapshot.replay_store() {
            Some(store) => store.healthy().await,
            None => true,
        }
    }

    pub async fn run(self: Arc<Self>, interval: Duration) {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if self.reload_once().await.is_err() {
                self.reload_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tenuo::SigningKey;

    struct MemoryPolicyProvider {
        document: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl PolicyProvider for MemoryPolicyProvider {
        async fn load(&self) -> Result<Vec<u8>, PolicyError> {
            Ok(self
                .document
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone())
        }

        fn kind(&self) -> &'static str {
            "memory-test"
        }
    }

    fn document(root: &SigningKey, version: u64) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "version": version,
            "max_warrant_lifetime_secs": 300,
            "approval_replay_protection": true,
            "sandboxes": {
                "sandbox": {
                    "trusted_roots": [hex::encode(root.public_key().to_bytes())]
                }
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn reload_is_atomic_versioned_and_keeps_last_good() {
        let root = SigningKey::generate();
        let first = document(&root, 1);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, &first).unwrap();
        let manager =
            PolicyManager::new(path.clone(), PolicySet::from_json(&first).unwrap(), first);

        let second = document(&root, 2);
        std::fs::write(&path, &second).unwrap();
        assert!(manager.reload_once().await.unwrap());
        assert_eq!(manager.snapshot().version(), 2);

        std::fs::write(&path, b"not-json").unwrap();
        assert!(manager.reload_once().await.is_err());
        assert_eq!(manager.snapshot().version(), 2);

        std::fs::write(&path, document(&root, 1)).unwrap();
        assert!(manager.reload_once().await.is_err());
        assert_eq!(manager.snapshot().version(), 2);
    }

    #[tokio::test]
    async fn provider_contract_activates_only_a_higher_valid_snapshot() {
        let root = SigningKey::generate();
        let first = document(&root, 1);
        let provider = Arc::new(MemoryPolicyProvider {
            document: Mutex::new(first.clone()),
        });
        let manager = PolicyManager::with_provider(
            provider.clone(),
            PolicySet::from_json(&first).unwrap(),
            first,
        );
        assert_eq!(manager.provider_kind(), "memory-test");
        assert!(!manager.reload_once().await.unwrap());

        *provider
            .document
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = document(&root, 2);
        assert!(manager.reload_once().await.unwrap());
        assert_eq!(manager.snapshot().version(), 2);

        *provider
            .document
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = b"not-json".to_vec();
        assert!(manager.reload_once().await.is_err());
        assert_eq!(manager.snapshot().version(), 2);
    }

    #[test]
    fn expired_provider_snapshot_is_unready_and_cannot_authorize() {
        let root = SigningKey::generate();
        let mut value: Value = serde_json::from_slice(&document(&root, 1)).unwrap();
        value["valid_until"] = json!(unix_time().saturating_sub(1));
        let policy = PolicySet::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(!policy.revocation_ready());
        assert!(matches!(
            policy.guard("sandbox"),
            Err(reason::VERIFIER_FAILED)
        ));
    }
}

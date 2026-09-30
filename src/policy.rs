//! Static sandbox-to-trust-root map. A missing sandbox denies.

use crate::reason;
use crate::replay::{
    claims, pop_claim, InMemoryReplayStore, ReplayReservation, ReplayStore, ReserveResult,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
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
    destinations: Vec<Destination>,
    mcp: McpOptions,
    single_use_tools: HashSet<String>,
    pop_replay_ttl_secs: u64,
}

/// One MCP server this sandbox may reach through the binding, and the tool
/// names a warrant may exercise there. Warrant capabilities name tools, not
/// servers, so this map is what keeps a `read_logs` grant meant for one server
/// from being spent on another server that exposes the same name.
struct Destination {
    host: String,
    port: u32,
    path: Option<String>,
    tools: ToolScope,
}

enum ToolScope {
    Any,
    Only(HashSet<String>),
}

impl Destination {
    fn matches(&self, target: &RequestTarget<'_>) -> bool {
        self.port == target.port
            && self.host.eq_ignore_ascii_case(target.host)
            && self.path.as_deref().is_none_or(|path| path == target.path)
    }

    fn allows(&self, tool: &str) -> bool {
        match &self.tools {
            ToolScope::Any => true,
            ToolScope::Only(tools) => tools.contains(tool),
        }
    }
}

/// The HTTP destination and method OpenShell admitted for one request.
#[derive(Clone, Copy, Debug)]
pub struct RequestTarget<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub port: u32,
    pub path: &'a str,
}

/// MCP traffic that is allowed without a warrant, beyond the built-in
/// lifecycle methods.
#[derive(Clone, Debug, Default)]
pub struct McpOptions {
    /// Additional JSON-RPC methods forwarded without a warrant, for example
    /// `resources/read`. `tools/call` is never accepted here.
    pub passthrough_methods: HashSet<String>,
    /// Forward JSON-RPC responses the client sends back to server-initiated
    /// requests (sampling, elicitation, roots).
    pub allow_client_responses: bool,
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

/// Approval nonces and single-use proofs reserved after verification and before
/// an effect is allowed. Commit it before the effect. Release it only when a
/// required pre-effect step, such as durable receipt persistence, fails.
pub struct ClaimReservation {
    store: Arc<dyn ReplayStore>,
    reservation: ReplayReservation,
}

impl ClaimReservation {
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
            Self::Invalid => {
                formatter.write_str("policy file is missing roots, destinations, or a lifetime")
            }
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
            // A proof of possession signs a time bucket, not a per-call nonce.
            // It verifies for at most `window * max_windows` seconds.
            let (window_secs, max_windows) = authorizer.pop_window_config();
            let pop_replay_ttl_secs = u64::try_from(window_secs)
                .map_err(|_| PolicyError::Invalid)?
                .saturating_mul(u64::from(max_windows));
            let destinations = parse_destinations(entry)?;
            let mcp = parse_mcp_options(entry)?;
            let single_use_tools = parse_single_use_tools(entry)?;
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
                    destinations,
                    mcp,
                    single_use_tools,
                    pop_replay_ttl_secs,
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
        let single_use = self
            .sandboxes
            .values()
            .any(|sandbox| !sandbox.single_use_tools.is_empty());
        (self.approval_replay_enabled || single_use).then_some(&self.replay_store)
    }

    fn replay_store_handle(&self) -> Arc<dyn ReplayStore> {
        self.replay_store.clone()
    }

    pub fn guard(&self, sandbox_id: &str) -> Result<&Guard, &'static str> {
        Ok(&self.sandbox(sandbox_id)?.guard)
    }

    pub fn mcp_options(&self, sandbox_id: &str) -> Result<&McpOptions, &'static str> {
        Ok(&self.sandbox(sandbox_id)?.mcp)
    }

    /// Deny a request whose destination is not configured for this sandbox,
    /// or, with `tool`, whose destination does not serve that tool.
    pub fn admit_destination(
        &self,
        sandbox_id: &str,
        target: &RequestTarget<'_>,
        tool: Option<&str>,
    ) -> Result<(), &'static str> {
        let sandbox = self.sandbox(sandbox_id)?;
        let admitted = sandbox
            .destinations
            .iter()
            .filter(|destination| destination.matches(target))
            .any(|destination| tool.is_none_or(|tool| destination.allows(tool)));
        if admitted {
            Ok(())
        } else {
            Err(reason::DESTINATION_DENIED)
        }
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

    /// Atomically reserve the approval nonces and, for a single-use tool, the
    /// proof of possession of a call that already passed Guard validation.
    ///
    /// The store is deliberately integration-owned: Tenuo signs a unique nonce into every
    /// approval but leaves replay persistence to the enforcing application.
    pub async fn reserve_claims(
        &self,
        sandbox_id: &str,
        tool: &str,
        pop_signature: &[u8],
        approvals: &[SignedApproval],
    ) -> Result<Option<ClaimReservation>, &'static str> {
        let sandbox = self.sandbox(sandbox_id)?;
        let mut reserved = Vec::new();
        let approval_claims = self.approval_replay_enabled && !approvals.is_empty();
        if approval_claims {
            reserved = claims(approvals).map_err(|_| reason::INVALID_AUTHORITY)?;
        }
        if sandbox.single_use_tools.contains(tool) {
            reserved.push(pop_claim(pop_signature, sandbox.pop_replay_ttl_secs));
        }
        if reserved.is_empty() {
            return Ok(None);
        }
        match self.replay_store.reserve(&reserved).await {
            Ok(ReserveResult::Reserved(reservation)) => Ok(Some(ClaimReservation {
                store: self.replay_store.clone(),
                reservation,
            })),
            Ok(ReserveResult::Replayed) if approval_claims => Err(reason::APPROVAL_REPLAYED),
            Ok(ReserveResult::Replayed) => Err(reason::POP_REPLAYED),
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

fn parse_destinations(entry: &Value) -> Result<Vec<Destination>, PolicyError> {
    let items = entry
        .get("destinations")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or(PolicyError::Invalid)?;
    let mut destinations = Vec::with_capacity(items.len());
    for item in items {
        let item = item.as_object().ok_or(PolicyError::Invalid)?;
        let host = item
            .get("host")
            .and_then(Value::as_str)
            .filter(|host| !host.is_empty())
            .ok_or(PolicyError::Invalid)?
            .to_ascii_lowercase();
        let port = item
            .get("port")
            .and_then(Value::as_u64)
            .filter(|port| (1..=65_535).contains(port))
            .ok_or(PolicyError::Invalid)? as u32;
        let path = match item.get("path") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|path| path.starts_with('/'))
                    .ok_or(PolicyError::Invalid)?
                    .to_string(),
            ),
        };
        let names = item
            .get("tools")
            .and_then(Value::as_array)
            .filter(|names| !names.is_empty())
            .ok_or(PolicyError::Invalid)?;
        let mut tools = HashSet::with_capacity(names.len());
        for name in names {
            let name = name
                .as_str()
                .filter(|name| !name.is_empty())
                .ok_or(PolicyError::Invalid)?;
            tools.insert(name.to_string());
        }
        let tools = if tools.contains("*") {
            if tools.len() != 1 {
                return Err(PolicyError::Invalid);
            }
            ToolScope::Any
        } else {
            ToolScope::Only(tools)
        };
        destinations.push(Destination {
            host,
            port,
            path,
            tools,
        });
    }
    Ok(destinations)
}

fn parse_mcp_options(entry: &Value) -> Result<McpOptions, PolicyError> {
    let Some(value) = entry.get("mcp") else {
        return Ok(McpOptions::default());
    };
    let value = value.as_object().ok_or(PolicyError::Invalid)?;
    let mut passthrough_methods = HashSet::new();
    if let Some(methods) = value.get("passthrough_methods") {
        for method in methods.as_array().ok_or(PolicyError::Invalid)? {
            let method = method
                .as_str()
                .filter(|method| !method.is_empty() && *method != "tools/call")
                .ok_or(PolicyError::Invalid)?;
            passthrough_methods.insert(method.to_string());
        }
    }
    let allow_client_responses = match value.get("allow_client_responses") {
        Some(flag) => flag.as_bool().ok_or(PolicyError::Invalid)?,
        None => false,
    };
    Ok(McpOptions {
        passthrough_methods,
        allow_client_responses,
    })
}

fn parse_single_use_tools(entry: &Value) -> Result<HashSet<String>, PolicyError> {
    let Some(value) = entry.get("single_use_tools") else {
        return Ok(HashSet::new());
    };
    let mut tools = HashSet::new();
    for name in value.as_array().ok_or(PolicyError::Invalid)? {
        let name = name
            .as_str()
            .filter(|name| !name.is_empty())
            .ok_or(PolicyError::Invalid)?;
        tools.insert(name.to_string());
    }
    Ok(tools)
}

fn parse_root(text: &str) -> Result<PublicKey, PolicyError> {
    let bytes = hex::decode(text.trim()).map_err(|_| PolicyError::Invalid)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| PolicyError::Invalid)?;
    PublicKey::from_bytes(&bytes).map_err(|_| PolicyError::Invalid)
}

pub fn meta_mode(config: &prost_types::Struct) -> Result<MetaMode, InvalidMiddlewareConfig> {
    if config.fields.is_empty() {
        return Ok(MetaMode::Strip);
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
                    "trusted_roots": [hex::encode(root.public_key().to_bytes())],
                    "destinations": [{"host": "mcp.test", "port": 443, "tools": ["*"]}]
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

    fn sandbox_document(root: &SigningKey, sandbox: Value) -> Vec<u8> {
        let mut sandbox = sandbox;
        sandbox["trusted_roots"] = json!([hex::encode(root.public_key().to_bytes())]);
        serde_json::to_vec(&json!({
            "max_warrant_lifetime_secs": 300,
            "sandboxes": { "sandbox": sandbox }
        }))
        .unwrap()
    }

    #[test]
    fn destinations_are_required_and_validated() {
        let root = SigningKey::generate();
        let destination = json!({"host": "mcp.test", "port": 443, "tools": ["read_logs"]});
        assert!(PolicySet::from_json(&sandbox_document(&root, json!({}))).is_err());
        assert!(
            PolicySet::from_json(&sandbox_document(&root, json!({"destinations": []}))).is_err()
        );
        for bad in [
            json!({"host": "", "port": 443, "tools": ["read_logs"]}),
            json!({"host": "mcp.test", "port": 0, "tools": ["read_logs"]}),
            json!({"host": "mcp.test", "port": 443, "tools": []}),
            json!({"host": "mcp.test", "port": 443, "tools": ["*", "read_logs"]}),
            json!({"host": "mcp.test", "port": 443, "path": "mcp", "tools": ["read_logs"]}),
        ] {
            let document = sandbox_document(&root, json!({"destinations": [bad]}));
            assert!(PolicySet::from_json(&document).is_err());
        }
        let document = sandbox_document(&root, json!({"destinations": [destination]}));
        assert!(PolicySet::from_json(&document).is_ok());
    }

    #[test]
    fn tools_call_cannot_be_configured_as_a_passthrough_method() {
        let root = SigningKey::generate();
        let document = sandbox_document(
            &root,
            json!({
                "destinations": [{"host": "mcp.test", "port": 443, "tools": ["*"]}],
                "mcp": {"passthrough_methods": ["tools/call"]}
            }),
        );
        assert!(PolicySet::from_json(&document).is_err());
    }

    #[test]
    fn single_use_tools_enable_the_replay_store() {
        let root = SigningKey::generate();
        let document = sandbox_document(
            &root,
            json!({
                "destinations": [{"host": "mcp.test", "port": 443, "tools": ["*"]}],
                "single_use_tools": ["restart_service"]
            }),
        );
        assert!(PolicySet::from_json(&document)
            .unwrap()
            .replay_store()
            .is_some());
    }

    #[test]
    fn unconfigured_bindings_strip_tenuo_meta() {
        assert_eq!(
            meta_mode(&prost_types::Struct::default()),
            Ok(MetaMode::Strip)
        );
    }
}

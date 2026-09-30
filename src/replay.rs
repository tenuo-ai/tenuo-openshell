//! Atomic replay protection for approval nonces and single-use proofs.

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::cluster_async::ClusterConnection;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use tenuo::{approval::SignedApproval, SigningKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayClaim {
    pub key: [u8; 48],
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReserveResult {
    Reserved(ReplayReservation),
    Replayed,
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayReservation {
    claims: Vec<ReplayClaim>,
    token: [u8; 32],
}

#[derive(Debug)]
pub struct ReplayError;

#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Reserve every claim atomically across the deployment.
    /// No claim is reserved when one was already used.
    async fn reserve(&self, claims: &[ReplayClaim]) -> Result<ReserveResult, ReplayError>;

    /// Commit a pending reservation after required pre-effect work succeeds.
    async fn commit(&self, reservation: &ReplayReservation) -> Result<(), ReplayError>;

    /// Release only claims still owned by this reservation. This is used when
    /// required evidence cannot be persisted before an effect is allowed.
    async fn release(&self, reservation: &ReplayReservation) -> Result<(), ReplayError>;

    async fn healthy(&self) -> bool;
}

struct ReservationEntry {
    expires_at: u64,
    token: [u8; 32],
    committed: bool,
}

const RESERVATION_LEASE_SECS: u64 = 30;

#[derive(Default)]
pub struct InMemoryReplayStore {
    used: Mutex<HashMap<[u8; 48], ReservationEntry>>,
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn reserve(&self, claims: &[ReplayClaim]) -> Result<ReserveResult, ReplayError> {
        if claims.is_empty() {
            return Ok(ReserveResult::Reserved(new_reservation(claims)));
        }
        let now = unix_time()?;
        let mut used = self.used.lock().map_err(|_| ReplayError)?;
        used.retain(|_, entry| entry.expires_at >= now);
        let mut pending = false;
        for claim in claims {
            if let Some(entry) = used.get(&claim.key) {
                if entry.committed {
                    return Ok(ReserveResult::Replayed);
                }
                pending = true;
            }
        }
        if pending {
            return Ok(ReserveResult::Pending);
        }
        let reservation = new_reservation(claims);
        used.extend(claims.iter().map(|claim| {
            (
                claim.key,
                ReservationEntry {
                    expires_at: claim
                        .expires_at
                        .min(now.saturating_add(RESERVATION_LEASE_SECS)),
                    token: reservation.token,
                    committed: false,
                },
            )
        }));
        Ok(ReserveResult::Reserved(reservation))
    }

    async fn commit(&self, reservation: &ReplayReservation) -> Result<(), ReplayError> {
        let mut used = self.used.lock().map_err(|_| ReplayError)?;
        if reservation.claims.iter().any(|claim| {
            !used
                .get(&claim.key)
                .is_some_and(|entry| entry.token == reservation.token && !entry.committed)
        }) {
            return Err(ReplayError);
        }
        for claim in &reservation.claims {
            if let Some(entry) = used.get_mut(&claim.key) {
                entry.expires_at = claim.expires_at;
                entry.committed = true;
            }
        }
        Ok(())
    }

    async fn release(&self, reservation: &ReplayReservation) -> Result<(), ReplayError> {
        let mut used = self.used.lock().map_err(|_| ReplayError)?;
        for claim in &reservation.claims {
            if used
                .get(&claim.key)
                .is_some_and(|entry| entry.token == reservation.token)
            {
                used.remove(&claim.key);
            }
        }
        Ok(())
    }

    async fn healthy(&self) -> bool {
        self.used.lock().is_ok()
    }
}

#[derive(Clone)]
pub struct RedisReplayStore {
    connection: RedisConnection,
    prefix: String,
    slot_tag: String,
}

#[derive(Clone)]
enum RedisConnection {
    Standalone(Box<ConnectionManager>),
    Cluster(ClusterConnection),
}

impl RedisReplayStore {
    pub async fn connect(url: &str, prefix: impl Into<String>) -> Result<Self, ReplayError> {
        let client = redis::Client::open(url).map_err(|_| ReplayError)?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| ReplayError)?;
        let prefix = prefix.into();
        let slot_tag = hex::encode(Sha256::digest(prefix.as_bytes()));
        Ok(Self {
            connection: RedisConnection::Standalone(Box::new(connection)),
            prefix,
            slot_tag,
        })
    }

    pub async fn connect_cluster(
        urls: &[String],
        prefix: impl Into<String>,
    ) -> Result<Self, ReplayError> {
        if urls.is_empty() {
            return Err(ReplayError);
        }
        let client = redis::cluster::ClusterClient::new(urls.iter().map(String::as_str))
            .map_err(|_| ReplayError)?;
        let connection = client
            .get_async_connection()
            .await
            .map_err(|_| ReplayError)?;
        let prefix = prefix.into();
        let slot_tag = hex::encode(Sha256::digest(prefix.as_bytes()));
        Ok(Self {
            connection: RedisConnection::Cluster(connection),
            prefix,
            slot_tag,
        })
    }

    fn redis_key(&self, claim: &ReplayClaim) -> String {
        redis_key(&self.prefix, &self.slot_tag, claim)
    }
}

fn redis_key(prefix: &str, slot_tag: &str, claim: &ReplayClaim) -> String {
    format!(
        "{{tenuo-{}}}:{}:{}",
        &slot_tag[..16],
        prefix,
        hex::encode(claim.key)
    )
}

#[async_trait]
impl ReplayStore for RedisReplayStore {
    async fn reserve(&self, claims: &[ReplayClaim]) -> Result<ReserveResult, ReplayError> {
        if claims.is_empty() {
            return Ok(ReserveResult::Reserved(new_reservation(claims)));
        }
        let now = unix_time()?;
        let reservation = new_reservation(claims);
        let token = format!("p:{}", hex::encode(reservation.token));
        let script = redis::Script::new(
            r#"
            for i = 1, #KEYS do
                local value = redis.call('GET', KEYS[i])
                if value then
                    if string.sub(value, 1, 2) == 'p:' then
                        return -1
                    end
                    return 0
                end
            end
            for i = 1, #KEYS do
                redis.call('SET', KEYS[i], ARGV[1], 'EX', ARGV[i + 1])
            end
            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();
        for claim in claims {
            invocation.key(self.redis_key(claim));
        }
        invocation.arg(token);
        for claim in claims {
            invocation.arg(
                claim
                    .expires_at
                    .saturating_sub(now)
                    .clamp(1, RESERVATION_LEASE_SECS),
            );
        }
        let consumed: i32 = match &self.connection {
            RedisConnection::Standalone(connection) => {
                let mut connection = connection.as_ref().clone();
                invocation.invoke_async(&mut connection).await
            }
            RedisConnection::Cluster(connection) => {
                let mut connection = connection.clone();
                invocation.invoke_async(&mut connection).await
            }
        }
        .map_err(|_| ReplayError)?;
        Ok(match consumed {
            1 => ReserveResult::Reserved(reservation),
            0 => ReserveResult::Replayed,
            -1 => ReserveResult::Pending,
            _ => return Err(ReplayError),
        })
    }

    async fn commit(&self, reservation: &ReplayReservation) -> Result<(), ReplayError> {
        if reservation.claims.is_empty() {
            return Ok(());
        }
        let script = redis::Script::new(
            r#"
            for i = 1, #KEYS do
                local value = redis.call('GET', KEYS[i])
                if value ~= ARGV[1] and value ~= ARGV[2] then
                    return 0
                end
            end
            for i = 1, #KEYS do
                redis.call('SET', KEYS[i], ARGV[2], 'EX', ARGV[i + 2])
            end
            return 1
            "#,
        );
        let now = unix_time()?;
        let token = hex::encode(reservation.token);
        let mut invocation = script.prepare_invoke();
        for claim in &reservation.claims {
            invocation.key(self.redis_key(claim));
        }
        invocation.arg(format!("p:{token}"));
        invocation.arg(format!("c:{token}"));
        for claim in &reservation.claims {
            invocation.arg(claim.expires_at.saturating_sub(now).max(1));
        }
        let committed: i32 = match &self.connection {
            RedisConnection::Standalone(connection) => {
                let mut connection = connection.as_ref().clone();
                invocation.invoke_async(&mut connection).await
            }
            RedisConnection::Cluster(connection) => {
                let mut connection = connection.clone();
                invocation.invoke_async(&mut connection).await
            }
        }
        .map_err(|_| ReplayError)?;
        if committed == 1 {
            Ok(())
        } else {
            Err(ReplayError)
        }
    }

    async fn release(&self, reservation: &ReplayReservation) -> Result<(), ReplayError> {
        if reservation.claims.is_empty() {
            return Ok(());
        }
        let script = redis::Script::new(
            r#"
            for i = 1, #KEYS do
                local value = redis.call('GET', KEYS[i])
                if value and value ~= ARGV[1] and value ~= ARGV[2] then
                    return 0
                end
            end
            for i = 1, #KEYS do
                local value = redis.call('GET', KEYS[i])
                if value == ARGV[1] or value == ARGV[2] then
                    redis.call('DEL', KEYS[i])
                end
            end
            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();
        for claim in &reservation.claims {
            invocation.key(self.redis_key(claim));
        }
        let token = hex::encode(reservation.token);
        invocation.arg(format!("p:{token}"));
        invocation.arg(format!("c:{token}"));
        let released: i32 = match &self.connection {
            RedisConnection::Standalone(connection) => {
                let mut connection = connection.as_ref().clone();
                invocation.invoke_async::<i32>(&mut connection).await
            }
            RedisConnection::Cluster(connection) => {
                let mut connection = connection.clone();
                invocation.invoke_async::<i32>(&mut connection).await
            }
        }
        .map_err(|_| ReplayError)?;
        if released == 1 {
            Ok(())
        } else {
            Err(ReplayError)
        }
    }

    async fn healthy(&self) -> bool {
        let response = match &self.connection {
            RedisConnection::Standalone(connection) => {
                let mut connection = connection.as_ref().clone();
                redis::cmd("PING")
                    .query_async::<String>(&mut connection)
                    .await
            }
            RedisConnection::Cluster(connection) => {
                let mut connection = connection.clone();
                redis::cmd("PING")
                    .query_async::<String>(&mut connection)
                    .await
            }
        };
        response.is_ok_and(|reply| reply == "PONG")
    }
}

pub fn claims(approvals: &[SignedApproval]) -> Result<Vec<ReplayClaim>, ReplayError> {
    let mut claims = Vec::with_capacity(approvals.len());
    let mut unique = HashSet::with_capacity(approvals.len());
    for approval in approvals {
        let payload = approval.verify().map_err(|_| ReplayError)?;
        let mut key = [0u8; 48];
        key[..32].copy_from_slice(&approval.approver_key.to_bytes());
        key[32..].copy_from_slice(&payload.nonce);
        if !unique.insert(key) {
            return Err(ReplayError);
        }
        claims.push(ReplayClaim {
            key,
            expires_at: payload.expires_at,
        });
    }
    Ok(claims)
}

/// Domain prefix for proof-of-possession claims. Approval claims start with a
/// 32-byte approver key, so the two claim families do not share keys.
const POP_CLAIM_DOMAIN: &[u8; 16] = b"tenuo-pop-claim1";

/// Claim for one proof-of-possession signature.
///
/// The proof signs the warrant, tool, arguments, and a time bucket. Ed25519 is
/// deterministic and verification is strict, so an identical call in the same
/// bucket has the same signature and maps to the same claim.
pub fn pop_claim(signature: &[u8], ttl_secs: u64) -> ReplayClaim {
    let mut key = [0u8; 48];
    key[..16].copy_from_slice(POP_CLAIM_DOMAIN);
    key[16..].copy_from_slice(&Sha256::digest(signature));
    let now = unix_time().unwrap_or(0);
    ReplayClaim {
        key,
        expires_at: now.saturating_add(ttl_secs.max(1)),
    }
}

fn new_reservation(claims: &[ReplayClaim]) -> ReplayReservation {
    ReplayReservation {
        claims: claims.to_vec(),
        token: SigningKey::generate().public_key().to_bytes(),
    }
}

fn unix_time() -> Result<u64, ReplayError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ReplayError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reserves_and_conditionally_releases_a_batch() {
        let store = InMemoryReplayStore::default();
        let claims = vec![
            ReplayClaim {
                key: [1; 48],
                expires_at: u64::MAX,
            },
            ReplayClaim {
                key: [2; 48],
                expires_at: u64::MAX,
            },
        ];
        let ReserveResult::Reserved(reservation) = store.reserve(&claims).await.unwrap() else {
            panic!("initial reservation was replayed");
        };
        assert_eq!(
            store.reserve(&claims).await.unwrap(),
            ReserveResult::Pending
        );
        store.release(&reservation).await.unwrap();
        let ReserveResult::Reserved(reservation) = store.reserve(&claims).await.unwrap() else {
            panic!("released reservation was not reusable");
        };
        store.commit(&reservation).await.unwrap();
        assert_eq!(
            store.reserve(&claims).await.unwrap(),
            ReserveResult::Replayed
        );
        store.release(&reservation).await.unwrap();
        assert!(matches!(
            store.reserve(&claims).await.unwrap(),
            ReserveResult::Reserved(_)
        ));
    }

    #[tokio::test]
    async fn stale_owner_cannot_release_a_new_reservation() {
        let store = InMemoryReplayStore::default();
        let expired = ReplayClaim {
            key: [3; 48],
            expires_at: 0,
        };
        let ReserveResult::Reserved(stale) = store.reserve(&[expired]).await.unwrap() else {
            panic!("initial reservation was replayed");
        };
        let current = ReplayClaim {
            key: [3; 48],
            expires_at: u64::MAX,
        };
        assert!(matches!(
            store.reserve(std::slice::from_ref(&current)).await.unwrap(),
            ReserveResult::Reserved(_)
        ));
        store.release(&stale).await.unwrap();
        assert_eq!(
            store.reserve(&[current]).await.unwrap(),
            ReserveResult::Pending
        );
    }

    #[tokio::test]
    async fn expired_pending_reservation_can_be_retried() {
        let store = InMemoryReplayStore::default();
        let claim = ReplayClaim {
            key: [4; 48],
            expires_at: u64::MAX,
        };
        assert!(matches!(
            store.reserve(std::slice::from_ref(&claim)).await.unwrap(),
            ReserveResult::Reserved(_)
        ));
        store
            .used
            .lock()
            .unwrap()
            .get_mut(&claim.key)
            .unwrap()
            .expires_at = 0;
        assert!(matches!(
            store.reserve(&[claim]).await.unwrap(),
            ReserveResult::Reserved(_)
        ));
    }

    #[tokio::test]
    async fn redis_reservation_is_global_and_shared_across_instances() {
        let Ok(url) = std::env::var("TENUO_TEST_REDIS_URL") else {
            return;
        };
        let prefix = format!("tenuo:test:{}", std::process::id());
        let first = RedisReplayStore::connect(&url, prefix.clone())
            .await
            .unwrap();
        let second = RedisReplayStore::connect(&url, prefix).await.unwrap();
        let claim = ReplayClaim {
            key: [7; 48],
            expires_at: unix_time().unwrap() + 60,
        };
        let ReserveResult::Reserved(reservation) =
            first.reserve(std::slice::from_ref(&claim)).await.unwrap()
        else {
            panic!("initial reservation was replayed");
        };
        assert_eq!(
            second.reserve(std::slice::from_ref(&claim)).await.unwrap(),
            ReserveResult::Pending
        );
        first.release(&reservation).await.unwrap();
        let ReserveResult::Reserved(reservation) =
            second.reserve(std::slice::from_ref(&claim)).await.unwrap()
        else {
            panic!("released Redis reservation was not reusable");
        };
        second.commit(&reservation).await.unwrap();
        assert_eq!(
            first.reserve(std::slice::from_ref(&claim)).await.unwrap(),
            ReserveResult::Replayed
        );
    }

    #[test]
    fn redis_batch_keys_share_a_cluster_hash_slot() {
        let prefix = "tenuo:deployment-a";
        let slot_tag = hex::encode(Sha256::digest(prefix.as_bytes()));
        let first = redis_key(
            prefix,
            &slot_tag,
            &ReplayClaim {
                key: [1; 48],
                expires_at: 1,
            },
        );
        let second = redis_key(
            prefix,
            &slot_tag,
            &ReplayClaim {
                key: [2; 48],
                expires_at: 1,
            },
        );
        assert_eq!(hash_tag(&first), hash_tag(&second));
    }

    fn hash_tag(key: &str) -> &str {
        key.split_once('{')
            .and_then(|(_, rest)| rest.split_once('}'))
            .map(|(tag, _)| tag)
            .expect("hash tag")
    }
}

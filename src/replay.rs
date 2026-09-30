//! Atomic approval replay protection.

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use std::collections::HashMap;
use std::sync::Mutex;
use tenuo::approval::SignedApproval;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayClaim {
    pub key: [u8; 48],
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsumeResult {
    Consumed,
    Replayed,
}

#[derive(Debug)]
pub struct ReplayError;

#[async_trait]
pub trait ReplayStore: Send + Sync {
    /// Consume every claim atomically. No claim is consumed when one was used.
    async fn consume(
        &self,
        sandbox_id: &str,
        claims: &[ReplayClaim],
    ) -> Result<ConsumeResult, ReplayError>;

    async fn healthy(&self) -> bool;
}

#[derive(Default)]
pub struct InMemoryReplayStore {
    used: Mutex<HashMap<[u8; 48], u64>>,
}

#[async_trait]
impl ReplayStore for InMemoryReplayStore {
    async fn consume(
        &self,
        _sandbox_id: &str,
        claims: &[ReplayClaim],
    ) -> Result<ConsumeResult, ReplayError> {
        let now = unix_time()?;
        let mut used = self.used.lock().map_err(|_| ReplayError)?;
        used.retain(|_, expires_at| *expires_at >= now);
        if claims.iter().any(|claim| used.contains_key(&claim.key)) {
            return Ok(ConsumeResult::Replayed);
        }
        used.extend(claims.iter().map(|claim| (claim.key, claim.expires_at)));
        Ok(ConsumeResult::Consumed)
    }

    async fn healthy(&self) -> bool {
        self.used.lock().is_ok()
    }
}

#[derive(Clone)]
pub struct RedisReplayStore {
    connection: ConnectionManager,
    prefix: String,
}

impl RedisReplayStore {
    pub async fn connect(url: &str, prefix: impl Into<String>) -> Result<Self, ReplayError> {
        let client = redis::Client::open(url).map_err(|_| ReplayError)?;
        let connection = ConnectionManager::new(client)
            .await
            .map_err(|_| ReplayError)?;
        Ok(Self {
            connection,
            prefix: prefix.into(),
        })
    }

    fn redis_key(&self, sandbox_id: &str, claim: &ReplayClaim) -> String {
        format!(
            "{}:{}:{}",
            self.prefix,
            hex::encode(sandbox_id.as_bytes()),
            hex::encode(claim.key)
        )
    }
}

#[async_trait]
impl ReplayStore for RedisReplayStore {
    async fn consume(
        &self,
        sandbox_id: &str,
        claims: &[ReplayClaim],
    ) -> Result<ConsumeResult, ReplayError> {
        if claims.is_empty() {
            return Ok(ConsumeResult::Consumed);
        }
        let now = unix_time()?;
        let script = redis::Script::new(
            r#"
            for i = 1, #KEYS do
                if redis.call('EXISTS', KEYS[i]) == 1 then
                    return 0
                end
            end
            for i = 1, #KEYS do
                redis.call('SET', KEYS[i], '1', 'EX', ARGV[i])
            end
            return 1
            "#,
        );
        let mut invocation = script.prepare_invoke();
        for claim in claims {
            invocation.key(self.redis_key(sandbox_id, claim));
        }
        for claim in claims {
            invocation.arg(claim.expires_at.saturating_sub(now).max(1));
        }
        let mut connection = self.connection.clone();
        let consumed: i32 = invocation
            .invoke_async(&mut connection)
            .await
            .map_err(|_| ReplayError)?;
        Ok(if consumed == 1 {
            ConsumeResult::Consumed
        } else {
            ConsumeResult::Replayed
        })
    }

    async fn healthy(&self) -> bool {
        let mut connection = self.connection.clone();
        redis::cmd("PING")
            .query_async::<String>(&mut connection)
            .await
            .is_ok_and(|reply| reply == "PONG")
    }
}

pub fn claims(approvals: &[SignedApproval]) -> Result<Vec<ReplayClaim>, ReplayError> {
    let mut claims = Vec::with_capacity(approvals.len());
    for approval in approvals {
        let payload = approval.verify().map_err(|_| ReplayError)?;
        let mut key = [0u8; 48];
        key[..32].copy_from_slice(&approval.approver_key.to_bytes());
        key[32..].copy_from_slice(&payload.nonce);
        claims.push(ReplayClaim {
            key,
            expires_at: payload.expires_at,
        });
    }
    Ok(claims)
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
    async fn consumes_a_batch_atomically() {
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
        assert_eq!(
            store.consume("sandbox", &claims).await.unwrap(),
            ConsumeResult::Consumed
        );
        assert_eq!(
            store.consume("sandbox", &claims).await.unwrap(),
            ConsumeResult::Replayed
        );
    }

    #[tokio::test]
    async fn redis_consumption_is_shared_across_instances() {
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
        assert_eq!(
            first
                .consume("sandbox", std::slice::from_ref(&claim))
                .await
                .unwrap(),
            ConsumeResult::Consumed
        );
        assert_eq!(
            second.consume("sandbox", &[claim]).await.unwrap(),
            ConsumeResult::Replayed
        );
    }
}

//! Kubernetes health and Prometheus endpoints on a credential-free admin port.

use crate::policy::PolicyManager;
use crate::telemetry::Telemetry;
use async_trait::async_trait;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
struct AdminState {
    policy: Arc<PolicyManager>,
    telemetry: Arc<Telemetry>,
    max_stale: Duration,
    checks: Arc<Vec<Arc<dyn ReadinessCheck>>>,
}

/// Optional dependency that can make the process unready without entering the
/// authorization hot path. Adapters should check only local state here (for
/// example, cache freshness or durable-export backlog), never perform network
/// I/O from the Kubernetes probe.
#[async_trait]
pub trait ReadinessCheck: Send + Sync {
    fn name(&self) -> &'static str;
    async fn ready(&self) -> bool;
}

pub async fn serve(
    listener: tokio::net::TcpListener,
    policy: Arc<PolicyManager>,
    telemetry: Arc<Telemetry>,
    max_stale: Duration,
) -> Result<(), String> {
    serve_with_checks(listener, policy, telemetry, max_stale, Vec::new()).await
}

pub async fn serve_with_checks(
    listener: tokio::net::TcpListener,
    policy: Arc<PolicyManager>,
    telemetry: Arc<Telemetry>,
    max_stale: Duration,
    checks: Vec<Arc<dyn ReadinessCheck>>,
) -> Result<(), String> {
    let state = AdminState {
        policy,
        telemetry,
        max_stale,
        checks: Arc::new(checks),
    };
    let app = Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(state);
    axum::serve(listener, app)
        .await
        .map_err(|error| format!("admin server stopped: {error}"))
}

async fn live() -> &'static str {
    "ok\n"
}

async fn ready(State(state): State<AdminState>) -> impl IntoResponse {
    if !state.policy.ready(state.max_stale).await {
        return (StatusCode::SERVICE_UNAVAILABLE, "not ready\n");
    }
    for check in state.checks.iter() {
        if !check.ready().await {
            return (StatusCode::SERVICE_UNAVAILABLE, "not ready\n");
        }
    }
    (StatusCode::OK, "ready\n")
}

async fn metrics(State(state): State<AdminState>) -> String {
    let snapshot = state.policy.snapshot();
    state
        .telemetry
        .prometheus(snapshot.version(), state.policy.reload_failures())
}

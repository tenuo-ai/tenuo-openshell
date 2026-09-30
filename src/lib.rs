//! OpenShell `HTTP_REQUEST` / `PRE_CREDENTIALS` evaluation.
//!
//! WebSocket sessions are not implemented. Production listeners authenticate
//! OpenShell extension JWTs and bind supervisor callers to `sandbox_id`.

pub mod admin;
pub mod auth;
pub mod evaluate;
pub mod mcp;
pub mod policy;
pub mod proto;
pub mod reason;
pub mod receipt;
pub mod replay;
pub mod service;
pub mod telemetry;

pub use admin::ReadinessCheck;
pub use evaluate::{evaluate, Outcome};
pub use policy::{FilePolicyProvider, MetaMode, PolicyProvider, PolicySet};
pub use service::MiddlewareService;

//! OpenShell `HTTP_REQUEST` / `PRE_CREDENTIALS` evaluation, with optional
//! `HTTP_RESPONSE` / `PRE_RETURN` evidence for the results of allowed calls.
//!
//! WebSocket sessions are not implemented. Production listeners authenticate
//! OpenShell extension JWTs and bind supervisor callers to `sandbox_id`.

pub mod admin;
pub mod auth;
pub mod evaluate;
pub mod export;
pub mod mcp;
pub mod otel;
pub mod policy;
pub mod proto;
pub mod reason;
pub mod receipt;
pub mod replay;
pub mod result;
pub mod result_receipt;
pub mod service;
pub mod telemetry;
pub mod templates;

pub use admin::ReadinessCheck;
pub use evaluate::{evaluate, Outcome};
pub use policy::{FilePolicyProvider, MetaMode, PolicyProvider, PolicySet, RequestTarget};
pub use service::MiddlewareService;

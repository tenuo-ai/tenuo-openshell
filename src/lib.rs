//! OpenShell `HTTP_REQUEST` / `PRE_CREDENTIALS` evaluation.
//!
//! WebSocket sessions are not implemented. Production listeners authenticate
//! OpenShell extension JWTs and bind supervisor callers to `sandbox_id`.

pub mod auth;
pub mod evaluate;
pub mod mcp;
pub mod policy;
pub mod proto;
pub mod reason;
pub mod service;

pub use evaluate::{evaluate, Outcome};
pub use policy::{MetaMode, PolicySet};
pub use service::MiddlewareService;

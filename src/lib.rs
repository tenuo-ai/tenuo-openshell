//! OpenShell `HTTP_REQUEST` / `PRE_CREDENTIALS` evaluation.
//!
//! WebSocket sessions and extension bearer authentication are not implemented.

pub mod evaluate;
pub mod mcp;
pub mod policy;
pub mod proto;
pub mod reason;
pub mod service;

pub use evaluate::{evaluate, Outcome};
pub use policy::{MetaMode, PolicySet};
pub use service::MiddlewareService;

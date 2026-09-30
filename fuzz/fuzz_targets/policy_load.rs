//! `PolicySet::from_json` on arbitrary bytes.
//!
//! A sandbox `revocation.rollback_floor_path` makes the loader create a file.
//! When a document parses and names one, the path is rewritten into a scratch
//! directory so a fuzzing run never writes outside it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::OnceLock;
use tenuo_openshell_middleware::policy::{PolicySet, RequestTarget};

fn scratch() -> &'static PathBuf {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    DIRECTORY.get_or_init(|| {
        let directory =
            std::env::temp_dir().join(format!("tenuo-fuzz-policy-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("scratch directory");
        directory
    })
}

/// Rewrite every rollback floor path into the scratch directory. Returns
/// `None` when the document names no floor path.
fn confine_floor_paths(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut document: Value = serde_json::from_slice(bytes).ok()?;
    let sandboxes = document.get_mut("sandboxes")?.as_object_mut()?;
    let mut rewritten = false;
    for (index, sandbox) in sandboxes.values_mut().enumerate() {
        let Some(floor) = sandbox.pointer_mut("/revocation/rollback_floor_path") else {
            continue;
        };
        if floor.is_string() {
            *floor = Value::String(
                scratch()
                    .join(format!("floor-{index}.json"))
                    .to_string_lossy()
                    .into_owned(),
            );
            rewritten = true;
        }
    }
    rewritten.then(|| serde_json::to_vec(&document).expect("re-encode"))
}

fuzz_target!(|bytes: &[u8]| {
    let confined = confine_floor_paths(bytes);
    let input = confined.as_deref().unwrap_or(bytes);
    let Ok(policy) = PolicySet::from_json(input) else {
        return;
    };
    assert!(policy.version() > 0);
    // A loaded policy answers lookups for unknown and empty sandboxes with a
    // denial, never a panic.
    let target = RequestTarget {
        method: "POST",
        host: "mcp.test",
        port: 443,
        path: "/mcp",
    };
    assert!(policy.guard("").is_err());
    assert!(policy.admit_destination("", &target, None).is_err());
    let _ = policy.revocation_ready();
    let _ = policy.replay_store();
    // Every listed sandbox is loaded. Without `valid_until` the snapshot
    // cannot be stale, so its guard must be available.
    let document: Value = serde_json::from_slice(input).expect("loaded policy is JSON");
    let fresh = document.get("valid_until").is_none();
    for sandbox_id in document["sandboxes"].as_object().expect("sandboxes").keys() {
        assert!(!fresh || policy.guard(sandbox_id).is_ok(), "{sandbox_id}");
        let _ = policy.admit_destination(sandbox_id, &target, None);
        let _ = policy.admit_destination(sandbox_id, &target, Some("read_logs"));
        let _ = policy.mcp_options(sandbox_id);
        let _ = policy.trusted_roots_hash(sandbox_id);
    }
});

//! Stable OpenShell `reason_code` values.
//!
//! Codes match the v0.1.2 grammar: a lowercase ASCII letter, then lowercase
//! ASCII letters, digits, or underscores, at most 64 bytes.

pub const MISSING_WARRANT: &str = "tenuo_missing_warrant";
pub const UNTRUSTED_ISSUER: &str = "tenuo_untrusted_issuer";
pub const INVALID_AUTHORITY: &str = "tenuo_invalid_authority";
pub const INVALID_POP: &str = "tenuo_invalid_pop";
pub const EXPIRED: &str = "tenuo_expired";
pub const REVOKED: &str = "tenuo_revoked";
pub const TOOL_DENIED: &str = "tenuo_tool_denied";
pub const CONSTRAINT_DENIED: &str = "tenuo_constraint_denied";
pub const APPROVAL_REQUIRED: &str = "tenuo_approval_required";
pub const INVALID_REQUEST: &str = "tenuo_invalid_request";
pub const VERIFIER_FAILED: &str = "tenuo_verifier_failed";

pub fn from_denial_code(code: &str) -> &'static str {
    match code {
        "untrusted-root" => UNTRUSTED_ISSUER,
        "tool-not-authorized" | "reserved-tool-name" => TOOL_DENIED,
        "constraint-violation" | "unknown-constraint-type" => CONSTRAINT_DENIED,
        "warrant-expired" | "warrant-not-yet-valid" | "issued-in-future" | "ttl-exceeded" => {
            EXPIRED
        }
        "warrant-revoked" | "srl-invalid" | "srl-version-rollback" | "srl-content-changed" => {
            REVOKED
        }
        "pop-signature-invalid" | "pop-expired" | "pop-challenge-invalid" => INVALID_POP,
        "approval-required" | "insufficient-approvals" => APPROVAL_REQUIRED,
        "authority-missing" => MISSING_WARRANT,
        "arguments-rejected" | "authority-malformed" => INVALID_REQUEST,
        "revocation-state-unavailable" | "signer-unavailable" | "evidence-unavailable" => {
            VERIFIER_FAILED
        }
        "invalid-issuer"
        | "parent-hash-mismatch"
        | "depth-exceeded"
        | "depth-violation"
        | "chain-too-long"
        | "chain-broken"
        | "signature-invalid"
        | "signature-algorithm-mismatch"
        | "unsupported-algorithm"
        | "invalid-key-length"
        | "invalid-signature-length"
        | "capability-expansion"
        | "invalid-attenuation"
        | "approval-invalid"
        | "approver-not-authorized"
        | "approval-expired"
        | "approval-request-hash-mismatch"
        | "approval-payload-invalid"
        | "unsupported-approval-version" => INVALID_AUTHORITY,
        _ => VERIFIER_FAILED,
    }
}

pub fn valid_reason_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    let Some((first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= 64
        && first.is_ascii_lowercase()
        && rest
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_codes_match_the_openshell_grammar() {
        for code in [
            MISSING_WARRANT,
            UNTRUSTED_ISSUER,
            INVALID_AUTHORITY,
            INVALID_POP,
            EXPIRED,
            REVOKED,
            TOOL_DENIED,
            CONSTRAINT_DENIED,
            APPROVAL_REQUIRED,
            INVALID_REQUEST,
            VERIFIER_FAILED,
        ] {
            assert!(valid_reason_code(code), "{code}");
        }
    }
}

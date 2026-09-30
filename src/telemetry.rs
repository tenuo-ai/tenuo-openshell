//! Bounded, argument-free service metrics.

use crate::evaluate::Outcome;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Telemetry {
    allows: AtomicU64,
    denies: AtomicU64,
    verifier_failures: AtomicU64,
    verify_us: AtomicU64,
}

impl Telemetry {
    pub fn observe(&self, outcome: &Outcome) {
        if outcome.allow {
            self.allows.fetch_add(1, Ordering::Relaxed);
        } else {
            self.denies.fetch_add(1, Ordering::Relaxed);
            if outcome.reason_code == crate::reason::VERIFIER_FAILED {
                self.verifier_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.verify_us
            .fetch_add(outcome.verify_us, Ordering::Relaxed);
    }

    pub fn prometheus(&self, policy_version: u64, reload_failures: u64) -> String {
        format!(
            concat!(
                "# TYPE tenuo_openshell_decisions_total counter\n",
                "tenuo_openshell_decisions_total{{outcome=\"allow\"}} {}\n",
                "tenuo_openshell_decisions_total{{outcome=\"deny\"}} {}\n",
                "# TYPE tenuo_openshell_verifier_failures_total counter\n",
                "tenuo_openshell_verifier_failures_total {}\n",
                "# TYPE tenuo_openshell_verify_microseconds_total counter\n",
                "tenuo_openshell_verify_microseconds_total {}\n",
                "# TYPE tenuo_openshell_policy_version gauge\n",
                "tenuo_openshell_policy_version {}\n",
                "# TYPE tenuo_openshell_policy_reload_failures_total counter\n",
                "tenuo_openshell_policy_reload_failures_total {}\n"
            ),
            self.allows.load(Ordering::Relaxed),
            self.denies.load(Ordering::Relaxed),
            self.verifier_failures.load(Ordering::Relaxed),
            self.verify_us.load(Ordering::Relaxed),
            policy_version,
            reload_failures,
        )
    }
}

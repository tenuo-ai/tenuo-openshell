//! Bounded, argument-free service metrics, and optional decision spans.

use crate::evaluate::Outcome;
use crate::otel::DecisionTracer;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Telemetry {
    allows: AtomicU64,
    denies: AtomicU64,
    verifier_failures: AtomicU64,
    decision_us: AtomicU64,
    results_delivered: AtomicU64,
    results_blocked: AtomicU64,
    results_incomplete: AtomicU64,
    results_skipped: AtomicU64,
    result_receipt_failures: AtomicU64,
    result_correlation_evictions: AtomicU64,
    tracer: Option<DecisionTracer>,
}

/// How one response evaluation ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultOutcome {
    Delivered,
    Blocked,
    Incomplete,
    Skipped,
}

impl ResultOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Blocked => "blocked",
            Self::Incomplete => "incomplete",
            Self::Skipped => "skipped",
        }
    }
}

impl Telemetry {
    pub fn with_tracer(mut self, tracer: DecisionTracer) -> Self {
        self.tracer = Some(tracer);
        self
    }

    pub fn tracer(&self) -> Option<&DecisionTracer> {
        self.tracer.as_ref()
    }

    pub fn observe(&self, outcome: &Outcome) {
        if outcome.allow {
            self.allows.fetch_add(1, Ordering::Relaxed);
        } else {
            self.denies.fetch_add(1, Ordering::Relaxed);
            if outcome.reason_code == crate::reason::VERIFIER_FAILED {
                self.verifier_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.decision_us
            .fetch_add(outcome.decision_us, Ordering::Relaxed);
    }

    pub fn observe_result(&self, outcome: ResultOutcome) {
        let counter = match outcome {
            ResultOutcome::Delivered => &self.results_delivered,
            ResultOutcome::Blocked => &self.results_blocked,
            ResultOutcome::Incomplete => &self.results_incomplete,
            ResultOutcome::Skipped => &self.results_skipped,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn result_receipt_failed(&self) {
        self.result_receipt_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn result_correlation_evicted(&self, count: u64) {
        self.result_correlation_evictions
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn prometheus(
        &self,
        policy_version: u64,
        policy_sandboxes: usize,
        reload_failures: u64,
    ) -> String {
        format!(
            concat!(
                "# TYPE tenuo_openshell_decisions_total counter\n",
                "tenuo_openshell_decisions_total{{outcome=\"allow\"}} {}\n",
                "tenuo_openshell_decisions_total{{outcome=\"deny\"}} {}\n",
                "# TYPE tenuo_openshell_verifier_failures_total counter\n",
                "tenuo_openshell_verifier_failures_total {}\n",
                "# TYPE tenuo_openshell_decision_microseconds_total counter\n",
                "tenuo_openshell_decision_microseconds_total {}\n",
                "# TYPE tenuo_openshell_policy_version gauge\n",
                "tenuo_openshell_policy_version {}\n",
                "# TYPE tenuo_openshell_policy_sandboxes gauge\n",
                "tenuo_openshell_policy_sandboxes {}\n",
                "# TYPE tenuo_openshell_policy_reload_failures_total counter\n",
                "tenuo_openshell_policy_reload_failures_total {}\n",
                "# TYPE tenuo_openshell_results_total counter\n",
                "tenuo_openshell_results_total{{outcome=\"delivered\"}} {}\n",
                "tenuo_openshell_results_total{{outcome=\"blocked\"}} {}\n",
                "tenuo_openshell_results_total{{outcome=\"incomplete\"}} {}\n",
                "tenuo_openshell_results_total{{outcome=\"skipped\"}} {}\n",
                "# TYPE tenuo_openshell_result_receipt_failures_total counter\n",
                "tenuo_openshell_result_receipt_failures_total {}\n",
                "# TYPE tenuo_openshell_result_correlation_evictions_total counter\n",
                "tenuo_openshell_result_correlation_evictions_total {}\n"
            ),
            self.allows.load(Ordering::Relaxed),
            self.denies.load(Ordering::Relaxed),
            self.verifier_failures.load(Ordering::Relaxed),
            self.decision_us.load(Ordering::Relaxed),
            policy_version,
            policy_sandboxes,
            reload_failures,
            self.results_delivered.load(Ordering::Relaxed),
            self.results_blocked.load(Ordering::Relaxed),
            self.results_incomplete.load(Ordering::Relaxed),
            self.results_skipped.load(Ordering::Relaxed),
            self.result_receipt_failures.load(Ordering::Relaxed),
            self.result_correlation_evictions.load(Ordering::Relaxed),
        )
    }
}

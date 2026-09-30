//! OpenShell `HTTP_RESPONSE` / `PRE_RETURN` evaluation of tool results.
//!
//! A response is evaluated only when this middleware allowed the matching
//! `tools/call`. The request path records the OpenShell `request_id`, which
//! OpenShell reuses for the response, with the JSON-RPC id, tool, leaf
//! warrant id, and the allow receipt hash. Every other response is skipped:
//! lifecycle traffic, denied calls, calls another stage stopped, and
//! responses that arrive after the entry expired or on another replica.
//!
//! For a matched response the stage reads the body, hashes it, and writes a
//! signed result receipt. It blocks delivery only for the sandbox's optional
//! `max_result_bytes`. The upstream call has already run, so a block withholds
//! the result; it does not undo the effect.
//!
//! Result receipts are best-effort, including with `--require-receipts`.
//! That flag guarantees an authorization receipt exists before an effect is
//! allowed. Withholding the result of an effect that already ran when its
//! result receipt cannot be written would add no evidence about the effect
//! and invites a retry of a non-idempotent call.

use crate::otel::DecisionSpan;
use crate::proto::openshell::middleware::v1::{
    http_response_body_result, http_response_body_unit, http_response_preflight_result,
    HttpResponseBlockDelivery, HttpResponseBodyMode, HttpResponseBodyPassThrough,
    HttpResponseBodyResult, HttpResponseBodyUnit, HttpResponsePreflight,
    HttpResponsePreflightInspect, HttpResponsePreflightResult, HttpResponsePreflightSkip,
    HttpResponseTrailersResult,
};
use crate::reason;
use crate::receipt::ReceiptLog;
use crate::result_receipt::{self, ResultPayload};
use crate::telemetry::{ResultOutcome, Telemetry};
use opentelemetry::trace::SpanContext;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// In-flight allowed calls one replica tracks. Entries leave when their
/// response arrives, so this bounds concurrency, not throughput.
pub const DEFAULT_CAPACITY: usize = 65_536;
/// An allowed call whose response has not arrived by then is forgotten.
pub const DEFAULT_TTL: Duration = Duration::from_secs(600);

/// What the request path knows about one allowed `tools/call`.
#[derive(Clone, Debug, Default)]
pub struct PendingResult {
    pub jsonrpc_id: String,
    pub tool: String,
    pub warrant_id: String,
    pub request_receipt_hash: Option<[u8; 32]>,
    /// The sandbox's limit when the call was allowed.
    pub max_result_bytes: Option<u64>,
    pub trace: Option<SpanContext>,
}

type Key = (String, String);

/// Bounded, expiring map from `(sandbox_id, request_id)` to an allowed call.
pub struct PendingResults {
    state: Mutex<PendingState>,
    capacity: usize,
    ttl: Duration,
}

#[derive(Default)]
struct PendingState {
    entries: HashMap<Key, Entry>,
    /// Insertion order. Stale positions are skipped and compacted.
    order: VecDeque<(u64, Key)>,
    next: u64,
}

struct Entry {
    seq: u64,
    at: Instant,
    value: PendingResult,
}

impl Default for PendingResults {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_TTL)
    }
}

impl PendingResults {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            state: Mutex::new(PendingState::default()),
            capacity: capacity.max(1),
            ttl,
        }
    }

    /// Track one allowed call. Returns how many live entries were evicted,
    /// oldest first, to stay within capacity.
    pub fn insert(&self, sandbox_id: &str, request_id: &str, value: PendingResult) -> u64 {
        self.insert_at(sandbox_id, request_id, value, Instant::now())
    }

    /// Remove and return the call for this response, unless it expired.
    pub fn take(&self, sandbox_id: &str, request_id: &str) -> Option<PendingResult> {
        self.take_at(sandbox_id, request_id, Instant::now())
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn insert_at(
        &self,
        sandbox_id: &str,
        request_id: &str,
        value: PendingResult,
        now: Instant,
    ) -> u64 {
        if sandbox_id.is_empty() || request_id.is_empty() {
            return 0;
        }
        let mut state = self.lock();
        let state = &mut *state;
        while let Some((seq, key)) = state.order.front() {
            match state.entries.get(key) {
                Some(entry) if entry.seq == *seq => {
                    if now.saturating_duration_since(entry.at) < self.ttl {
                        break;
                    }
                    state.entries.remove(key);
                }
                _ => {}
            }
            state.order.pop_front();
        }
        let key = (sandbox_id.to_string(), request_id.to_string());
        let seq = state.next;
        state.next += 1;
        state.order.push_back((seq, key.clone()));
        state.entries.insert(
            key,
            Entry {
                seq,
                at: now,
                value,
            },
        );
        let mut evicted = 0;
        while state.entries.len() > self.capacity {
            let Some((seq, key)) = state.order.pop_front() else {
                break;
            };
            if state
                .entries
                .get(&key)
                .is_some_and(|entry| entry.seq == seq)
            {
                state.entries.remove(&key);
                evicted += 1;
            }
        }
        if state.order.len() > self.capacity.saturating_mul(2) {
            let entries = &state.entries;
            state
                .order
                .retain(|(seq, key)| entries.get(key).is_some_and(|entry| entry.seq == *seq));
        }
        evicted
    }

    fn take_at(&self, sandbox_id: &str, request_id: &str, now: Instant) -> Option<PendingResult> {
        let key = (sandbox_id.to_string(), request_id.to_string());
        let entry = self.lock().entries.remove(&key)?;
        (now.saturating_duration_since(entry.at) < self.ttl).then_some(entry.value)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, PendingState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Shared state one response stage reads and writes.
pub struct ResultDeps<'a> {
    pub pending: &'a PendingResults,
    pub receipts: Option<&'a ReceiptLog>,
    pub telemetry: &'a Telemetry,
}

/// One matched response being read.
pub struct Inspection {
    sandbox_id: String,
    openshell_request_id: String,
    pending: PendingResult,
    status_code: u32,
    mode: &'static str,
    hasher: Sha256,
    bytes: u64,
    started: SystemTime,
    finished: bool,
}

/// Decide what to do with one response head. `Some` means the stage asked
/// OpenShell for the body and must see it through `body` and `end`.
pub fn preflight(
    deps: &ResultDeps<'_>,
    preflight: &HttpResponsePreflight,
) -> (HttpResponsePreflightResult, Option<Inspection>) {
    let started = SystemTime::now();
    let Some(context) = preflight.context.as_ref() else {
        deps.telemetry.observe_result(ResultOutcome::Skipped);
        return (skip(), None);
    };
    let Some(pending) = deps.pending.take(&context.sandbox_id, &context.request_id) else {
        deps.telemetry.observe_result(ResultOutcome::Skipped);
        return (skip(), None);
    };
    let mut inspection = Inspection {
        sandbox_id: context.sandbox_id.clone(),
        openshell_request_id: context.request_id.clone(),
        pending,
        status_code: preflight.status_code,
        mode: result_receipt::MODE_HEADERS,
        hasher: Sha256::new(),
        bytes: 0,
        started,
        finished: false,
    };
    let limit = inspection.pending.max_result_bytes;
    let declared = content_length(preflight);
    if let (Some(limit), Some(declared)) = (limit, declared) {
        if declared > limit {
            inspection.bytes = declared;
            finish_blocked(deps, &mut inspection, reason::RESULT_TOO_LARGE);
            return (block(reason::RESULT_TOO_LARGE), None);
        }
    }
    let permitted =
        |mode: HttpResponseBodyMode| preflight.permitted_body_modes.contains(&(mode as i32));
    // A known length within the limit fits in one unit, so the head is held
    // and a block still returns OpenShell's canonical 403. An unknown length
    // could exceed max_payload_bytes and turn into an on_error failure, so it
    // streams instead.
    let mode = if declared.is_some() && permitted(HttpResponseBodyMode::WholeBodyBytes) {
        HttpResponseBodyMode::WholeBodyBytes
    } else if permitted(HttpResponseBodyMode::StreamBytes) {
        HttpResponseBodyMode::StreamBytes
    } else {
        // Only HEADERS_ONLY: bodyless, partial, encoded, or no-transform.
        if limit.is_some() && declared.is_none() && body_capable(preflight) {
            finish_blocked(deps, &mut inspection, reason::RESULT_UNMEASURABLE);
            return (block(reason::RESULT_UNMEASURABLE), None);
        }
        deps.telemetry.observe_result(ResultOutcome::Skipped);
        return (skip(), None);
    };
    inspection.mode = if mode == HttpResponseBodyMode::WholeBodyBytes {
        result_receipt::MODE_WHOLE_BODY
    } else {
        result_receipt::MODE_STREAM
    };
    let result = HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::Inspect(
            HttpResponsePreflightInspect {
                body_mode: mode as i32,
                header_mutations: Vec::new(),
            },
        )),
        ..Default::default()
    };
    (result, Some(inspection))
}

/// Count and hash one body unit. The final unit writes the receipt.
pub fn body(
    deps: &ResultDeps<'_>,
    inspection: &mut Inspection,
    unit: &HttpResponseBodyUnit,
) -> HttpResponseBodyResult {
    let data = match &unit.payload {
        Some(http_response_body_unit::Payload::Data(data)) => data.as_slice(),
        None => &[],
    };
    if inspection.finished {
        return pass_through(unit.sequence);
    }
    inspection.bytes = inspection
        .bytes
        .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    if inspection
        .pending
        .max_result_bytes
        .is_some_and(|limit| inspection.bytes > limit)
    {
        finish_blocked(deps, inspection, reason::RESULT_TOO_LARGE);
        return HttpResponseBodyResult {
            sequence: unit.sequence,
            action: Some(http_response_body_result::Action::BlockDelivery(
                HttpResponseBlockDelivery {},
            )),
            reason_code: reason::RESULT_TOO_LARGE.to_string(),
            ..Default::default()
        };
    }
    inspection.hasher.update(data);
    if unit.end_of_stream {
        let digest: [u8; 32] = std::mem::take(&mut inspection.hasher).finalize().into();
        finish(
            deps,
            inspection,
            ResultOutcome::Delivered,
            None,
            Some(digest),
        );
    }
    pass_through(unit.sequence)
}

/// Trailers are never changed.
pub fn trailers() -> HttpResponseTrailersResult {
    HttpResponseTrailersResult::default()
}

/// The stream closed. A body that did not reach its final unit is recorded
/// as incomplete: in stream mode, earlier units may already be delivered.
pub fn end(deps: &ResultDeps<'_>, mut inspection: Inspection) {
    if !inspection.finished {
        finish(deps, &mut inspection, ResultOutcome::Incomplete, None, None);
    }
}

fn finish_blocked(deps: &ResultDeps<'_>, inspection: &mut Inspection, code: &'static str) {
    finish(deps, inspection, ResultOutcome::Blocked, Some(code), None);
}

fn finish(
    deps: &ResultDeps<'_>,
    inspection: &mut Inspection,
    outcome: ResultOutcome,
    code: Option<&'static str>,
    digest: Option<[u8; 32]>,
) {
    inspection.finished = true;
    deps.telemetry.observe_result(outcome);
    let pending = &inspection.pending;
    if let Some(log) = deps.receipts {
        let stored = log.record_result(ResultPayload {
            version: result_receipt::RESULT_PAYLOAD_VERSION,
            authorizer_id: String::new(),
            timestamp: unix_time(),
            sandbox_id: inspection.sandbox_id.clone(),
            openshell_request_id: inspection.openshell_request_id.clone(),
            request_id: pending.jsonrpc_id.clone(),
            tool: pending.tool.clone(),
            warrant_id: pending.warrant_id.clone(),
            request_receipt_hash: pending.request_receipt_hash,
            status_code: inspection.status_code,
            body_mode: inspection.mode.to_string(),
            outcome: outcome.as_str().to_string(),
            decision_code: code.map(str::to_string),
            result_bytes: inspection.bytes,
            result_sha256: digest,
            prev_receipt_hash: None,
        });
        if !stored {
            deps.telemetry.result_receipt_failed();
        }
    }
    let decision_us = SystemTime::now()
        .duration_since(inspection.started)
        .map(|elapsed| u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    if crate::evaluate::decision_log_enabled() && !pending.jsonrpc_id.is_empty() {
        eprintln!(
            "tenuo_result request_id={} decision_us={} outcome={} reason={} bytes={}",
            crate::evaluate::log_safe_id(&pending.jsonrpc_id),
            decision_us,
            outcome.as_str(),
            code.unwrap_or("-"),
            inspection.bytes
        );
    }
    if let Some(tracer) = deps.telemetry.tracer() {
        tracer.record(
            &tracer.parent_from_span(pending.trace.as_ref()),
            DecisionSpan {
                name: "tenuo.result",
                started: inspection.started,
                sandbox_id: &inspection.sandbox_id,
                tool: Some(&pending.tool),
                outcome: outcome.as_str(),
                reason_code: code.unwrap_or(""),
                decision_us,
                warrant_id: Some(&pending.warrant_id),
                jsonrpc_id: &pending.jsonrpc_id,
                status_code: Some(inspection.status_code),
                result_bytes: Some(inspection.bytes),
            },
        );
    }
}

fn skip() -> HttpResponsePreflightResult {
    HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::Skip(
            HttpResponsePreflightSkip {},
        )),
        ..Default::default()
    }
}

fn block(code: &'static str) -> HttpResponsePreflightResult {
    HttpResponsePreflightResult {
        action: Some(http_response_preflight_result::Action::BlockDelivery(
            HttpResponseBlockDelivery {},
        )),
        reason_code: code.to_string(),
        ..Default::default()
    }
}

fn pass_through(sequence: u64) -> HttpResponseBodyResult {
    HttpResponseBodyResult {
        sequence,
        action: Some(http_response_body_result::Action::PassThrough(
            HttpResponseBodyPassThrough {},
        )),
        ..Default::default()
    }
}

/// The upstream `Content-Length`, when present exactly once and valid.
fn content_length(preflight: &HttpResponsePreflight) -> Option<u64> {
    let mut values = preflight
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"));
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.value.trim().parse().ok()
}

/// A response that can carry a body under RFC 9110.
fn body_capable(preflight: &HttpResponsePreflight) -> bool {
    let head = preflight
        .target
        .as_ref()
        .is_some_and(|target| target.method.eq_ignore_ascii_case("HEAD"));
    !head && preflight.status_code != 204 && preflight.status_code != 304
}

fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::openshell::middleware::v1::{HttpHeader, HttpRequestTarget, RequestContext};
    use crate::result_receipt::ResultReceipt;

    const WHOLE: i32 = HttpResponseBodyMode::WholeBodyBytes as i32;
    const STREAM: i32 = HttpResponseBodyMode::StreamBytes as i32;
    const HEADERS: i32 = HttpResponseBodyMode::HeadersOnly as i32;

    struct Fixture {
        pending: PendingResults,
        telemetry: Telemetry,
        receipts: Option<ReceiptLog>,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let receipts =
                ReceiptLog::open(&dir.path().join("key"), &dir.path().join("r.jsonl")).unwrap();
            Self {
                pending: PendingResults::default(),
                telemetry: Telemetry::default(),
                receipts: Some(receipts),
                _dir: dir,
            }
        }

        fn deps(&self) -> ResultDeps<'_> {
            ResultDeps {
                pending: &self.pending,
                receipts: self.receipts.as_ref(),
                telemetry: &self.telemetry,
            }
        }

        fn allow(&self, request_id: &str, limit: Option<u64>) {
            self.pending.insert(
                "sbx",
                request_id,
                PendingResult {
                    jsonrpc_id: "7".to_string(),
                    tool: "read_logs".to_string(),
                    warrant_id: "tnu_wrt_leaf".to_string(),
                    request_receipt_hash: Some([9; 32]),
                    max_result_bytes: limit,
                    trace: None,
                },
            );
        }

        fn results(&self) -> Vec<ResultPayload> {
            let Some(log) = &self.receipts else {
                return Vec::new();
            };
            let Ok(text) = std::fs::read_to_string(log.results_path()) else {
                return Vec::new();
            };
            text.lines()
                .map(|line| {
                    ResultReceipt::from_bytes(&hex::decode(line).unwrap())
                        .unwrap()
                        .verify()
                        .unwrap()
                })
                .collect()
        }

        fn metrics(&self) -> String {
            self.telemetry.prometheus(1, 0)
        }
    }

    fn head(request_id: &str, headers: &[(&str, &str)], modes: &[i32]) -> HttpResponsePreflight {
        HttpResponsePreflight {
            context: Some(RequestContext {
                request_id: request_id.to_string(),
                sandbox_id: "sbx".to_string(),
                ..Default::default()
            }),
            target: Some(HttpRequestTarget {
                method: "POST".to_string(),
                ..Default::default()
            }),
            status_code: 200,
            headers: headers
                .iter()
                .map(|(name, value)| HttpHeader {
                    name: name.to_string(),
                    value: value.to_string(),
                })
                .collect(),
            max_payload_bytes: 262_144,
            permitted_body_modes: modes.to_vec(),
            ..Default::default()
        }
    }

    fn unit(sequence: u64, data: &[u8], end_of_stream: bool) -> HttpResponseBodyUnit {
        HttpResponseBodyUnit {
            sequence,
            payload: Some(http_response_body_unit::Payload::Data(data.to_vec())),
            end_of_stream,
        }
    }

    fn action(result: &HttpResponsePreflightResult) -> &http_response_preflight_result::Action {
        result.action.as_ref().unwrap()
    }

    fn is_skip(result: &HttpResponsePreflightResult) -> bool {
        matches!(
            action(result),
            http_response_preflight_result::Action::Skip(_)
        )
    }

    fn inspected_mode(result: &HttpResponsePreflightResult) -> i32 {
        match action(result) {
            http_response_preflight_result::Action::Inspect(inspect) => inspect.body_mode,
            _ => panic!("not an inspect result"),
        }
    }

    fn is_body_block(result: &HttpResponseBodyResult) -> bool {
        matches!(
            result.action,
            Some(http_response_body_result::Action::BlockDelivery(_))
        )
    }

    #[test]
    fn responses_to_calls_this_middleware_did_not_allow_are_skipped() {
        let fixture = Fixture::new();
        let (result, inspection) = preflight(
            &fixture.deps(),
            &head("unknown", &[("content-length", "3")], &[HEADERS, WHOLE]),
        );
        assert!(is_skip(&result) && inspection.is_none());
        let mut no_context = head("unknown", &[], &[HEADERS]);
        no_context.context = None;
        assert!(is_skip(&preflight(&fixture.deps(), &no_context).0));

        // Another sandbox's response with the same request id is unrelated.
        fixture.allow("r1", Some(1));
        let mut other = head("r1", &[("content-length", "100")], &[HEADERS, WHOLE]);
        other.context.as_mut().unwrap().sandbox_id = "sbx-other".to_string();
        assert!(is_skip(&preflight(&fixture.deps(), &other).0));
        assert!(fixture.results().is_empty());
        assert!(fixture
            .metrics()
            .contains("tenuo_openshell_results_total{outcome=\"skipped\"} 3"));
    }

    #[test]
    fn a_known_length_result_is_read_whole_hashed_and_receipted_once() {
        let fixture = Fixture::new();
        fixture.allow("r1", Some(64));
        let body = br#"{"jsonrpc":"2.0","id":7,"result":{}}"#;
        let length = body.len().to_string();
        let (result, inspection) = preflight(
            &fixture.deps(),
            &head(
                "r1",
                &[("content-length", &length)],
                &[HEADERS, WHOLE, STREAM],
            ),
        );
        assert_eq!(inspected_mode(&result), WHOLE);
        let mut inspection = inspection.unwrap();
        let body_result = super::body(&fixture.deps(), &mut inspection, &unit(1, body, true));
        assert_eq!(body_result.sequence, 1);
        assert!(!is_body_block(&body_result));
        assert!(trailers().trailer_mutations.is_empty());
        end(&fixture.deps(), inspection);

        let receipts = fixture.results();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.outcome, result_receipt::DELIVERED);
        assert_eq!(receipt.body_mode, result_receipt::MODE_WHOLE_BODY);
        assert_eq!(receipt.request_id, "7");
        assert_eq!(receipt.openshell_request_id, "r1");
        assert_eq!(receipt.tool, "read_logs");
        assert_eq!(receipt.warrant_id, "tnu_wrt_leaf");
        assert_eq!(receipt.request_receipt_hash, Some([9; 32]));
        assert_eq!(receipt.status_code, 200);
        assert_eq!(receipt.result_bytes, body.len() as u64);
        assert_eq!(
            receipt.result_sha256,
            Some(<[u8; 32]>::from(Sha256::digest(body)))
        );
        // The entry is consumed: a second response for the id is unrelated.
        assert!(is_skip(
            &preflight(
                &fixture.deps(),
                &head("r1", &[("content-length", &length)], &[HEADERS, WHOLE])
            )
            .0
        ));
    }

    #[test]
    fn a_declared_length_over_the_limit_blocks_before_the_body() {
        let fixture = Fixture::new();
        fixture.allow("r1", Some(10));
        let (result, inspection) = preflight(
            &fixture.deps(),
            &head("r1", &[("content-length", "11")], &[HEADERS, WHOLE, STREAM]),
        );
        assert!(inspection.is_none());
        assert!(matches!(
            action(&result),
            http_response_preflight_result::Action::BlockDelivery(_)
        ));
        assert_eq!(result.reason_code, reason::RESULT_TOO_LARGE);
        let receipt = &fixture.results()[0];
        assert_eq!(receipt.outcome, result_receipt::BLOCKED);
        assert_eq!(receipt.body_mode, result_receipt::MODE_HEADERS);
        assert_eq!(
            receipt.decision_code.as_deref(),
            Some(reason::RESULT_TOO_LARGE)
        );
        assert_eq!(receipt.result_bytes, 11);
        assert!(fixture
            .metrics()
            .contains("tenuo_openshell_results_total{outcome=\"blocked\"} 1"));
    }

    #[test]
    fn an_unknown_length_streams_and_blocks_once_it_passes_the_limit() {
        let fixture = Fixture::new();
        fixture.allow("r1", Some(8));
        let (result, inspection) = preflight(
            &fixture.deps(),
            &head(
                "r1",
                &[("content-type", "text/event-stream")],
                &[HEADERS, WHOLE, STREAM],
            ),
        );
        assert_eq!(inspected_mode(&result), STREAM);
        let mut inspection = inspection.unwrap();
        let deps = fixture.deps();
        assert!(!is_body_block(&super::body(
            &deps,
            &mut inspection,
            &unit(1, b"12345", false)
        )));
        let blocked = super::body(&deps, &mut inspection, &unit(2, b"6789", false));
        assert!(is_body_block(&blocked));
        assert_eq!(blocked.sequence, 2);
        assert_eq!(blocked.reason_code, reason::RESULT_TOO_LARGE);
        end(&deps, inspection);
        let receipts = fixture.results();
        assert_eq!(receipts.len(), 1, "a finished stage is not also incomplete");
        assert_eq!(receipts[0].outcome, result_receipt::BLOCKED);
        assert_eq!(receipts[0].body_mode, result_receipt::MODE_STREAM);
        assert_eq!(receipts[0].result_bytes, 9);
    }

    #[test]
    fn a_stream_within_the_limit_hashes_every_unit() {
        let fixture = Fixture::new();
        fixture.allow("r1", None);
        let (_, inspection) = preflight(
            &fixture.deps(),
            &head(
                "r1",
                &[("content-type", "text/event-stream")],
                &[HEADERS, STREAM],
            ),
        );
        let mut inspection = inspection.unwrap();
        let deps = fixture.deps();
        super::body(&deps, &mut inspection, &unit(1, b"data: a\n\n", false));
        super::body(&deps, &mut inspection, &unit(2, b"data: b\n\n", false));
        super::body(&deps, &mut inspection, &unit(3, b"", true));
        end(&deps, inspection);
        let receipt = &fixture.results()[0];
        assert_eq!(receipt.outcome, result_receipt::DELIVERED);
        assert_eq!(receipt.result_bytes, 18);
        assert_eq!(
            receipt.result_sha256,
            Some(<[u8; 32]>::from(Sha256::digest(b"data: a\n\ndata: b\n\n")))
        );
    }

    #[test]
    fn a_stream_that_ends_early_is_incomplete() {
        let fixture = Fixture::new();
        fixture.allow("r1", None);
        let (_, inspection) =
            preflight(&fixture.deps(), &head("r1", &[], &[HEADERS, WHOLE, STREAM]));
        let mut inspection = inspection.unwrap();
        super::body(
            &fixture.deps(),
            &mut inspection,
            &unit(1, b"partial", false),
        );
        end(&fixture.deps(), inspection);
        let receipt = &fixture.results()[0];
        assert_eq!(receipt.outcome, result_receipt::INCOMPLETE);
        assert_eq!(receipt.result_bytes, 7);
        assert_eq!(receipt.result_sha256, None);
    }

    #[test]
    fn headers_only_responses_skip_unless_a_limit_cannot_be_checked() {
        let fixture = Fixture::new();
        // Encoded with a known length within the limit: delivered unread.
        fixture.allow("r1", Some(100));
        let encoded = head(
            "r1",
            &[("content-encoding", "gzip"), ("content-length", "40")],
            &[HEADERS],
        );
        assert!(is_skip(&preflight(&fixture.deps(), &encoded).0));

        // No limit: an unmeasurable response is skipped.
        fixture.allow("r2", None);
        assert!(is_skip(
            &preflight(
                &fixture.deps(),
                &head("r2", &[("content-encoding", "gzip")], &[HEADERS])
            )
            .0
        ));

        // Bodyless responses have nothing to measure.
        fixture.allow("r3", Some(100));
        let mut no_content = head("r3", &[], &[HEADERS]);
        no_content.status_code = 204;
        assert!(is_skip(&preflight(&fixture.deps(), &no_content).0));

        // A limit with an unknown, uninspectable length fails closed.
        fixture.allow("r4", Some(100));
        let (result, _) = preflight(
            &fixture.deps(),
            &head("r4", &[("content-encoding", "gzip")], &[HEADERS]),
        );
        assert_eq!(result.reason_code, reason::RESULT_UNMEASURABLE);
        let receipts = fixture.results();
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].decision_code.as_deref(),
            Some(reason::RESULT_UNMEASURABLE)
        );
    }

    #[test]
    fn repeated_or_invalid_content_length_is_treated_as_unknown() {
        let mut duplicated = head(
            "r",
            &[("content-length", "3"), ("content-length", "3")],
            &[],
        );
        assert_eq!(content_length(&duplicated), None);
        duplicated.headers.pop();
        assert_eq!(content_length(&duplicated), Some(3));
        assert_eq!(
            content_length(&head("r", &[("content-length", "x")], &[])),
            None
        );
    }

    #[test]
    fn a_failed_result_receipt_does_not_change_delivery() {
        let mut fixture = Fixture::new();
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("r.jsonl");
        let receipts = ReceiptLog::open(&dir.path().join("key"), &log_path).unwrap();
        std::fs::create_dir(receipts.results_path()).unwrap();
        fixture.receipts = Some(receipts);
        fixture.allow("r1", None);
        let (_, inspection) = preflight(
            &fixture.deps(),
            &head("r1", &[("content-length", "2")], &[HEADERS, WHOLE]),
        );
        let mut inspection = inspection.unwrap();
        let result = super::body(&fixture.deps(), &mut inspection, &unit(1, b"ok", true));
        assert!(!is_body_block(&result));
        assert!(fixture
            .metrics()
            .contains("tenuo_openshell_result_receipt_failures_total 1"));
        assert!(fixture
            .metrics()
            .contains("tenuo_openshell_results_total{outcome=\"delivered\"} 1"));
    }

    #[test]
    fn limits_apply_without_a_receipt_log() {
        let mut fixture = Fixture::new();
        fixture.receipts = None;
        fixture.allow("r1", Some(1));
        let (result, _) = preflight(
            &fixture.deps(),
            &head("r1", &[("content-length", "2")], &[HEADERS, WHOLE]),
        );
        assert_eq!(result.reason_code, reason::RESULT_TOO_LARGE);
    }

    #[test]
    fn pending_calls_expire_and_are_bounded() {
        let pending = PendingResults::new(2, Duration::from_secs(10));
        let start = Instant::now();
        let value = PendingResult::default;
        assert_eq!(pending.insert_at("s", "", value(), start), 0);
        assert!(pending.is_empty());
        pending.insert_at("s", "a", value(), start);
        pending.insert_at("s", "b", value(), start);
        assert_eq!(pending.insert_at("s", "c", value(), start), 1);
        assert!(pending.take_at("s", "a", start).is_none(), "oldest evicted");
        assert!(pending.take_at("s", "b", start).is_some());
        assert!(pending.take_at("s", "b", start).is_none(), "taken once");
        let later = start + Duration::from_secs(10);
        assert!(pending.take_at("s", "c", later).is_none(), "expired");
        pending.insert_at("s", "d", value(), start);
        pending.insert_at("s", "e", value(), later);
        assert_eq!(pending.len(), 1, "expired entries are purged on insert");
        // Taken entries leave stale order positions; compaction bounds them.
        for index in 0..100 {
            let id = index.to_string();
            pending.insert_at("s", &id, value(), later);
            pending.take_at("s", &id, later);
        }
        assert!(pending.lock().order.len() <= 5);
    }
}

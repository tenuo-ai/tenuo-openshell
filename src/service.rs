//! gRPC `SupervisorMiddleware` server for the HTTP request binding, and the
//! optional `HttpResponsePreReturn` server for tool results.

use crate::auth::{AuthenticatedCaller, CallerKind};
use crate::evaluate::{self, Outcome};
use crate::otel::DecisionSpan;
use crate::policy::{self, PolicyManager, PolicySet, RequestTarget};
use crate::proto::openshell::middleware::v1::http_response_pre_return_server::HttpResponsePreReturn;
use crate::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use crate::proto::openshell::middleware::v1::{
    http_response_event, http_response_event_result, Decision, HttpHeader, HttpRequestEvaluation,
    HttpRequestResult, HttpResponseEvent, HttpResponseEventResult, MiddlewareBinding,
    MiddlewareDescribeRequest, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
};
use crate::reason;
use crate::receipt::ReceiptLog;
use crate::result::{self, PendingResult, PendingResults, ResultDeps};
use crate::telemetry::Telemetry;
use std::sync::Arc;
use std::time::SystemTime;
use tonic::{Request, Response, Status};

const MAX_PAYLOAD_BYTES: u64 = 262_144;
const CONTRACT_CAPABILITY: &str = "openshell.supervisor-middleware.contract";

pub struct MiddlewareService {
    policy: Arc<PolicyManager>,
    expected_audience: Option<String>,
    receipts: Option<Arc<ReceiptLog>>,
    telemetry: Arc<Telemetry>,
    /// Set when the `HTTP_RESPONSE` binding is advertised.
    results: Option<Arc<PendingResults>>,
}

impl MiddlewareService {
    pub fn new(policy: PolicySet) -> Self {
        Self::build(Arc::new(PolicyManager::fixed(policy)), None)
    }

    pub fn authenticated(policy: PolicySet, expected_audience: String) -> Self {
        Self::build(
            Arc::new(PolicyManager::fixed(policy)),
            Some(expected_audience),
        )
    }

    pub fn authenticated_with_manager(
        policy: Arc<PolicyManager>,
        expected_audience: String,
    ) -> Self {
        Self::build(policy, Some(expected_audience))
    }

    pub fn with_manager(policy: Arc<PolicyManager>) -> Self {
        Self::build(policy, None)
    }

    fn build(policy: Arc<PolicyManager>, expected_audience: Option<String>) -> Self {
        Self {
            policy,
            expected_audience,
            receipts: None,
            telemetry: Arc::new(Telemetry::default()),
            results: None,
        }
    }

    pub fn with_telemetry(mut self, telemetry: Arc<Telemetry>) -> Self {
        self.telemetry = telemetry;
        self
    }

    pub fn with_receipts(mut self, receipts: ReceiptLog) -> Self {
        self.receipts = Some(Arc::new(receipts));
        self
    }

    /// Advertise `HTTP_RESPONSE` / `PRE_RETURN` and evaluate the results of
    /// calls this service allows.
    pub fn with_results(mut self, pending: PendingResults) -> Self {
        self.results = Some(Arc::new(pending));
        self
    }

    #[allow(clippy::result_large_err)]
    fn require_gateway<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if self.expected_audience.is_none() {
            return Ok(());
        }
        match request.extensions().get::<AuthenticatedCaller>() {
            Some(caller) if caller.kind == CallerKind::Gateway => Ok(()),
            _ => Err(Status::permission_denied("gateway caller required")),
        }
    }

    #[allow(clippy::result_large_err)]
    fn require_supervisor<T>(&self, request: &Request<T>, sandbox_id: &str) -> Result<(), Status> {
        supervisor_matches(
            self.expected_audience.is_some(),
            request.extensions().get::<AuthenticatedCaller>(),
            sandbox_id,
        )
    }

    /// Metrics, one span, and, for an allowed tool call, the entry its
    /// response is matched against.
    fn finish_request(&self, outcome: &Outcome, request: RequestFacts<'_>) {
        self.telemetry.observe(outcome);
        let trace = self.telemetry.tracer().map(|tracer| {
            tracer.record(
                &tracer.parent_from_headers(request.headers),
                DecisionSpan {
                    name: "tenuo.authorize",
                    started: request.started,
                    sandbox_id: request.sandbox_id,
                    tool: outcome.tool.as_deref(),
                    outcome: if outcome.allow { "allow" } else { "deny" },
                    reason_code: outcome.reason_code,
                    decision_us: outcome.decision_us,
                    warrant_id: outcome.warrant_id.as_deref(),
                    jsonrpc_id: &outcome.request_id,
                    status_code: None,
                    result_bytes: None,
                },
            )
        });
        let Some(pending) = self.results.as_ref() else {
            return;
        };
        let (true, Some(tool), Some(warrant_id)) =
            (outcome.allow, &outcome.tool, &outcome.warrant_id)
        else {
            return;
        };
        let evicted = pending.insert(
            request.sandbox_id,
            request.request_id,
            PendingResult {
                jsonrpc_id: outcome.request_id.clone(),
                tool: tool.clone(),
                warrant_id: warrant_id.clone(),
                request_receipt_hash: outcome.receipt_hash,
                max_result_bytes: request.max_result_bytes,
                trace,
            },
        );
        if evicted > 0 {
            self.telemetry.result_correlation_evicted(evicted);
        }
    }
}

struct RequestFacts<'a> {
    sandbox_id: &'a str,
    request_id: &'a str,
    headers: &'a [HttpHeader],
    started: SystemTime,
    max_result_bytes: Option<u64>,
}

#[allow(clippy::result_large_err)]
fn supervisor_matches(
    authenticated: bool,
    caller: Option<&AuthenticatedCaller>,
    sandbox_id: &str,
) -> Result<(), Status> {
    if !authenticated {
        return Ok(());
    }
    match caller {
        Some(caller)
            if caller.kind == CallerKind::Supervisor
                && caller.sandbox_id.as_deref() == Some(sandbox_id)
                && !sandbox_id.is_empty() =>
        {
            Ok(())
        }
        _ => Err(Status::permission_denied(
            "supervisor credential does not match request sandbox",
        )),
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for MiddlewareService {
    async fn describe(
        &self,
        request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        if self.expected_audience.is_some()
            && request.extensions().get::<AuthenticatedCaller>().is_none()
        {
            return Err(Status::unauthenticated("authenticated caller required"));
        }
        validate_gateway_metadata(request.get_ref())?;
        let mut bindings = vec![MiddlewareBinding {
            operation: SupervisorMiddlewareOperation::HttpRequest as i32,
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            max_payload_bytes: MAX_PAYLOAD_BYTES,
            request_timeout: None,
        }];
        if self.results.is_some() {
            bindings.push(MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpResponse as i32,
                phase: SupervisorMiddlewarePhase::PreReturn as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                request_timeout: None,
            });
        }
        Ok(Response::new(MiddlewareManifest {
            name: "tenuo-openshell-middleware".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings,
            expected_audience: self.expected_audience.clone().unwrap_or_default(),
            extension: Some(extension_metadata()),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        self.require_gateway(&request)?;
        let config = request.into_inner().config.unwrap_or_default();
        let response = match policy::meta_mode(&config) {
            Ok(_) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(policy::InvalidMiddlewareConfig) => ValidateConfigResponse {
                valid: false,
                reason: "config accepts only tenuo_meta=preserve|strip".to_string(),
            },
        };
        Ok(Response::new(response))
    }

    async fn evaluate_http_request(
        &self,
        request: Request<HttpRequestEvaluation>,
    ) -> Result<Response<HttpRequestResult>, Status> {
        let started = SystemTime::now();
        let authenticated_sandbox_id = request
            .get_ref()
            .context
            .as_ref()
            .map(|context| context.sandbox_id.as_str())
            .unwrap_or("");
        self.require_supervisor(&request, authenticated_sandbox_id)?;
        let request = request.into_inner();
        let (sandbox_id, request_id) = request
            .context
            .as_ref()
            .map(|context| (context.sandbox_id.as_str(), context.request_id.as_str()))
            .unwrap_or(("", ""));
        let config = request.config.clone().unwrap_or_default();
        let policy = self.policy.snapshot();
        let outcome = match (
            request.body.len() as u64 > MAX_PAYLOAD_BYTES,
            policy::meta_mode(&config),
            request.target.as_ref(),
        ) {
            (false, Ok(meta_mode), Some(target)) => {
                let target = RequestTarget {
                    method: &target.method,
                    host: &target.host,
                    port: target.port,
                    path: &target.path,
                };
                let pre_credentials =
                    request.phase == SupervisorMiddlewarePhase::PreCredentials as i32;
                evaluate::evaluate(
                    &policy,
                    sandbox_id,
                    pre_credentials,
                    &target,
                    &request.body,
                    meta_mode,
                    self.receipts.as_deref(),
                )
                .await
            }
            _ => evaluate::deny(reason::INVALID_REQUEST),
        };
        self.finish_request(
            &outcome,
            RequestFacts {
                sandbox_id,
                request_id,
                headers: &request.headers,
                started,
                // The limit in force when the call was allowed applies to its
                // result, even if the policy reloads before the response.
                max_result_bytes: policy.max_result_bytes(sandbox_id).ok().flatten(),
            },
        );
        Ok(Response::new(http_result(outcome)))
    }

    type EvaluateWebSocketSessionStream = std::pin::Pin<
        Box<
            dyn tokio_stream::Stream<
                    Item = Result<
                        crate::proto::openshell::middleware::v1::WebSocketSessionEventResult,
                        Status,
                    >,
                > + Send,
        >,
    >;

    async fn evaluate_web_socket_session(
        &self,
        _request: Request<
            tonic::Streaming<crate::proto::openshell::middleware::v1::WebSocketSessionEvent>,
        >,
    ) -> Result<Response<Self::EvaluateWebSocketSessionStream>, Status> {
        Err(Status::unimplemented(
            "websocket sessions are not implemented",
        ))
    }
}

type ResultStream = std::pin::Pin<
    Box<dyn tokio_stream::Stream<Item = Result<HttpResponseEventResult, Status>> + Send>,
>;

#[tonic::async_trait]
impl HttpResponsePreReturn for MiddlewareService {
    type EvaluateStream = ResultStream;

    /// One stage stream: preflight, then the selected body units and
    /// trailers in lockstep, then an optional `session_end`.
    async fn evaluate(
        &self,
        request: Request<tonic::Streaming<HttpResponseEvent>>,
    ) -> Result<Response<Self::EvaluateStream>, Status> {
        let caller = request.extensions().get::<AuthenticatedCaller>().cloned();
        Ok(Response::new(
            self.result_stream(caller, request.into_inner()),
        ))
    }
}

impl MiddlewareService {
    fn result_stream<S>(&self, caller: Option<AuthenticatedCaller>, mut events: S) -> ResultStream
    where
        S: tokio_stream::Stream<Item = Result<HttpResponseEvent, Status>> + Send + Unpin + 'static,
    {
        use tokio_stream::StreamExt;
        let authenticated = self.expected_audience.is_some();
        // Without the binding nothing is pending, so every response skips.
        let pending = self
            .results
            .clone()
            .unwrap_or_else(|| Arc::new(PendingResults::new(1, std::time::Duration::ZERO)));
        let receipts = self.receipts.clone();
        let telemetry = self.telemetry.clone();
        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        tokio::spawn(async move {
            let deps = ResultDeps {
                pending: &pending,
                receipts: receipts.as_deref(),
                telemetry: &telemetry,
            };
            let mut inspection = None;
            let mut opened = false;
            while let Some(Ok(event)) = events.next().await {
                let result = match event.event {
                    Some(http_response_event::Event::Preflight(preflight)) if !opened => {
                        opened = true;
                        let sandbox_id = preflight
                            .context
                            .as_ref()
                            .map(|context| context.sandbox_id.as_str())
                            .unwrap_or("");
                        if let Err(status) =
                            supervisor_matches(authenticated, caller.as_ref(), sandbox_id)
                        {
                            let _ = sender.send(Err(status)).await;
                            break;
                        }
                        let (result, next) = result::preflight(&deps, &preflight);
                        inspection = next;
                        http_response_event_result::Result::PreflightResult(result)
                    }
                    Some(http_response_event::Event::Body(unit)) if inspection.is_some() => {
                        let current = inspection.as_mut().expect("checked above");
                        http_response_event_result::Result::BodyResult(result::body(
                            &deps, current, &unit,
                        ))
                    }
                    Some(http_response_event::Event::Trailers(_)) if inspection.is_some() => {
                        http_response_event_result::Result::TrailersResult(result::trailers())
                    }
                    Some(http_response_event::Event::SessionEnd(_)) => break,
                    _ => {
                        let _ = sender
                            .send(Err(Status::failed_precondition(
                                "unexpected response event",
                            )))
                            .await;
                        break;
                    }
                };
                let reply = HttpResponseEventResult {
                    result: Some(result),
                };
                if sender.send(Ok(reply)).await.is_err() {
                    break;
                }
            }
            if let Some(inspection) = inspection {
                result::end(&deps, inspection);
            }
        });
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(receiver))
    }
}

fn http_result(outcome: Outcome) -> HttpRequestResult {
    if outcome.allow {
        let (body, has_body) = match outcome.replacement {
            Some(body) => (body, true),
            None => (Vec::new(), false),
        };
        HttpRequestResult {
            decision: Decision::Allow as i32,
            reason: String::new(),
            body,
            has_body,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: Default::default(),
            reason_code: String::new(),
        }
    } else {
        HttpRequestResult {
            decision: Decision::Deny as i32,
            reason: String::new(),
            body: Vec::new(),
            has_body: false,
            header_mutations: Vec::new(),
            findings: Vec::new(),
            metadata: Default::default(),
            reason_code: outcome.reason_code.to_string(),
        }
    }
}

fn extension_metadata() -> crate::proto::openshell::extension::v1::PeerMetadata {
    crate::proto::openshell::extension::v1::PeerMetadata {
        protocol_version: Some(crate::proto::openshell::extension::v1::ProtocolVersion {
            major: 1,
            minor: 0,
        }),
        implementation_name: "tenuo/openshell-middleware".to_string(),
        implementation_version: env!("CARGO_PKG_VERSION").to_string(),
        supported_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
        required_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
    }
}

#[allow(clippy::result_large_err)]
fn validate_gateway_metadata(request: &MiddlewareDescribeRequest) -> Result<(), Status> {
    let gateway = request
        .gateway
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("gateway protocol metadata is required"))?;
    let version = gateway
        .protocol_version
        .as_ref()
        .ok_or_else(|| Status::failed_precondition("gateway protocol version is required"))?;
    if version.major != 1 {
        return Err(Status::failed_precondition(
            "incompatible gateway protocol major version",
        ));
    }
    if !gateway
        .supported_capabilities
        .iter()
        .any(|capability| capability == CONTRACT_CAPABILITY)
    {
        return Err(Status::failed_precondition(
            "gateway does not support the supervisor middleware contract",
        ));
    }
    if gateway
        .required_capabilities
        .iter()
        .any(|capability| capability != CONTRACT_CAPABILITY)
    {
        return Err(Status::failed_precondition(
            "gateway requires an unsupported supervisor middleware capability",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::openshell::extension::v1::{PeerMetadata, ProtocolVersion};
    use crate::proto::openshell::middleware::v1::{
        http_response_body_unit, http_response_preflight_result, HttpRequestTarget,
        HttpResponseBodyMode, HttpResponseBodyUnit, HttpResponsePreflight, HttpResponseTrailers,
        MiddlewareSessionEnd, RequestContext,
    };
    use crate::result_receipt::{ResultReceipt, DELIVERED};
    use serde_json::json;
    use std::time::UNIX_EPOCH;
    use tenuo::sdk::prelude::Call;
    use tenuo::sdk::transport::mcp_meta::encode_meta;
    use tenuo::{ConstraintSet, SigningKey, Warrant, SIGNATURE_CONTEXT};
    use tokio_stream::StreamExt;

    struct Setup {
        root: SigningKey,
        holder: SigningKey,
        dir: tempfile::TempDir,
    }

    fn setup() -> Setup {
        Setup {
            root: SigningKey::generate(),
            holder: SigningKey::generate(),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    impl Setup {
        fn policy(&self, max_result_bytes: Option<u64>) -> PolicySet {
            let mut sandbox = json!({
                "trusted_roots": [hex::encode(self.root.public_key().to_bytes())],
                "destinations": [{"host": "mcp.test", "port": 443, "path": "/mcp", "tools": ["*"]}]
            });
            if let Some(limit) = max_result_bytes {
                sandbox["max_result_bytes"] = json!(limit);
            }
            let document = json!({
                "max_warrant_lifetime_secs": 3600,
                "sandboxes": {"sbx": sandbox}
            });
            PolicySet::from_json(document.to_string().as_bytes()).unwrap()
        }

        fn service(&self, max_result_bytes: Option<u64>, results: bool) -> MiddlewareService {
            let receipts = ReceiptLog::open(
                &self.dir.path().join("key"),
                &self.dir.path().join("r.jsonl"),
            )
            .unwrap();
            let service =
                MiddlewareService::new(self.policy(max_result_bytes)).with_receipts(receipts);
            if results {
                service.with_results(PendingResults::default())
            } else {
                service
            }
        }

        /// A signed `read_logs` call, or with `tool`, an unauthorized one.
        fn call(&self, tool: &str) -> Vec<u8> {
            let warrant = Warrant::builder()
                .capability("read_logs", ConstraintSet::new())
                .holder(self.holder.public_key())
                .ttl(std::time::Duration::from_secs(300))
                .build(&self.root)
                .unwrap();
            let arguments = json!({"service": "payments"});
            let call = Call::try_from_json(tool, &arguments).unwrap();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let preimage = warrant
                .pop_preimage(call.capability(), call.pop_args(), now, 30)
                .unwrap();
            let mut message = SIGNATURE_CONTEXT.to_vec();
            message.extend(preimage);
            let signature = self.holder.sign_raw(&message);
            let meta = encode_meta(std::slice::from_ref(&warrant), &signature, &[]).unwrap();
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments, "_meta": {"tenuo": meta}}
            }))
            .unwrap()
        }

        fn authorization_lines(&self) -> Vec<Vec<u8>> {
            lines(&self.dir.path().join("r.jsonl"))
        }

        fn result_lines(&self) -> Vec<Vec<u8>> {
            lines(&self.dir.path().join("r.results.jsonl"))
        }
    }

    fn lines(path: &std::path::Path) -> Vec<Vec<u8>> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| hex::decode(line).unwrap())
            .collect()
    }

    fn context(request_id: &str, sandbox_id: &str) -> Option<RequestContext> {
        Some(RequestContext {
            request_id: request_id.to_string(),
            sandbox_id: sandbox_id.to_string(),
            ..Default::default()
        })
    }

    async fn authorize(service: &MiddlewareService, body: Vec<u8>, request_id: &str) -> bool {
        let request = HttpRequestEvaluation {
            phase: SupervisorMiddlewarePhase::PreCredentials as i32,
            context: context(request_id, "sbx"),
            target: Some(HttpRequestTarget {
                scheme: "https".to_string(),
                host: "mcp.test".to_string(),
                port: 443,
                method: "POST".to_string(),
                path: "/mcp".to_string(),
                query: String::new(),
            }),
            body,
            ..Default::default()
        };
        let result = service
            .evaluate_http_request(Request::new(request))
            .await
            .unwrap()
            .into_inner();
        result.decision == Decision::Allow as i32
    }

    fn preflight(request_id: &str, sandbox_id: &str, length: usize) -> HttpResponseEvent {
        HttpResponseEvent {
            event: Some(http_response_event::Event::Preflight(
                HttpResponsePreflight {
                    context: context(request_id, sandbox_id),
                    target: Some(HttpRequestTarget {
                        method: "POST".to_string(),
                        ..Default::default()
                    }),
                    status_code: 200,
                    headers: vec![HttpHeader {
                        name: "content-length".to_string(),
                        value: length.to_string(),
                    }],
                    max_payload_bytes: MAX_PAYLOAD_BYTES,
                    permitted_body_modes: vec![
                        HttpResponseBodyMode::HeadersOnly as i32,
                        HttpResponseBodyMode::WholeBodyBytes as i32,
                        HttpResponseBodyMode::StreamBytes as i32,
                    ],
                    ..Default::default()
                },
            )),
        }
    }

    fn body(data: &[u8]) -> HttpResponseEvent {
        HttpResponseEvent {
            event: Some(http_response_event::Event::Body(HttpResponseBodyUnit {
                sequence: 1,
                payload: Some(http_response_body_unit::Payload::Data(data.to_vec())),
                end_of_stream: true,
            })),
        }
    }

    fn trailers() -> HttpResponseEvent {
        HttpResponseEvent {
            event: Some(http_response_event::Event::Trailers(
                HttpResponseTrailers::default(),
            )),
        }
    }

    fn session_end() -> HttpResponseEvent {
        HttpResponseEvent {
            event: Some(http_response_event::Event::SessionEnd(
                MiddlewareSessionEnd::default(),
            )),
        }
    }

    async fn run(
        service: &MiddlewareService,
        caller: Option<AuthenticatedCaller>,
        events: Vec<HttpResponseEvent>,
    ) -> Vec<Result<HttpResponseEventResult, Status>> {
        let events = tokio_stream::iter(events.into_iter().map(Ok));
        service.result_stream(caller, events).collect().await
    }

    fn preflight_action(
        result: &Result<HttpResponseEventResult, Status>,
    ) -> &http_response_preflight_result::Action {
        match result.as_ref().unwrap().result.as_ref().unwrap() {
            http_response_event_result::Result::PreflightResult(result) => {
                result.action.as_ref().unwrap()
            }
            _ => panic!("not a preflight result"),
        }
    }

    fn gateway() -> MiddlewareDescribeRequest {
        MiddlewareDescribeRequest {
            gateway: Some(PeerMetadata {
                protocol_version: Some(ProtocolVersion { major: 1, minor: 0 }),
                implementation_name: "openshell".to_string(),
                implementation_version: "0.1.2".to_string(),
                supported_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
                required_capabilities: vec![CONTRACT_CAPABILITY.to_string()],
            }),
        }
    }

    #[tokio::test]
    async fn the_response_binding_is_advertised_only_when_enabled() {
        let setup = setup();
        let pairs = |service: MiddlewareService| async move {
            service
                .describe(Request::new(gateway()))
                .await
                .unwrap()
                .into_inner()
                .bindings
                .iter()
                .map(|binding| (binding.operation, binding.phase, binding.max_payload_bytes))
                .collect::<Vec<_>>()
        };
        let request = (
            SupervisorMiddlewareOperation::HttpRequest as i32,
            SupervisorMiddlewarePhase::PreCredentials as i32,
            MAX_PAYLOAD_BYTES,
        );
        let response = (
            SupervisorMiddlewareOperation::HttpResponse as i32,
            SupervisorMiddlewarePhase::PreReturn as i32,
            MAX_PAYLOAD_BYTES,
        );
        assert_eq!(pairs(setup.service(None, false)).await, [request]);
        assert_eq!(pairs(setup.service(None, true)).await, [request, response]);
    }

    #[tokio::test]
    async fn an_allowed_calls_result_is_receipted_and_linked_to_its_authorization() {
        let setup = setup();
        let service = setup.service(None, true);
        assert!(authorize(&service, setup.call("read_logs"), "exchange-1").await);
        let result = br#"{"jsonrpc":"2.0","id":7,"result":{"content":[]}}"#;
        let replies = run(
            &service,
            None,
            vec![
                preflight("exchange-1", "sbx", result.len()),
                body(result),
                trailers(),
                session_end(),
            ],
        )
        .await;
        assert_eq!(
            replies.len(),
            3,
            "preflight, body, and trailers each get one result"
        );
        assert!(matches!(
            preflight_action(&replies[0]),
            http_response_preflight_result::Action::Inspect(_)
        ));
        let authorization = setup.authorization_lines();
        let results = setup.result_lines();
        assert_eq!((authorization.len(), results.len()), (1, 1));
        let payload = ResultReceipt::from_bytes(&results[0])
            .unwrap()
            .verify()
            .unwrap();
        assert_eq!(payload.outcome, DELIVERED);
        assert_eq!(payload.request_id, "7");
        assert_eq!(payload.tool, "read_logs");
        assert!(payload.warrant_id.starts_with("tnu_wrt_"));
        assert_eq!(
            payload.request_receipt_hash,
            Some(crate::result_receipt::line_digest(&authorization[0]))
        );
    }

    #[tokio::test]
    async fn the_limit_in_the_policy_blocks_a_large_result() {
        let setup = setup();
        let service = setup.service(Some(16), true);
        assert!(authorize(&service, setup.call("read_logs"), "exchange-1").await);
        let replies = run(&service, None, vec![preflight("exchange-1", "sbx", 17)]).await;
        let HttpResponseEventResult {
            result: Some(http_response_event_result::Result::PreflightResult(result)),
        } = replies[0].as_ref().unwrap()
        else {
            panic!("not a preflight result");
        };
        assert!(matches!(
            result.action,
            Some(http_response_preflight_result::Action::BlockDelivery(_))
        ));
        assert_eq!(result.reason_code, reason::RESULT_TOO_LARGE);
    }

    #[tokio::test]
    async fn denied_calls_and_a_disabled_binding_are_skipped() {
        let setup = setup();
        let service = setup.service(Some(1), true);
        assert!(!authorize(&service, setup.call("restart_service"), "denied").await);
        let replies = run(&service, None, vec![preflight("denied", "sbx", 100)]).await;
        assert!(matches!(
            preflight_action(&replies[0]),
            http_response_preflight_result::Action::Skip(_)
        ));

        let disabled = setup.service(Some(1), false);
        assert!(authorize(&disabled, setup.call("read_logs"), "allowed").await);
        let replies = run(&disabled, None, vec![preflight("allowed", "sbx", 100)]).await;
        assert!(matches!(
            preflight_action(&replies[0]),
            http_response_preflight_result::Action::Skip(_)
        ));
        assert!(setup.result_lines().is_empty());
    }

    #[tokio::test]
    async fn a_supervisor_cannot_open_another_sandboxs_response_stream() {
        let setup = setup();
        let service = MiddlewareService::authenticated(setup.policy(None), "aud".to_string())
            .with_results(PendingResults::default());
        let caller = AuthenticatedCaller {
            kind: CallerKind::Supervisor,
            sandbox_id: Some("sbx-a".to_string()),
            jti: String::new(),
        };
        let replies = run(
            &service,
            Some(caller.clone()),
            vec![preflight("r", "sbx-b", 1)],
        )
        .await;
        assert_eq!(replies.len(), 1);
        assert_eq!(
            replies[0].as_ref().unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        let replies = run(&service, None, vec![preflight("r", "sbx-a", 1)]).await;
        assert!(replies[0].is_err());
        let replies = run(&service, Some(caller), vec![preflight("r", "sbx-a", 1)]).await;
        assert!(matches!(
            preflight_action(&replies[0]),
            http_response_preflight_result::Action::Skip(_)
        ));
    }

    #[tokio::test]
    async fn out_of_order_events_end_the_stream() {
        let setup = setup();
        let service = setup.service(None, true);
        let replies = run(&service, None, vec![body(b"x")]).await;
        assert_eq!(
            replies[0].as_ref().unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        let replies = run(
            &service,
            None,
            vec![preflight("r", "sbx", 1), preflight("r", "sbx", 1)],
        )
        .await;
        assert_eq!(replies.len(), 2);
        assert!(replies[1].is_err());
    }
}

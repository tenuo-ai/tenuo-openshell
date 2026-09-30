//! gRPC `SupervisorMiddleware` server for one HTTP binding.

use crate::auth::{AuthenticatedCaller, CallerKind};
use crate::evaluate::{self, Outcome};
use crate::policy::{self, PolicySet};
use crate::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use crate::proto::openshell::middleware::v1::{
    Decision, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    MiddlewareDescribeRequest, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
};
use crate::reason;
use crate::receipt::ReceiptLog;
use std::sync::Arc;
use tonic::{Request, Response, Status};

const MAX_PAYLOAD_BYTES: u64 = 262_144;
const CONTRACT_CAPABILITY: &str = "openshell.supervisor-middleware.contract";

pub struct MiddlewareService {
    policy: Arc<PolicySet>,
    expected_audience: Option<String>,
    receipts: Option<Arc<ReceiptLog>>,
}

impl MiddlewareService {
    pub fn new(policy: PolicySet) -> Self {
        Self {
            policy: Arc::new(policy),
            expected_audience: None,
            receipts: None,
        }
    }

    pub fn authenticated(policy: PolicySet, expected_audience: String) -> Self {
        Self {
            policy: Arc::new(policy),
            expected_audience: Some(expected_audience),
            receipts: None,
        }
    }

    pub fn with_receipts(mut self, receipts: ReceiptLog) -> Self {
        self.receipts = Some(Arc::new(receipts));
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
        if self.expected_audience.is_none() {
            return Ok(());
        }
        match request.extensions().get::<AuthenticatedCaller>() {
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
        Ok(Response::new(MiddlewareManifest {
            name: "tenuo-openshell-middleware".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                request_timeout: None,
            }],
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
        let authenticated_sandbox_id = request
            .get_ref()
            .context
            .as_ref()
            .map(|context| context.sandbox_id.as_str())
            .unwrap_or("");
        self.require_supervisor(&request, authenticated_sandbox_id)?;
        let request = request.into_inner();
        if request.body.len() as u64 > MAX_PAYLOAD_BYTES {
            return Ok(Response::new(http_result(evaluate::Outcome {
                allow: false,
                reason_code: reason::INVALID_REQUEST,
                replacement: None,
                request_id: String::new(),
                verify_us: 0,
            })));
        }
        let config = request.config.unwrap_or_default();
        let meta_mode = match policy::meta_mode(&config) {
            Ok(mode) => mode,
            Err(policy::InvalidMiddlewareConfig) => {
                return Ok(Response::new(http_result(evaluate::Outcome {
                    allow: false,
                    reason_code: reason::INVALID_REQUEST,
                    replacement: None,
                    request_id: String::new(),
                    verify_us: 0,
                })));
            }
        };
        let sandbox_id = request
            .context
            .as_ref()
            .map(|context| context.sandbox_id.as_str())
            .unwrap_or("");
        let pre_credentials = request.phase == SupervisorMiddlewarePhase::PreCredentials as i32;
        let outcome = evaluate::evaluate(
            &self.policy,
            sandbox_id,
            pre_credentials,
            &request.body,
            meta_mode,
            self.receipts.as_deref(),
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

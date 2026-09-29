//! gRPC `SupervisorMiddleware` server for one HTTP binding.

use crate::evaluate::{self, Outcome};
use crate::policy::{self, PolicySet};
use crate::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddleware;
use crate::proto::openshell::middleware::v1::{
    Decision, HttpRequestEvaluation, HttpRequestResult, MiddlewareBinding,
    MiddlewareDescribeRequest, MiddlewareManifest, SupervisorMiddlewareOperation,
    SupervisorMiddlewarePhase, ValidateConfigRequest, ValidateConfigResponse,
};
use crate::reason;
use std::sync::Arc;
use tonic::{Request, Response, Status};

const MAX_PAYLOAD_BYTES: u64 = 262_144;

pub struct MiddlewareService {
    policy: Arc<PolicySet>,
}

impl MiddlewareService {
    pub fn new(policy: PolicySet) -> Self {
        Self {
            policy: Arc::new(policy),
        }
    }
}

#[tonic::async_trait]
impl SupervisorMiddleware for MiddlewareService {
    async fn describe(
        &self,
        _request: Request<MiddlewareDescribeRequest>,
    ) -> Result<Response<MiddlewareManifest>, Status> {
        Ok(Response::new(MiddlewareManifest {
            name: "tenuo-openshell-middleware".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            bindings: vec![MiddlewareBinding {
                operation: SupervisorMiddlewareOperation::HttpRequest as i32,
                phase: SupervisorMiddlewarePhase::PreCredentials as i32,
                max_payload_bytes: MAX_PAYLOAD_BYTES,
                request_timeout: None,
            }],
            expected_audience: String::new(),
            extension: Some(extension_metadata()),
        }))
    }

    async fn validate_config(
        &self,
        request: Request<ValidateConfigRequest>,
    ) -> Result<Response<ValidateConfigResponse>, Status> {
        let config = request.into_inner().config.unwrap_or_default();
        let response = match policy::meta_mode(&config) {
            Ok(_) => ValidateConfigResponse {
                valid: true,
                reason: String::new(),
            },
            Err(()) => ValidateConfigResponse {
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
        let request = request.into_inner();
        if request.body.len() as u64 > MAX_PAYLOAD_BYTES {
            return Ok(Response::new(http_result(evaluate::Outcome {
                allow: false,
                reason_code: reason::INVALID_REQUEST,
                replacement: None,
            })));
        }
        let config = request.config.unwrap_or_default();
        let meta_mode = match policy::meta_mode(&config) {
            Ok(mode) => mode,
            Err(()) => {
                return Ok(Response::new(http_result(evaluate::Outcome {
                    allow: false,
                    reason_code: reason::INVALID_REQUEST,
                    replacement: None,
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
        supported_capabilities: Vec::new(),
        required_capabilities: Vec::new(),
    }
}

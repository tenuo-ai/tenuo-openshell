//! OpenShell supervisor middleware listener.

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use tenuo_openshell_middleware::auth::ExtensionJwtVerifier;
use tenuo_openshell_middleware::policy::{PolicyManager, PolicySet};
use tenuo_openshell_middleware::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use tenuo_openshell_middleware::receipt::ReceiptLog;
use tenuo_openshell_middleware::replay::RedisReplayStore;
use tenuo_openshell_middleware::service::MiddlewareService;
use tenuo_openshell_middleware::telemetry::Telemetry;
use tokio::net::TcpListener;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const DEFAULT_AUDIENCE: &str = "urn:openshell:extension:middleware:tenuo/authorization";

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Tenuo sandbox trust policy.
    #[arg(long)]
    policy: PathBuf,

    /// Listener address.
    #[arg(long, default_value = "127.0.0.1:50051")]
    listen: SocketAddr,

    /// Disable TLS and caller authentication. Local development only.
    #[arg(long)]
    insecure_dev: bool,

    /// PEM certificate presented by this middleware service.
    #[arg(long)]
    tls_cert: Option<PathBuf>,

    /// PEM private key for --tls-cert.
    #[arg(long)]
    tls_key: Option<PathBuf>,

    /// Operator-provisioned OpenShell gateway Ed25519 public key PEM.
    #[arg(long)]
    openshell_jwt_public_key: Option<PathBuf>,

    /// Expected OpenShell gateway id; JWT issuer is openshell-gateway:<id>.
    #[arg(long)]
    openshell_gateway_id: Option<String>,

    /// Exact audience configured on the OpenShell middleware registration.
    #[arg(long, default_value = DEFAULT_AUDIENCE)]
    audience: String,

    /// Optional exact JWT kid expected from the OpenShell gateway.
    #[arg(long)]
    openshell_jwt_key_id: Option<String>,

    /// 32-byte Ed25519 key that signs authorization receipts. Created mode 0600 when missing.
    #[arg(long)]
    receipt_key: Option<PathBuf>,

    /// Hex receipt log. A write failure does not change the authorization decision.
    #[arg(long)]
    receipt_log: Option<PathBuf>,

    /// Deny allowed operations when their signed receipt cannot be persisted.
    #[arg(long)]
    require_receipts: bool,

    /// Redis URL for durable, cross-replica approval replay protection.
    #[arg(long, env = "TENUO_REPLAY_REDIS_URL")]
    replay_redis_url: Option<String>,

    /// Deployment-specific Redis key prefix for replay isolation.
    #[arg(long, default_value = "tenuo:openshell:approval")]
    replay_key_prefix: String,

    /// Explicitly accept process-local replay state. Development and demos only.
    #[arg(long)]
    allow_in_memory_replay: bool,

    /// Credential-free health and Prometheus listener.
    #[arg(long, default_value = "127.0.0.1:9090")]
    admin_listen: SocketAddr,

    /// Poll interval for atomic policy reloads.
    #[arg(long, default_value_t = 5)]
    policy_reload_secs: u64,

    /// Readiness fails after the policy provider cannot be read for this long.
    #[arg(long, default_value_t = 30)]
    policy_max_stale_secs: u64,
}

struct ProductionSecurity {
    identity: Identity,
    verifier: ExtensionJwtVerifier,
}

#[derive(Clone)]
struct OpenShellAuthInterceptor {
    verifier: ExtensionJwtVerifier,
}

impl tonic::service::Interceptor for OpenShellAuthInterceptor {
    #[allow(clippy::result_large_err)]
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let caller = self.verifier.verify_metadata(request.metadata())?;
        request.extensions_mut().insert(caller);
        Ok(request)
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let policy_document = match std::fs::read(&args.policy) {
        Ok(document) => document,
        Err(error) => return usage_error(format!("policy load failed: {error}")),
    };
    let mut policy = match PolicySet::from_json(&policy_document) {
        Ok(policy) => policy,
        Err(error) => return usage_error(format!("policy load failed: {error}")),
    };
    let security = match production_security(&args) {
        Ok(security) => security,
        Err(error) => return usage_error(error),
    };
    match args.replay_redis_url.as_deref() {
        Some(url) => {
            let store = match RedisReplayStore::connect(url, &args.replay_key_prefix).await {
                Ok(store) => store,
                Err(_) => return usage_error("Redis replay store is unavailable".to_string()),
            };
            policy = policy.with_replay_store(std::sync::Arc::new(store));
        }
        None if security.is_some() && !args.allow_in_memory_replay => {
            return usage_error(
                "the production profile requires --replay-redis-url; use --allow-in-memory-replay only for a single-instance evaluation".to_string(),
            );
        }
        None => {}
    }
    let policy = std::sync::Arc::new(PolicyManager::new(
        args.policy.clone(),
        policy,
        policy_document,
    ));
    let telemetry = std::sync::Arc::new(Telemetry::default());
    let admin_listener = match TcpListener::bind(args.admin_listen).await {
        Ok(listener) => listener,
        Err(error) => {
            return usage_error(format!("admin bind {} failed: {error}", args.admin_listen));
        }
    };
    tokio::spawn(policy.clone().run(std::time::Duration::from_secs(
        args.policy_reload_secs.max(1),
    )));
    let admin_policy = policy.clone();
    let admin_telemetry = telemetry.clone();
    let admin_max_stale = std::time::Duration::from_secs(args.policy_max_stale_secs.max(1));
    tokio::spawn(async move {
        if let Err(error) = tenuo_openshell_middleware::admin::serve(
            admin_listener,
            admin_policy,
            admin_telemetry,
            admin_max_stale,
        )
        .await
        {
            eprintln!("{error}");
        }
    });
    let receipts = match receipt_log(&args, security.is_some() && !args.allow_in_memory_replay) {
        Ok(receipts) => receipts,
        Err(error) => return usage_error(error),
    };
    let listener = match TcpListener::bind(args.listen).await {
        Ok(listener) => listener,
        Err(error) => return usage_error(format!("bind {} failed: {error}", args.listen)),
    };
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let result = match security {
        None => {
            eprintln!(
                "development-only: accepting unauthenticated middleware calls on {}",
                args.listen
            );
            let service = SupervisorMiddlewareServer::new(install_receipts(
                MiddlewareService::with_manager(policy).with_telemetry(telemetry),
                receipts,
            ));
            Server::builder()
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, shutdown_signal())
                .await
        }
        Some(security) => {
            let audience = security.verifier.audience().to_string();
            let service = install_receipts(
                MiddlewareService::authenticated_with_manager(policy, audience)
                    .with_telemetry(telemetry),
                receipts,
            );
            let interceptor = OpenShellAuthInterceptor {
                verifier: security.verifier,
            };
            let service = SupervisorMiddlewareServer::with_interceptor(service, interceptor);
            eprintln!("authenticated TLS middleware listening on {}", args.listen);
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(security.identity))
                .expect("validated TLS identity")
                .add_service(service)
                .serve_with_incoming_shutdown(incoming, shutdown_signal())
                .await
        }
    };

    if let Err(error) = result {
        eprintln!("server stopped: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn receipt_log(args: &Args, require_existing_key: bool) -> Result<Option<ReceiptLog>, String> {
    let log = match (&args.receipt_key, &args.receipt_log) {
        (None, None) if args.require_receipts => {
            return Err("--require-receipts needs --receipt-key and --receipt-log".to_string());
        }
        (None, None) => None,
        (Some(key), Some(log)) if require_existing_key => {
            Some(ReceiptLog::open_existing(key, log)?)
        }
        (Some(key), Some(log)) => Some(ReceiptLog::open(key, log)?),
        _ => return Err("--receipt-key and --receipt-log must be set together".to_string()),
    };
    Ok(log.map(|log| {
        if args.require_receipts {
            log.require_delivery()
        } else {
            log
        }
    }))
}

async fn shutdown_signal() {
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("failed to install shutdown signal: {error}");
    }
}

fn install_receipts(service: MiddlewareService, receipts: Option<ReceiptLog>) -> MiddlewareService {
    match receipts {
        Some(receipts) => service.with_receipts(receipts),
        None => service,
    }
}

fn production_security(args: &Args) -> Result<Option<ProductionSecurity>, String> {
    let configured = args.tls_cert.is_some()
        || args.tls_key.is_some()
        || args.openshell_jwt_public_key.is_some()
        || args.openshell_gateway_id.is_some()
        || args.openshell_jwt_key_id.is_some();
    if args.insecure_dev {
        if configured {
            return Err(
                "--insecure-dev cannot be combined with production TLS or JWT options".to_string(),
            );
        }
        return Ok(None);
    }

    let cert_path = args
        .tls_cert
        .as_deref()
        .ok_or_else(|| "production mode requires --tls-cert".to_string())?;
    let key_path = args
        .tls_key
        .as_deref()
        .ok_or_else(|| "production mode requires --tls-key".to_string())?;
    let jwt_key_path = args
        .openshell_jwt_public_key
        .as_deref()
        .ok_or_else(|| "production mode requires --openshell-jwt-public-key".to_string())?;
    let gateway_id = args
        .openshell_gateway_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "production mode requires --openshell-gateway-id".to_string())?;
    if args.audience.is_empty() {
        return Err("production mode requires a non-empty --audience".to_string());
    }

    let cert = std::fs::read(cert_path)
        .map_err(|error| format!("read TLS certificate {}: {error}", cert_path.display()))?;
    let key = std::fs::read(key_path)
        .map_err(|error| format!("read TLS private key {}: {error}", key_path.display()))?;
    let verifier = ExtensionJwtVerifier::from_pem_file(
        jwt_key_path,
        gateway_id,
        &args.audience,
        args.openshell_jwt_key_id.clone(),
    )?;
    Ok(Some(ProductionSecurity {
        identity: Identity::from_pem(cert, key),
        verifier,
    }))
}

fn usage_error(message: String) -> ExitCode {
    eprintln!("{message}");
    ExitCode::from(2)
}

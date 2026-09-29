//! OpenShell supervisor middleware listener.

use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use tenuo_openshell_middleware::auth::ExtensionJwtVerifier;
use tenuo_openshell_middleware::policy::PolicySet;
use tenuo_openshell_middleware::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use tenuo_openshell_middleware::service::MiddlewareService;
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
}

struct ProductionSecurity {
    identity: Identity,
    verifier: ExtensionJwtVerifier,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    let policy = match PolicySet::load(&args.policy) {
        Ok(policy) => policy,
        Err(error) => return usage_error(format!("policy load failed: {error}")),
    };
    let security = match production_security(&args) {
        Ok(security) => security,
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
            let service = SupervisorMiddlewareServer::new(MiddlewareService::new(policy));
            Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
        }
        Some(security) => {
            let audience = security.verifier.audience().to_string();
            let service = MiddlewareService::authenticated(policy, audience);
            let verifier = security.verifier;
            let service = SupervisorMiddlewareServer::with_interceptor(
                service,
                move |mut request: tonic::Request<()>| {
                    let caller = verifier.verify_metadata(request.metadata())?;
                    request.extensions_mut().insert(caller);
                    Ok(request)
                },
            );
            eprintln!("authenticated TLS middleware listening on {}", args.listen);
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(security.identity))
                .expect("validated TLS identity")
                .add_service(service)
                .serve_with_incoming(incoming)
                .await
        }
    };

    if let Err(error) = result {
        eprintln!("server stopped: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
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

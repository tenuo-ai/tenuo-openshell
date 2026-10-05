//! OpenShell supervisor middleware listener and offline receipt tools.

use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use tenuo_openshell_middleware::auth::ExtensionJwtVerifier;
use tenuo_openshell_middleware::policy::{
    policy_signature_path, verify_policy_document, PolicyManager, PolicySet,
};
use tenuo_openshell_middleware::proto::openshell::middleware::v1::http_response_pre_return_server::HttpResponsePreReturnServer;
use tenuo_openshell_middleware::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use tenuo_openshell_middleware::receipt::ReceiptLog;
use tenuo_openshell_middleware::replay::{require_confidential_replay_url, RedisReplayStore};
use tenuo_openshell_middleware::result::PendingResults;
use tenuo_openshell_middleware::service::MiddlewareService;
use tenuo_openshell_middleware::telemetry::Telemetry;
use tokio::net::TcpListener;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Identity, Server, ServerTlsConfig};

const DEFAULT_AUDIENCE: &str = "urn:openshell:extension:middleware:tenuo/authorization";

#[derive(Debug, Parser)]
#[command(
    version,
    about,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    serve: Args,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Work with signed receipt logs offline.
    Receipts {
        #[command(subcommand)]
        command: ReceiptsCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ReceiptsCommand {
    /// Verify a receipt log and print one JSON object per receipt.
    ///
    /// Nothing is printed unless every signature and chain link verifies.
    /// Exits 1 when verification fails.
    Export {
        /// Authorization log, or its `.results.jsonl` result log.
        #[arg(long)]
        log: PathBuf,

        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,

        /// Receipt public key, as 64 hex characters or a `.pub` file. Every
        /// receipt must be signed by it.
        #[arg(long)]
        verify_with: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExportFormat {
    /// One JSON object per line.
    Json,
}

#[derive(Debug, clap::Args)]
struct Args {
    /// Tenuo sandbox trust policy.
    #[arg(long, required = true)]
    policy: Option<PathBuf>,

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

    /// Hex receipt log. Best-effort write failures do not change the decision.
    #[arg(long)]
    receipt_log: Option<PathBuf>,

    /// Deny allowed operations when their signed receipt cannot be persisted.
    /// Result receipts stay best-effort.
    #[arg(long)]
    require_receipts: bool,

    /// Advertise HTTP_RESPONSE / PRE_RETURN: receipt the results of allowed
    /// tool calls and enforce sandbox max_result_bytes.
    #[arg(long, env = "TENUO_EVALUATE_RESULTS")]
    evaluate_results: bool,

    /// Redis URL for durable, cross-replica approval replay protection.
    #[arg(long, env = "TENUO_REPLAY_REDIS_URL")]
    replay_redis_url: Option<String>,

    /// Comma-separated Redis Cluster bootstrap URLs. Mutually exclusive with --replay-redis-url.
    #[arg(long, env = "TENUO_REPLAY_REDIS_CLUSTER_URLS", value_delimiter = ',')]
    replay_redis_cluster_urls: Vec<String>,

    /// Deployment-specific Redis key prefix for replay isolation.
    #[arg(long, default_value = "tenuo:openshell:approval")]
    replay_key_prefix: String,

    /// Explicitly accept process-local replay state. Development and demos only.
    #[arg(long)]
    allow_in_memory_replay: bool,

    /// Explicitly accept a replay Redis URL that is not `rediss://` with a
    /// password. A plaintext or unauthenticated store can be rewritten by
    /// anyone on its network, which defeats single-use proofs and approvals.
    #[arg(long)]
    allow_plaintext_replay: bool,

    /// Public key that must sign the policy file. Production requires it.
    /// The file is 64 hex characters, or a path to that text.
    #[arg(long, env = "TENUO_POLICY_SIGNING_KEY")]
    policy_signing_key: Option<String>,

    /// Explicitly run production without a signed policy file.
    #[arg(long)]
    allow_unsigned_policy: bool,

    /// Explicitly allow `approval_replay_protection: false`.
    #[arg(long)]
    allow_reusable_approvals: bool,

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
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Receipts {
            command:
                ReceiptsCommand::Export {
                    log,
                    format: ExportFormat::Json,
                    verify_with,
                },
        }) => export_receipts(&log, verify_with.as_deref()),
        None => serve(cli.serve).await,
    }
}

fn export_receipts(log: &std::path::Path, verify_with: Option<&str>) -> ExitCode {
    let key = match verify_with
        .map(tenuo_openshell_middleware::export::load_public_key)
        .transpose()
    {
        Ok(key) => key,
        Err(error) => return usage_error(error),
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    match tenuo_openshell_middleware::export::export(log, key.as_ref(), &mut out) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("receipt log does not verify: {error}");
            ExitCode::from(1)
        }
    }
}

async fn serve(args: Args) -> ExitCode {
    let Some(policy_path) = args.policy.clone() else {
        return usage_error("--policy is required".to_string());
    };
    let policy_document = match std::fs::read(&policy_path) {
        Ok(document) => document,
        Err(error) => return usage_error(format!("policy load failed: {error}")),
    };
    let mut policy = match PolicySet::from_json(&policy_document) {
        Ok(policy) => policy,
        Err(error) => return usage_error(format!("policy load failed: {error}")),
    };
    if policy.limits_results() && !args.evaluate_results {
        return usage_error(
            "the policy sets max_result_bytes, which is enforced only with --evaluate-results"
                .to_string(),
        );
    }
    let security = match production_security(&args) {
        Ok(security) => security,
        Err(error) => return usage_error(error),
    };
    if args.replay_redis_url.is_some() && !args.replay_redis_cluster_urls.is_empty() {
        return usage_error(
            "--replay-redis-url and --replay-redis-cluster-urls are mutually exclusive".to_string(),
        );
    }
    match (
        args.replay_redis_url.as_deref(),
        args.replay_redis_cluster_urls.as_slice(),
    ) {
        (Some(url), []) => {
            if let Err(error) =
                require_replay_transport(security.is_some(), args.allow_plaintext_replay, [url])
            {
                return usage_error(error);
            }
            let store = match RedisReplayStore::connect(url, &args.replay_key_prefix).await {
                Ok(store) => store,
                Err(_) => return usage_error("Redis replay store is unavailable".to_string()),
            };
            policy = policy.with_replay_store(Arc::new(store));
        }
        (None, []) if security.is_some() && !args.allow_in_memory_replay => {
            return usage_error(
                "the production profile requires --replay-redis-url or --replay-redis-cluster-urls; use --allow-in-memory-replay only for a single-instance evaluation".to_string(),
            );
        }
        (None, []) => {}
        (None, urls) => {
            if let Err(error) = require_replay_transport(
                security.is_some(),
                args.allow_plaintext_replay,
                urls.iter().map(String::as_str),
            ) {
                return usage_error(error);
            }
            let store = match RedisReplayStore::connect_cluster(urls, &args.replay_key_prefix).await
            {
                Ok(store) => store,
                Err(_) => {
                    return usage_error("Redis Cluster replay store is unavailable".to_string());
                }
            };
            policy = policy.with_replay_store(Arc::new(store));
        }
        (Some(_), _) => unreachable!("conflicting replay options were rejected"),
    }
    if security.is_some() && policy.reusable_approvals() && !args.allow_reusable_approvals {
        return usage_error(
            "production refuses approval_replay_protection set to false; pass --allow-reusable-approvals to keep approvals reusable until they expire"
                .to_string(),
        );
    }
    if args.allow_unsigned_policy && args.policy_signing_key.is_some() {
        return usage_error(
            "--allow-unsigned-policy cannot be combined with --policy-signing-key".to_string(),
        );
    }
    let signing_key = match args.policy_signing_key.as_deref() {
        Some(value) => match load_policy_key(value) {
            Ok(key) => Some(key),
            Err(error) => return usage_error(error),
        },
        None if security.is_some() && !args.allow_unsigned_policy => {
            return usage_error(
                "production requires --policy-signing-key, or --allow-unsigned-policy".to_string(),
            );
        }
        None => None,
    };
    let signature_path = policy_signature_path(&policy_path);
    if let Some(key) = &signing_key {
        let signature = match std::fs::read(&signature_path) {
            Ok(bytes) => bytes,
            Err(error) => {
                return usage_error(format!(
                    "policy signature {}: {error}",
                    signature_path.display()
                ));
            }
        };
        if verify_policy_document(&policy_document, &signature, key).is_err() {
            return usage_error("policy signature does not match --policy-signing-key".to_string());
        }
    }
    let mut manager = PolicyManager::new(policy_path, policy, policy_document);
    if let Some(key) = signing_key {
        manager = manager.requiring_signature(key, signature_path);
    }
    let policy = Arc::new(manager);
    // Export is off, and nothing is sent, unless an OTLP endpoint is set.
    let (telemetry, otel_guard) = match tenuo_openshell_middleware::otel::from_env() {
        Ok(Some((tracer, guard))) => (Telemetry::default().with_tracer(tracer), Some(guard)),
        Ok(None) => (Telemetry::default(), None),
        Err(error) => return usage_error(error),
    };
    let telemetry = Arc::new(telemetry);
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
            let service = Arc::new(configure(
                MiddlewareService::with_manager(policy).with_telemetry(telemetry),
                receipts,
                args.evaluate_results,
            ));
            Server::builder()
                .add_service(SupervisorMiddlewareServer::from_arc(service.clone()))
                .add_service(HttpResponsePreReturnServer::from_arc(service))
                .serve_with_incoming_shutdown(incoming, shutdown_signal())
                .await
        }
        Some(security) => {
            let audience = security.verifier.audience().to_string();
            let service = Arc::new(configure(
                MiddlewareService::authenticated_with_manager(policy, audience)
                    .with_telemetry(telemetry),
                receipts,
                args.evaluate_results,
            ));
            let interceptor = OpenShellAuthInterceptor {
                verifier: security.verifier,
            };
            eprintln!("authenticated TLS middleware listening on {}", args.listen);
            Server::builder()
                .tls_config(ServerTlsConfig::new().identity(security.identity))
                .expect("validated TLS identity")
                .add_service(InterceptedService::new(
                    SupervisorMiddlewareServer::from_arc(service.clone()),
                    interceptor.clone(),
                ))
                .add_service(InterceptedService::new(
                    HttpResponsePreReturnServer::from_arc(service),
                    interceptor,
                ))
                .serve_with_incoming_shutdown(incoming, shutdown_signal())
                .await
        }
    };
    // Shutdown flushes pending spans and waits on the export task.
    if let Some(guard) = otel_guard {
        let _ = tokio::task::spawn_blocking(move || drop(guard)).await;
    }

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

fn configure(
    service: MiddlewareService,
    receipts: Option<ReceiptLog>,
    evaluate_results: bool,
) -> MiddlewareService {
    let service = match receipts {
        Some(receipts) => service.with_receipts(receipts),
        None => service,
    };
    if evaluate_results {
        service.with_results(PendingResults::default())
    } else {
        service
    }
}

fn load_policy_key(value: &str) -> Result<tenuo::PublicKey, String> {
    let text = match std::fs::read_to_string(value) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => value.to_string(),
        Err(error) => return Err(format!("policy signing key: {error}")),
    };
    let bytes = hex::decode(text.trim()).map_err(|_| "policy signing key must be 32 bytes")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "policy signing key must be 32 bytes")?;
    tenuo::PublicKey::from_bytes(&bytes).map_err(|error| error.to_string())
}

fn require_replay_transport<'a>(
    production: bool,
    allow_plaintext: bool,
    urls: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    if !production || allow_plaintext {
        return Ok(());
    }
    for url in urls {
        require_confidential_replay_url(url).map_err(str::to_string)?;
    }
    Ok(())
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

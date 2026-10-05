//! Load generator for the middleware's `EvaluateHttpRequest` decision path.
//!
//! Each configuration starts the real `tenuo-openshell-middleware` binary as a
//! child process and drives it over gRPC from concurrent clients. Every call
//! is a distinct signed `tools/call`, so single-use reservation admits each
//! one once. Any response other than allow fails the run.
//!
//! `scripts/bench.sh` builds the release binaries, starts Redis in Docker,
//! and runs this. `docs/performance.md` explains the method and the results.

use clap::Parser;
use serde::Serialize;
use serde_json::json;
use std::fs;
use std::net::TcpListener as StdTcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::encode_meta;
use tenuo::{ConstraintSet, Exact, Range, SigningKey, Warrant, SIGNATURE_CONTEXT};
use tenuo_openshell_middleware::proto::openshell::middleware::v1::{
    Decision, HttpRequestEvaluation, HttpRequestResult, HttpRequestTarget, RequestContext,
    SupervisorMiddlewarePhase,
};
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};

const SANDBOX: &str = "bench";
const TOOL: &str = "read_logs";
const MCP_HOST: &str = "mcp.bench.internal";
const MCP_PORT: u32 = 8080;
const GATEWAY_ID: &str = "bench-gateway";
const AUDIENCE: &str = "urn:openshell:extension:middleware:tenuo/authorization";
const EVALUATE_PATH: &str = "/openshell.middleware.v1.SupervisorMiddleware/EvaluateHttpRequest";

#[derive(Debug, Parser)]
#[command(about = "Measure tenuo-openshell-middleware decisions over gRPC")]
struct Args {
    /// Middleware binary. Defaults to the one next to this executable.
    #[arg(long)]
    server: Option<PathBuf>,

    /// Plain Redis URL for the `single-use-redis` and `production` scenarios.
    #[arg(long)]
    redis_url: Option<String>,

    /// TLS Redis URL for the `single-use-rediss` scenario.
    #[arg(long)]
    rediss_url: Option<String>,

    /// Comma-separated scenarios: idempotent, single-use-memory,
    /// single-use-redis, single-use-rediss, production.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "idempotent,single-use-memory,single-use-redis,single-use-rediss,production"
    )]
    scenarios: Vec<String>,

    /// Comma-separated client concurrency levels.
    #[arg(long, value_delimiter = ',', default_value = "1,8,64")]
    concurrency: Vec<usize>,

    /// Measured calls per run.
    #[arg(long, default_value_t = 10_000)]
    requests: usize,

    /// Unmeasured calls sent at the same concurrency before each run.
    #[arg(long, default_value_t = 1_000)]
    warmup: usize,

    /// Repetitions per configuration. The report is the per-metric median.
    #[arg(long, default_value_t = 3)]
    repeat: usize,

    /// Client runtime worker threads. The server uses its own default runtime.
    #[arg(long, default_value_t = 4)]
    client_threads: usize,

    /// Also time `evaluate` in process, without gRPC, at concurrency 1.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    in_process: bool,

    /// Write one JSON object per run to this file.
    #[arg(long)]
    json: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Store {
    None,
    Memory,
    Redis,
    Rediss,
}

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    single_use: bool,
    store: Store,
    /// TLS listener and OpenShell JWT caller authentication.
    production: bool,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "idempotent",
        single_use: false,
        store: Store::None,
        production: false,
    },
    Scenario {
        name: "single-use-memory",
        single_use: true,
        store: Store::Memory,
        production: false,
    },
    Scenario {
        name: "single-use-redis",
        single_use: true,
        store: Store::Redis,
        production: false,
    },
    Scenario {
        name: "single-use-rediss",
        single_use: true,
        store: Store::Rediss,
        production: false,
    },
    Scenario {
        name: "production",
        single_use: true,
        store: Store::Redis,
        production: true,
    },
];

#[derive(Serialize)]
struct RunResult {
    scenario: String,
    receipts: bool,
    transport: &'static str,
    concurrency: usize,
    requests: usize,
    warmup: usize,
    /// `run` for one repetition, `median` for the summary.
    kind: &'static str,
    seconds: f64,
    calls_per_sec: f64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

struct Material {
    issuer: SigningKey,
    holder: SigningKey,
    warrant: Warrant,
    /// Next `offset` argument. Every signed call in a process is distinct.
    next: AtomicUsize,
}

impl Material {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let mut constraints = ConstraintSet::new();
        constraints.insert("service", Exact::new("payments"));
        constraints.insert("environment", Exact::new("staging"));
        constraints.insert("offset", Range::new(Some(0.0), Some(1e12))?);
        let warrant = Warrant::builder()
            .capability(TOOL, constraints)
            .holder(holder.public_key())
            .ttl(Duration::from_secs(3000))
            .build(&issuer)?;
        Ok(Self {
            issuer,
            holder,
            warrant,
            next: AtomicUsize::new(0),
        })
    }

    fn policy(&self, single_use: bool) -> Vec<u8> {
        let mut sandbox = json!({
            "trusted_roots": [hex::encode(self.issuer.public_key().to_bytes())],
            "destinations": [{
                "host": MCP_HOST,
                "port": MCP_PORT,
                "path": "/mcp",
                "tools": [TOOL]
            }]
        });
        if single_use {
            sandbox["single_use_tools"] = json!([TOOL]);
        }
        serde_json::to_vec_pretty(&json!({
            "max_warrant_lifetime_secs": 3600,
            "sandboxes": { (SANDBOX): sandbox }
        }))
        .expect("policy encodes")
    }

    /// Sign `count` distinct calls, in parallel. Signed just before each run
    /// so every proof is inside its time window.
    fn sign(&self, count: usize) -> Vec<Vec<u8>> {
        let start = self.next.fetch_add(count, Ordering::Relaxed);
        let threads = std::thread::available_parallelism().map_or(4, usize::from);
        let chunk = count.div_ceil(threads).max(1);
        let mut bodies = vec![Vec::new(); count];
        std::thread::scope(|scope| {
            for (index, slots) in bodies.chunks_mut(chunk).enumerate() {
                let base = start + index * chunk;
                scope.spawn(move || {
                    for (offset, slot) in slots.iter_mut().enumerate() {
                        *slot = self.call(base + offset).expect("call signs");
                    }
                });
            }
        });
        bodies
    }

    fn call(&self, offset: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let arguments = json!({
            "service": "payments",
            "environment": "staging",
            "offset": offset,
        });
        let call = Call::try_from_json(TOOL, &arguments)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let preimage = self
            .warrant
            .pop_preimage(call.capability(), call.pop_args(), now, 30)?;
        let mut message = SIGNATURE_CONTEXT.to_vec();
        message.extend(preimage);
        let signature = self.holder.sign_raw(&message);
        let meta = encode_meta(std::slice::from_ref(&self.warrant), &signature, &[])?;
        Ok(serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": offset,
            "method": "tools/call",
            "params": {
                "name": TOOL,
                "arguments": arguments,
                "_meta": {"tenuo": meta},
            },
        }))?)
    }
}

/// TLS and JWT material for the production listener.
struct Production {
    cert_pem: String,
    cert_path: PathBuf,
    key_path: PathBuf,
    jwt_public: PathBuf,
    bearer: String,
}

impl Production {
    fn create(dir: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rcgen::{generate_simple_self_signed, KeyPair, PKCS_ED25519};

        let tls = generate_simple_self_signed(vec!["localhost".to_string()])?;
        let cert_pem = tls.cert.pem();
        let cert_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        fs::write(&cert_path, &cert_pem)?;
        fs::write(&key_path, tls.signing_key.serialize_pem())?;

        let jwt = KeyPair::generate_for(&PKCS_ED25519)?;
        let jwt_public = dir.join("jwt.pub.pem");
        fs::write(&jwt_public, jwt.public_key_pem())?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let mut header = Header::new(Algorithm::EdDSA);
        header.typ = Some("openshell-ext+jwt".to_string());
        let claims = json!({
            "iss": format!("openshell-gateway:{GATEWAY_ID}"),
            "aud": AUDIENCE,
            "sub": format!("spiffe://openshell/sandbox/{SANDBOX}"),
            "iat": now,
            "exp": now + 3000,
            "jti": "bench",
            "caller_kind": "supervisor",
            "sandbox_id": SANDBOX,
        });
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_ed_pem(jwt.serialize_pem().as_bytes())?,
        )?;
        Ok(Self {
            cert_pem,
            cert_path,
            key_path,
            jwt_public,
            bearer: format!("Bearer {token}"),
        })
    }
}

struct Server {
    child: Child,
    dir: PathBuf,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> std::io::Result<u16> {
    Ok(StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

struct Run<'a> {
    args: &'a Args,
    material: &'a Material,
    server_bin: &'a Path,
    work: &'a Path,
}

impl Run<'_> {
    fn redis_url(&self, store: Store) -> Option<&str> {
        match store {
            Store::Redis => self.args.redis_url.as_deref(),
            Store::Rediss => self.args.rediss_url.as_deref(),
            Store::None | Store::Memory => None,
        }
    }

    fn start(
        &self,
        scenario: &Scenario,
        receipts: bool,
        production: Option<&Production>,
        tag: &str,
    ) -> Result<(Server, u16), Box<dyn std::error::Error>> {
        let dir = self.work.join(tag);
        fs::create_dir_all(&dir)?;
        let policy = dir.join("policy.json");
        fs::write(&policy, self.material.policy(scenario.single_use))?;
        let port = free_port()?;
        let admin = free_port()?;
        let mut command = Command::new(self.server_bin);
        command
            .arg("--policy")
            .arg(&policy)
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--admin-listen")
            .arg(format!("127.0.0.1:{admin}"))
            .arg("--replay-key-prefix")
            .arg(format!("tenuo:bench:{}:{tag}", std::process::id()))
            .env_remove("TENUO_DECISION_LOG")
            .env_remove("TENUO_REPLAY_REDIS_URL")
            .env_remove("TENUO_REPLAY_REDIS_CLUSTER_URLS")
            .env_remove("OTEL_EXPORTER_OTLP_ENDPOINT")
            .env_remove("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
            .stdout(Stdio::null())
            .stderr(fs::File::create(dir.join("server.log"))?);
        match production {
            Some(material) => {
                command
                    .arg("--tls-cert")
                    .arg(&material.cert_path)
                    .arg("--tls-key")
                    .arg(&material.key_path)
                    .arg("--openshell-jwt-public-key")
                    .arg(&material.jwt_public)
                    .arg("--openshell-gateway-id")
                    .arg(GATEWAY_ID);
            }
            None => {
                command.arg("--insecure-dev");
            }
        }
        if let Some(url) = self.redis_url(scenario.store) {
            command.arg("--replay-redis-url").arg(url);
        } else if scenario.store != Store::None && scenario.store != Store::Memory {
            return Err(format!("{} needs a Redis URL", scenario.name).into());
        }
        if receipts {
            let key = dir.join("receipt.key");
            fs::write(&key, SigningKey::generate().secret_key_bytes())?;
            command
                .arg("--receipt-key")
                .arg(&key)
                .arg("--receipt-log")
                .arg(dir.join("receipts.jsonl"))
                .arg("--require-receipts");
        }
        let child = command.spawn()?;
        Ok((Server { child, dir }, port))
    }

    /// Print the median of the repetitions. The JSON file gets every
    /// repetition and the median.
    fn report(&self, repetitions: Vec<RunResult>) -> Result<(), Box<dyn std::error::Error>> {
        let result = median(&repetitions);
        println!(
            "{:<18} receipts={:<3} {:<10} c={:<3} {:>9.0} calls/s  p50 {:>6} us  p95 {:>6} us  p99 {:>6} us  max {:>7} us  (median of {})",
            result.scenario,
            if result.receipts { "on" } else { "off" },
            result.transport,
            result.concurrency,
            result.calls_per_sec,
            result.p50_us,
            result.p95_us,
            result.p99_us,
            result.max_us,
            repetitions.len(),
        );
        if let Some(path) = &self.args.json {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            for repetition in &repetitions {
                writeln!(file, "{}", serde_json::to_string(repetition)?)?;
            }
            writeln!(file, "{}", serde_json::to_string(&result)?)?;
        }
        Ok(())
    }
}

/// Per-metric median across repetitions; `max_us` is the largest seen.
fn median(repetitions: &[RunResult]) -> RunResult {
    fn mid<T: Copy + PartialOrd>(mut values: Vec<T>) -> T {
        values.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
        values[values.len() / 2]
    }
    let first = &repetitions[0];
    RunResult {
        scenario: first.scenario.clone(),
        receipts: first.receipts,
        transport: first.transport,
        concurrency: first.concurrency,
        requests: first.requests,
        warmup: first.warmup,
        kind: "median",
        seconds: mid(repetitions.iter().map(|r| r.seconds).collect()),
        calls_per_sec: mid(repetitions.iter().map(|r| r.calls_per_sec).collect()),
        p50_us: mid(repetitions.iter().map(|r| r.p50_us).collect()),
        p95_us: mid(repetitions.iter().map(|r| r.p95_us).collect()),
        p99_us: mid(repetitions.iter().map(|r| r.p99_us).collect()),
        max_us: repetitions.iter().map(|r| r.max_us).max().unwrap_or(0),
    }
}

async fn connect(
    port: u16,
    tls: Option<&Production>,
) -> Result<Channel, Box<dyn std::error::Error>> {
    let endpoint = match tls {
        Some(material) => Endpoint::from_shared(format!("https://localhost:{port}"))?.tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(&material.cert_pem))
                .domain_name("localhost"),
        )?,
        None => Endpoint::from_shared(format!("http://127.0.0.1:{port}"))?,
    }
    .tcp_nodelay(true);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match endpoint.connect().await {
            Ok(channel) => return Ok(channel),
            Err(error) if Instant::now() > deadline => {
                return Err(format!("middleware did not start: {error}").into())
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

fn evaluation(body: Vec<u8>, index: usize) -> HttpRequestEvaluation {
    HttpRequestEvaluation {
        phase: SupervisorMiddlewarePhase::PreCredentials as i32,
        context: Some(RequestContext {
            request_id: format!("bench-{index}"),
            sandbox_id: SANDBOX.to_string(),
            ..Default::default()
        }),
        config: None,
        target: Some(HttpRequestTarget {
            scheme: "https".to_string(),
            host: MCP_HOST.to_string(),
            port: MCP_PORT,
            method: "POST".to_string(),
            path: "/mcp".to_string(),
            query: String::new(),
        }),
        body,
        ..Default::default()
    }
}

/// Send every body once, `concurrency` at a time. Each worker has its own
/// connection, as each OpenShell supervisor would. Returns the wall time and
/// the per-call latencies in microseconds.
async fn drive(
    channels: &[Channel],
    bodies: Vec<Vec<u8>>,
    bearer: Option<&str>,
) -> Result<(Duration, Vec<u64>), Box<dyn std::error::Error>> {
    let bodies = Arc::new(bodies);
    let index = Arc::new(AtomicUsize::new(0));
    let bearer: Option<tonic::metadata::MetadataValue<tonic::metadata::Ascii>> =
        bearer.map(str::parse).transpose()?;
    let started = Instant::now();
    let mut workers = Vec::with_capacity(channels.len());
    for channel in channels {
        let mut client = tonic::client::Grpc::new(channel.clone());
        let bodies = bodies.clone();
        let index = index.clone();
        let bearer = bearer.clone();
        workers.push(tokio::spawn(async move {
            let mut samples = Vec::with_capacity(bodies.len() / 4 + 1);
            loop {
                let next = index.fetch_add(1, Ordering::Relaxed);
                let Some(body) = bodies.get(next) else {
                    break;
                };
                let mut request = tonic::Request::new(evaluation(body.clone(), next));
                if let Some(bearer) = &bearer {
                    request
                        .metadata_mut()
                        .insert("authorization", bearer.clone());
                }
                let sent = Instant::now();
                client
                    .ready()
                    .await
                    .map_err(|error| format!("channel: {error}"))?;
                let response: tonic::Response<HttpRequestResult> = client
                    .unary(
                        request,
                        PathAndQuery::from_static(EVALUATE_PATH),
                        tonic_prost::ProstCodec::default(),
                    )
                    .await
                    .map_err(|status| format!("call {next}: {status}"))?;
                let micros = sent.elapsed().as_micros() as u64;
                let result = response.into_inner();
                if result.decision != Decision::Allow as i32 {
                    return Err(format!(
                        "call {next} was not allowed: {}",
                        result.reason_code
                    ));
                }
                samples.push(micros);
            }
            Ok::<_, String>(samples)
        }));
    }
    let mut samples = Vec::with_capacity(bodies.len());
    for worker in workers {
        samples.extend(worker.await??);
    }
    Ok((started.elapsed(), samples))
}

fn summarize(
    scenario: &str,
    receipts: bool,
    transport: &'static str,
    concurrency: usize,
    warmup: usize,
    elapsed: Duration,
    mut samples: Vec<u64>,
) -> RunResult {
    samples.sort_unstable();
    let pick = |quantile: f64| {
        let rank = ((samples.len() as f64) * quantile).ceil() as usize;
        samples[rank.clamp(1, samples.len()) - 1]
    };
    RunResult {
        scenario: scenario.to_string(),
        receipts,
        transport,
        concurrency,
        requests: samples.len(),
        warmup,
        kind: "run",
        seconds: elapsed.as_secs_f64(),
        calls_per_sec: samples.len() as f64 / elapsed.as_secs_f64(),
        p50_us: pick(0.50),
        p95_us: pick(0.95),
        p99_us: pick(0.99),
        max_us: *samples.last().unwrap_or(&0),
    }
}

/// Time `evaluate` directly with the same policy, store, and receipt log the
/// server would use. No gRPC, no client.
async fn in_process(
    run: &Run<'_>,
    scenario: &Scenario,
    receipts: bool,
    tag: &str,
) -> Result<RunResult, Box<dyn std::error::Error>> {
    use tenuo_openshell_middleware::receipt::ReceiptLog;
    use tenuo_openshell_middleware::replay::RedisReplayStore;
    use tenuo_openshell_middleware::{evaluate, MetaMode, PolicySet, RequestTarget};

    let dir = run.work.join(tag);
    fs::create_dir_all(&dir)?;
    let mut policy = PolicySet::from_json(&run.material.policy(scenario.single_use))
        .map_err(|error| format!("policy: {error:?}"))?;
    if let Some(url) = run.redis_url(scenario.store) {
        let store = RedisReplayStore::connect(url, format!("tenuo:bench:inproc:{tag}"))
            .await
            .map_err(|_| "Redis is unavailable")?;
        policy = policy.with_replay_store(Arc::new(store));
    }
    let log = if receipts {
        Some(
            ReceiptLog::open(&dir.join("receipt.key"), &dir.join("receipts.jsonl"))?
                .require_delivery(),
        )
    } else {
        None
    };
    let target = RequestTarget {
        method: "POST",
        host: MCP_HOST,
        port: MCP_PORT,
        path: "/mcp",
    };
    let args = run.args;
    let measure = |bodies: Vec<Vec<u8>>| {
        let policy = &policy;
        let log = log.as_ref();
        let target = &target;
        async move {
            let mut samples = Vec::with_capacity(bodies.len());
            let started = Instant::now();
            for body in &bodies {
                let sent = Instant::now();
                let outcome =
                    evaluate(policy, SANDBOX, true, target, body, MetaMode::Strip, log).await;
                samples.push(sent.elapsed().as_micros() as u64);
                if !outcome.allow {
                    return Err(format!("in-process call denied: {}", outcome.reason_code));
                }
            }
            Ok((started.elapsed(), samples))
        }
    };
    measure(run.material.sign(args.warmup)).await?;
    let (elapsed, samples) = measure(run.material.sign(args.requests)).await?;
    let _ = fs::remove_dir_all(&dir);
    Ok(summarize(
        scenario.name,
        receipts,
        "in-process",
        1,
        args.warmup,
        elapsed,
        samples,
    ))
}

async fn redis_ping(
    url: &str,
    label: &str,
    count: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = redis::Client::open(url)?;
    let mut connection = redis::aio::ConnectionManager::new(client).await?;
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count + 200 {
        let sent = Instant::now();
        let _: String = redis::cmd("PING").query_async(&mut connection).await?;
        samples.push(sent.elapsed().as_micros() as u64);
    }
    samples.drain(..200);
    samples.sort_unstable();
    let at = |quantile: f64| {
        samples[((samples.len() as f64 * quantile).ceil() as usize).clamp(1, samples.len()) - 1]
    };
    println!(
        "redis PING round trip ({label}): p50 {} us  p99 {} us over {count} pings",
        at(0.50),
        at(0.99)
    );
    Ok(())
}

/// One fresh middleware process, one warm-up, one measured run.
async fn grpc_run(
    run: &Run<'_>,
    scenario: &Scenario,
    receipts: bool,
    concurrency: usize,
    production: &Production,
    tag: &str,
) -> Result<RunResult, Box<dyn std::error::Error>> {
    let tls = scenario.production.then_some(production);
    let (server, port) = run.start(scenario, receipts, tls, tag)?;
    let mut channels = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        channels.push(connect(port, tls).await.inspect_err(|_| {
            let log = fs::read_to_string(server.dir.join("server.log")).unwrap_or_default();
            eprintln!("{log}");
        })?);
    }
    let bearer = tls.map(|material| material.bearer.as_str());
    drive(&channels, run.material.sign(run.args.warmup), bearer).await?;
    let (elapsed, samples) = drive(&channels, run.material.sign(run.args.requests), bearer).await?;
    drop(channels);
    drop(server);
    Ok(summarize(
        scenario.name,
        receipts,
        if scenario.production {
            "grpc+tls"
        } else {
            "grpc"
        },
        concurrency,
        run.args.warmup,
        elapsed,
        samples,
    ))
}

async fn bench(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    let server_bin = match &args.server {
        Some(path) => path.clone(),
        None => std::env::current_exe()?
            .parent()
            .ok_or("no executable directory")?
            .join("tenuo-openshell-middleware"),
    };
    if !server_bin.exists() {
        return Err(format!("{} not found; build it first", server_bin.display()).into());
    }
    let work = std::env::temp_dir().join(format!("tenuo-openshell-bench-{}", std::process::id()));
    fs::create_dir_all(&work)?;
    let material = Material::new()?;
    let production = Production::create(&work)?;
    println!(
        "request: one-warrant tools/call, {} byte body",
        material.call(0)?.len()
    );
    let run = Run {
        args: &args,
        material: &material,
        server_bin: &server_bin,
        work: &work,
    };

    if let Some(url) = &args.redis_url {
        redis_ping(url, "redis://", 5_000).await?;
    }
    if let Some(url) = &args.rediss_url {
        redis_ping(url, "rediss://", 5_000).await?;
    }

    let mut selected = Vec::new();
    for name in &args.scenarios {
        let scenario = SCENARIOS
            .iter()
            .find(|scenario| scenario.name == name)
            .ok_or_else(|| format!("unknown scenario {name}"))?;
        if run.redis_url(scenario.store).is_none()
            && matches!(scenario.store, Store::Redis | Store::Rediss)
        {
            eprintln!("skipping {name}: no Redis URL for it");
            continue;
        }
        selected.push(*scenario);
    }

    let mut serial = 0;
    for scenario in &selected {
        for receipts in [false, true] {
            if args.in_process && !scenario.production {
                let mut repetitions = Vec::with_capacity(args.repeat);
                for _ in 0..args.repeat {
                    serial += 1;
                    let tag = format!("inproc-{serial}");
                    repetitions.push(in_process(&run, scenario, receipts, &tag).await?);
                }
                run.report(repetitions)?;
            }
            for &concurrency in &args.concurrency {
                let mut repetitions = Vec::with_capacity(args.repeat);
                for _ in 0..args.repeat {
                    serial += 1;
                    let tag = format!("run-{serial}");
                    repetitions.push(
                        grpc_run(&run, scenario, receipts, concurrency, &production, &tag).await?,
                    );
                }
                run.report(repetitions)?;
            }
        }
    }
    let _ = fs::remove_dir_all(&work);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.concurrency.contains(&0) || args.requests == 0 || args.repeat == 0 {
        return Err("concurrency, requests, and repeat must be positive".into());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.client_threads.max(1))
        .enable_all()
        .build()?
        .block_on(bench(args))
}

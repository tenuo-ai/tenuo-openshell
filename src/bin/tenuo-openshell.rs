//! Operator commands for Tenuo on NVIDIA OpenShell.
//!
//! ```text
//! tenuo-openshell keygen --out issuer.key --public-out issuer.pub
//! tenuo-openshell policy init --policy policy.json
//! tenuo-openshell policy add --policy policy.json --sandbox-id <id> \
//!     --trusted-root <hex> --mcp https://mcp.internal/mcp --tools read_logs
//! tenuo-openshell register --middleware-endpoint https://tenuo:50051 \
//!     --ca /etc/openshell/tenuo-ca.pem --mcp-host mcp.internal
//! tenuo-openshell provision --sandbox <name> --issuer-key issuer.key \
//!     --capabilities caps.json --ttl 3600
//! ```

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode};
use std::time::Duration;
use tenuo::approval::ApprovalRequest;
use tenuo::{
    ConstraintSet, ConstraintValue, Exact, OneOf, Pattern, PublicKey, Range, SigningKey, Warrant,
    Wildcard,
};
use tenuo_openshell_middleware::PolicySet;

const DEFAULT_AUDIENCE: &str = "urn:openshell:extension:middleware:tenuo/authorization";
const AGENT: &str = "tenuo-openshell-agent";

#[derive(Parser)]
#[command(
    name = "tenuo-openshell",
    version,
    about = "Operator commands for Tenuo on NVIDIA OpenShell"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create an Ed25519 key: an issuer, approver, or policy signing key.
    /// Prints the public key in the form `--trusted-root` and
    /// `--policy-signing-key` accept.
    Keygen(KeygenArgs),
    /// Edit the middleware trust policy.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Print the OpenShell gateway registration and sandbox policy blocks.
    Register(RegisterArgs),
    /// Issue warrants to holder keys.
    #[command(subcommand)]
    Warrant(WarrantCommand),
    /// Generate a holder key in a sandbox, issue a warrant to it, and install it.
    Provision(ProvisionArgs),
    /// Delegate part of one sandbox's authority to another sandbox. The parent
    /// sandbox signs the child warrant; only public keys and warrants cross.
    Delegate(DelegateArgs),
    /// Review a pending approval request, sign it, and install it.
    Approve(ApproveArgs),
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Create a policy that trusts no sandboxes. The middleware starts on it
    /// and denies every request until `policy add` adds a sandbox.
    Init(PolicyInitArgs),
    /// Add a sandbox, trust root, or MCP destination. Creates the file if needed
    /// and increments its version.
    Add(PolicyAddArgs),
    /// Write `<policy>.sig` over the exact policy bytes.
    Sign(PolicySignArgs),
    /// Same as `tenuo-openshell keygen`.
    #[command(hide = true)]
    Keygen(KeygenArgs),
}

#[derive(Args)]
struct PolicyInitArgs {
    /// Policy file to create. An existing file is never overwritten.
    #[arg(long)]
    policy: PathBuf,
    /// Longest warrant lifetime the middleware accepts, in seconds.
    #[arg(long, default_value_t = 3600)]
    max_warrant_lifetime_secs: u64,
    /// Also sign the written policy with this key, writing `<policy>.sig`.
    /// The key is a secret from `tenuo-openshell keygen`.
    #[arg(long, value_name = "KEY")]
    sign_with: Option<PathBuf>,
}

#[derive(Args)]
struct PolicyAddArgs {
    #[arg(long)]
    policy: PathBuf,
    /// OpenShell sandbox id (not the display name).
    #[arg(long)]
    sandbox_id: String,
    /// Issuer public key, 64 hex characters or a file containing them.
    #[arg(long)]
    trusted_root: Vec<String>,
    /// MCP endpoint URL, for example https://mcp.internal/mcp.
    #[arg(long)]
    mcp: Option<String>,
    /// Tools the destination serves, comma-separated, or `*`.
    #[arg(long, value_delimiter = ',', requires = "mcp")]
    tools: Vec<String>,
    /// Deprecated and ignored: every tool is single-use unless it is listed
    /// with --idempotent.
    #[arg(long, value_delimiter = ',', hide = true)]
    single_use: Vec<String>,
    /// Tools for which a resent identical call is the same effect. A captured
    /// body for any other tool is denied `tenuo_pop_replayed`.
    #[arg(long, value_delimiter = ',')]
    idempotent: Vec<String>,
    /// Maximum warrant lifetime for a new policy file.
    #[arg(long, default_value_t = 3600)]
    max_warrant_lifetime_secs: u64,
    /// Also sign the written policy with this key, writing `<policy>.sig`.
    /// The key is a secret from `tenuo-openshell keygen`.
    #[arg(long, value_name = "KEY")]
    sign_with: Option<PathBuf>,
}

#[derive(Args)]
struct KeygenArgs {
    /// File to create for the secret key, as 64 hex characters, mode 0600.
    /// An existing file is never overwritten.
    #[arg(long)]
    out: PathBuf,
    /// Also write the public key, as 64 hex characters, to this new file.
    /// The public key is always printed on stdout.
    #[arg(long)]
    public_out: Option<PathBuf>,
}

#[derive(Args)]
struct PolicySignArgs {
    #[arg(long)]
    policy: PathBuf,
    /// Ed25519 secret key file. The matching public key is what the middleware
    /// receives as `--policy-signing-key`.
    #[arg(long)]
    key: PathBuf,
}

#[derive(Args)]
struct RegisterArgs {
    /// HTTPS endpoint the OpenShell gateway uses to reach the middleware.
    /// Required unless `--only sandbox`.
    #[arg(long)]
    middleware_endpoint: Option<String>,
    /// CA certificate path, as seen by the gateway. Required for the gateway
    /// block unless `--insecure-dev`.
    #[arg(long, conflicts_with = "insecure_dev")]
    ca: Option<String>,
    /// Register an `http://` endpoint with `allow_insecure_transport`, for a
    /// middleware started with `--insecure-dev`. OpenShell then sends no
    /// credential and anything on the network can call the middleware.
    /// Local development only.
    #[arg(long)]
    insecure_dev: bool,
    /// Print only one block: the gateway TOML or the sandbox policy YAML.
    #[arg(long, value_enum)]
    only: Option<RegisterPart>,
    /// MCP host the sandbox policy attaches the middleware to. Repeatable.
    /// Required unless only the gateway block is printed.
    #[arg(long)]
    mcp_host: Vec<String>,
    #[arg(long, default_value = DEFAULT_AUDIENCE)]
    audience: String,
    /// Mention in the printed block that the Tenuo policy sets
    /// `forward_proof` to `preserve`. The sandbox attachment cannot do that.
    #[arg(long)]
    preserve_meta: bool,
    /// OpenShell sandbox policy to check before printing. Refuses when an
    /// endpoint that can match a protected host is L4 TCP (no `protocol`, or
    /// `tcp`), `websocket`, `sql`, or `tls: skip`.
    #[arg(long)]
    openshell_policy: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum RegisterPart {
    /// The `[[openshell.supervisor.middleware]]` block for `gateway.toml`.
    Gateway,
    /// The `network_middlewares` block for the sandbox policy.
    Sandbox,
}

#[derive(Subcommand)]
enum WarrantCommand {
    /// Print an encoded warrant for a holder public key.
    Issue(IssueArgs),
}

#[derive(Args)]
struct AuthorityArgs {
    /// Issuer private key (32 raw bytes or 64 hex characters). Mints a root warrant.
    #[arg(long, conflicts_with_all = ["parent_key", "parent_warrant"])]
    issuer_key: Option<PathBuf>,
    /// Parent holder private key. Attenuates `--parent-warrant`.
    #[arg(long, requires = "parent_warrant")]
    parent_key: Option<PathBuf>,
    #[arg(long, requires = "parent_key")]
    parent_warrant: Option<PathBuf>,
    /// Capabilities as JSON, or @file. See `docs/deployment.md`.
    #[arg(long)]
    capabilities: String,
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
}

#[derive(Args)]
struct IssueArgs {
    /// Holder public key, 64 hex characters or a file containing them.
    #[arg(long)]
    holder: String,
    #[command(flatten)]
    authority: AuthorityArgs,
}

#[derive(Args)]
struct ProvisionArgs {
    #[command(flatten)]
    sandbox: SandboxArgs,
    #[command(flatten)]
    authority: AuthorityArgs,
}

#[derive(Args, Clone)]
struct SandboxArgs {
    /// OpenShell sandbox name.
    #[arg(long)]
    sandbox: String,
    /// OpenShell CLI to run.
    #[arg(long, default_value = "openshell")]
    openshell: String,
    /// Passed to the OpenShell CLI as `--gateway-endpoint`.
    #[arg(long)]
    gateway_endpoint: Option<String>,
}

#[derive(Args)]
struct DelegateArgs {
    /// Sandbox whose agent holds the parent warrant and signs the delegation.
    #[arg(long)]
    from_sandbox: String,
    /// Sandbox that receives a new holder key and the narrowed warrant.
    #[arg(long)]
    to_sandbox: String,
    /// Tools to pass on, comma-separated. Each keeps the parent's constraints.
    #[arg(long, value_delimiter = ',', required = true)]
    tools: Vec<String>,
    /// Child lifetime in seconds, never longer than the parent's.
    #[arg(long, default_value_t = 300)]
    ttl: u64,
    /// The child sandbox may not delegate further.
    #[arg(long)]
    terminal: bool,
    /// OpenShell CLI to run.
    #[arg(long, default_value = "openshell")]
    openshell: String,
    /// Passed to the OpenShell CLI as `--gateway-endpoint`.
    #[arg(long)]
    gateway_endpoint: Option<String>,
}

#[derive(Args)]
struct ApproveArgs {
    /// Request hash from the agent's `-32002` error or `tenuo-openshell-agent
    /// pending`. A unique prefix is enough.
    #[arg(long)]
    request: String,
    /// Approver private key (32 raw bytes or 64 hex characters).
    #[arg(long)]
    approver_key: PathBuf,
    /// Issuer public key the pending warrant chain must verify to (64 hex
    /// characters or a file). Repeatable; usually the sandbox's
    /// `trusted_roots`.
    #[arg(long = "trusted-root", required = true)]
    trusted_root: Vec<String>,
    /// Seconds the approval stays valid.
    #[arg(long, default_value_t = 300)]
    ttl: u64,
    /// Approve without the interactive confirmation.
    #[arg(long)]
    yes: bool,
    /// Read pending requests from this file (the output of
    /// `tenuo-openshell-agent pending --json`) and print the approval instead
    /// of installing it in a sandbox.
    #[arg(long, conflicts_with = "sandbox")]
    pending: Option<PathBuf>,
    #[arg(long, requires = "sandbox")]
    openshell: Option<String>,
    #[arg(long, requires = "sandbox")]
    gateway_endpoint: Option<String>,
    /// OpenShell sandbox whose pending request to approve.
    #[arg(long, required_unless_present = "pending")]
    sandbox: Option<String>,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tenuo-openshell: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen(args) | Command::Policy(PolicyCommand::Keygen(args)) => keygen(&args),
        Command::Policy(PolicyCommand::Init(args)) => policy_init(&args),
        Command::Policy(PolicyCommand::Add(args)) => policy_add(&args),
        Command::Policy(PolicyCommand::Sign(args)) => policy_sign(&args),
        Command::Register(args) => {
            print!("{}", register(&args)?);
            Ok(())
        }
        Command::Warrant(WarrantCommand::Issue(args)) => {
            let holder = read_public(&args.holder)?;
            let chain = issue(&args.authority, &holder)?;
            println!("{}", encode_chain(&chain)?);
            Ok(())
        }
        Command::Provision(args) => provision(&args),
        Command::Approve(args) => approve(&args),
        Command::Delegate(args) => delegate(&args),
    }
}

fn empty_policy(max_warrant_lifetime_secs: u64) -> Value {
    json!({
        "version": 1,
        "max_warrant_lifetime_secs": max_warrant_lifetime_secs,
        "approval_replay_protection": true,
        "sandboxes": {}
    })
}

fn policy_init(args: &PolicyInitArgs) -> Result<()> {
    use std::io::Write;
    let document = empty_policy(args.max_warrant_lifetime_secs);
    let bytes = [serde_json::to_vec_pretty(&document)?.as_slice(), b"\n"].concat();
    PolicySet::from_json(&bytes).map_err(|error| format!("policy is invalid: {error}"))?;
    if args.policy.exists() {
        return Err(format!("{}: already exists", args.policy.display()).into());
    }
    // Signature first, the same order as `policy add`.
    if let Some(key) = &args.sign_with {
        write_policy_signature(&args.policy, &bytes, key)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.policy)
        .map_err(|error| format!("{}: {error}", args.policy.display()))?;
    file.write_all(&bytes)?;
    println!("wrote {} version 1", args.policy.display());
    Ok(())
}

/// Sign `bytes`, the exact contents of `policy`, into `<policy>.sig`, through
/// a staging file so a reader never sees a partial signature.
fn write_policy_signature(policy: &Path, bytes: &[u8], key: &Path) -> Result<()> {
    let key = read_secret(key)?;
    let signature = tenuo_openshell_middleware::policy::sign_policy_document(bytes, &key);
    let path = tenuo_openshell_middleware::policy::policy_signature_path(policy);
    let staging = path.with_extension("sig.tmp");
    fs::write(&staging, format!("{signature}\n"))?;
    fs::rename(&staging, &path)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn policy_add(args: &PolicyAddArgs) -> Result<()> {
    if !args.single_use.is_empty() {
        eprintln!(
            "warning: --single-use is deprecated and ignored; every tool is single-use unless listed with --idempotent"
        );
    }
    let mut document = match fs::read(&args.policy) {
        Ok(bytes) => serde_json::from_slice(&bytes)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => json!({
            "version": 0,
            "max_warrant_lifetime_secs": args.max_warrant_lifetime_secs,
            "approval_replay_protection": true,
            "sandboxes": {}
        }),
        Err(error) => return Err(error.into()),
    };
    let roots = args
        .trusted_root
        .iter()
        .map(|root| read_public(root).map(|key| hex::encode(key.to_bytes())))
        .collect::<Result<Vec<_>>>()?;
    let destination = match &args.mcp {
        Some(url) => Some(destination(url, &args.tools)?),
        None => None,
    };
    add_to_policy(
        &mut document,
        &args.sandbox_id,
        &roots,
        destination,
        &args.idempotent,
    )?;
    let bytes = serde_json::to_vec_pretty(&document)?;
    PolicySet::from_json(&bytes)
        .map_err(|error| format!("resulting policy is invalid: {error}"))?;
    let bytes = [bytes.as_slice(), b"\n"].concat();
    // Signature first: a running middleware skips the reload until the policy
    // bytes change, so it never pairs the new policy with the old signature.
    if let Some(key) = &args.sign_with {
        write_policy_signature(&args.policy, &bytes, key)?;
    }
    let staging = args.policy.with_extension("tmp");
    fs::write(&staging, &bytes)?;
    fs::rename(&staging, &args.policy)?;
    println!(
        "wrote {} version {}",
        args.policy.display(),
        document["version"]
    );
    Ok(())
}

fn add_to_policy(
    document: &mut Value,
    sandbox_id: &str,
    roots: &[String],
    destination: Option<Value>,
    idempotent: &[String],
) -> Result<()> {
    let version = document["version"].as_u64().unwrap_or(0) + 1;
    document["version"] = json!(version);
    let sandboxes = document
        .get_mut("sandboxes")
        .and_then(Value::as_object_mut)
        .ok_or("policy has no sandboxes object")?;
    let entry = sandboxes
        .entry(sandbox_id.to_string())
        .or_insert_with(|| json!({"trusted_roots": [], "destinations": []}));
    let entry = entry
        .as_object_mut()
        .ok_or("sandbox entry is not an object")?;
    union(entry, "trusted_roots", roots.iter().map(|root| json!(root)));
    union(
        entry,
        "idempotent_tools",
        idempotent.iter().map(|tool| json!(tool)),
    );
    if let Some(destination) = destination {
        let list = entry
            .entry("destinations")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or("destinations is not a list")?;
        let same = |existing: &&mut Value| {
            ["host", "port", "path"]
                .iter()
                .all(|field| existing.get(*field) == destination.get(*field))
        };
        match list.iter_mut().find(same) {
            Some(existing) => {
                let tools = existing["tools"]
                    .as_array_mut()
                    .ok_or("tools is not a list")?;
                for tool in destination["tools"].as_array().into_iter().flatten() {
                    if !tools.contains(tool) {
                        tools.push(tool.clone());
                    }
                }
            }
            None => list.push(destination),
        }
    }
    Ok(())
}

fn union(entry: &mut Map<String, Value>, field: &str, values: impl Iterator<Item = Value>) {
    let values: Vec<Value> = values.collect();
    if values.is_empty() {
        return;
    }
    let list = entry.entry(field).or_insert_with(|| json!([]));
    if let Some(list) = list.as_array_mut() {
        for value in values {
            if !list.contains(&value) {
                list.push(value);
            }
        }
    }
}

/// Parse `scheme://host[:port][/path]` into a policy destination.
fn destination(url: &str, tools: &[String]) -> Result<Value> {
    if tools.is_empty() {
        return Err("--mcp needs --tools".into());
    }
    let (scheme, rest) = url.split_once("://").ok_or("MCP URL needs a scheme")?;
    let default_port = match scheme {
        "https" => 443,
        "http" => 80,
        _ => return Err("MCP URL scheme must be http or https".into()),
    };
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    let path = path.split(['?', '#']).next().unwrap_or("");
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().map_err(|_| "invalid MCP port")?),
        None => (authority, default_port),
    };
    if host.is_empty() || authority.contains('@') {
        return Err("MCP URL needs a host and no credentials".into());
    }
    let mut value = json!({"host": host.to_ascii_lowercase(), "port": port, "tools": tools});
    if !path.is_empty() {
        value["path"] = json!(path);
    }
    Ok(value)
}

fn policy_sign(args: &PolicySignArgs) -> Result<()> {
    let document = fs::read(&args.policy)?;
    let key = read_secret(&args.key)?;
    let signature = tenuo_openshell_middleware::policy::sign_policy_document(&document, &key);
    let path = tenuo_openshell_middleware::policy::policy_signature_path(&args.policy);
    fs::write(&path, format!("{signature}\n"))?;
    println!("wrote {}", path.display());
    println!("public {}", hex::encode(key.public_key().to_bytes()));
    Ok(())
}

/// Write a new key pair. Neither file is ever overwritten, and nothing is
/// written unless both files can be created.
fn keygen(args: &KeygenArgs) -> Result<()> {
    use std::io::Write;
    let key = SigningKey::generate();
    let public = hex::encode(key.public_key().to_bytes());
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut secret = options
        .open(&args.out)
        .map_err(|error| format!("{}: {error}", args.out.display()))?;
    let public_file = match &args.public_out {
        Some(path) => match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => Some(file),
            Err(error) => {
                drop(secret);
                let _ = fs::remove_file(&args.out);
                return Err(format!("{}: {error}", path.display()).into());
            }
        },
        None => None,
    };
    writeln!(secret, "{}", hex::encode(key.secret_key_bytes()))?;
    if let Some(mut file) = public_file {
        writeln!(file, "{public}")?;
    }
    println!("{public}");
    Ok(())
}

fn register(args: &RegisterArgs) -> Result<String> {
    let gateway_only = matches!(args.only, Some(RegisterPart::Gateway));
    if args.mcp_host.is_empty() && (!gateway_only || args.openshell_policy.is_some()) {
        return Err("--mcp-host is required for the sandbox block and --openshell-policy".into());
    }
    if let Some(path) = &args.openshell_policy {
        let document = fs::read_to_string(path)?;
        reject_uncovered_routes(&document, &args.mcp_host)?;
    }
    match args.only {
        Some(RegisterPart::Gateway) => register_gateway(args),
        Some(RegisterPart::Sandbox) => Ok(register_sandbox(args)),
        None => Ok(format!(
            "{}\n{}",
            register_gateway(args)?,
            register_sandbox(args)
        )),
    }
}

/// The gateway's `[[openshell.supervisor.middleware]]` registration.
///
/// Production registers an `https://` endpoint with a CA. `--insecure-dev`
/// registers an `http://` endpoint with `allow_insecure_transport`, which
/// OpenShell requires for plaintext and which turns off its caller credential.
fn register_gateway(args: &RegisterArgs) -> Result<String> {
    let endpoint = args
        .middleware_endpoint
        .as_deref()
        .ok_or("the gateway block needs --middleware-endpoint")?;
    let transport = if args.insecure_dev {
        if !endpoint.starts_with("http://") {
            return Err("--insecure-dev registers an http:// endpoint".into());
        }
        "# Development only: no TLS and no caller credential. Start the\n\
         # middleware with --insecure-dev.\n\
         allow_insecure_transport = true\n"
            .to_string()
    } else {
        if !endpoint.starts_with("https://") {
            return Err(
                "--middleware-endpoint must be https://; pass --insecure-dev for a local http:// middleware"
                    .into(),
            );
        }
        let ca = args
            .ca
            .as_deref()
            .ok_or("an https:// endpoint needs --ca")?;
        format!("tls_ca_cert_path = \"{ca}\"\n")
    };
    Ok(format!(
        "# OpenShell gateway configuration\n\
         [[openshell.supervisor.middleware]]\n\
         name = \"tenuo/authorization\"\n\
         grpc_endpoint = \"{endpoint}\"\n\
         {transport}\
         audience = \"{audience}\"\n\
         max_payload_bytes = 262144\n\
         timeout = \"2s\"\n",
        audience = args.audience,
    ))
}

/// The sandbox policy's `network_middlewares` attachment.
fn register_sandbox(args: &RegisterArgs) -> String {
    let hosts = args
        .mcp_host
        .iter()
        .map(|host| format!("        - {host}\n"))
        .collect::<String>();
    let preserve = if args.preserve_meta {
        "# Set \"forward_proof\": \"preserve\" on this sandbox in the Tenuo policy.\n\
         # The sandbox attachment cannot forward the proof.\n"
    } else {
        ""
    };
    format!(
        "# Sandbox policy. List {AGENT} as the only binary allowed to reach\n\
         # these hosts so every tools/call is signed in the sandbox.\n\
         {preserve}\
         network_middlewares:\n  \
           tenuo-task-authority:\n    \
             middleware: tenuo/authorization\n    \
             on_error: fail_closed\n    \
             endpoints:\n      \
               include:\n\
         {hosts}"
    )
}

/// Refuse a printed registration when a protected host is reachable on a
/// route this middleware does not see.
///
/// The check reads each `network_policies.*.endpoints[]` entry whose `host`
/// pattern can match a protected host. It uses OpenShell's host-pattern rules:
/// case-insensitive, `*` within one DNS label, and a `**` label for one or more
/// labels. The middleware sees HTTP requests only. An endpoint without a
/// `protocol` is L4 TCP in OpenShell, as is `protocol: tcp`. `websocket` and
/// `sql` traffic is not delivered to this middleware's HTTP binding, and
/// `tls: skip` hides the request.
fn reject_uncovered_routes(document: &str, hosts: &[String]) -> Result<()> {
    let value: serde_yaml::Value = serde_yaml::from_str(document)
        .map_err(|error| format!("OpenShell policy did not parse: {error}"))?;
    let mut found = Vec::new();
    if let Some(policies) = value
        .get("network_policies")
        .and_then(serde_yaml::Value::as_mapping)
    {
        for (name, policy) in policies {
            let name = name.as_str().unwrap_or("?");
            let Some(endpoints) = policy
                .get("endpoints")
                .and_then(serde_yaml::Value::as_sequence)
            else {
                continue;
            };
            for endpoint in endpoints {
                let Some(pattern) = endpoint.get("host").and_then(serde_yaml::Value::as_str) else {
                    continue;
                };
                if !hosts.iter().any(|host| host_pattern_matches(pattern, host)) {
                    continue;
                }
                let field = |key: &str| endpoint.get(key).and_then(serde_yaml::Value::as_str);
                let reason = match (field("tls"), field("protocol")) {
                    (Some(tls), _) if tls.eq_ignore_ascii_case("skip") => "tls: skip".to_string(),
                    (_, None) => "no protocol, so L4 TCP".to_string(),
                    (_, Some(protocol))
                        if ["tcp", "websocket", "sql"]
                            .iter()
                            .any(|uncovered| protocol.eq_ignore_ascii_case(uncovered)) =>
                    {
                        format!("protocol: {protocol}")
                    }
                    _ => continue,
                };
                found.push(format!("{name}: {pattern} ({reason})"));
            }
        }
    }
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "protected hosts are reachable outside the middleware's HTTP binding: {}",
            found.join(", ")
        )
        .into())
    }
}

/// OpenShell host-pattern matching for a concrete host.
fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    let pattern: Vec<&str> = pattern.split('.').collect();
    let host: Vec<&str> = host.split('.').collect();
    fn walk(pattern: &[&str], host: &[&str]) -> bool {
        match (pattern.first(), host.first()) {
            (None, None) => true,
            (Some(&"**"), Some(_)) => walk(&pattern[1..], &host[1..]) || walk(pattern, &host[1..]),
            (Some(label), Some(part)) => {
                label_matches(label, part) && walk(&pattern[1..], &host[1..])
            }
            _ => false,
        }
    }
    walk(&pattern, &host)
}

/// `*` and `?` within one DNS label. A character class is treated as a match,
/// so the check errs toward refusing.
fn label_matches(pattern: &str, label: &str) -> bool {
    if pattern.contains('[') {
        return true;
    }
    let pattern: Vec<char> = pattern.chars().collect();
    let label: Vec<char> = label.chars().collect();
    fn walk(pattern: &[char], label: &[char]) -> bool {
        match (pattern.first(), label.first()) {
            (None, None) => true,
            (Some('*'), _) => {
                walk(&pattern[1..], label) || (!label.is_empty() && walk(pattern, &label[1..]))
            }
            (Some('?'), Some(_)) => walk(&pattern[1..], &label[1..]),
            (Some(expected), Some(actual)) => {
                expected == actual && walk(&pattern[1..], &label[1..])
            }
            _ => false,
        }
    }
    walk(&pattern, &label)
}

fn issue(args: &AuthorityArgs, holder: &PublicKey) -> Result<Vec<Warrant>> {
    let capabilities = parse_capabilities(&read_arg(&args.capabilities)?)?;
    let ttl = Duration::from_secs(args.ttl);
    if let Some(path) = &args.issuer_key {
        let issuer = read_secret(path)?;
        let mut builder = Warrant::builder();
        for (tool, constraints) in capabilities {
            builder = builder.capability(tool, constraints);
        }
        return Ok(vec![builder
            .holder(holder.clone())
            .ttl(ttl)
            .build(&issuer)?]);
    }
    let (Some(key), Some(warrant)) = (&args.parent_key, &args.parent_warrant) else {
        return Err("pass --issuer-key, or --parent-key with --parent-warrant".into());
    };
    let parent_key = read_secret(key)?;
    let mut chain = decode_chain(&fs::read(warrant)?)?;
    let parent = chain.last().ok_or("parent warrant is empty")?;
    let mut builder = parent.attenuate().holder(holder.clone()).ttl(ttl);
    for (tool, constraints) in capabilities {
        builder = builder.tool(tool, constraints);
    }
    let child = builder.build(&parent_key)?;
    chain.push(child);
    Ok(chain)
}

/// Relay a delegation between two sandboxes.
///
/// OpenShell has no sandbox-to-sandbox channel, so this moves the public
/// material: the child's public key to the parent, and the child chain the
/// parent's agent signs back to the child. No private key leaves a sandbox.
fn delegate(args: &DelegateArgs) -> Result<()> {
    let sandbox = |name: &str| SandboxArgs {
        sandbox: name.to_string(),
        openshell: args.openshell.clone(),
        gateway_endpoint: args.gateway_endpoint.clone(),
    };
    let (parent, child) = (sandbox(&args.from_sandbox), sandbox(&args.to_sandbox));
    let public = openshell_exec(&child, &[AGENT, "keygen"])?;
    let public = public.lines().last().unwrap_or_default().trim().to_string();
    read_public(&public)?;
    let tools = args.tools.join(",");
    let ttl = args.ttl.to_string();
    let mut command = vec![
        AGENT,
        "delegate",
        "--child-pub",
        &public,
        "--tools",
        &tools,
        "--ttl",
        &ttl,
    ];
    if args.terminal {
        command.push("--terminal");
    }
    let chain = openshell_exec(&parent, &command)?;
    let chain = chain.lines().last().unwrap_or_default().trim().to_string();
    let decoded = decode_chain(chain.as_bytes())?;
    let leaf = decoded.last().ok_or("empty delegated chain")?;
    if leaf.authorized_holder() != &read_public(&public)? {
        return Err("the parent returned a warrant for a different holder".into());
    }
    openshell_exec(&child, &[AGENT, "install-warrant", &chain])?;
    println!("from    {}", args.from_sandbox);
    println!("to      {}", args.to_sandbox);
    println!("holder  {public}");
    println!("warrant {}", leaf.id());
    println!("depth   {}", decoded.len());
    println!("tools   {}", leaf.tools().join(", "));
    Ok(())
}

fn provision(args: &ProvisionArgs) -> Result<()> {
    let public = openshell_exec(&args.sandbox, &[AGENT, "keygen"])?;
    let holder = read_public(public.lines().last().unwrap_or_default())?;
    let chain = issue(&args.authority, &holder)?;
    let encoded = encode_chain(&chain)?;
    openshell_exec(&args.sandbox, &[AGENT, "install-warrant", &encoded])?;
    let leaf = chain.last().ok_or("empty chain")?;
    println!("sandbox {}", args.sandbox.sandbox);
    println!("holder  {}", hex::encode(holder.to_bytes()));
    println!("warrant {}", leaf.id());
    println!("tools   {}", leaf.tools().join(", "));
    Ok(())
}

fn openshell_exec(args: &SandboxArgs, command: &[&str]) -> Result<String> {
    let mut process = Process::new(&args.openshell);
    if let Some(endpoint) = &args.gateway_endpoint {
        process.args(["--gateway-endpoint", endpoint]);
    }
    process.args(["sandbox", "exec", "--name", &args.sandbox, "--no-tty", "--"]);
    process.args(command);
    let output = process.output()?;
    if !output.status.success() {
        return Err(format!(
            "`{} {}` failed in sandbox {}: {}",
            args.openshell,
            command.join(" "),
            args.sandbox,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8(output.stdout)?.replace('\r', ""))
}

fn approve(args: &ApproveArgs) -> Result<()> {
    let sandbox = args.sandbox.as_ref().map(|name| SandboxArgs {
        sandbox: name.clone(),
        openshell: args
            .openshell
            .clone()
            .unwrap_or_else(|| "openshell".to_string()),
        gateway_endpoint: args.gateway_endpoint.clone(),
    });
    let listing = match (&sandbox, &args.pending) {
        (Some(sandbox), _) => openshell_exec(sandbox, &[AGENT, "pending", "--json"])?,
        (None, Some(path)) => fs::read_to_string(path)?,
        (None, None) => return Err("pass --sandbox or --pending".into()),
    };
    let listing: Value = serde_json::from_str(listing.lines().last().unwrap_or("[]"))?;
    let record = find_request(&listing, &args.request)?;
    let roots = args
        .trusted_root
        .iter()
        .map(|root| read_public(root))
        .collect::<Result<Vec<_>>>()?;
    let (request, leaf) = review(record, &roots)?;
    let approver = read_secret(&args.approver_key)?;
    let listed = leaf
        .required_approvers()
        .is_some_and(|keys| keys.contains(&approver.public_key()));
    if !listed {
        return Err("this approver key is not one the warrant accepts".into());
    }

    // Everything shown here comes from the verified request and warrant.
    eprintln!("tool      {}", request.tool);
    eprintln!("arguments {}", serde_json::to_string(&request.args)?);
    eprintln!("message   {}", request.message);
    eprintln!("warrant   {}", leaf.id());
    eprintln!("request   {}", hex::encode(request.request_hash));
    eprintln!("expires   in {} seconds", args.ttl);
    if !args.yes && !confirm()? {
        return Err("not approved".into());
    }

    let who = std::env::var("USER").unwrap_or_else(|_| "operator".to_string());
    let approval = tenuo::sdk::approve_request(
        &request,
        &leaf,
        &approver,
        format!("tenuo-openshell:{who}"),
        Duration::from_secs(args.ttl.max(1)),
    )
    .map_err(|error| format!("approval refused: {error}"))?
    .to_cbor_b64()?;
    match &sandbox {
        Some(sandbox) => {
            openshell_exec(sandbox, &[AGENT, "install-approval", &approval])?;
            println!(
                "approved {} in sandbox {}",
                hex::encode(request.request_hash),
                sandbox.sandbox
            );
        }
        None => println!("{approval}"),
    }
    Ok(())
}

fn find_request<'a>(listing: &'a Value, wanted: &str) -> Result<&'a Value> {
    let wanted = wanted.trim().to_ascii_lowercase();
    if wanted.len() < 8 {
        return Err("use at least 8 characters of the request hash".into());
    }
    let matches: Vec<&Value> = listing
        .as_array()
        .ok_or("pending listing is not a JSON array")?
        .iter()
        .filter(|request| {
            request["request_hash"]
                .as_str()
                .is_some_and(|hash| hash.starts_with(&wanted))
        })
        .collect();
    match matches.as_slice() {
        [request] => Ok(request),
        [] => Err(format!("no pending request {wanted}").into()),
        _ => Err(format!("{wanted} matches more than one pending request").into()),
    }
}

/// Verify a pending record before anything in it is shown.
///
/// The sandbox wrote the record, so none of it is trusted: the warrant chain
/// must verify to one of `roots`, and the request core produced must match
/// that warrant (hash, holder, gate message, approvers, threshold, expiry).
fn review(record: &Value, roots: &[PublicKey]) -> Result<(ApprovalRequest, Warrant)> {
    let request: ApprovalRequest = serde_json::from_value(record["request"].clone())
        .map_err(|_| "pending record has no approval request")?;
    let chain = tenuo::meta_envelope::decode_warrant_chain(
        record["warrant"]
            .as_str()
            .ok_or("pending record has no warrant")?,
    )
    .map_err(|error| format!("pending warrant: {error}"))?;
    let mut authorizer = tenuo::Authorizer::new();
    for root in roots {
        authorizer.add_trusted_root(root.clone());
    }
    authorizer
        .verify_chain(&chain)
        .map_err(|error| format!("pending warrant does not verify to a trusted root: {error}"))?;
    let leaf = chain.last().ok_or("pending warrant is empty")?.clone();
    if !request.matches_warrant(&leaf)? {
        return Err("pending request does not match its warrant".into());
    }
    if record["request_hash"].as_str() != Some(hex::encode(request.request_hash).as_str()) {
        return Err("pending record hash does not match its request".into());
    }
    Ok((request, leaf))
}

fn confirm() -> Result<bool> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        return Err(
            "confirmation needs a terminal; pass --yes to approve non-interactively".into(),
        );
    }
    eprint!("approve this call? [y/N] ");
    std::io::stderr().flush()?;
    let mut answer = String::new();
    std::io::stdin().lock().read_line(&mut answer)?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

/// Capabilities JSON: tool name to argument constraints.
///
/// ```json
/// {"read_logs": {"service": "payments",
///                "environment": {"one_of": ["staging", "dev"]},
///                "lines": {"range": {"max": 500}},
///                "path": {"pattern": "/var/log/*"},
///                "query": {"wildcard": true}}}
/// ```
///
/// A bare value is an exact match.
fn parse_capabilities(text: &str) -> Result<Vec<(String, ConstraintSet)>> {
    let document: Value = serde_json::from_str(text)?;
    let tools = document
        .as_object()
        .filter(|tools| !tools.is_empty())
        .ok_or("capabilities must be a non-empty object of tools")?;
    let mut parsed = Vec::with_capacity(tools.len());
    for (tool, arguments) in tools {
        let arguments = arguments
            .as_object()
            .ok_or_else(|| format!("{tool}: constraints must be an object"))?;
        let mut set = ConstraintSet::new();
        for (field, spec) in arguments {
            add_constraint(&mut set, field, spec)
                .map_err(|error| format!("{tool}.{field}: {error}"))?;
        }
        parsed.push((tool.clone(), set));
    }
    Ok(parsed)
}

fn add_constraint(set: &mut ConstraintSet, field: &str, spec: &Value) -> Result<()> {
    let Some(object) = spec.as_object() else {
        set.insert(field, Exact::new(scalar(spec)?));
        return Ok(());
    };
    let (kind, value) = match object.iter().next() {
        Some(pair) if object.len() == 1 => pair,
        _ => return Err("use one of exact, one_of, pattern, range, wildcard".into()),
    };
    match kind.as_str() {
        "exact" => set.insert(field, Exact::new(scalar(value)?)),
        "one_of" => {
            let values = value
                .as_array()
                .filter(|values| !values.is_empty())
                .ok_or("one_of needs a non-empty list")?
                .iter()
                .map(scalar)
                .collect::<Result<Vec<_>>>()?;
            set.insert(field, OneOf::from_values(values));
        }
        "pattern" => set.insert(
            field,
            Pattern::new(value.as_str().ok_or("pattern needs a string")?)?,
        ),
        "range" => {
            let min = value.get("min").and_then(Value::as_f64);
            let max = value.get("max").and_then(Value::as_f64);
            if min.is_none() && max.is_none() {
                return Err("range needs min or max".into());
            }
            set.insert(field, Range::new(min, max)?);
        }
        "wildcard" if value == &Value::Bool(true) => set.insert(field, Wildcard::new()),
        _ => return Err(format!("unknown constraint {kind}").into()),
    }
    Ok(())
}

fn scalar(value: &Value) -> Result<ConstraintValue> {
    Ok(match value {
        Value::String(text) => ConstraintValue::String(text.clone()),
        Value::Bool(flag) => ConstraintValue::Boolean(*flag),
        Value::Number(number) => match number.as_i64() {
            Some(integer) => ConstraintValue::Integer(integer),
            None => ConstraintValue::Float(number.as_f64().ok_or("number out of range")?),
        },
        _ => return Err("expected a string, number, or boolean".into()),
    })
}

fn read_arg(value: &str) -> Result<String> {
    match value.strip_prefix('@') {
        Some(path) => Ok(fs::read_to_string(path)?),
        None => Ok(value.to_string()),
    }
}

fn read_public(value: &str) -> Result<PublicKey> {
    let text = if Path::new(value).is_file() {
        fs::read_to_string(value)?
    } else {
        value.to_string()
    };
    let bytes: [u8; 32] = hex::decode(text.trim())?
        .try_into()
        .map_err(|_| "public key must be 32 bytes")?;
    Ok(PublicKey::from_bytes(&bytes)?)
}

fn read_secret(path: &Path) -> Result<SigningKey> {
    let raw = fs::read(path)?;
    let bytes = match raw.len() {
        32 => raw,
        _ => hex::decode(String::from_utf8(raw)?.trim())?,
    };
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "private key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn decode_chain(bytes: &[u8]) -> Result<Vec<Warrant>> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(chain) = tenuo::meta_envelope::decode_warrant_chain(text) {
            return Ok(chain);
        }
    }
    if let Ok(stack) = tenuo::wire::decode_stack(bytes) {
        if !stack.0.is_empty() {
            return Ok(stack.0);
        }
    }
    Ok(vec![tenuo::wire::decode(bytes)?])
}

fn encode_chain(chain: &[Warrant]) -> Result<String> {
    Ok(tenuo::meta_envelope::encode_warrant_chain(chain)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_urls_parse_to_policy_entries() {
        let tools = vec!["read_logs".to_string()];
        assert_eq!(
            destination("https://MCP.internal/mcp?x=1", &tools).unwrap(),
            json!({"host": "mcp.internal", "port": 443, "path": "/mcp", "tools": ["read_logs"]})
        );
        assert_eq!(
            destination("http://mcp.internal:8080", &tools).unwrap(),
            json!({"host": "mcp.internal", "port": 8080, "tools": ["read_logs"]})
        );
        for bad in [
            "mcp.internal/mcp",
            "ftp://mcp/x",
            "https://user@mcp/x",
            "https://:1/x",
        ] {
            assert!(destination(bad, &tools).is_err(), "{bad}");
        }
        assert!(destination("https://mcp.internal/mcp", &[]).is_err());
    }

    #[test]
    fn adding_merges_and_bumps_the_version() {
        let root = hex::encode(SigningKey::generate().public_key().to_bytes());
        let mut document = json!({"version": 3, "max_warrant_lifetime_secs": 600, "sandboxes": {}});
        let read = destination("https://mcp.internal/mcp", &["read_logs".into()]).unwrap();
        add_to_policy(
            &mut document,
            "sbx",
            std::slice::from_ref(&root),
            Some(read),
            &[],
        )
        .unwrap();
        let restart = destination("https://mcp.internal/mcp", &["restart_service".into()]).unwrap();
        add_to_policy(
            &mut document,
            "sbx",
            std::slice::from_ref(&root),
            Some(restart),
            &["read_logs".into()],
        )
        .unwrap();
        assert_eq!(document["version"], 5);
        let sandbox = &document["sandboxes"]["sbx"];
        assert_eq!(sandbox["trusted_roots"].as_array().unwrap().len(), 1);
        assert_eq!(sandbox["destinations"].as_array().unwrap().len(), 1);
        assert_eq!(
            sandbox["destinations"][0]["tools"],
            json!(["read_logs", "restart_service"])
        );
        assert!(sandbox.get("single_use_tools").is_none());
        assert_eq!(sandbox["idempotent_tools"], json!(["read_logs"]));
        PolicySet::from_json(&serde_json::to_vec(&document).unwrap()).unwrap();
    }

    #[test]
    fn capability_specs_become_enforced_constraints() {
        let capabilities = parse_capabilities(
            r#"{"read_logs": {"service": "payments",
                              "environment": {"one_of": ["staging", "dev"]},
                              "lines": {"range": {"max": 500}},
                              "path": {"pattern": "/var/log/*"},
                              "query": {"wildcard": true}}}"#,
        )
        .unwrap();
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let (tool, constraints) = capabilities.into_iter().next().unwrap();
        let warrant = Warrant::builder()
            .capability(tool, constraints)
            .holder(holder.public_key())
            .ttl(Duration::from_secs(60))
            .build(&issuer)
            .unwrap();
        let allowed = json!({"service": "payments", "environment": "dev", "lines": 20,
                             "path": "/var/log/app.log", "query": "error"});
        let denied = json!({"service": "payments", "environment": "production", "lines": 20,
                            "path": "/var/log/app.log", "query": "error"});
        let args = |value: &Value| {
            value
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| (key.clone(), scalar(value).unwrap()))
                .collect::<std::collections::HashMap<_, _>>()
        };
        assert!(warrant
            .check_constraints("read_logs", &args(&allowed))
            .is_ok());
        assert!(warrant
            .check_constraints("read_logs", &args(&denied))
            .is_err());

        for bad in [
            r#"{}"#,
            r#"{"t": {"a": {"range": {}}}}"#,
            r#"{"t": {"a": {"one_of": []}}}"#,
            r#"{"t": {"a": {"exact": 1, "pattern": "x"}}}"#,
            r#"{"t": {"a": {"regex": "x"}}}"#,
        ] {
            assert!(parse_capabilities(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn listed_constraints_close_the_argument_set() {
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let mut capabilities = parse_capabilities(r#"{"closed": {"a": "x"}, "open": {}}"#).unwrap();
        let mut builder = Warrant::builder();
        for (tool, constraints) in capabilities.drain(..) {
            builder = builder.capability(tool, constraints);
        }
        let warrant = builder
            .holder(holder.public_key())
            .ttl(Duration::from_secs(60))
            .build(&issuer)
            .unwrap();
        let extra: std::collections::HashMap<String, ConstraintValue> = [
            ("a".to_string(), ConstraintValue::String("x".into())),
            ("b".to_string(), ConstraintValue::String("y".into())),
        ]
        .into();
        assert!(warrant.check_constraints("closed", &extra).is_err());
        assert!(warrant.check_constraints("open", &extra).is_ok());
    }

    #[test]
    fn attenuation_narrows_the_parent() {
        let directory = tempfile::tempdir().unwrap();
        let issuer = SigningKey::generate();
        let parent_key = SigningKey::generate();
        let child = SigningKey::generate();
        let parent_key_path = directory.path().join("parent.key");
        fs::write(&parent_key_path, parent_key.secret_key_bytes()).unwrap();
        let parent = Warrant::builder()
            .capability("read_logs", ConstraintSet::new())
            .capability("restart_service", ConstraintSet::new())
            .holder(parent_key.public_key())
            .ttl(Duration::from_secs(600))
            .build(&issuer)
            .unwrap();
        let parent_path = directory.path().join("parent.warrant");
        fs::write(&parent_path, encode_chain(&[parent]).unwrap()).unwrap();
        let args = AuthorityArgs {
            issuer_key: None,
            parent_key: Some(parent_key_path),
            parent_warrant: Some(parent_path),
            capabilities: r#"{"read_logs": {}}"#.to_string(),
            ttl: 60,
        };
        let chain = issue(&args, &child.public_key()).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].tools(), vec!["read_logs".to_string()]);
        assert_eq!(chain[1].authorized_holder(), &child.public_key());
    }

    fn gated_warrant(issuer: &SigningKey, holder: &SigningKey, approver: &SigningKey) -> Warrant {
        let mut gates = tenuo::ApprovalGateMap::new();
        gates.insert(
            "restart_service".to_string(),
            tenuo::ToolApprovalGate::whole_tool(),
        );
        Warrant::builder()
            .capability("restart_service", ConstraintSet::new())
            .holder(holder.public_key())
            .required_approvers(vec![approver.public_key()])
            .min_approvals(1)
            .extension(
                tenuo::APPROVAL_GATE_EXTENSION_KEY,
                tenuo::encode_approval_gate_map(&gates).unwrap(),
            )
            .ttl(Duration::from_secs(300))
            .build(issuer)
            .unwrap()
    }

    #[test]
    fn review_shows_only_a_request_that_matches_a_trusted_warrant() {
        use std::sync::Arc;
        use tenuo::sdk::prelude::*;
        let issuer = SigningKey::generate();
        let holder = SigningKey::generate();
        let approver = SigningKey::generate();
        let warrant = gated_warrant(&issuer, &holder, &approver);
        let authority =
            PresentedAuthority::new(vec![warrant.clone()], Arc::new(LocalSigner::new(holder)))
                .unwrap();
        let mut authorizer = tenuo::Authorizer::new();
        authorizer.add_trusted_root(issuer.public_key());
        let guard = Guard::builder()
            .authorizer(authorizer)
            .revocation(RevocationMode::TtlOnly {
                max_lifetime: Duration::from_secs(3600),
            })
            .build()
            .unwrap();
        let arguments = json!({"service": "payments", "replicas": 3});
        let call = Call::try_from_json("restart_service", &arguments).unwrap();
        let Err(denial) = guard.check(&authority, &call) else {
            panic!("a gated call was allowed without an approval");
        };
        let request = denial.approval_request().unwrap().clone();
        let record = json!({
            "request_hash": hex::encode(request.request_hash),
            "tool": "restart_service",
            "arguments": arguments,
            "request": request,
            "warrant": encode_chain(std::slice::from_ref(&warrant)).unwrap(),
        });
        let roots = [issuer.public_key()];

        let (reviewed, leaf) = review(&record, &roots).unwrap();
        let approval =
            tenuo::sdk::approve_request(&reviewed, &leaf, &approver, "t", Duration::from_secs(60))
                .unwrap();
        assert_eq!(
            approval.verify().unwrap().request_hash,
            request.request_hash
        );

        assert!(review(&record, &[SigningKey::generate().public_key()]).is_err());
        let mut tampered = record.clone();
        tampered["request"]["args"]["replicas"] = json!(30);
        assert!(review(&tampered, &roots).is_err());
        let mut message = record.clone();
        message["request"]["message"] = json!("Approve a harmless read");
        assert!(review(&message, &roots).is_err());
        let other = gated_warrant(&issuer, &SigningKey::generate(), &approver);
        let mut swapped = record.clone();
        swapped["warrant"] = json!(encode_chain(&[other]).unwrap());
        assert!(review(&swapped, &roots).is_err());
        let mut listed = record.clone();
        listed["request_hash"] = json!("00".repeat(32));
        assert!(review(&listed, &roots).is_err());

        let listing = json!([record, {"request_hash": "ffff0000aaaa"}]);
        let prefix = &hex::encode(request.request_hash)[..10];
        assert_eq!(
            find_request(&listing, prefix).unwrap()["tool"],
            "restart_service"
        );
        assert!(find_request(&listing, "ab").is_err());
        assert!(find_request(&listing, "0000000000").is_err());
    }

    fn register_args() -> RegisterArgs {
        RegisterArgs {
            middleware_endpoint: Some("https://tenuo:50051".into()),
            ca: Some("/etc/ca.pem".into()),
            insecure_dev: false,
            only: None,
            mcp_host: vec!["mcp.internal".into()],
            audience: DEFAULT_AUDIENCE.into(),
            preserve_meta: true,
            openshell_policy: None,
        }
    }

    #[test]
    fn register_output_names_the_hosts_and_meta_mode() {
        let text = register(&register_args()).unwrap();
        assert!(text.contains("grpc_endpoint = \"https://tenuo:50051\""));
        assert!(text.contains("tls_ca_cert_path = \"/etc/ca.pem\"\n"));
        assert!(text.contains("        - mcp.internal\n"));
        assert!(text.contains("forward_proof"));
        assert!(!text.contains("tenuo_meta"));
        assert!(!text.contains("allow_insecure_transport"));
        assert!(text.contains("timeout = \"2s\"\n\n# Sandbox policy."));
    }

    #[test]
    fn mcp_host_is_needed_only_for_the_sandbox_block() {
        let mut args = register_args();
        args.mcp_host.clear();
        args.only = Some(RegisterPart::Gateway);
        assert!(register(&args).is_ok());
        args.only = Some(RegisterPart::Sandbox);
        assert!(register(&args).is_err());
        args.only = None;
        assert!(register(&args).is_err());
    }

    #[test]
    fn register_prints_one_block_on_request() {
        let both = register(&register_args()).unwrap();
        let gateway = register(&RegisterArgs {
            only: Some(RegisterPart::Gateway),
            ..register_args()
        })
        .unwrap();
        let sandbox = register(&RegisterArgs {
            only: Some(RegisterPart::Sandbox),
            middleware_endpoint: None,
            ca: None,
            ..register_args()
        })
        .unwrap();
        assert_eq!(both, format!("{gateway}\n{sandbox}"));
        assert!(gateway.contains("[[openshell.supervisor.middleware]]"));
        assert!(!gateway.contains("network_middlewares"));
        assert!(sandbox.contains("network_middlewares:"));
        assert!(!sandbox.contains("grpc_endpoint"));
        assert!(gateway.ends_with("timeout = \"2s\"\n"));
        let yaml: serde_yaml::Value = serde_yaml::from_str(&sandbox).unwrap();
        assert!(yaml["network_middlewares"]["tenuo-task-authority"].is_mapping());
    }

    #[test]
    fn register_keeps_plaintext_behind_insecure_dev() {
        let plaintext = RegisterArgs {
            middleware_endpoint: Some("http://127.0.0.1:50051".into()),
            ..register_args()
        };
        assert!(register(&plaintext).is_err());
        let no_ca = RegisterArgs {
            ca: None,
            ..register_args()
        };
        assert!(register(&no_ca).is_err());
        assert!(register(&RegisterArgs {
            middleware_endpoint: None,
            ..register_args()
        })
        .is_err());

        let dev = RegisterArgs {
            ca: None,
            insecure_dev: true,
            ..plaintext
        };
        let text = register(&dev).unwrap();
        assert!(text.contains("grpc_endpoint = \"http://127.0.0.1:50051\""));
        assert!(text.contains("allow_insecure_transport = true\n"));
        assert!(!text.contains("tls_ca_cert_path"));
        assert!(register(&RegisterArgs {
            middleware_endpoint: Some("https://tenuo:50051".into()),
            ..dev
        })
        .is_err());
    }

    #[test]
    fn keygen_writes_a_key_pair_the_other_commands_read() {
        let directory = tempfile::tempdir().unwrap();
        let secret = directory.path().join("issuer.key");
        let public = directory.path().join("issuer.pub");
        keygen(&KeygenArgs {
            out: secret.clone(),
            public_out: Some(public.clone()),
        })
        .unwrap();
        let key = read_secret(&secret).unwrap();
        let listed = read_public(public.to_str().unwrap()).unwrap();
        assert_eq!(key.public_key(), listed);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Neither file is overwritten, and a refused public file leaves no
        // orphaned secret behind.
        let again = KeygenArgs {
            out: secret.clone(),
            public_out: None,
        };
        assert!(keygen(&again).is_err());
        assert_eq!(read_secret(&secret).unwrap().public_key(), listed);
        let fresh = directory.path().join("other.key");
        assert!(keygen(&KeygenArgs {
            out: fresh.clone(),
            public_out: Some(public.clone()),
        })
        .is_err());
        assert!(!fresh.exists());
    }

    #[test]
    fn sign_with_signs_every_policy_version_written() {
        use tenuo_openshell_middleware::policy::{policy_signature_path, verify_policy_document};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let key_path = directory.path().join("policy-signing.key");
        let key = SigningKey::generate();
        fs::write(&key_path, hex::encode(key.secret_key_bytes())).unwrap();
        let verify = || {
            let document = fs::read(&path).unwrap();
            let signature = fs::read(policy_signature_path(&path)).unwrap();
            verify_policy_document(&document, &signature, &key.public_key())
        };

        policy_init(&PolicyInitArgs {
            policy: path.clone(),
            max_warrant_lifetime_secs: 600,
            sign_with: Some(key_path.clone()),
        })
        .unwrap();
        assert!(verify().is_ok());

        let root = hex::encode(SigningKey::generate().public_key().to_bytes());
        policy_add(&PolicyAddArgs {
            policy: path.clone(),
            sandbox_id: "sbx".into(),
            trusted_root: vec![root],
            mcp: Some("https://mcp.internal/mcp".into()),
            tools: vec!["read_logs".into()],
            single_use: vec![],
            idempotent: vec![],
            max_warrant_lifetime_secs: 600,
            sign_with: Some(key_path),
        })
        .unwrap();
        assert!(verify().is_ok());
        assert_eq!(PolicySet::load(&path).unwrap().version(), 2);
    }

    #[test]
    fn policy_init_creates_an_empty_policy_once() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.json");
        let args = PolicyInitArgs {
            policy: path.clone(),
            max_warrant_lifetime_secs: 600,
            sign_with: None,
        };
        policy_init(&args).unwrap();
        let policy = PolicySet::load(&path).unwrap();
        assert_eq!(policy.sandbox_count(), 0);
        assert_eq!(policy.version(), 1);
        assert!(policy_init(&args).is_err());

        let root = hex::encode(SigningKey::generate().public_key().to_bytes());
        let mut document: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        add_to_policy(&mut document, "sbx", &[root], None, &[]).unwrap();
        assert_eq!(document["version"], 2);
        assert_eq!(document["max_warrant_lifetime_secs"], 600);
    }

    #[test]
    fn register_refuses_an_uncovered_route_to_a_protected_host() {
        let hosts = ["mcp.internal".to_string()];
        let policy = |endpoint: &str| {
            format!("network_policies:\n  mcp:\n    endpoints:\n      - {endpoint}\n")
        };
        let covered = policy("{host: mcp.internal, port: 443, protocol: mcp}");
        assert!(reject_uncovered_routes(&covered, &hosts).is_ok());
        let other = policy("{host: other.internal, port: 443, tls: skip}");
        assert!(reject_uncovered_routes(&other, &hosts).is_ok());
        for uncovered in [
            "{host: mcp.internal, port: 443}",
            "{host: MCP.INTERNAL, port: 443, protocol: tcp}",
            "{host: mcp.internal, port: 443, protocol: mcp, tls: skip}",
            "{host: '*.internal', port: 443}",
            "{host: '**', port: 443, protocol: websocket}",
        ] {
            assert!(
                reject_uncovered_routes(&policy(uncovered), &hosts).is_err(),
                "{uncovered}"
            );
        }
        // A middleware selector naming the host is not a route.
        let selector =
            "network_middlewares:\n  t:\n    endpoints:\n      include: [mcp.internal]\n";
        assert!(reject_uncovered_routes(selector, &hosts).is_ok());
    }

    #[test]
    fn host_patterns_follow_openshell_label_rules() {
        assert!(host_pattern_matches("mcp.internal", "MCP.internal"));
        assert!(host_pattern_matches("*.internal", "mcp.internal"));
        assert!(!host_pattern_matches("*.internal", "a.mcp.internal"));
        assert!(host_pattern_matches("**.internal", "a.mcp.internal"));
        assert!(!host_pattern_matches("**.internal", "internal"));
        assert!(host_pattern_matches("mcp-?.internal", "mcp-1.internal"));
        assert!(!host_pattern_matches("other.internal", "mcp.internal"));
    }
}

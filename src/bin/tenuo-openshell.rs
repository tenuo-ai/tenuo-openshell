//! Operator commands for Tenuo on NVIDIA OpenShell.
//!
//! ```text
//! tenuo-openshell policy add --policy policy.json --sandbox-id <id> \
//!     --trusted-root <hex> --mcp https://mcp.internal/mcp --tools read_logs
//! tenuo-openshell register --middleware-endpoint https://tenuo:50051 \
//!     --ca /etc/openshell/tenuo-ca.pem --mcp-host mcp.internal
//! tenuo-openshell provision --sandbox <name> --issuer-key issuer.key \
//!     --capabilities caps.json --ttl 3600
//! ```

use clap::{Args, Parser, Subcommand};
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
#[command(version, about = "Operator commands for Tenuo on NVIDIA OpenShell")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    /// Review a pending approval request, sign it, and install it.
    Approve(ApproveArgs),
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Add a sandbox, trust root, or MCP destination. Creates the file if needed
    /// and increments its version.
    Add(PolicyAddArgs),
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
    /// Tools whose signed calls are accepted once.
    #[arg(long, value_delimiter = ',')]
    single_use: Vec<String>,
    /// Maximum warrant lifetime for a new policy file.
    #[arg(long, default_value_t = 3600)]
    max_warrant_lifetime_secs: u64,
}

#[derive(Args)]
struct RegisterArgs {
    /// HTTPS endpoint the OpenShell gateway uses to reach the middleware.
    #[arg(long)]
    middleware_endpoint: String,
    /// CA certificate path, as seen by the gateway.
    #[arg(long)]
    ca: String,
    /// MCP host the sandbox policy attaches the middleware to. Repeatable.
    #[arg(long, required = true)]
    mcp_host: Vec<String>,
    #[arg(long, default_value = DEFAULT_AUDIENCE)]
    audience: String,
    /// Keep `_meta.tenuo` on forwarded requests for a destination that verifies it.
    #[arg(long)]
    preserve_meta: bool,
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
        Command::Policy(PolicyCommand::Add(args)) => policy_add(&args),
        Command::Register(args) => {
            print!("{}", register(&args));
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
    }
}

fn policy_add(args: &PolicyAddArgs) -> Result<()> {
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
        &args.single_use,
    )?;
    let bytes = serde_json::to_vec_pretty(&document)?;
    PolicySet::from_json(&bytes)
        .map_err(|error| format!("resulting policy is invalid: {error}"))?;
    let staging = args.policy.with_extension("tmp");
    fs::write(&staging, [bytes.as_slice(), b"\n"].concat())?;
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
    single_use: &[String],
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
        "single_use_tools",
        single_use.iter().map(|tool| json!(tool)),
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

fn register(args: &RegisterArgs) -> String {
    let hosts = args
        .mcp_host
        .iter()
        .map(|host| format!("        - {host}\n"))
        .collect::<String>();
    let config = if args.preserve_meta {
        "    config:\n      tenuo_meta: preserve\n"
    } else {
        ""
    };
    format!(
        "# OpenShell gateway configuration\n\
         [[openshell.supervisor.middleware]]\n\
         name = \"tenuo/authorization\"\n\
         grpc_endpoint = \"{endpoint}\"\n\
         tls_ca_cert_path = \"{ca}\"\n\
         audience = \"{audience}\"\n\
         max_payload_bytes = 262144\n\
         timeout = \"2s\"\n\
         \n\
         # Sandbox policy. List {AGENT} as the only binary allowed to reach\n\
         # these hosts so every tools/call is signed in the sandbox.\n\
         network_middlewares:\n  \
           tenuo-task-authority:\n    \
             middleware: tenuo/authorization\n    \
             on_error: fail_closed\n\
         {config}    \
             endpoints:\n      \
               include:\n\
         {hosts}",
        endpoint = args.middleware_endpoint,
        ca = args.ca,
        audience = args.audience,
    )
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
            &["restart_service".into()],
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
        assert_eq!(sandbox["single_use_tools"], json!(["restart_service"]));
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

    #[test]
    fn register_output_names_the_hosts_and_meta_mode() {
        let text = register(&RegisterArgs {
            middleware_endpoint: "https://tenuo:50051".into(),
            ca: "/etc/ca.pem".into(),
            mcp_host: vec!["mcp.internal".into()],
            audience: DEFAULT_AUDIENCE.into(),
            preserve_meta: true,
        });
        assert!(text.contains("grpc_endpoint = \"https://tenuo:50051\""));
        assert!(text.contains("        - mcp.internal\n"));
        assert!(text.contains("tenuo_meta: preserve"));
    }
}

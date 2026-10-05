//! `tenuo-openshell dev`: a development middleware and demo MCP server next
//! to an installed OpenShell gateway.
//!
//! Both run as Docker containers published on 127.0.0.1 only. That one
//! address works from the gateway on the host and from OpenShell's Docker
//! supervisors, which use host networking: on Linux that is the host itself,
//! and on Docker Desktop the published port is also bound on the Linux VM's
//! loopback. The OpenShell installation is never edited; `dev up` prints the
//! registration block for the operator to add.

use crate::{
    add_to_policy, destination, empty_policy, openshell_command, register_gateway, write_key_pair,
    RegisterArgs, Result, SandboxArgs, DEFAULT_AUDIENCE,
};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::time::{Duration, Instant};

pub const MIDDLEWARE_CONTAINER: &str = "tenuo-openshell-dev";
pub const MCP_CONTAINER: &str = "tenuo-openshell-dev-mcp";
pub const DEMO_SANDBOX: &str = "tenuo-demo";
pub const DEMO_TOOLS: [&str; 2] = ["read_logs", "restart_service"];
const SPEC_LABEL: &str = "ai.tenuo.openshell.dev.spec";
const DEFAULT_IMAGE: &str = concat!(
    "ghcr.io/tenuo-ai/tenuo-openshell:v",
    env!("CARGO_PKG_VERSION")
);
const DEFAULT_DEMO_IMAGE: &str = concat!(
    "ghcr.io/tenuo-ai/tenuo-openshell-demo:v",
    env!("CARGO_PKG_VERSION")
);
const DOCKER: &str = "docker";

#[derive(Subcommand)]
pub enum DevCommand {
    /// Start the development middleware and the demo MCP server, and print
    /// the OpenShell gateway registration. Safe to run again.
    Up(UpArgs),
    /// Stop both containers. Keys and policy stay for the next `dev up`.
    Down,
    /// Show the containers, the policy they serve, and the gateway registration.
    Status,
}

#[derive(Args)]
pub struct UpArgs {
    /// Middleware port on 127.0.0.1. Its health port is the next one.
    #[arg(long, default_value_t = 18651)]
    port: u16,
    /// Demo MCP server port on 127.0.0.1.
    #[arg(long, default_value_t = 18680)]
    mcp_port: u16,
    /// Middleware image.
    #[arg(long, env = "TENUO_OPENSHELL_IMAGE", default_value = DEFAULT_IMAGE)]
    image: String,
    /// Demo image: the sandbox image and the demo MCP server.
    #[arg(long, env = "TENUO_OPENSHELL_DEMO_IMAGE", default_value = DEFAULT_DEMO_IMAGE)]
    demo_image: String,
}

/// What `dev up` started, for the commands that use it later.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DevConfig {
    pub port: u16,
    pub mcp_port: u16,
    pub image: String,
    pub demo_image: String,
}

impl DevConfig {
    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn admin_port(&self) -> u16 {
        self.port + 1
    }

    /// The demo MCP server as the sandbox reaches it.
    pub fn mcp_url(&self) -> String {
        format!("http://host.openshell.internal:{}/mcp", self.mcp_port)
    }
}

/// The dev state directory: keys, the middleware policy, and the demo
/// sandbox policy. `TENUO_OPENSHELL_DEV_DIR`, or
/// `$XDG_STATE_HOME/tenuo-openshell/dev` (`~/.local/state/...`).
pub struct DevState {
    pub dir: PathBuf,
}

impl DevState {
    pub fn locate() -> Result<Self> {
        if let Some(dir) = std::env::var_os("TENUO_OPENSHELL_DEV_DIR").filter(|v| !v.is_empty()) {
            return Ok(Self { dir: dir.into() });
        }
        let base = match std::env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => home()?.join(".local/state"),
        };
        Ok(Self {
            dir: base.join("tenuo-openshell/dev"),
        })
    }

    pub fn issuer_key(&self) -> PathBuf {
        self.dir.join("issuer.key")
    }

    pub fn issuer_public(&self) -> PathBuf {
        self.dir.join("issuer.pub")
    }

    pub fn approver_key(&self) -> PathBuf {
        self.dir.join("approver.key")
    }

    pub fn approver_public(&self) -> PathBuf {
        self.dir.join("approver.pub")
    }

    fn policy_dir(&self) -> PathBuf {
        self.dir.join("policy")
    }

    pub fn policy(&self) -> PathBuf {
        self.policy_dir().join("policy.json")
    }

    pub fn sandbox_policy(&self) -> PathBuf {
        self.dir.join("demo-policy.yaml")
    }

    fn config_path(&self) -> PathBuf {
        self.dir.join("dev.json")
    }

    pub fn config(&self) -> Result<DevConfig> {
        let bytes = fs::read(self.config_path()).map_err(|_| {
            format!(
                "no dev environment in {}; run `tenuo-openshell dev up` first",
                self.dir.display()
            )
        })?;
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn home() -> Result<PathBuf> {
    Ok(std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or("HOME is not set")?
        .into())
}

pub fn run(command: &DevCommand) -> Result<()> {
    let state = DevState::locate()?;
    match command {
        DevCommand::Up(args) => up(&state, args),
        DevCommand::Down => down(&state),
        DevCommand::Status => status(&state),
    }
}

fn up(state: &DevState, args: &UpArgs) -> Result<()> {
    if args.port == u16::MAX || args.port + 1 == args.mcp_port || args.port == args.mcp_port {
        return Err("--port, its health port (--port + 1), and --mcp-port must differ".into());
    }
    let config = DevConfig {
        port: args.port,
        mcp_port: args.mcp_port,
        image: args.image.clone(),
        demo_image: args.demo_image.clone(),
    };
    prepare_state(state, &config)?;

    let started = ensure_container(MIDDLEWARE_CONTAINER, &middleware_spec(state, &config)?)?;
    let mcp_started = ensure_container(MCP_CONTAINER, &mcp_spec(&config))?;
    wait_until(MIDDLEWARE_CONTAINER, || {
        http_get(config.admin_port(), "/ready").is_ok_and(|(code, _)| code == 200)
    })?;
    wait_until(MCP_CONTAINER, || http_get(config.mcp_port, "/mcp").is_ok())?;

    let verb = |fresh: bool| if fresh { "started" } else { "running" };
    println!(
        "middleware  {}  {}  ({})",
        verb(started),
        config.endpoint(),
        config.image
    );
    println!(
        "MCP server  {}  {}  ({})",
        verb(mcp_started),
        config.mcp_url(),
        config.demo_image
    );
    println!("state       {}", state.dir.display());
    println!();
    println!("Development only: no TLS, no caller authentication, unsigned policy.");
    println!();
    print!("{}", next_steps(state, &config, &GatewayConfig::locate()?)?);
    Ok(())
}

/// Keys, policy, and the demo sandbox policy. Existing keys and policy are
/// kept, so a second `dev up` serves the same trust.
fn prepare_state(state: &DevState, config: &DevConfig) -> Result<()> {
    create_private_dir(&state.dir)?;
    fs::create_dir_all(state.policy_dir())?;
    for (key, public) in [
        (state.issuer_key(), state.issuer_public()),
        (state.approver_key(), state.approver_public()),
    ] {
        match (key.exists(), public.exists()) {
            (true, true) => {}
            (false, false) => {
                write_key_pair(&key, Some(&public))?;
            }
            _ => {
                return Err(format!(
                    "{} and {} must both exist or both be missing",
                    key.display(),
                    public.display()
                )
                .into())
            }
        }
    }
    if !state.policy().exists() {
        let bytes = [
            serde_json::to_vec_pretty(&empty_policy(3600))?.as_slice(),
            b"\n",
        ]
        .concat();
        write_atomic(&state.policy(), &bytes)?;
    }
    write_atomic(
        &state.sandbox_policy(),
        demo_sandbox_policy(config).as_bytes(),
    )?;
    write_atomic(
        &state.config_path(),
        &[serde_json::to_vec_pretty(config)?.as_slice(), b"\n"].concat(),
    )?;
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let staging = path.with_extension("tmp");
    fs::write(&staging, bytes)?;
    fs::rename(&staging, path)?;
    Ok(())
}

/// The OpenShell sandbox policy for the demo. The agent is the only binary
/// that may reach the MCP server with a signed call. curl may reach it too,
/// only so `demo call --unsigned` can show the middleware deny a call that
/// skips the agent.
pub fn demo_sandbox_policy(config: &DevConfig) -> String {
    format!(
        "# OpenShell sandbox policy for the Tenuo demo. Written by `tenuo-openshell dev up`.\n\
         version: 1\n\
         \n\
         network_middlewares:\n  \
           tenuo:\n    \
             middleware: tenuo/authorization\n    \
             on_error: fail_closed\n    \
             endpoints:\n      \
               include:\n        \
                 - host.openshell.internal\n\
         \n\
         network_policies:\n  \
           tenuo-demo-mcp:\n    \
             name: Tenuo demo MCP server\n    \
             endpoints:\n      \
               - host: host.openshell.internal\n        \
                 port: {port}\n        \
                 path: /mcp\n        \
                 protocol: mcp\n        \
                 enforcement: enforce\n        \
                 rules:\n          \
                   - allow: {{method: initialize}}\n          \
                   - allow: {{method: notifications/initialized}}\n          \
                   - allow: {{method: tools/list}}\n          \
                   - allow: {{method: tools/call, tool: read_logs}}\n          \
                   - allow: {{method: tools/call, tool: restart_service}}\n    \
             binaries:\n      \
               - path: /usr/local/bin/tenuo-openshell-agent\n      \
               # Only so `tenuo-openshell demo call --unsigned` can show a call\n      \
               # that skips the agent. List only the agent in your own policy.\n      \
               - path: /usr/bin/curl\n",
        port = config.mcp_port
    )
}

fn middleware_spec(state: &DevState, config: &DevConfig) -> Result<Vec<String>> {
    let mut spec = vec![
        "-e".to_string(),
        "TENUO_DECISION_LOG=1".to_string(),
        "-p".to_string(),
        format!("127.0.0.1:{}:50051", config.port),
        "-p".to_string(),
        format!("127.0.0.1:{}:9090", config.admin_port()),
        "-v".to_string(),
        format!("{}:/etc/tenuo:ro", state.policy_dir().display()),
    ];
    // Run as the owner of the state directory, so the policy is readable
    // whatever its mode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&state.dir)?;
        spec.extend([
            "--user".to_string(),
            format!("{}:{}", metadata.uid(), metadata.gid()),
        ]);
    }
    spec.extend(
        [
            config.image.as_str(),
            "--policy",
            "/etc/tenuo/policy.json",
            "--insecure-dev",
            "--allow-in-memory-replay",
            "--listen",
            "0.0.0.0:50051",
            "--admin-listen",
            "0.0.0.0:9090",
            "--policy-reload-secs",
            "1",
        ]
        .map(String::from),
    );
    Ok(spec)
}

fn mcp_spec(config: &DevConfig) -> Vec<String> {
    vec![
        "-p".to_string(),
        format!("127.0.0.1:{}:8080", config.mcp_port),
        config.demo_image.clone(),
        "tenuo-demo-mcp".to_string(),
        "--port".to_string(),
        "8080".to_string(),
    ]
}

fn spec_hash(spec: &[String]) -> String {
    hex::encode(&Sha256::digest(spec.join("\0").as_bytes())[..8])
}

/// Run `docker run -d <spec>` as `name`, unless a container with that name
/// already runs the same spec. Returns whether it started one.
fn ensure_container(name: &str, spec: &[String]) -> Result<bool> {
    let hash = spec_hash(spec);
    let format = format!("{{{{.State.Running}}}} {{{{index .Config.Labels \"{SPEC_LABEL}\"}}}}");
    let inspected = Process::new(DOCKER)
        .args(["inspect", "--type", "container", "--format", &format, name])
        .stderr(Stdio::null())
        .output()
        .map_err(|error| format!("{DOCKER}: {error}"))?;
    if inspected.status.success() {
        if String::from_utf8_lossy(&inspected.stdout).trim() == format!("true {hash}") {
            return Ok(false);
        }
        remove_container(name)?;
    }
    let output = Process::new(DOCKER)
        .args(["run", "-d", "--name", name, "--label"])
        .arg(format!("{SPEC_LABEL}={hash}"))
        .args(spec)
        .stderr(Stdio::inherit())
        .output()?;
    if !output.status.success() {
        return Err(format!("could not start {name}").into());
    }
    Ok(true)
}

/// Remove a container. Returns whether one existed.
fn remove_container(name: &str) -> Result<bool> {
    let exists = Process::new(DOCKER)
        .args([
            "inspect",
            "--type",
            "container",
            "--format",
            "{{.Id}}",
            name,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("{DOCKER}: {error}"))?
        .success();
    if !exists {
        return Ok(false);
    }
    let output = Process::new(DOCKER).args(["rm", "-f", name]).output()?;
    if !output.status.success() {
        return Err(format!(
            "{DOCKER} rm {name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(true)
}

fn wait_until(name: &str, ready: impl Fn() -> bool) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if ready() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let logs = Process::new(DOCKER)
        .args(["logs", "--tail", "20", name])
        .output()
        .map(|output| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .unwrap_or_default();
    Err(format!(
        "{name} did not become ready; its last log lines:\n{}",
        logs.trim_end()
    )
    .into())
}

/// A minimal HTTP/1.0 GET to 127.0.0.1, for health and metrics.
fn http_get(port: u16, path: &str) -> Result<(u16, String)> {
    let timeout = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&([127, 0, 0, 1], port).into(), timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let code = response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or("not an HTTP response")?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok((code, body))
}

fn policy_metrics(config: &DevConfig) -> Option<(u64, u64)> {
    let (_, body) = http_get(config.admin_port(), "/metrics").ok()?;
    let metric = |name: &str| {
        body.lines()
            .find_map(|line| line.strip_prefix(name)?.trim().parse::<u64>().ok())
    };
    Some((
        metric("tenuo_openshell_policy_version ")?,
        metric("tenuo_openshell_policy_sandboxes ")?,
    ))
}

/// Where the installed gateway reads its configuration: the XDG path, then
/// on macOS the Homebrew prefix path. When neither exists, the XDG path,
/// which the operator creates.
pub struct GatewayConfig {
    pub path: PathBuf,
    pub contents: Option<String>,
}

impl GatewayConfig {
    pub fn locate() -> Result<Self> {
        let config_home = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Some(dir) => PathBuf::from(dir),
            None => home()?.join(".config"),
        };
        let xdg = config_home.join("openshell/gateway.toml");
        let mut candidates = vec![xdg.clone()];
        if cfg!(target_os = "macos") {
            let prefix = std::env::var_os("HOMEBREW_PREFIX")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt/homebrew"));
            candidates.push(prefix.join("var/openshell/gateway.toml"));
        }
        for path in candidates {
            if let Ok(contents) = fs::read_to_string(&path) {
                return Ok(Self {
                    path,
                    contents: Some(contents),
                });
            }
        }
        Ok(Self {
            path: xdg,
            contents: None,
        })
    }

    /// The `grpc_endpoint` of the `tenuo/authorization` registration, if any.
    pub fn registered_endpoint(&self) -> Option<String> {
        registered_endpoint(self.contents.as_deref()?)
    }
}

/// Find the `tenuo/authorization` entry among the
/// `[[openshell.supervisor.middleware]]` tables and return its endpoint.
/// A line scan, enough for the flat tables `register` prints.
fn registered_endpoint(toml: &str) -> Option<String> {
    let mut in_middleware = false;
    let mut name = None;
    let mut endpoint = None;
    let mut found = None;
    let mut finish = |name: &mut Option<String>, endpoint: &mut Option<String>| {
        if name.as_deref() == Some("tenuo/authorization") {
            found = endpoint.take().or(Some(String::new()));
        }
        *name = None;
        *endpoint = None;
    };
    for line in toml.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            if in_middleware {
                finish(&mut name, &mut endpoint);
            }
            in_middleware = line.replace(' ', "") == "[[openshell.supervisor.middleware]]";
            continue;
        }
        if !in_middleware {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"').to_string();
            match key.trim() {
                "name" => name = Some(value),
                "grpc_endpoint" => endpoint = Some(value),
                _ => {}
            }
        }
    }
    if in_middleware {
        finish(&mut name, &mut endpoint);
    }
    found
}

pub fn restart_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "brew services restart openshell"
    } else {
        "systemctl --user restart openshell-gateway"
    }
}

fn registration_block(config: &DevConfig) -> Result<String> {
    register_gateway(&RegisterArgs {
        middleware_endpoint: Some(config.endpoint()),
        ca: None,
        insecure_dev: true,
        only: None,
        mcp_host: Vec::new(),
        audience: DEFAULT_AUDIENCE.to_string(),
        preserve_meta: false,
        openshell_policy: None,
    })
}

fn next_steps(state: &DevState, config: &DevConfig, gateway: &GatewayConfig) -> Result<String> {
    let block = registration_block(config)?;
    let restart = restart_command();
    let path = gateway.path.display();
    let register = match (&gateway.contents, gateway.registered_endpoint()) {
        (_, Some(endpoint)) if endpoint == config.endpoint() => format!(
            "1. {path} already registers this middleware.\n   \
             If the gateway is not running, restart it: {restart}\n"
        ),
        (_, Some(endpoint)) => format!(
            "1. {path} registers tenuo/authorization at {endpoint}.\n   \
             Replace that block with this one:\n\n{block}\n   \
             Then restart the gateway:\n\n   {restart}\n"
        ),
        (Some(_), None) => format!(
            "1. Register the middleware with your OpenShell gateway. Add this block\n   \
             to the end of {path}:\n\n{block}\n   \
             Then restart the gateway:\n\n   {restart}\n"
        ),
        (None, None) => format!(
            "1. Register the middleware with your OpenShell gateway. Create\n   \
             {path} with:\n\n[openshell]\nversion = 2\n\n{block}\n   \
             Then restart the gateway:\n\n   {restart}\n"
        ),
    };
    Ok(format!(
        "{register}\n\
         2. Create the demo sandbox. It runs the Tenuo agent's MCP proxy:\n\n   \
         openshell sandbox create --name {DEMO_SANDBOX} \\\n     \
         --from {image} \\\n     \
         --policy {policy} \\\n     \
         --no-tty --detach -- tenuo-openshell-agent proxy --upstream {mcp}\n\n\
         3. Give it a task:\n\n   \
         tenuo-openshell provision --dev --sandbox {DEMO_SANDBOX} --preset demo\n",
        image = config.demo_image,
        policy = state.sandbox_policy().display(),
        mcp = config.mcp_url(),
    ))
}

fn down(state: &DevState) -> Result<()> {
    for name in [MIDDLEWARE_CONTAINER, MCP_CONTAINER] {
        if remove_container(name)? {
            println!("removed {name}");
        } else {
            println!("{name} is not running");
        }
    }
    println!(
        "Keys and policy stay in {}; `dev up` reuses them.",
        state.dir.display()
    );
    let gateway = GatewayConfig::locate()?;
    if let Some(endpoint) = gateway.registered_endpoint() {
        println!();
        println!(
            "{} still registers tenuo/authorization at {endpoint}.",
            gateway.path.display()
        );
        println!("The gateway checks it at startup, and sandboxes that attach it now fail closed.");
        println!(
            "Remove that block and restart the gateway: {}",
            restart_command()
        );
    }
    Ok(())
}

fn status(state: &DevState) -> Result<()> {
    let config = state.config().ok();
    for (label, name) in [
        ("middleware", MIDDLEWARE_CONTAINER),
        ("MCP server", MCP_CONTAINER),
    ] {
        let output = Process::new(DOCKER)
            .args(["inspect", "--type", "container"])
            .args(["--format", "{{.State.Status}}", name])
            .stderr(Stdio::null())
            .output()?;
        let state = if output.status.success() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            "not created".to_string()
        };
        let detail = match (&config, label) {
            (Some(config), "middleware") => {
                let policy = policy_metrics(config)
                    .map(|(version, sandboxes)| {
                        format!(", policy version {version}, {sandboxes} sandbox(es)")
                    })
                    .unwrap_or_default();
                format!("  {}{policy}", config.endpoint())
            }
            (Some(config), _) => format!("  {}", config.mcp_url()),
            (None, _) => String::new(),
        };
        println!("{label:<11} {state}{detail}");
    }
    let gateway = GatewayConfig::locate()?;
    match (gateway.registered_endpoint(), &config) {
        (Some(endpoint), Some(config)) if endpoint == config.endpoint() => {
            println!("gateway     registered in {}", gateway.path.display())
        }
        (Some(endpoint), _) => println!(
            "gateway     {} registers tenuo/authorization at {endpoint}",
            gateway.path.display()
        ),
        (None, _) => println!(
            "gateway     not registered in {}; `dev up` prints the block",
            gateway.path.display()
        ),
    }
    println!("state       {}", state.dir.display());
    Ok(())
}

/// Add a sandbox to the dev policy: the dev issuer as its trust root, the
/// demo MCP server as its destination, and `read_logs` as idempotent. Waits
/// until the middleware serves the new version. Returns the sandbox id.
pub fn trust_sandbox(state: &DevState, sandbox: &SandboxArgs) -> Result<String> {
    let config = state.config()?;
    let id = sandbox_id(sandbox)?;
    let path = state.policy();
    let mut document: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let root = fs::read_to_string(state.issuer_public())?
        .trim()
        .to_string();
    let tools: Vec<String> = DEMO_TOOLS.iter().map(|tool| tool.to_string()).collect();
    let mut updated = document.clone();
    add_to_policy(
        &mut updated,
        &id,
        std::slice::from_ref(&root),
        Some(destination(&config.mcp_url(), &tools)?),
        &["read_logs".to_string()],
    )?;
    if updated["sandboxes"] != document["sandboxes"] {
        document = updated;
        let bytes = [serde_json::to_vec_pretty(&document)?.as_slice(), b"\n"].concat();
        tenuo_openshell_middleware::PolicySet::from_json(&bytes)
            .map_err(|error| format!("resulting policy is invalid: {error}"))?;
        write_atomic(&path, &bytes)?;
        println!(
            "trusted sandbox {} ({id}) in the dev policy, version {}",
            sandbox.sandbox, document["version"]
        );
    }
    let version = document["version"].as_u64().unwrap_or(0);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match policy_metrics(&config) {
            Some((served, _)) if served >= version => return Ok(id),
            _ if Instant::now() > deadline => {
                return Err(format!(
                    "the dev middleware does not serve policy version {version}; is `tenuo-openshell dev up` running?"
                )
                .into())
            }
            _ => std::thread::sleep(Duration::from_millis(250)),
        }
    }
}

fn sandbox_id(sandbox: &SandboxArgs) -> Result<String> {
    let output = openshell_command(sandbox)
        .args(["sandbox", "get", &sandbox.sandbox, "-o", "json"])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "`{} sandbox get {}` failed: {}",
            sandbox.openshell,
            sandbox.sandbox,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)?;
    value["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("sandbox {} has no id", sandbox.sandbox).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DevConfig {
        DevConfig {
            port: 18651,
            mcp_port: 18680,
            image: "middleware:test".into(),
            demo_image: "demo:test".into(),
        }
    }

    #[test]
    fn finds_the_tenuo_registration_among_middleware_tables() {
        let toml = "[openshell]\nversion = 2\n\n[openshell.gateway]\n\n\
                    [[openshell.supervisor.middleware]]\nname = \"other\"\n\
                    grpc_endpoint = \"http://other:1\"\n\n\
                    [[ openshell.supervisor.middleware ]]\n# a comment\n\
                    name = \"tenuo/authorization\" # trailing\n\
                    grpc_endpoint = \"http://127.0.0.1:18651\"\n\
                    allow_insecure_transport = true\n\n[openshell.drivers.docker]\n";
        assert_eq!(
            registered_endpoint(toml).as_deref(),
            Some("http://127.0.0.1:18651")
        );
        assert_eq!(registered_endpoint("[openshell]\nversion = 2\n"), None);
        let other_only = "[[openshell.supervisor.middleware]]\nname = \"other\"\n";
        assert_eq!(registered_endpoint(other_only), None);
        // The block `dev up` prints is found once appended.
        let block = registration_block(&config()).unwrap();
        let appended = format!("[openshell]\nversion = 2\n\n[openshell.gateway]\n\n{block}");
        assert_eq!(
            registered_endpoint(&appended).as_deref(),
            Some("http://127.0.0.1:18651")
        );
    }

    #[test]
    fn registration_is_plaintext_loopback_for_dev() {
        let block = registration_block(&config()).unwrap();
        assert!(block.contains("name = \"tenuo/authorization\"\n"));
        assert!(block.contains("grpc_endpoint = \"http://127.0.0.1:18651\"\n"));
        assert!(block.contains("allow_insecure_transport = true\n"));
        assert!(!block.contains("tls_ca_cert_path"));
    }

    #[test]
    fn next_steps_match_the_gateway_configuration() {
        let directory = tempfile::tempdir().unwrap();
        let state = DevState {
            dir: directory.path().to_path_buf(),
        };
        let path = directory.path().join("gateway.toml");
        let gateway = |contents: Option<&str>| GatewayConfig {
            path: path.clone(),
            contents: contents.map(str::to_string),
        };
        let missing = next_steps(&state, &config(), &gateway(None)).unwrap();
        assert!(missing.contains("Create\n"));
        assert!(missing.contains("[openshell]\nversion = 2\n\n# OpenShell gateway"));
        assert!(missing.contains(restart_command()));
        assert!(missing.contains("--from demo:test"));
        assert!(missing.contains("--upstream http://host.openshell.internal:18680/mcp"));
        assert!(missing.contains("provision --dev --sandbox tenuo-demo --preset demo"));

        let plain = next_steps(&state, &config(), &gateway(Some("[openshell]\n"))).unwrap();
        assert!(plain.contains("Add this block"));
        assert!(!plain.contains("version = 2"));

        let block = registration_block(&config()).unwrap();
        let registered = next_steps(&state, &config(), &gateway(Some(&block))).unwrap();
        assert!(registered.contains("already registers this middleware"));
        assert!(!registered.contains("[[openshell.supervisor.middleware]]"));

        let moved = DevConfig {
            port: 19000,
            ..config()
        };
        let stale = next_steps(&state, &moved, &gateway(Some(&block))).unwrap();
        assert!(stale.contains("registers tenuo/authorization at http://127.0.0.1:18651"));
        assert!(stale.contains("grpc_endpoint = \"http://127.0.0.1:19000\""));
    }

    #[test]
    fn prepared_state_is_reused_and_serves_the_demo() {
        let directory = tempfile::tempdir().unwrap();
        let state = DevState {
            dir: directory.path().join("dev"),
        };
        prepare_state(&state, &config()).unwrap();
        let issuer = fs::read_to_string(state.issuer_public()).unwrap();
        let policy = tenuo_openshell_middleware::PolicySet::load(&state.policy()).unwrap();
        assert_eq!(policy.sandbox_count(), 0);
        assert_eq!(state.config().unwrap(), config());

        // A second run keeps the keys and the policy.
        fs::write(state.policy(), fs::read(state.policy()).unwrap()).unwrap();
        prepare_state(&state, &config()).unwrap();
        assert_eq!(fs::read_to_string(state.issuer_public()).unwrap(), issuer);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&state.dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }

        // Half a key pair is refused rather than replaced.
        fs::remove_file(state.approver_public()).unwrap();
        assert!(prepare_state(&state, &config()).is_err());

        let yaml: serde_yaml::Value =
            serde_yaml::from_str(&fs::read_to_string(state.sandbox_policy()).unwrap()).unwrap();
        assert_eq!(
            yaml["network_policies"]["tenuo-demo-mcp"]["endpoints"][0]["port"],
            18680
        );
        assert_eq!(
            yaml["network_middlewares"]["tenuo"]["middleware"],
            "tenuo/authorization"
        );
        // The policy register checks against: every route to the MCP host is
        // one the middleware sees.
        crate::reject_uncovered_routes(
            &fs::read_to_string(state.sandbox_policy()).unwrap(),
            &["host.openshell.internal".to_string()],
        )
        .unwrap();
    }

    #[test]
    fn container_specs_publish_on_loopback_only() {
        let directory = tempfile::tempdir().unwrap();
        let state = DevState {
            dir: directory.path().to_path_buf(),
        };
        let middleware = middleware_spec(&state, &config()).unwrap();
        assert!(middleware.contains(&"127.0.0.1:18651:50051".to_string()));
        assert!(middleware.contains(&"127.0.0.1:18652:9090".to_string()));
        assert!(middleware.contains(&"--insecure-dev".to_string()));
        let mcp = mcp_spec(&config());
        assert!(mcp.contains(&"127.0.0.1:18680:8080".to_string()));
        for spec in [&middleware, &mcp] {
            assert!(spec
                .iter()
                .filter(|arg| arg.contains(':') && arg.ends_with(char::is_numeric))
                .filter(|arg| arg.split(':').count() == 3)
                .all(|arg| arg.starts_with("127.0.0.1:")));
        }
        assert_ne!(spec_hash(&middleware), spec_hash(&mcp));
        let moved = mcp_spec(&DevConfig {
            mcp_port: 18681,
            ..config()
        });
        assert_ne!(spec_hash(&mcp), spec_hash(&moved));
    }
}

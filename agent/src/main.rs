//! Tenuo task runtime for an OpenShell sandbox.
//!
//! ```text
//! tenuo-openshell-agent keygen                       # prints the holder public key
//! tenuo-openshell-agent install-warrant <warrant>    # after the orchestrator delegates
//! tenuo-openshell-agent proxy --upstream https://mcp.internal/mcp
//! ```

mod approvals;
mod authority;
mod proxy;
mod sign;

use authority::{Holder, WarrantSource};
use clap::{Args, Parser, Subcommand};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Tenuo holder key, warrant, and MCP signing proxy for an OpenShell sandbox"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct KeyArgs {
    /// Holder private key. Created by `keygen`; never leaves the sandbox.
    #[arg(long, env = "TENUO_HOLDER_KEY_FILE")]
    key: Option<PathBuf>,
}

#[derive(Args, Clone)]
struct WarrantArgs {
    /// Encoded warrant or warrant stack. Takes precedence over the file.
    #[arg(long = "warrant", env = "TENUO_WARRANT", hide_env_values = true)]
    inline: Option<String>,

    /// Warrant file, re-read on every call.
    #[arg(long, env = "TENUO_WARRANT_FILE")]
    warrant_file: Option<PathBuf>,

    /// Directory for signed approvals and pending approval requests.
    #[arg(long, env = "TENUO_APPROVALS_DIR")]
    approvals_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Create the holder key if needed and print its public key as hex.
    Keygen {
        #[command(flatten)]
        key: KeyArgs,
    },
    /// Validate a warrant against the holder key and install it. `-` reads stdin.
    InstallWarrant {
        #[command(flatten)]
        key: KeyArgs,
        #[arg(long, env = "TENUO_WARRANT_FILE")]
        warrant_file: Option<PathBuf>,
        warrant: String,
    },
    /// Show the holder key and the installed warrant.
    Status {
        #[command(flatten)]
        key: KeyArgs,
        #[command(flatten)]
        warrant: WarrantArgs,
    },
    /// List calls waiting for approval.
    Pending {
        #[arg(long, env = "TENUO_APPROVALS_DIR")]
        approvals_dir: Option<PathBuf>,
        /// One JSON array instead of a summary.
        #[arg(long)]
        json: bool,
    },
    /// Verify and install a signed approval. `-` reads stdin.
    InstallApproval {
        #[arg(long, env = "TENUO_APPROVALS_DIR")]
        approvals_dir: Option<PathBuf>,
        approval: String,
    },
    /// Attenuate this holder's warrant to a child holder key and print the
    /// child's warrant chain. The child gets the named tools with this
    /// warrant's constraints and a shorter lifetime.
    Delegate {
        #[command(flatten)]
        key: KeyArgs,
        #[command(flatten)]
        warrant: WarrantArgs,
        /// Child holder public key: 64 hex characters, as printed by `keygen`.
        #[arg(long)]
        child_pub: String,
        /// Tools to pass on, comma-separated. Each must be in this warrant.
        #[arg(long, value_delimiter = ',', required = true)]
        tools: Vec<String>,
        /// Child lifetime in seconds. Never longer than this warrant's.
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        /// The child may not delegate further.
        #[arg(long)]
        terminal: bool,
    },
    /// Sign one JSON-RPC message from stdin and write it to stdout.
    Sign {
        #[command(flatten)]
        key: KeyArgs,
        #[command(flatten)]
        warrant: WarrantArgs,
    },
    /// Serve a loopback MCP endpoint that signs tools/call and forwards to the server.
    /// Creates the holder key if needed, so the proxy can start before the
    /// sandbox is provisioned.
    Proxy {
        #[command(flatten)]
        key: KeyArgs,
        #[command(flatten)]
        warrant: WarrantArgs,
        /// Loopback address the agent's MCP client connects to.
        #[arg(long, default_value = "127.0.0.1:7415", env = "TENUO_PROXY_LISTEN")]
        listen: SocketAddr,
        /// MCP server endpoint, for example https://mcp.internal/mcp.
        #[arg(long, env = "TENUO_MCP_UPSTREAM")]
        upstream: reqwest::Url,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tenuo-openshell-agent: {error}");
            ExitCode::FAILURE
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Keygen { key } => {
            let public = authority::ensure_key(&key_path(&key)?)?;
            println!("{}", hex::encode(public.to_bytes()));
            Ok(())
        }
        Command::InstallWarrant {
            key,
            warrant_file,
            warrant,
        } => {
            let encoded = if warrant == "-" {
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input)?;
                input
            } else {
                warrant.into_bytes()
            };
            let path = warrant_path(warrant_file)?;
            let chain = authority::install_warrant(&key_path(&key)?, &path, &encoded)?;
            println!(
                "installed warrant {} at {}",
                chain
                    .last()
                    .map(|leaf| leaf.id().to_string())
                    .unwrap_or_default(),
                path.display()
            );
            Ok(())
        }
        Command::Status { key, warrant } => status(&holder(&key, warrant)?),
        Command::Pending {
            approvals_dir,
            json,
        } => {
            let pending =
                approvals::ApprovalStore::new(approvals_path(approvals_dir)?).list_pending();
            if json {
                println!("{}", serde_json::Value::Array(pending));
            } else {
                for request in &pending {
                    println!(
                        "{}  {}  {}",
                        request["request_hash"].as_str().unwrap_or_default(),
                        request["tool"].as_str().unwrap_or_default(),
                        request["arguments"]
                    );
                }
            }
            Ok(())
        }
        Command::InstallApproval {
            approvals_dir,
            approval,
        } => {
            let bytes = if approval == "-" {
                let mut input = Vec::new();
                std::io::stdin().read_to_end(&mut input)?;
                input
            } else {
                approval.into_bytes()
            };
            let hash =
                approvals::ApprovalStore::new(approvals_path(approvals_dir)?).install(&bytes)?;
            println!("installed approval for request {}", hex::encode(hash));
            Ok(())
        }
        Command::Delegate {
            key,
            warrant,
            child_pub,
            tools,
            ttl,
            terminal,
        } => {
            let holder = holder(&key, warrant)?;
            let signing = authority::load_key(&key_path(&key)?)?;
            let bytes: [u8; 32] = hex::decode(child_pub.trim())?
                .try_into()
                .map_err(|_| "child public key must be 32 bytes")?;
            let child = tenuo::PublicKey::from_bytes(&bytes)?;
            let chain = authority::delegate(
                &signing,
                &holder.chain()?,
                &child,
                &tools,
                std::time::Duration::from_secs(ttl.max(1)),
                terminal,
            )?;
            println!("{}", authority::encode_chain(&chain)?);
            Ok(())
        }
        Command::Sign { key, warrant } => {
            let holder = holder(&key, warrant)?;
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input)?;
            match sign::sign_body(&holder, &input) {
                sign::Signed::Unchanged => std::io::stdout().write_all(&input)?,
                sign::Signed::Body(body) => std::io::stdout().write_all(&body)?,
                sign::Signed::Denied(body) => {
                    std::io::stdout().write_all(&body)?;
                    return Err("the call was not signed; see the JSON-RPC error on stdout".into());
                }
            }
            Ok(())
        }
        Command::Proxy {
            key,
            warrant,
            listen,
            upstream,
        } => {
            if !listen.ip().is_loopback() {
                return Err(
                    "the proxy signs with this sandbox's holder key and listens on loopback only"
                        .into(),
                );
            }
            authority::ensure_key(&key_path(&key)?)?;
            let holder = holder(&key, warrant)?;
            if let Err(error) = holder.chain() {
                eprintln!("tenuo-openshell-agent: {error}; tools/call will be denied until one is installed");
            }
            let router = proxy::Proxy::new(holder, upstream)?.router();
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind(listen).await?;
                eprintln!("tenuo-openshell-agent: MCP proxy listening on http://{listen}");
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = tokio::signal::ctrl_c().await;
                    })
                    .await?;
                Ok::<(), Box<dyn std::error::Error>>(())
            })
        }
    }
}

fn status(holder: &Holder) -> Result<()> {
    println!("holder  {}", hex::encode(holder.public_key().to_bytes()));
    match holder.present() {
        Ok(presented) => {
            let authority = &presented.authority;
            println!("warrant {}", authority.leaf().id());
            println!("depth   {}", authority.chain().len());
            println!("tools   {}", authority.capabilities().names().join(", "));
            println!("expires {}", authority.expires_at().to_rfc3339());
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn holder(key: &KeyArgs, warrant: WarrantArgs) -> Result<Holder> {
    let key = authority::load_key(&key_path(key)?)?;
    let store = approvals::ApprovalStore::new(approvals_path(warrant.approvals_dir.clone())?);
    let source = match warrant.inline {
        Some(text) if !text.trim().is_empty() => WarrantSource::Inline(text),
        _ => WarrantSource::File(warrant_path(warrant.warrant_file)?),
    };
    Ok(Holder::new(key, source).with_approvals(store))
}

fn approvals_path(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => Ok(tenuo_dir()?.join("approvals")),
    }
}

fn key_path(key: &KeyArgs) -> Result<PathBuf> {
    match &key.key {
        Some(path) => Ok(path.clone()),
        None => Ok(tenuo_dir()?.join("holder.key")),
    }
}

fn warrant_path(path: Option<PathBuf>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path),
        None => Ok(tenuo_dir()?.join("warrant")),
    }
}

fn tenuo_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set; pass --key")?;
    Ok(Path::new(&home).join(".tenuo"))
}

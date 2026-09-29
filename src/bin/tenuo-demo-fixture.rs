//! Build the two-task OpenShell demo requests.
//!
//! `prepare` never loads a holder key. It runs one process per holder. The
//! issuer process writes warrants and the trust policy, then discards the
//! issuer secret. Each signing process reads only the holder key it is given.

use clap::{Parser, Subcommand};
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::encode_meta;
use tenuo::{ConstraintSet, Exact, PublicKey, Range, SigningKey, Warrant, SIGNATURE_CONTEXT};

#[derive(Debug, Parser)]
struct Args {
    #[command(subcommand)]
    command: Option<CommandKind>,

    /// Directory for the prepared requests. Used when no subcommand is given.
    #[arg(long)]
    output: Option<PathBuf>,

    #[arg(long, default_value = "bootstrap")]
    sandbox_id: String,

    /// Optional directory for an OpenShell-compatible Ed25519 PKCS#8 keypair.
    #[arg(long)]
    openshell_jwt_dir: Option<PathBuf>,

    #[arg(long, requires = "openshell_jwt_dir")]
    openshell_jwt_key_id: Option<String>,
}

#[derive(Debug, Subcommand)]
enum CommandKind {
    /// Create one holder key in its own directory.
    Keygen {
        #[arg(long)]
        dir: PathBuf,
    },
    /// Mint both warrants from holder public keys. The issuer secret is not written.
    Issue {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        sandbox_id: String,
        #[arg(long)]
        task_a_pub: PathBuf,
        #[arg(long)]
        task_b_pub: PathBuf,
    },
    /// Sign one `tools/call` with one holder key.
    Sign {
        #[arg(long)]
        holder_key: PathBuf,
        #[arg(long)]
        warrant: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        id: u64,
        #[arg(long)]
        tool: String,
        #[arg(long)]
        arguments: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    match args.command {
        Some(CommandKind::Keygen { dir }) => keygen(&dir),
        Some(CommandKind::Issue {
            output,
            sandbox_id,
            task_a_pub,
            task_b_pub,
        }) => issue(&output, &sandbox_id, &task_a_pub, &task_b_pub),
        Some(CommandKind::Sign {
            holder_key,
            warrant,
            output,
            id,
            tool,
            arguments,
        }) => sign_request(&holder_key, &warrant, &output, id, &tool, &arguments),
        None => {
            let Some(output) = args.output.as_deref() else {
                return Err("--output is required".into());
            };
            prepare(
                output,
                &args.sandbox_id,
                args.openshell_jwt_dir.as_deref(),
                args.openshell_jwt_key_id.as_deref(),
            )
        }
    }
}

fn prepare(
    output: &Path,
    sandbox_id: &str,
    jwt_dir: Option<&Path>,
    jwt_key_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output)?;
    if let Some(jwt_dir) = jwt_dir {
        write_openshell_jwt_material(jwt_dir, jwt_key_id.unwrap_or("tenuo-demo"))?;
    }

    let task_a = output.join("signers/task-a");
    let task_b = output.join("signers/task-b");
    let exe = std::env::current_exe()?;
    spawn(
        &exe,
        &["keygen".to_string(), "--dir".to_string(), path_arg(&task_a)],
    )?;
    spawn(
        &exe,
        &["keygen".to_string(), "--dir".to_string(), path_arg(&task_b)],
    )?;
    spawn(
        &exe,
        &[
            "issue".to_string(),
            "--output".to_string(),
            path_arg(output),
            "--sandbox-id".to_string(),
            sandbox_id.to_string(),
            "--task-a-pub".to_string(),
            path_arg(&task_a.join("public")),
            "--task-b-pub".to_string(),
            path_arg(&task_b.join("public")),
        ],
    )?;

    let warrant_a = output.join("warrants/task-a.cbor");
    let warrant_b = output.join("warrants/task-b.cbor");
    let key_a = task_a.join("key");
    let key_b = task_b.join("key");
    let payments = r#"{"service":"payments","environment":"staging"}"#;
    let restart = r#"{"service":"payments","environment":"staging","replicas":3}"#;
    sign_with(
        &exe,
        &key_a,
        &warrant_a,
        &output.join("task-a-read.json"),
        1,
        "read_logs",
        payments,
    )?;
    sign_with(
        &exe,
        &key_a,
        &warrant_a,
        &output.join("task-a-restart.json"),
        2,
        "restart_service",
        restart,
    )?;
    sign_with(
        &exe,
        &key_a,
        &warrant_a,
        &output.join("task-a-constraint.json"),
        3,
        "read_logs",
        r#"{"service":"identity","environment":"production"}"#,
    )?;
    sign_with(
        &exe,
        &key_a,
        &warrant_a,
        &output.join("task-a-replicas.json"),
        4,
        "restart_service",
        r#"{"service":"payments","environment":"staging","replicas":8}"#,
    )?;
    sign_with(
        &exe,
        &key_b,
        &warrant_b,
        &output.join("task-b-read.json"),
        5,
        "read_logs",
        payments,
    )?;
    sign_with(
        &exe,
        &key_b,
        &warrant_b,
        &output.join("task-b-restart.json"),
        6,
        "restart_service",
        restart,
    )?;
    sign_with(
        &exe,
        &key_b,
        &warrant_a,
        &output.join("copied-warrant.json"),
        7,
        "restart_service",
        restart,
    )?;
    write_json(
        &output.join("missing-warrant.json"),
        &tools_call(8, "restart_service", serde_json::from_str(restart)?, None),
    )?;
    Ok(())
}

fn sign_with(
    exe: &Path,
    holder_key: &Path,
    warrant: &Path,
    output: &Path,
    id: u64,
    tool: &str,
    arguments: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    spawn(
        exe,
        &[
            "sign".to_string(),
            "--holder-key".to_string(),
            path_arg(holder_key),
            "--warrant".to_string(),
            path_arg(warrant),
            "--output".to_string(),
            path_arg(output),
            "--id".to_string(),
            id.to_string(),
            "--tool".to_string(),
            tool.to_string(),
            "--arguments".to_string(),
            arguments.to_string(),
        ],
    )
}

fn spawn(exe: &Path, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(exe).args(args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "fixture step {} failed",
            args.first().map_or("prepare", String::as_str)
        )
        .into())
    }
}

fn path_arg(path: &Path) -> String {
    path.display().to_string()
}

fn keygen(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir)?;
    let key = SigningKey::generate();
    let key_path = dir.join("key");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(&key_path)?
        .write_all(&key.secret_key_bytes())?;
    fs::write(
        dir.join("public"),
        format!("{}\n", hex::encode(key.public_key().to_bytes())),
    )?;
    Ok(())
}

fn issue(
    output: &Path,
    sandbox_id: &str,
    task_a_pub: &Path,
    task_b_pub: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let issuer = SigningKey::generate();
    let holder_a = read_public(task_a_pub)?;
    let holder_b = read_public(task_b_pub)?;
    let warrant_a = Warrant::builder()
        .capability("read_logs", read_constraints()?)
        .capability("restart_service", restart_constraints()?)
        .holder(holder_a)
        .ttl(Duration::from_secs(300))
        .build(&issuer)?;
    let warrant_b = Warrant::builder()
        .capability("read_logs", read_constraints()?)
        .holder(holder_b)
        .ttl(Duration::from_secs(300))
        .build(&issuer)?;

    let warrants = output.join("warrants");
    fs::create_dir_all(&warrants)?;
    fs::write(
        warrants.join("task-a.cbor"),
        tenuo::wire::encode(&warrant_a)?,
    )?;
    fs::write(
        warrants.join("task-b.cbor"),
        tenuo::wire::encode(&warrant_b)?,
    )?;

    let mut sandboxes = Map::new();
    sandboxes.insert(
        sandbox_id.to_string(),
        json!({"trusted_roots": [hex::encode(issuer.public_key().to_bytes())]}),
    );
    write_json(
        &output.join("policy.json"),
        &json!({
            "max_warrant_lifetime_secs": 3600,
            "sandboxes": Value::Object(sandboxes),
        }),
    )?;
    Ok(())
}

fn read_constraints() -> Result<ConstraintSet, Box<dyn std::error::Error>> {
    let mut constraints = ConstraintSet::new();
    constraints.insert("service", Exact::new("payments"));
    constraints.insert("environment", Exact::new("staging"));
    Ok(constraints)
}

fn restart_constraints() -> Result<ConstraintSet, Box<dyn std::error::Error>> {
    let mut constraints = read_constraints()?;
    constraints.insert("replicas", Range::max(5.0)?);
    Ok(constraints)
}

fn read_public(path: &Path) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let raw = hex::decode(text.trim())?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| "holder public key must be 32 bytes")?;
    Ok(PublicKey::from_bytes(&bytes)?)
}

fn sign_request(
    holder_key: &Path,
    warrant_path: &Path,
    output: &Path,
    id: u64,
    tool: &str,
    arguments: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = fs::read(holder_key)?;
    let secret: [u8; 32] = secret
        .try_into()
        .map_err(|_| "holder key must be 32 bytes")?;
    let holder = SigningKey::from_bytes(&secret);
    let warrant = tenuo::wire::decode(&fs::read(warrant_path)?)?;
    let arguments: Value = serde_json::from_str(arguments)?;
    let meta = sign(&warrant, &holder, tool, &arguments)?;
    write_json(output, &tools_call(id, tool, arguments, Some(meta)))?;
    Ok(())
}

fn write_openshell_jwt_material(
    directory: &Path,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use rcgen::{KeyPair, PKCS_ED25519};

    fs::create_dir_all(directory)?;
    let key = KeyPair::generate_for(&PKCS_ED25519)?;
    fs::write(directory.join("signing.pem"), key.serialize_pem())?;
    fs::write(directory.join("public.pem"), key.public_key_pem())?;
    fs::write(directory.join("kid"), format!("{key_id}\n"))?;
    Ok(())
}

fn sign(
    warrant: &Warrant,
    holder: &SigningKey,
    name: &str,
    arguments: &Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let call = Call::try_from_json(name, arguments)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
    let preimage = warrant.pop_preimage(call.capability(), call.pop_args(), now, 30)?;
    let mut message = SIGNATURE_CONTEXT.to_vec();
    message.extend(preimage);
    let signature = holder.sign_raw(&message);
    Ok(encode_meta(std::slice::from_ref(warrant), &signature, &[])?)
}

fn tools_call(id: u64, name: &str, arguments: Value, tenuo: Option<Value>) -> Value {
    let mut params = Map::new();
    params.insert("name".to_string(), Value::String(name.to_string()));
    params.insert("arguments".to_string(), arguments);
    if let Some(tenuo) = tenuo {
        params.insert("_meta".to_string(), json!({"tenuo": tenuo}));
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": Value::Object(params),
    })
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(fs::write(path, bytes)?)
}

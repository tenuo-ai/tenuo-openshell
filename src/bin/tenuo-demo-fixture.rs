//! Generate deterministic-shape, short-lived requests for the OpenShell demo.

use clap::Parser;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tenuo::sdk::prelude::*;
use tenuo::sdk::transport::mcp_meta::encode_meta;
use tenuo::{ConstraintSet, Exact, SigningKey, Warrant, SIGNATURE_CONTEXT};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    output: PathBuf,

    #[arg(long, default_value = "bootstrap")]
    sandbox_id: String,

    /// Optional directory for an OpenShell-compatible Ed25519 PKCS#8 keypair.
    #[arg(long)]
    openshell_jwt_dir: Option<PathBuf>,

    #[arg(long, requires = "openshell_jwt_dir")]
    openshell_jwt_key_id: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)?;
    if let Some(jwt_dir) = &args.openshell_jwt_dir {
        write_openshell_jwt_material(
            jwt_dir,
            args.openshell_jwt_key_id.as_deref().unwrap_or("tenuo-demo"),
        )?;
    }

    let issuer = SigningKey::generate();
    let holder = SigningKey::generate();
    let mut constraints = ConstraintSet::new();
    constraints.insert("service", Exact::new("payments"));
    constraints.insert("environment", Exact::new("staging"));
    let warrant = Warrant::builder()
        .capability("read_logs", constraints)
        .holder(holder.public_key())
        .ttl(Duration::from_secs(300))
        .build(&issuer)?;

    let allowed_arguments = json!({"service": "payments", "environment": "staging"});
    let denied_arguments = json!({"service": "identity", "environment": "production"});
    write_json(
        &args.output.join("allowed.json"),
        &tools_call(
            1,
            "read_logs",
            allowed_arguments.clone(),
            Some(sign(&warrant, &holder, "read_logs", &allowed_arguments)?),
        ),
    )?;
    write_json(
        &args.output.join("constraint-denied.json"),
        &tools_call(
            2,
            "read_logs",
            denied_arguments.clone(),
            Some(sign(&warrant, &holder, "read_logs", &denied_arguments)?),
        ),
    )?;
    write_json(
        &args.output.join("missing-warrant.json"),
        &tools_call(3, "read_logs", allowed_arguments, None),
    )?;

    let mut sandboxes = Map::new();
    sandboxes.insert(
        args.sandbox_id,
        json!({"trusted_roots": [hex::encode(issuer.public_key().to_bytes())]}),
    );
    write_json(
        &args.output.join("policy.json"),
        &json!({
            "max_warrant_lifetime_secs": 3600,
            "sandboxes": Value::Object(sandboxes),
        }),
    )?;
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
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(fs::write(path, bytes)?)
}

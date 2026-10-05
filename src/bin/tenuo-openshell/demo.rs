//! `tenuo-openshell demo call`: one MCP `tools/call` from inside a sandbox,
//! with a one-line outcome.

use crate::dev::{DevState, DEMO_SANDBOX};
use crate::{openshell_exec, Result, SandboxArgs};
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};

/// The agent's loopback MCP proxy inside the sandbox.
const PROXY_URL: &str = "http://127.0.0.1:7415/mcp";

#[derive(Subcommand)]
pub enum DemoCommand {
    /// Send one MCP tools/call from inside the sandbox, through the agent's
    /// proxy, and print whether it was allowed, denied, or held for approval.
    Call(CallArgs),
}

#[derive(Args)]
pub struct CallArgs {
    /// Tool to call.
    tool: String,
    /// Arguments as key=value. A value that reads as JSON, such as 3 or
    /// true, keeps that type; anything else is a string.
    arguments: Vec<String>,
    /// OpenShell sandbox to call from.
    #[arg(long, default_value = DEMO_SANDBOX)]
    sandbox: String,
    /// Skip the agent and send the call straight to the MCP server, with no
    /// warrant, as a compromised agent could. Uses curl in the sandbox.
    #[arg(long)]
    unsigned: bool,
    /// MCP server URL for --unsigned, as the sandbox reaches it. Defaults to
    /// the `dev up` demo MCP server.
    #[arg(long, requires = "unsigned")]
    mcp_url: Option<String>,
    /// Print the JSON-RPC response as received instead.
    #[arg(long)]
    json: bool,
    /// OpenShell CLI to run.
    #[arg(long, default_value = "openshell")]
    openshell: String,
    /// Passed to the OpenShell CLI as `--gateway-endpoint`.
    #[arg(long)]
    gateway_endpoint: Option<String>,
}

pub fn run(command: &DemoCommand) -> Result<()> {
    match command {
        DemoCommand::Call(args) => call(args),
    }
}

fn call(args: &CallArgs) -> Result<()> {
    let arguments = parse_arguments(&args.arguments)?;
    let url = if args.unsigned {
        match &args.mcp_url {
            Some(url) => url.clone(),
            None => DevState::locate()?.config()?.mcp_url(),
        }
    } else {
        PROXY_URL.to_string()
    };
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": args.tool, "arguments": Value::Object(arguments)},
    })
    .to_string();
    let sandbox = SandboxArgs {
        sandbox: args.sandbox.clone(),
        openshell: args.openshell.clone(),
        gateway_endpoint: args.gateway_endpoint.clone(),
    };
    let response = openshell_exec(
        &sandbox,
        &[
            "curl",
            "-sS",
            "--max-time",
            "30",
            &url,
            "-H",
            "content-type: application/json",
            "-H",
            "accept: application/json, text/event-stream",
            "-H",
            "mcp-protocol-version: 2025-11-25",
            "-d",
            &body,
        ],
    )
    .map_err(|error| {
        if args.unsigned {
            error
        } else {
            format!(
                "{error}\nThe call goes through the agent's proxy on {PROXY_URL}; the demo sandbox runs it as its command."
            )
            .into()
        }
    })?;
    if args.json {
        println!("{}", response.trim_end());
        return Ok(());
    }
    let shown = describe_call(&args.tool, &args.arguments);
    print!("{}", outcome(response.trim()).render(&shown, &args.sandbox));
    Ok(())
}

/// `key=value` pairs to a JSON object.
fn parse_arguments(pairs: &[String]) -> Result<Map<String, Value>> {
    let mut arguments = Map::new();
    for pair in pairs {
        let (key, value) = pair
            .split_once('=')
            .filter(|(key, _)| !key.is_empty())
            .ok_or_else(|| format!("{pair}: arguments are key=value"))?;
        let value = match serde_json::from_str::<Value>(value) {
            Ok(value @ (Value::Number(_) | Value::Bool(_) | Value::Null)) => value,
            _ => Value::String(value.to_string()),
        };
        if arguments.insert(key.to_string(), value).is_some() {
            return Err(format!("{key} is given twice").into());
        }
    }
    Ok(arguments)
}

/// The call as the operator typed it, in their order.
fn describe_call(tool: &str, pairs: &[String]) -> String {
    format!("{tool}({})", pairs.join(", "))
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Allowed(String),
    Denied { code: String, by: &'static str },
    Held { request: String },
    Unknown(String),
}

impl Outcome {
    fn render(&self, call: &str, sandbox: &str) -> String {
        match self {
            Outcome::Allowed(text) => format!("allowed  {call}: {text}\n"),
            Outcome::Denied { code, by } => format!("denied   {call} by {by}: {code}\n"),
            Outcome::Held { request } => {
                let short = request.chars().take(12).collect::<String>();
                format!(
                    "held     {call}: waiting for approval, request {short}\n         \
                     approve it with: tenuo-openshell approve --dev --sandbox {sandbox} --request {short}\n"
                )
            }
            Outcome::Unknown(body) => format!("unknown  {call}: {body}\n"),
        }
    }
}

const BY_AGENT: &str = "the Tenuo agent, before it left the sandbox";
const BY_MIDDLEWARE: &str = "the Tenuo middleware in OpenShell";
const BY_OPENSHELL: &str = "OpenShell's sandbox policy";

/// Classify a response: a JSON-RPC result or error from the proxy or the
/// MCP server, or an OpenShell denial body for a call that skipped the proxy.
fn outcome(body: &str) -> Outcome {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Outcome::Unknown(body.to_string());
    };
    if let Some(result) = value.get("result") {
        let text = result["content"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|item| item["text"].as_str())
            .collect::<Vec<_>>()
            .join(" ");
        return if result["isError"] == Value::Bool(true) {
            Outcome::Denied {
                code: format!("the tool returned an error: {text}"),
                by: "the MCP server",
            }
        } else {
            Outcome::Allowed(text)
        };
    }
    if let Some(error) = value.get("error").filter(|error| error.is_object()) {
        let tenuo = &error["data"]["tenuo"];
        if let Some(request) = tenuo["request_hash"].as_str() {
            return Outcome::Held {
                request: request.to_string(),
            };
        }
        if let Some(code) = tenuo["code"].as_str() {
            let by = match tenuo["source"].as_str() {
                Some("agent") => BY_AGENT,
                _ if code.starts_with("tenuo_") => BY_MIDDLEWARE,
                _ => BY_OPENSHELL,
            };
            return Outcome::Denied {
                code: code.to_string(),
                by,
            };
        }
        return Outcome::Unknown(body.to_string());
    }
    // OpenShell's own 403 body: {"error": "middleware_denied", "reason_code": ...}.
    if let Some(error) = value["error"].as_str() {
        let reason = value["reason_code"].as_str();
        return match reason {
            Some(code) if code.starts_with("tenuo_") => Outcome::Denied {
                code: code.to_string(),
                by: BY_MIDDLEWARE,
            },
            _ => Outcome::Denied {
                code: reason.unwrap_or(error).to_string(),
                by: BY_OPENSHELL,
            },
        };
    }
    Outcome::Unknown(body.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_keep_json_scalars_and_order_of_display() {
        let pairs: Vec<String> = ["service=payments", "replicas=3", "dry=true", "tag=\"3\""]
            .map(String::from)
            .to_vec();
        let parsed = parse_arguments(&pairs).unwrap();
        assert_eq!(
            Value::Object(parsed),
            json!({"service": "payments", "replicas": 3, "dry": true, "tag": "\"3\""})
        );
        assert_eq!(
            describe_call("restart_service", &pairs[..2]),
            "restart_service(service=payments, replicas=3)"
        );
        for bad in ["service", "=x"] {
            assert!(parse_arguments(&[bad.to_string()]).is_err(), "{bad}");
        }
        assert!(parse_arguments(&["a=1".into(), "a=2".into()]).is_err());
    }

    #[test]
    fn outcomes_name_who_decided() {
        let allowed = r#"{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "restarted payments"}]}}"#;
        assert_eq!(
            outcome(allowed),
            Outcome::Allowed("restarted payments".into())
        );

        let agent = r#"{"error":{"code":-32001,"data":{"tenuo":{"code":"constraint-violation","message":"Constraint not satisfied","source":"agent"}},"message":"Authorization denied: Constraint not satisfied"},"id":1,"jsonrpc":"2.0"}"#;
        assert_eq!(
            outcome(agent),
            Outcome::Denied {
                code: "constraint-violation".into(),
                by: BY_AGENT
            }
        );

        let middleware = r#"{"error":{"code":-32001,"data":{"tenuo":{"code":"tenuo_unknown_sandbox","source":"openshell"}},"message":"x"},"id":1,"jsonrpc":"2.0"}"#;
        assert_eq!(
            outcome(middleware),
            Outcome::Denied {
                code: "tenuo_unknown_sandbox".into(),
                by: BY_MIDDLEWARE
            }
        );
        let policy = r#"{"error":{"code":-32001,"data":{"tenuo":{"code":"policy_denied","source":"openshell"}},"message":"x"},"id":1,"jsonrpc":"2.0"}"#;
        assert_eq!(
            outcome(policy),
            Outcome::Denied {
                code: "policy_denied".into(),
                by: BY_OPENSHELL
            }
        );

        let held = r#"{"error":{"code":-32002,"data":{"tenuo":{"code":"approval-required","request_hash":"88c676b2aabbccddeeff","source":"agent"}},"message":"x"},"id":1,"jsonrpc":"2.0"}"#;
        let held = outcome(held);
        assert_eq!(
            held,
            Outcome::Held {
                request: "88c676b2aabbccddeeff".into()
            }
        );
        let text = held.render("restart_service(service=payments)", "tenuo-demo");
        assert!(text.contains("request 88c676b2aabb\n"));
        assert!(text.contains(
            "tenuo-openshell approve --dev --sandbox tenuo-demo --request 88c676b2aabb\n"
        ));
        let malformed = Outcome::Held {
            request: "a💥💥💥".into(),
        }
        .render("restart_service()", "tenuo-demo");
        assert!(malformed.contains("request a💥💥💥\n"));

        let unsigned = r#"{"binary":"/usr/bin/curl","error":"middleware_denied","middleware":"tenuo","reason_code":"tenuo_missing_warrant"}"#;
        assert_eq!(
            outcome(unsigned),
            Outcome::Denied {
                code: "tenuo_missing_warrant".into(),
                by: BY_MIDDLEWARE
            }
        );
        let blocked = r#"{"error":"policy_denied","detail":"no rule"}"#;
        assert_eq!(
            outcome(blocked),
            Outcome::Denied {
                code: "policy_denied".into(),
                by: BY_OPENSHELL
            }
        );
        assert!(matches!(outcome("curl: (7) refused"), Outcome::Unknown(_)));
    }
}

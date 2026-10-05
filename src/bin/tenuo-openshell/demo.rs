//! `tenuo-openshell demo call`: one MCP `tools/call` from inside a sandbox,
//! with a one-line outcome. `tenuo-openshell demo agent`: one NeMo Agent
//! Toolkit run in a sandbox, with the outcome of each tool call it made.

use crate::dev::{DevState, DEMO_SANDBOX};
use crate::{openshell_command, openshell_exec, Result, SandboxArgs};
use clap::{Args, Subcommand};
use serde_json::{json, Map, Value};

/// The agent's loopback MCP proxy inside the sandbox.
const PROXY_URL: &str = "http://127.0.0.1:7415/mcp";

/// The sandbox the NeMo Agent Toolkit guide (docs/nat-agent.md) creates.
pub const NAT_SANDBOX: &str = "tenuo-nat";
/// Runs a workflow in the NAT demo image (deploy/nat-demo-image).
const NAT_RUN: &str = "tenuo-nat-run";

#[derive(Subcommand)]
pub enum DemoCommand {
    /// Send one MCP tools/call from inside the sandbox, through the agent's
    /// proxy, and print whether it was allowed, denied, or held for approval.
    Call(CallArgs),
    /// Run the NeMo Agent Toolkit agent in the sandbox on one prompt, and
    /// print each tool call it made and whether it was allowed, denied, or
    /// held for approval.
    ///
    /// Runs `tenuo-nat-run WORKFLOW PROMPT` in the sandbox, which is `nat run`
    /// on /etc/tenuo-nat/WORKFLOW.yml in the tenuo-openshell-nat-demo image.
    Agent(AgentArgs),
}

#[derive(Args)]
pub struct AgentArgs {
    /// What to ask the agent.
    prompt: String,
    /// OpenShell sandbox the agent runs in.
    #[arg(long, default_value = NAT_SANDBOX)]
    sandbox: String,
    /// Workflow: `scripted` (a scripted model in the sandbox, no key),
    /// `scripted-plugin` (the same, with the nemo-agent-toolkit-tenuo plugin
    /// checking each call in the agent), `nim` (an NVIDIA-hosted model
    /// through an attached provider), or the path of a NAT configuration
    /// file in the sandbox. With a dev environment, the sandbox command gets
    /// the dev issuer's public key as TENUO_TRUSTED_ROOT.
    #[arg(long, default_value = "scripted")]
    workflow: String,
    /// Also print NAT's own output.
    #[arg(long)]
    verbose: bool,
    /// OpenShell CLI to run.
    #[arg(long, default_value = "openshell")]
    openshell: String,
    /// Passed to the OpenShell CLI as `--gateway-endpoint`.
    #[arg(long)]
    gateway_endpoint: Option<String>,
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
        DemoCommand::Agent(args) => agent(args),
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
    Denied {
        code: String,
        by: &'static str,
    },
    Held {
        request: String,
    },
    /// A tool error the agent saw, with its text.
    Refused(String),
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
            Outcome::Refused(text) => format!("denied   {call}: {text}\n"),
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

fn agent(args: &AgentArgs) -> Result<()> {
    let sandbox = SandboxArgs {
        sandbox: args.sandbox.clone(),
        openshell: args.openshell.clone(),
        gateway_endpoint: args.gateway_endpoint.clone(),
    };
    let mut exec = openshell_command(&sandbox);
    exec.args(["sandbox", "exec", "--name", &args.sandbox, "--no-tty"]);
    // The plugin workflow trusts the issuer named here: the dev issuer.
    if let Some(root) = dev_issuer() {
        exec.args(["--env", &format!("TENUO_TRUSTED_ROOT={root}")]);
    }
    // NAT logs to stderr and prints its result to stdout; read them as one
    // stream, in order.
    let output = exec
        .arg("--")
        .args(["sh", "-c", "exec \"$0\" \"$1\" \"$2\" 2>&1", NAT_RUN])
        .args([&args.workflow, &args.prompt])
        .output()
        .map_err(|error| format!("{}: {error}", args.openshell))?;
    let text = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    if args.verbose {
        println!("{}", text.trim_end());
        println!();
    }
    let run = parse_nat_run(&text);
    print!("{}", run.render(&args.sandbox));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = run
            .error
            .or_else(|| (!stderr.trim().is_empty()).then(|| stderr.trim().to_string()))
            .unwrap_or_else(|| "see --verbose".to_string());
        return Err(format!("the agent run failed in sandbox {}: {reason}", args.sandbox).into());
    }
    if run.steps.is_empty() && run.answer.is_none() {
        return Err("no agent steps in NAT's output; run again with --verbose".into());
    }
    Ok(())
}

/// The dev issuer's public key as hex, when `dev up` has made one.
fn dev_issuer() -> Option<String> {
    let path = DevState::locate().ok()?.issuer_public();
    let text = std::fs::read_to_string(path).ok()?;
    let root = text.trim();
    (root.len() == 64 && root.chars().all(|c| c.is_ascii_hexdigit())).then(|| root.to_string())
}

/// What one `nat run` of a ReAct agent did, read from its verbose log.
#[derive(Debug, Default, PartialEq)]
struct NatRun {
    steps: Vec<(String, Outcome)>,
    answer: Option<String>,
    error: Option<String>,
}

impl NatRun {
    fn render(&self, sandbox: &str) -> String {
        let mut text = String::new();
        for (call, outcome) in &self.steps {
            text.push_str(&outcome.render(call, sandbox));
        }
        if let Some(answer) = &self.answer {
            text.push_str(&format!(
                "answer   {}\n",
                answer.replace('\n', "\n         ")
            ));
        }
        text
    }
}

/// Remove terminal color codes.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

/// The ReAct agent's verbose log is a series of blocks between dashed
/// lines. A tool block names the tool, its input, and its response; the
/// result block follows "Workflow Result:".
fn parse_nat_run(text: &str) -> NatRun {
    let mut run = NatRun::default();
    let mut block: Vec<&str> = Vec::new();
    let mut blocks: Vec<Vec<&str>> = Vec::new();
    for line in text.lines() {
        if line.len() >= 10 && line.trim().chars().all(|c| c == '-') {
            blocks.push(std::mem::take(&mut block));
        } else {
            block.push(line);
        }
    }
    blocks.push(block);
    for block in blocks {
        if let Some(step) = tool_step(&block) {
            run.steps.push(step);
        }
        if let Some(at) = block
            .iter()
            .position(|line| line.trim() == "Workflow Result:")
        {
            let answer = block[at + 1..].join("\n").trim().to_string();
            run.answer = Some(answer);
        }
    }
    run.error = text
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("Error: "))
        .map(|error| error.trim().to_string());
    run
}

fn tool_step(block: &[&str]) -> Option<(String, Outcome)> {
    let tool = block
        .iter()
        .find_map(|line| line.trim().strip_prefix("Calling tools: "))?
        .trim();
    // A function in a NAT function group is named <group>__<function>.
    let tool = tool.split_once("__").map_or(tool, |(_, name)| name);
    let input = block
        .iter()
        .find_map(|line| line.trim().strip_prefix("Tool's input: "))
        .unwrap_or("");
    let response_at = block
        .iter()
        .position(|line| line.trim_start().starts_with("Tool's response:"))?;
    let first = block[response_at]
        .trim_start()
        .trim_start_matches("Tool's response:");
    let response = std::iter::once(first)
        .chain(block[response_at + 1..].iter().copied())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    let call = format!("{tool}({})", python_dict_pairs(input).join(", "));
    Some((call, tool_outcome(&response)))
}

/// How NAT's MCP client reports a tool error to the agent.
const TOOL_FAILED: [&str; 2] = [
    "MCPToolClient tool call failed: ",
    "Tool call failed after all retry attempts. Last error: ",
];

fn tool_outcome(response: &str) -> Outcome {
    let Some(error) = TOOL_FAILED
        .iter()
        .find_map(|prefix| response.split_once(prefix).map(|(_, error)| error))
    else {
        return Outcome::Allowed(response.to_string());
    };
    if let Some(request) = error
        .strip_prefix("Approval required: request ")
        .and_then(|rest| rest.split_whitespace().next())
        .filter(|hash| hash.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Outcome::Held {
            request: request.to_string(),
        };
    }
    Outcome::Refused(error.trim().to_string())
}

/// `{'service': 'payments', 'replicas': 3}`, as NAT logs a tool's input, to
/// `["service=payments", "replicas=3"]` in the same order. Anything else is
/// returned whole.
fn python_dict_pairs(input: &str) -> Vec<String> {
    let input = input.trim();
    let Some(inner) = input.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return if input.is_empty() {
            Vec::new()
        } else {
            vec![input.to_string()]
        };
    };
    let mut items = Vec::new();
    let mut item = String::new();
    let mut quote = None;
    let mut depth = 0usize;
    for c in inner.chars() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '\'' | '"') => quote = Some(c),
            (None, '{' | '[' | '(') => depth += 1,
            (None, '}' | ']' | ')') => depth = depth.saturating_sub(1),
            (None, ',') if depth == 0 => {
                items.push(std::mem::take(&mut item));
                continue;
            }
            _ => {}
        }
        item.push(c);
    }
    items.push(item);
    let unquote = |text: &str| {
        let text = text.trim();
        for q in ['\'', '"'] {
            if let Some(inner) = text.strip_prefix(q).and_then(|t| t.strip_suffix(q)) {
                return inner.to_string();
            }
        }
        text.to_string()
    };
    items
        .iter()
        .filter(|item| !item.trim().is_empty())
        .map(|item| match item.split_once(':') {
            Some((key, value)) => format!("{}={}", unquote(key), unquote(value)),
            None => item.trim().to_string(),
        })
        .collect()
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

    /// `nat run` output for a ReAct agent with `verbose: true`, trimmed: a
    /// read that ran, a restart held for approval, and the result.
    const NAT_RUN_LOG: &str = "2026-10-05 16:38:08 - INFO     - nat.cli.commands.start:192 - Starting NAT from config file: '/etc/tenuo-nat/scripted.yml'\n\
Configuration Summary:\n\
--------------------\n\
Workflow Type: react_agent\n\
2026-10-05 16:38:10 - INFO     - nat.plugins.langchain.agent.base:303 - \n\
------------------------------\n\
[AGENT]\n\
\x1b[37mCalling tools: ops__read_logs\n\
\x1b[33mTool's input: {'service': 'payments', 'environment': 'staging'}\n\
\x1b[36mTool's response: \n\
payments/staging: 3 lines, last: GET /health 200\x1b[39m\n\
------------------------------\n\
2026-10-05 16:38:10 - ERROR    - nat.plugins.mcp.exception_handler:48 - MCP operation failed: Unexpected error: Approval required: request b31bd30e5656999e48ff7159f8e93cf8ec64d66c1d8a9c55b06f03b37b7ed6b5 is waiting for an approver\n\
2026-10-05 16:38:10 - INFO     - nat.plugins.langchain.agent.base:303 - \n\
------------------------------\n\
[AGENT]\n\
\x1b[37mCalling tools: ops__restart_service\n\
\x1b[33mTool's input: {'service': 'payments', 'environment': 'staging', 'replicas': 3}\n\
\x1b[36mTool's response: \n\
MCPToolClient tool call failed: Approval required: request b31bd30e5656999e48ff7159f8e93cf8ec64d66c1d8a9c55b06f03b37b7ed6b5 is waiting for an approver (`tenuo-openshell approve --request b31bd30e5656999e48ff7159f8e93cf8ec64d66c1d8a9c55b06f03b37b7ed6b5`); retry the same call once it is approved\x1b[39m\n\
------------------------------\n\
2026-10-05 16:38:10 - INFO     - nat.front_ends.console.console_front_end_plugin:183 - --------------------------------------------------\n\
\x1b[32mWorkflow Result:\n\
Read the logs and requested a restart.\x1b[39m\n\
--------------------------------------------------\n\
\x1b[0m\x1b[0m";

    #[test]
    fn nat_run_steps_name_the_mcp_tool_and_its_outcome() {
        let run = parse_nat_run(&strip_ansi(NAT_RUN_LOG));
        assert_eq!(
            run.steps,
            vec![
                (
                    "read_logs(service=payments, environment=staging)".to_string(),
                    Outcome::Allowed("payments/staging: 3 lines, last: GET /health 200".into())
                ),
                (
                    "restart_service(service=payments, environment=staging, replicas=3)"
                        .to_string(),
                    Outcome::Held {
                        request: "b31bd30e5656999e48ff7159f8e93cf8ec64d66c1d8a9c55b06f03b37b7ed6b5"
                            .into()
                    }
                ),
            ]
        );
        assert_eq!(
            run.answer.as_deref(),
            Some("Read the logs and requested a restart.")
        );
        assert_eq!(run.error, None);
        let text = run.render("tenuo-nat");
        assert!(text.starts_with(
            "allowed  read_logs(service=payments, environment=staging): payments/staging"
        ));
        assert!(text.contains(
            "approve it with: tenuo-openshell approve --dev --sandbox tenuo-nat --request b31bd30e5656\n"
        ));
        assert!(text.ends_with("answer   Read the logs and requested a restart.\n"));
    }

    #[test]
    fn nat_tool_errors_are_denials_with_their_text() {
        assert_eq!(
            tool_outcome(
                "MCPToolClient tool call failed: Authorization denied: Constraint not satisfied"
            ),
            Outcome::Refused("Authorization denied: Constraint not satisfied".into())
        );
        // The in-process plugin's denial, after NAT's retries.
        assert_eq!(
            tool_outcome("Tool call failed after all retry attempts. Last error: Authorization denied (constraint_violation, ref=7542c5a4c3ef4c8c)"),
            Outcome::Refused("Authorization denied (constraint_violation, ref=7542c5a4c3ef4c8c)".into())
        );
        // Not a hash: a denial, not a request to approve.
        assert!(matches!(
            tool_outcome("MCPToolClient tool call failed: Approval required: request <none>"),
            Outcome::Refused(_)
        ));
    }

    #[test]
    fn failed_nat_runs_keep_the_error() {
        let log = "Configuration Summary:\n2026-10-05 - ERROR - Failed to initialize workflow\nError: [403] Forbidden\nAuthorization failed\n";
        let run = parse_nat_run(log);
        assert!(run.steps.is_empty() && run.answer.is_none());
        assert_eq!(run.error.as_deref(), Some("[403] Forbidden"));
    }

    #[test]
    fn python_dicts_become_pairs_in_order() {
        assert_eq!(
            python_dict_pairs(
                "{'service': 'payments', 'note': 'a, b: c', 'replicas': 3, 'tags': ['x', 'y']}"
            ),
            [
                "service=payments",
                "note=a, b: c",
                "replicas=3",
                "tags=['x', 'y']"
            ]
        );
        assert!(python_dict_pairs("").is_empty());
        assert!(python_dict_pairs("{}").is_empty());
        assert_eq!(python_dict_pairs("payments"), ["payments"]);
        assert_eq!(strip_ansi("\x1b[33mTool\x1b[39m\r"), "Tool");
    }
}

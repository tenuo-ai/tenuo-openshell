//! Local listener for the OpenShell supervisor middleware.
//!
//! Extension bearer authentication is not implemented. The process starts
//! only when `--insecure-dev` is set, and that mode accepts any caller who
//! can reach the socket.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use tenuo_openshell_middleware::policy::PolicySet;
use tenuo_openshell_middleware::proto::openshell::middleware::v1::supervisor_middleware_server::SupervisorMiddlewareServer;
use tenuo_openshell_middleware::service::MiddlewareService;
use tokio::net::TcpListener;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let insecure = args.iter().any(|arg| arg == "--insecure-dev");
    if !insecure {
        eprintln!(
            "extension bearer authentication is not implemented; pass --insecure-dev for a local listener"
        );
        return ExitCode::from(2);
    }
    let policy_path = match flag_value(&args, "--policy") {
        Some(path) => PathBuf::from(path),
        None => {
            eprintln!("missing --policy <file>");
            return ExitCode::from(2);
        }
    };
    let listen = flag_value(&args, "--listen").unwrap_or("127.0.0.1:50051");
    let policy = match PolicySet::load(&policy_path) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("policy load failed: {error}");
            return ExitCode::from(2);
        }
    };
    let listener = match TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("bind {listen} failed: {error}");
            return ExitCode::from(2);
        }
    };
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    eprintln!("development-only: accepting unauthenticated middleware calls on {listen}");
    let service = SupervisorMiddlewareServer::new(MiddlewareService::new(policy));
    if let Err(error) = Server::builder()
        .add_service(service)
        .serve_with_incoming(incoming)
        .await
    {
        eprintln!("server stopped: {error}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == name)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

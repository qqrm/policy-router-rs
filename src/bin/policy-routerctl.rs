use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use interprocess::local_socket::{Stream, prelude::*};
use policy_router_rs::ipc::{ExplainRequest, Request, Response, SOCKET_ENV_VAR, client_roundtrip};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "policy-routerctl")]
struct Cli {
    #[arg(long)]
    socket: Option<String>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    Status,
    Reload,
    Stop,
    Diagnostics,
    Explain {
        #[arg(long)]
        process: Option<String>,
        #[arg(long)]
        domain: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let name = resolve_ipc_socket(cli.socket.as_deref())?;
    let mut conn = Stream::connect(name).context("failed to connect to policy-routerd")?;

    let req = match cli.cmd {
        Cmd::Status => Request::Status,
        Cmd::Reload => Request::Reload,
        Cmd::Stop => Request::Stop,
        Cmd::Diagnostics => Request::Diagnostics,
        Cmd::Explain { process, domain } => Request::Explain(ExplainRequest { process, domain }),
    };

    let resp = client_roundtrip(&mut conn, &req)?;

    let res = match cli.format {
        OutputFormat::Text => print_text(resp.clone()),
        OutputFormat::Json => print_json(&resp),
    };

    if matches!(resp, Response::Err(_)) {
        // Deterministic non-zero exit for scripted usage.
        std::process::exit(2);
    }

    res
}

fn resolve_ipc_socket(
    cli_socket: Option<&str>,
) -> Result<interprocess::local_socket::Name<'static>> {
    let env_socket = std::env::var(SOCKET_ENV_VAR).ok();
    let override_socket = cli_socket.or(env_socket.as_deref());
    let (name, _fs_path) = policy_router_rs::ipc::socket_name_with_override(override_socket)?;
    Ok(name)
}

fn fmt_snake_case<T: Serialize>(value: &T) -> Result<String> {
    let raw = serde_json::to_string(value).context("failed to serialize enum")?;
    Ok(raw.trim_matches('"').to_string())
}

fn print_json(resp: &Response) -> Result<()> {
    let s = serde_json::to_string_pretty(&resp).context("failed to serialize response as JSON")?;
    println!("{s}");
    Ok(())
}

fn print_text(resp: Response) -> Result<()> {
    match resp {
        Response::OkStatus(s) => {
            println!("uptime_ms: {}", s.uptime_ms);
            println!("config_path: {}", s.config_path);
            println!("egress:");
            for e in s.egress {
                println!("  - id: {}", e.id);
                println!("    kind: {}", e.kind);
                if let Some(ep) = e.endpoint {
                    println!("    endpoint: {ep}",);
                }
            }
        }
        Response::OkReload => {
            println!("ok: reloaded");
        }
        Response::OkStop => {
            println!("ok: stopping");
        }
        Response::OkExplain(x) => {
            println!("egress: {}", x.decision.egress);
            println!("source: {}", fmt_snake_case(&x.decision.source)?);
            if let Some(rule_egress) = x.decision.rule_egress {
                println!("rule_egress: {rule_egress}");
            }
            if let Some(m) = x.decision.matcher {
                println!("matcher:");
                println!("  type: {}", fmt_snake_case(&m.kind)?);
                println!("  pattern: {}", m.pattern);
            }
            println!("reason: {}", x.decision.reason);
        }
        Response::OkDiagnostics(d) => {
            println!("uptime_ms: {}", d.uptime_ms);
            println!("config_path: {}", d.config_path);
            println!("socket: {}", d.socket);
            println!("egress_count: {}", d.egress_count);
            println!("running: {}", d.running);
            println!("ipc_requests: {}", d.ipc_requests);
            println!("reload_ok: {}", d.reload_ok);
            println!("reload_err: {}", d.reload_err);
        }
        Response::Err(e) => {
            anyhow::bail!("error: {}", e.message);
        }
    }

    Ok(())
}

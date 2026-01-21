use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use interprocess::local_socket::{Stream, prelude::*};
use policy_router_rs::ipc::{ExplainRequest, Request, Response, client_roundtrip, socket_name};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "policy-routerctl")]
struct Cli {
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
    Explain {
        #[arg(long)]
        process: Option<String>,
        #[arg(long)]
        domain: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let name = socket_name()?;
    let mut conn = Stream::connect(name).context("failed to connect to policy-routerd")?;

    let req = match cli.cmd {
        Cmd::Status => Request::Status,
        Cmd::Reload => Request::Reload,
        Cmd::Stop => Request::Stop,
        Cmd::Explain { process, domain } => Request::Explain(ExplainRequest { process, domain }),
    };

    let resp = client_roundtrip(&mut conn, &req)?;

    match cli.format {
        OutputFormat::Text => print_text(resp),
        OutputFormat::Json => print_json(&resp),
    }
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
        Response::Err(e) => {
            anyhow::bail!("error: {}", e.message);
        }
    }

    Ok(())
}

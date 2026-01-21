use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use interprocess::local_socket::{Stream, prelude::*};
use policy_router_rs::ipc::{ExplainRequest, Request, Response, client_roundtrip, socket_name};

#[derive(Debug, Parser)]
#[command(name = "policy-routerctl")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
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
            println!("reason: {}", x.decision.reason);
        }
        Response::Err(e) => {
            anyhow::bail!("error: {}", e.message);
        }
    }

    Ok(())
}

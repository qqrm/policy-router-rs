use std::{
    io::{self, BufReader},
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::Parser;
use interprocess::local_socket::{ListenerNonblockingMode, ListenerOptions, prelude::*};
use policy_router_rs::{
    ipc::{
        DecisionInfo, EgressInfo, ErrorResponse, Request, Response, StatusResponse, read_json_line,
        socket_name, write_json_line,
    },
    policy::{config::AppConfig, engine},
};

#[derive(Debug, Parser)]
#[command(name = "policy-routerd")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Debug)]
struct State {
    started_at: Instant,
    config_path: PathBuf,
    cfg: RwLock<AppConfig>,
    running: AtomicBool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = AppConfig::load_from_path(&cli.config)?;

    let state = Arc::new(State {
        started_at: Instant::now(),
        config_path: cli.config,
        cfg: RwLock::new(cfg),
        running: AtomicBool::new(true),
    });

    ctrlc::set_handler({
        let state = Arc::clone(&state);
        move || {
            state.running.store(false, Ordering::SeqCst);
        }
    })
    .context("failed to set Ctrl+C handler")?;

    let name = socket_name()?;

    let listener = ListenerOptions::new()
        .name(name)
        .nonblocking(ListenerNonblockingMode::Accept)
        .create_sync()
        .context("failed to create IPC listener")?;

    while state.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(conn) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(&state, conn) {
                        eprintln!("ipc error: {e:#}");
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                eprintln!("accept error: {e}");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    Ok(())
}

fn handle_conn(state: &Arc<State>, mut conn: interprocess::local_socket::Stream) -> Result<()> {
    let req: Request = read_json_line(BufReader::new(&mut conn))?;
    let resp = handle_request(state.as_ref(), req);
    write_json_line(&mut conn, &resp)?;
    Ok(())
}

fn handle_request(state: &State, req: Request) -> Response {
    match req {
        Request::Status => Response::OkStatus(build_status(state)),
        Request::Reload => match reload_config(state) {
            Ok(()) => Response::OkReload,
            Err(e) => Response::Err(ErrorResponse {
                message: format!("{e:#}"),
            }),
        },
        Request::Stop => {
            state.running.store(false, Ordering::SeqCst);
            Response::OkStop
        }
        Request::Explain(x) => {
            Response::OkExplain(explain(state, x.process.as_deref(), x.domain.as_deref()))
        }
    }
}

fn build_status(state: &State) -> StatusResponse {
    let egress = {
        let cfg = state.cfg.read().expect("config lock poisoned");

        cfg.egress
            .iter()
            .map(|(id, spec)| EgressInfo {
                id: id.to_string(),
                kind: spec.kind.to_string(),
                endpoint: spec.endpoint.clone(),
            })
            .collect::<Vec<_>>()
    };

    StatusResponse {
        uptime_ms: u64::try_from(state.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        config_path: state.config_path.display().to_string(),
        egress,
    }
}

fn reload_config(state: &State) -> Result<()> {
    let next = AppConfig::load_from_path(&state.config_path)?;
    *state.cfg.write().expect("config lock poisoned") = next;
    Ok(())
}

fn explain(
    state: &State,
    process: Option<&str>,
    domain: Option<&str>,
) -> policy_router_rs::ipc::ExplainResponse {
    let decision = {
        let cfg = state.cfg.read().expect("config lock poisoned");
        engine::decide(&cfg, process, domain)
    };

    policy_router_rs::ipc::ExplainResponse {
        decision: DecisionInfo {
            egress: decision.egress.to_string(),
            reason: decision.reason.to_human(),
        },
    }
}

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
use interprocess::local_socket::{
    GenericNamespaced, ListenerNonblockingMode, ListenerOptions, prelude::*,
};
use policy_router_rs::{
    ipc::{
        DecisionInfo, DecisionSource, ErrorResponse, MatcherInfo, MatcherKind, Request, Response,
        SOCKET_FS_FALLBACK, StatusResponse, read_json_line, socket_name, write_json_line,
    },
    policy::{config::AppConfig, engine},
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "policy-routerd")]
struct Cli {
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,

    #[arg(long, default_value = "info")]
    log_level: String,
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

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cli.log_level.clone()));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .init();

    if !GenericNamespaced::is_supported() {
        let _ = std::fs::remove_file(SOCKET_FS_FALLBACK);
    }

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

    info!("started");

    while state.running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok(conn) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(e) = handle_conn(&state, conn) {
                        warn!(error = %format!("{e:#}"), "ipc error");
                    }
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                warn!(error = %e, "accept error");
                thread::sleep(Duration::from_millis(50));
            }
        }
    }

    info!("stopping");

    if !GenericNamespaced::is_supported() {
        let _ = std::fs::remove_file(SOCKET_FS_FALLBACK);
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
            Ok(()) => {
                info!("reloaded config");
                Response::OkReload
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "reload failed");
                Response::Err(ErrorResponse {
                    message: format!("{e:#}"),
                })
            }
        },
        Request::Stop => {
            state.running.store(false, Ordering::SeqCst);
            info!("stop requested");
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
            .map(|(id, spec)| policy_router_rs::ipc::EgressInfo {
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

    let (source, rule_egress, matcher) = match &decision.reason {
        engine::DecisionReason::BlockByApp { pattern, .. } => (
            DecisionSource::BlockApp,
            Some("block".to_owned()),
            Some(MatcherInfo {
                kind: MatcherKind::Exact,
                pattern: pattern.clone(),
            }),
        ),
        engine::DecisionReason::BlockByDomain {
            pattern,
            match_kind,
            ..
        } => (
            DecisionSource::BlockDomain,
            Some("block".to_owned()),
            Some(MatcherInfo {
                kind: match match_kind {
                    engine::MatchKind::Exact => MatcherKind::Exact,
                    engine::MatchKind::Suffix => MatcherKind::Suffix,
                },
                pattern: pattern.clone(),
            }),
        ),
        engine::DecisionReason::AppMatch {
            pattern, egress, ..
        } => (
            DecisionSource::AppRule,
            Some(egress.to_string()),
            Some(MatcherInfo {
                kind: MatcherKind::Exact,
                pattern: pattern.clone(),
            }),
        ),
        engine::DecisionReason::DomainMatch {
            pattern,
            match_kind,
            egress,
            ..
        } => (
            DecisionSource::DomainRule,
            Some(egress.to_string()),
            Some(MatcherInfo {
                kind: match match_kind {
                    engine::MatchKind::Exact => MatcherKind::Exact,
                    engine::MatchKind::Suffix => MatcherKind::Suffix,
                },
                pattern: pattern.clone(),
            }),
        ),
        engine::DecisionReason::Default { egress } => {
            (DecisionSource::Default, Some(egress.to_string()), None)
        }
    };

    policy_router_rs::ipc::ExplainResponse {
        decision: DecisionInfo {
            egress: decision.egress.to_string(),
            reason: decision.reason.to_human(),
            source,
            rule_egress,
            matcher,
        },
    }
}

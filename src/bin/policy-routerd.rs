use std::{
    io::{self, BufReader},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use interprocess::local_socket::{
    GenericNamespaced, ListenerNonblockingMode, ListenerOptions, prelude::*,
};
use policy_router_rs::{
    ipc::{
        DecisionInfo, DecisionSource, DiagnosticsResponse, ErrorResponse, MatcherInfo, MatcherKind,
        Request, Response, SOCKET_ENV_VAR, StatusResponse, read_json_line, write_json_line,
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

    #[arg(long)]
    socket: Option<String>,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[derive(Debug)]
struct State {
    started_at: Instant,
    config_path: PathBuf,
    socket: String,
    cfg: ArcSwap<AppConfig>,
    running: AtomicBool,
    ipc_requests: std::sync::atomic::AtomicU64,
    reload_ok: std::sync::atomic::AtomicU64,
    reload_err: std::sync::atomic::AtomicU64,
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

    let cfg = AppConfig::load_from_path(&cli.config)?;

    let socket_label = resolve_socket_label(cli.socket.as_deref());

    let state = Arc::new(State {
        started_at: Instant::now(),
        config_path: cli.config,
        socket: socket_label,
        cfg: ArcSwap::from_pointee(cfg),
        running: AtomicBool::new(true),
        ipc_requests: std::sync::atomic::AtomicU64::new(0),
        reload_ok: std::sync::atomic::AtomicU64::new(0),
        reload_err: std::sync::atomic::AtomicU64::new(0),
    });

    ctrlc::set_handler({
        let state = Arc::clone(&state);
        move || {
            state.running.store(false, Ordering::SeqCst);
        }
    })
    .context("failed to set Ctrl+C handler")?;

    let (name, fs_socket_path) = resolve_ipc_socket(cli.socket.as_deref())?;
    cleanup_fs_socket(fs_socket_path.as_ref());

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

    cleanup_fs_socket(fs_socket_path.as_ref());

    Ok(())
}

fn resolve_ipc_socket(
    cli_socket: Option<&str>,
) -> Result<(interprocess::local_socket::Name<'static>, Option<PathBuf>)> {
    let env_socket = std::env::var(SOCKET_ENV_VAR).ok();
    let override_socket = cli_socket.or(env_socket.as_deref());
    policy_router_rs::ipc::socket_name_with_override(override_socket)
}

fn resolve_socket_label(cli_socket: Option<&str>) -> String {
    let env_socket = std::env::var(SOCKET_ENV_VAR).ok();
    let override_socket = cli_socket.or(env_socket.as_deref());

    override_socket.map_or_else(
        || {
            if GenericNamespaced::is_supported() {
                policy_router_rs::ipc::SOCKET_PRINT_NAME.to_owned()
            } else {
                policy_router_rs::ipc::SOCKET_FS_FALLBACK.to_owned()
            }
        },
        str::to_owned,
    )
}

fn cleanup_fs_socket(path: Option<&PathBuf>) {
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
}

fn handle_conn(state: &Arc<State>, mut conn: interprocess::local_socket::Stream) -> Result<()> {
    let req: Request = read_json_line(BufReader::new(&mut conn))?;

    state
        .ipc_requests
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

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
                    message: format!("reload failed for {}: {:#}", state.config_path.display(), e),
                })
            }
        },
        Request::Stop => {
            state.running.store(false, Ordering::SeqCst);
            info!("stop requested");
            Response::OkStop
        }
        Request::Explain(x) => handle_explain(state, &x),
        Request::Diagnostics => Response::OkDiagnostics(build_diagnostics(state)),
    }
}

fn build_status(state: &State) -> StatusResponse {
    let cfg = state.cfg.load();
    let egress = cfg
        .egress
        .iter()
        .map(|(id, spec)| policy_router_rs::ipc::EgressInfo {
            id: id.to_string(),
            kind: spec.kind.to_string(),
            endpoint: spec.endpoint.clone(),
        })
        .collect::<Vec<_>>();

    StatusResponse {
        uptime_ms: u64::try_from(state.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        config_path: state.config_path.display().to_string(),
        egress,
    }
}

fn build_diagnostics(state: &State) -> DiagnosticsResponse {
    let uptime_ms = u64::try_from(state.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);

    let cfg = state.cfg.load();

    DiagnosticsResponse {
        uptime_ms,
        config_path: state.config_path.display().to_string(),
        socket: state.socket.clone(),
        egress_count: cfg.egress.len(),
        running: state.running.load(Ordering::SeqCst),
        ipc_requests: state.ipc_requests.load(std::sync::atomic::Ordering::SeqCst),
        reload_ok: state.reload_ok.load(std::sync::atomic::Ordering::SeqCst),
        reload_err: state.reload_err.load(std::sync::atomic::Ordering::SeqCst),
    }
}

fn reload_config(state: &State) -> Result<()> {
    let next = match AppConfig::load_from_path(&state.config_path)
        .with_context(|| format!("failed to load config {}", state.config_path.display()))
    {
        Ok(cfg) => cfg,
        Err(err) => {
            state.reload_err.fetch_add(1, Ordering::Relaxed);
            return Err(err);
        }
    };

    state.cfg.store(Arc::new(next));
    state.reload_ok.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

fn handle_explain(state: &State, req: &policy_router_rs::ipc::ExplainRequest) -> Response {
    let decision = explain(state, req.process.as_deref(), req.domain.as_deref());
    Response::OkExplain(decision)
}

fn explain(
    state: &State,
    process: Option<&str>,
    domain: Option<&str>,
) -> policy_router_rs::ipc::ExplainResponse {
    let decision = {
        let cfg = state.cfg.load();
        engine::decide(&cfg, process, domain)
    };

    let source = map_source(&decision.reason);
    let rule_egress = Some(map_rule_egress(&decision.reason));
    let matcher = map_matcher(&decision.reason);

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

const fn map_source(reason: &engine::DecisionReason) -> DecisionSource {
    match reason {
        engine::DecisionReason::BlockByApp { .. } => DecisionSource::BlockApp,
        engine::DecisionReason::BlockByDomain { .. } => DecisionSource::BlockDomain,
        engine::DecisionReason::AppRule { .. } => DecisionSource::AppRule,
        engine::DecisionReason::DomainRule { .. } => DecisionSource::DomainRule,
        engine::DecisionReason::Default { .. } => DecisionSource::Default,
    }
}

fn map_rule_egress(reason: &engine::DecisionReason) -> String {
    match reason {
        engine::DecisionReason::BlockByApp { egress, .. }
        | engine::DecisionReason::BlockByDomain { egress, .. }
        | engine::DecisionReason::AppRule { egress, .. }
        | engine::DecisionReason::DomainRule { egress, .. }
        | engine::DecisionReason::Default { egress } => egress.to_string(),
    }
}

fn map_matcher(reason: &engine::DecisionReason) -> Option<MatcherInfo> {
    match reason {
        engine::DecisionReason::BlockByApp { pattern, .. }
        | engine::DecisionReason::AppRule { pattern, .. } => Some(MatcherInfo {
            kind: MatcherKind::Exact,
            pattern: pattern.clone(),
        }),
        engine::DecisionReason::BlockByDomain {
            pattern,
            match_kind,
            ..
        }
        | engine::DecisionReason::DomainRule {
            pattern,
            match_kind,
            ..
        } => Some(MatcherInfo {
            kind: map_matcher_kind(*match_kind),
            pattern: pattern.clone(),
        }),
        engine::DecisionReason::Default { .. } => None,
    }
}

const fn map_matcher_kind(match_kind: engine::MatchKind) -> MatcherKind {
    match match_kind {
        engine::MatchKind::Exact => MatcherKind::Exact,
        engine::MatchKind::Suffix => MatcherKind::Suffix,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn write_file(path: &PathBuf, contents: &str) {
        fs::write(path, contents).expect("failed to write temp config");
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);

        std::env::temp_dir().join(format!("policy-router-{tag}-{pid}-{nanos}.toml"))
    }

    fn load_example_config() -> AppConfig {
        let raw = include_str!("../../config/config.example.toml");
        let cfg = toml::from_str::<AppConfig>(raw).expect("config.example.toml must parse");
        cfg.validate().expect("config.example.toml must validate");
        cfg
    }

    fn make_state(config_path: PathBuf, cfg: AppConfig) -> State {
        State {
            started_at: Instant::now(),
            config_path,
            socket: "test.sock".to_owned(),
            cfg: ArcSwap::from_pointee(cfg),
            running: AtomicBool::new(true),
            ipc_requests: std::sync::atomic::AtomicU64::new(0),
            reload_ok: std::sync::atomic::AtomicU64::new(0),
            reload_err: std::sync::atomic::AtomicU64::new(0),
        }
    }

    #[test]
    fn reload_invalid_config_keeps_old() {
        let path = tmp_path("reload-invalid");

        // Initial valid config
        let original_cfg = load_example_config();
        write_file(&path, include_str!("../../config/config.example.toml"));

        let state = make_state(path.clone(), original_cfg.clone());

        // Break the file
        write_file(&path, "this = [ is not valid toml");

        // Reload must fail
        let err = reload_config(&state).err();
        assert!(err.is_some());

        // Config must remain unchanged in memory
        let current = state.cfg.load();
        assert_eq!(current.defaults.egress.0, original_cfg.defaults.egress.0);

        assert_eq!(state.reload_ok.load(Ordering::Relaxed), 0);
        assert_eq!(state.reload_err.load(Ordering::Relaxed), 1);

        // Best effort cleanup
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reload_valid_config_updates_state() {
        let path = tmp_path("reload-valid");

        // Initial valid config from example
        write_file(&path, include_str!("../../config/config.example.toml"));
        let original_cfg = AppConfig::load_from_path(&path).expect("must load initial config");

        let state = make_state(path.clone(), original_cfg);

        // Write another valid config with different defaults.egress
        // Minimal toml: keep required sections only
        let next_raw = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"

[rules.app]
direct = []

[rules.domain]
direct = []
"#;

        write_file(&path, next_raw);

        // Reload must succeed
        reload_config(&state).expect("reload should succeed");

        // Must be updated
        let current = state.cfg.load();
        assert_eq!(current.defaults.egress.0, "direct");

        assert_eq!(state.reload_ok.load(Ordering::Relaxed), 1);
        assert_eq!(state.reload_err.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reload_invalid_config_returns_error_with_path() {
        let path = tmp_path("reload-invalid-path");

        write_file(&path, "this = [ is not valid toml");

        let state = make_state(path.clone(), load_example_config());

        let err = reload_config(&state).expect_err("reload should fail");
        assert!(err.to_string().contains(&path.display().to_string()));

        let _ = std::fs::remove_file(path);
    }
}

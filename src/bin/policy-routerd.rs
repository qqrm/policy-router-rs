use std::{
    collections::HashSet,
    io::{self, BufReader},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
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
use notify::{Event, EventKind, RecursiveMode, Watcher};
use policy_router_rs::{
    ipc::{
        DecisionInfo, DecisionSource, DiagnosticsResponse, ErrorResponse, MatcherInfo, MatcherKind,
        ProcessStatus, Request, Response, SOCKET_ENV_VAR, StatusResponse, read_json_line,
        write_json_line,
    },
    policy::{
        config::{AppConfig, RuleTier, ValidatedAppConfig},
        engine,
    },
    supervisor::{DesiredProcess, Supervisor, SupervisorCmd},
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

    #[arg(long, default_value_t = false)]
    watch: bool,
}

#[derive(Debug)]
struct State {
    started_at: Instant,
    config_path: PathBuf,
    socket: String,
    watch_enabled: bool,
    runtime: ArcSwap<RuntimeConfig>,
    include_deps: ArcSwap<Vec<PathBuf>>,
    running: AtomicBool,
    ipc_requests: std::sync::atomic::AtomicU64,
    reload_ok: std::sync::atomic::AtomicU64,
    reload_err: std::sync::atomic::AtomicU64,
    last_reload_epoch_ms: std::sync::atomic::AtomicU64,
    supervisor_tx: Mutex<Option<mpsc::Sender<SupervisorCmd>>>,
    supervisor_handle: Mutex<Option<thread::JoinHandle<()>>>,
    supervisor_status: Arc<Mutex<Vec<ProcessStatus>>>,
}

#[derive(Debug)]
struct RuntimeConfig {
    cfg: ValidatedAppConfig,
    engine: engine::CompiledEngine,
}

fn now_epoch_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
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

    let (cfg, deps) = AppConfig::load_from_path_with_deps(&cli.config)?;
    let cfg = cfg.validate_into()?;
    let runtime = RuntimeConfig {
        engine: engine::CompiledEngine::compile(&cfg),
        cfg,
    };

    let socket_label = resolve_socket_label(cli.socket.as_deref());
    let supervisor_status = Arc::new(Mutex::new(Vec::new()));
    let (supervisor_tx, supervisor_handle) = if has_any_process_spec(&runtime.cfg) {
        let (tx, rx) = mpsc::channel::<SupervisorCmd>();
        let handle = spawn_supervisor(rx, Arc::clone(&supervisor_status));
        (Some(tx), Some(handle))
    } else {
        (None, None)
    };

    let initial_last_reload = now_epoch_ms();

    let state = Arc::new(State {
        started_at: Instant::now(),
        config_path: cli.config,
        socket: socket_label,
        watch_enabled: cli.watch,
        runtime: ArcSwap::from_pointee(runtime),
        include_deps: ArcSwap::from_pointee(deps),
        running: AtomicBool::new(true),
        ipc_requests: std::sync::atomic::AtomicU64::new(0),
        reload_ok: std::sync::atomic::AtomicU64::new(0),
        reload_err: std::sync::atomic::AtomicU64::new(0),
        last_reload_epoch_ms: std::sync::atomic::AtomicU64::new(initial_last_reload),
        supervisor_tx: Mutex::new(supervisor_tx),
        supervisor_handle: Mutex::new(supervisor_handle),
        supervisor_status,
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

    let watcher_handle = if cli.watch {
        info!("watch enabled");
        Some(spawn_config_watcher(Arc::clone(&state)))
    } else {
        None
    };

    let runtime = state.runtime.load();
    apply_desired_if_running(&state, &runtime.cfg);

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

    stop_supervisor_if_running(&state);

    cleanup_fs_socket(fs_socket_path.as_ref());

    if let Some(handle) = watcher_handle {
        match handle.join() {
            Ok(()) => {}
            Err(err) => {
                warn!(error = ?err, "config watcher thread join failed");
            }
        }
    }

    Ok(())
}

fn spawn_supervisor(
    rx: mpsc::Receiver<SupervisorCmd>,
    status: Arc<Mutex<Vec<ProcessStatus>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut supervisor = Supervisor::new(status);
        let tick = Duration::from_millis(200);
        loop {
            match rx.recv_timeout(tick) {
                Ok(SupervisorCmd::ApplyDesired(desired)) => {
                    supervisor.reconcile(desired);
                }
                Ok(SupervisorCmd::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    supervisor.stop_all();
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    supervisor.tick();
                }
            }
        }
    })
}

fn has_any_process_spec(cfg: &AppConfig) -> bool {
    cfg.egress.values().any(|spec| spec.process.is_some())
}

fn apply_desired_if_running(state: &State, cfg: &AppConfig) {
    let maybe_tx = state
        .supervisor_tx
        .lock()
        .ok()
        .and_then(|guard| guard.clone());
    if let Some(tx) = maybe_tx {
        let desired = build_desired_processes(cfg);
        let _ = tx.send(SupervisorCmd::ApplyDesired(desired));
    }
}

fn start_supervisor_if_needed(state: &State, cfg: &AppConfig) -> bool {
    if !has_any_process_spec(cfg) {
        return false;
    }
    let Ok(mut tx_guard) = state.supervisor_tx.lock() else {
        return false;
    };
    if tx_guard.is_some() {
        return false;
    }
    let (tx, rx) = mpsc::channel::<SupervisorCmd>();
    let handle = spawn_supervisor(rx, Arc::clone(&state.supervisor_status));
    *tx_guard = Some(tx.clone());
    drop(tx_guard);
    if let Ok(mut handle_guard) = state.supervisor_handle.lock() {
        *handle_guard = Some(handle);
    }
    let desired = build_desired_processes(cfg);
    let _ = tx.send(SupervisorCmd::ApplyDesired(desired));
    true
}

fn stop_supervisor_if_running(state: &State) {
    let tx = {
        let Ok(mut guard) = state.supervisor_tx.lock() else {
            return;
        };
        guard.take()
    };
    let handle = {
        let Ok(mut guard) = state.supervisor_handle.lock() else {
            return;
        };
        guard.take()
    };

    if let Some(tx) = tx {
        let _ = tx.send(SupervisorCmd::Stop);
    }
    if let Some(handle) = handle {
        match handle.join() {
            Ok(()) => {}
            Err(err) => {
                warn!(error = ?err, "supervisor thread join failed");
            }
        }
    }
    if let Ok(mut guard) = state.supervisor_status.lock() {
        guard.clear();
    }
}

fn reconcile_supervisor(state: &State, cfg: &AppConfig) {
    if has_any_process_spec(cfg) {
        let started = start_supervisor_if_needed(state, cfg);
        if !started {
            apply_desired_if_running(state, cfg);
        }
    } else {
        stop_supervisor_if_running(state);
    }
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

fn spawn_config_watcher(state: Arc<State>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = run_config_watcher(&state) {
            warn!(error = %format!("{err:#}"), "config watcher stopped");
        }
    })
}

fn run_config_watcher(state: &Arc<State>) -> Result<()> {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .context("failed to create config watcher")?;

    watcher
        .watch(&state.config_path, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch config {}", state.config_path.display()))?;

    let mut watched_includes: HashSet<PathBuf> = HashSet::new();
    {
        let deps = state.include_deps.load();
        for p in deps.iter() {
            let _ = watcher.watch(p, RecursiveMode::NonRecursive);
            watched_includes.insert(p.clone());
        }
    }

    let debounce = Duration::from_millis(350);
    let mut last_event: Option<Instant> = None;

    while state.running.load(Ordering::SeqCst) {
        {
            let deps = state.include_deps.load();
            let next: HashSet<PathBuf> = deps.iter().cloned().collect();
            if next != watched_includes {
                for old in watched_includes.difference(&next) {
                    let _ = watcher.unwatch(old);
                }
                for add in next.difference(&watched_includes) {
                    let _ = watcher.watch(add, RecursiveMode::NonRecursive);
                }
                watched_includes = next;
            }
        }

        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(event)) => {
                if should_reload_event(&event, &state.config_path, &watched_includes) {
                    last_event = Some(Instant::now());
                }
            }
            Ok(Err(err)) => {
                warn!(error = %err, "config watch error");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        let should_reload = last_event
            .as_ref()
            .is_some_and(|since| since.elapsed() >= debounce);
        if should_reload {
            last_event = None;
            match reload_config(state) {
                Ok(()) => info!("reloaded config (auto)"),
                Err(err) => {
                    warn!(error = %format!("{err:#}"), "auto reload failed");
                }
            }
        }
    }

    Ok(())
}

fn should_reload_event(
    event: &Event,
    config_path: &Path,
    watched_includes: &HashSet<PathBuf>,
) -> bool {
    if !matches!(
        &event.kind,
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_) | EventKind::Any
    ) {
        return false;
    }

    event.paths.iter().any(|path| {
        if path == config_path {
            return true;
        }
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
        watched_includes.contains(&key)
    })
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
        Request::Reload => reload_config_response(
            state,
            Response::OkReload,
            "reloaded config",
            "reload failed",
        ),
        Request::Apply => {
            reload_config_response(state, Response::OkApply, "applied config", "apply failed")
        }
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
    let runtime = state.runtime.load();
    let egress = runtime
        .cfg
        .egress
        .iter()
        .map(|(id, spec)| policy_router_rs::ipc::EgressInfo {
            id: id.to_string(),
            kind: spec.kind.to_string(),
            endpoint: spec.endpoint.clone(),
        })
        .collect::<Vec<_>>();

    let last_reload_ms = match state.last_reload_epoch_ms.load(Ordering::Relaxed) {
        0 => None,
        value => Some(value),
    };

    StatusResponse {
        uptime_ms: u64::try_from(state.started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
        last_reload_ms,
        config_path: state.config_path.display().to_string(),
        egress,
    }
}

fn build_diagnostics(state: &State) -> DiagnosticsResponse {
    let uptime_ms = u64::try_from(state.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);

    let runtime = state.runtime.load();

    let last_reload_ms = match state.last_reload_epoch_ms.load(Ordering::Relaxed) {
        0 => None,
        value => Some(value),
    };

    DiagnosticsResponse {
        uptime_ms,
        last_reload_ms,
        config_path: state.config_path.display().to_string(),
        socket: state.socket.clone(),
        egress_count: runtime.cfg.egress.len(),
        running: state.running.load(Ordering::SeqCst),
        ipc_requests: state.ipc_requests.load(std::sync::atomic::Ordering::SeqCst),
        reload_ok: state.reload_ok.load(std::sync::atomic::Ordering::SeqCst),
        reload_err: state.reload_err.load(std::sync::atomic::Ordering::SeqCst),
        watch_enabled: state.watch_enabled,
        processes: state
            .supervisor_status
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default(),
    }
}

fn reload_config_response(
    state: &State,
    ok_response: Response,
    ok_log: &str,
    err_label: &str,
) -> Response {
    match reload_config(state) {
        Ok(()) => {
            info!(message = ok_log);
            ok_response
        }
        Err(e) => {
            warn!(error = %format!("{e:#}"), "{err_label}");
            Response::Err(ErrorResponse {
                message: format!("{err_label} for {}: {:#}", state.config_path.display(), e),
            })
        }
    }
}

fn reload_config(state: &State) -> Result<()> {
    let (next, deps) = match AppConfig::load_from_path_with_deps(&state.config_path)
        .with_context(|| format!("failed to load config {}", state.config_path.display()))
    {
        Ok(cfg) => cfg,
        Err(err) => {
            state.reload_err.fetch_add(1, Ordering::Relaxed);
            return Err(err);
        }
    };

    let next = next.validate_into()?;
    let runtime = RuntimeConfig {
        engine: engine::CompiledEngine::compile(&next),
        cfg: next,
    };
    state.runtime.store(Arc::new(runtime));
    state.include_deps.store(Arc::new(deps));
    state
        .last_reload_epoch_ms
        .store(now_epoch_ms(), Ordering::Relaxed);
    state.reload_ok.fetch_add(1, Ordering::Relaxed);
    let runtime = state.runtime.load();
    reconcile_supervisor(state, &runtime.cfg);
    Ok(())
}

fn handle_explain(state: &State, req: &policy_router_rs::ipc::ExplainRequest) -> Response {
    let dst_ip = match req.dst_ip.as_deref() {
        Some(raw) => match raw.parse::<IpAddr>() {
            Ok(ip) => Some(ip),
            Err(_) => {
                return Response::Err(ErrorResponse {
                    message: format!("invalid dst_ip '{raw}' (expected IP address)"),
                });
            }
        },
        None => None,
    };

    let decision = explain(state, req.process.as_deref(), req.domain.as_deref(), dst_ip);
    Response::OkExplain(decision)
}

fn explain(
    state: &State,
    process: Option<&str>,
    domain: Option<&str>,
    dst_ip: Option<IpAddr>,
) -> policy_router_rs::ipc::ExplainResponse {
    let decision = {
        let runtime = state.runtime.load();
        runtime.engine.decide(process, domain, dst_ip)
    };

    let source = map_source(&decision.reason);
    let rule_egress = Some(map_rule_egress(&decision.reason));
    let matcher = map_matcher(&decision.reason);
    let (rule_index, rule_name) = match &decision.reason {
        engine::DecisionReason::RuleMatch {
            rule_index,
            rule_name,
            ..
        } => (Some(*rule_index), rule_name.clone()),
        engine::DecisionReason::Default { .. } => (None, None),
    };

    policy_router_rs::ipc::ExplainResponse {
        decision: DecisionInfo {
            egress: decision.egress.to_string(),
            reason: decision.reason.to_human(),
            source,
            rule_egress,
            rule_index,
            rule_name,
            matcher,
        },
    }
}

const fn map_source(reason: &engine::DecisionReason) -> DecisionSource {
    match reason {
        engine::DecisionReason::RuleMatch { tier, .. } => match tier {
            RuleTier::AppDomain => DecisionSource::AppDomainRule,
            RuleTier::Domain => DecisionSource::DomainRule,
            RuleTier::DstIp => DecisionSource::DstIpCidrRule,
            RuleTier::App => DecisionSource::AppRule,
            RuleTier::Default => DecisionSource::Default,
        },
        engine::DecisionReason::Default { .. } => DecisionSource::Default,
    }
}

fn map_rule_egress(reason: &engine::DecisionReason) -> String {
    match reason {
        engine::DecisionReason::RuleMatch { egress, .. }
        | engine::DecisionReason::Default { egress } => egress.to_string(),
    }
}

fn map_matcher(reason: &engine::DecisionReason) -> Option<MatcherInfo> {
    match reason {
        engine::DecisionReason::RuleMatch {
            app,
            domain,
            dst_ip_cidr,
            ..
        } => {
            if let Some(domain) = domain {
                return Some(MatcherInfo {
                    kind: map_matcher_kind(domain.match_kind),
                    pattern: domain.pattern.clone(),
                });
            }
            if let Some(cidr) = dst_ip_cidr {
                return Some(MatcherInfo {
                    kind: MatcherKind::Cidr,
                    pattern: cidr.to_string(),
                });
            }
            app.as_ref().map(|pattern| MatcherInfo {
                kind: MatcherKind::Exact,
                pattern: pattern.clone(),
            })
        }
        engine::DecisionReason::Default { .. } => None,
    }
}

const fn map_matcher_kind(match_kind: engine::MatchKind) -> MatcherKind {
    match match_kind {
        engine::MatchKind::Exact => MatcherKind::Exact,
        engine::MatchKind::Suffix => MatcherKind::Suffix,
    }
}

fn build_desired_processes(cfg: &AppConfig) -> Vec<DesiredProcess> {
    cfg.egress
        .iter()
        .filter_map(|(id, spec)| {
            spec.process.as_ref().map(|process| DesiredProcess {
                egress_id: id.clone(),
                spec: process.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use notify::EventKind;

    use super::*;

    fn write_file(path: &PathBuf, contents: &str) {
        fs::write(path, contents).expect("failed to write temp config");
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());

        std::env::temp_dir().join(format!("policy-router-{tag}-{pid}-{nanos}.toml"))
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());

        std::env::temp_dir().join(format!("policy-router-{tag}-{pid}-{nanos}"))
    }

    fn mk_event(kind: notify::EventKind, paths: Vec<PathBuf>) -> notify::Event {
        notify::Event {
            kind,
            paths,
            attrs: notify::event::EventAttributes::default(),
        }
    }

    fn load_example_config() -> ValidatedAppConfig {
        let raw = include_str!("../../config/config.example.toml");
        let cfg = toml::from_str::<AppConfig>(raw).expect("config.example.toml must parse");
        cfg.validate_into()
            .expect("config.example.toml must validate")
    }

    fn make_state(config_path: PathBuf, cfg: ValidatedAppConfig) -> State {
        let runtime = RuntimeConfig {
            engine: engine::CompiledEngine::compile(&cfg),
            cfg,
        };
        let deps = Vec::new();
        State {
            started_at: Instant::now(),
            config_path,
            socket: "test.sock".to_owned(),
            watch_enabled: false,
            runtime: ArcSwap::from_pointee(runtime),
            include_deps: ArcSwap::from_pointee(deps),
            running: AtomicBool::new(true),
            ipc_requests: std::sync::atomic::AtomicU64::new(0),
            reload_ok: std::sync::atomic::AtomicU64::new(0),
            reload_err: std::sync::atomic::AtomicU64::new(0),
            last_reload_epoch_ms: std::sync::atomic::AtomicU64::new(0),
            supervisor_tx: Mutex::new(None),
            supervisor_handle: Mutex::new(None),
            supervisor_status: Arc::new(Mutex::new(Vec::new())),
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
        let current = state.runtime.load();
        assert_eq!(
            current.cfg.defaults.egress.0,
            original_cfg.defaults.egress.0
        );

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
        let original_cfg = AppConfig::load_from_path(&path)
            .expect("must load initial config")
            .validate_into()
            .expect("config must validate");

        let state = make_state(path.clone(), original_cfg);

        // Write another valid config with different defaults.egress
        // Minimal toml: keep required sections only
        let next_raw = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"
"#;

        write_file(&path, next_raw);

        // Reload must succeed
        reload_config(&state).expect("reload should succeed");

        // Must be updated
        let current = state.runtime.load();
        assert_eq!(current.cfg.defaults.egress.0, "direct");

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

    #[test]
    fn reload_event_triggers_on_config_path() {
        let dir = tmp_dir("reload-event-config");
        let config_path = dir.join("config.toml");
        let watched_includes = HashSet::new();

        let event = mk_event(
            EventKind::Modify(notify::event::ModifyKind::Any),
            vec![config_path.clone()],
        );

        assert!(should_reload_event(&event, &config_path, &watched_includes));
    }

    #[test]
    fn reload_event_triggers_on_include_canonicalization() {
        let dir = tmp_dir("reload-event-include");
        let include_real = dir.join("lists").join("vpn.txt");
        fs::create_dir_all(include_real.parent().expect("include parent"))
            .expect("create include dir");
        fs::write(&include_real, "data").expect("write include file");

        let watched_key = fs::canonicalize(&include_real).expect("canonicalize include file");
        let mut watched_includes = HashSet::new();
        watched_includes.insert(watched_key);

        let noncanonical = dir.join("lists").join("..").join("lists").join("vpn.txt");
        let event = mk_event(
            EventKind::Modify(notify::event::ModifyKind::Any),
            vec![noncanonical],
        );

        assert!(should_reload_event(
            &event,
            &dir.join("config.toml"),
            &watched_includes
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_event_ignores_unrelated_path() {
        let dir = tmp_dir("reload-event-unrelated");
        let config_path = dir.join("config.toml");
        let include_real = dir.join("lists").join("vpn.txt");
        fs::create_dir_all(include_real.parent().expect("include parent"))
            .expect("create include dir");
        fs::write(&include_real, "data").expect("write include file");

        let watched_key = fs::canonicalize(&include_real).expect("canonicalize include file");
        let mut watched_includes = HashSet::new();
        watched_includes.insert(watched_key);

        let other = dir.join("other.txt");
        let event = mk_event(
            EventKind::Modify(notify::event::ModifyKind::Any),
            vec![other],
        );

        assert!(!should_reload_event(
            &event,
            &config_path,
            &watched_includes
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reload_event_ignores_irrelevant_kind() {
        let dir = tmp_dir("reload-event-kind");
        let config_path = dir.join("config.toml");
        let watched_includes = HashSet::new();

        let event = mk_event(
            EventKind::Access(notify::event::AccessKind::Any),
            vec![config_path.clone()],
        );

        assert!(!should_reload_event(
            &event,
            &config_path,
            &watched_includes
        ));
    }
}

use std::{io::BufReader, thread};

use anyhow::{Context, Result};
use interprocess::local_socket::{
    GenericFilePath, GenericNamespaced, ListenerOptions, Stream, prelude::*,
};
use policy_router_rs::ipc::{
    DecisionInfo, DecisionSource, DiagnosticsResponse, EgressInfo, ExplainRequest, ExplainResponse,
    MatcherInfo, MatcherKind, Request, Response, StatusResponse, client_roundtrip, read_json_line,
    write_json_line,
};

fn unique_tag() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let pid = std::process::id();
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    format!("{pid}-{nanos}-{seq}")
}

fn make_name() -> Result<interprocess::local_socket::Name<'static>> {
    let tag = unique_tag();

    if GenericNamespaced::is_supported() {
        let raw = format!("policy-router-test-{tag}");
        let leaked: &'static str = Box::leak(raw.into_boxed_str());
        Ok(leaked
            .to_ns_name::<GenericNamespaced>()
            .context("failed to build namespaced socket name")?)
    } else {
        let raw = format!("/tmp/policy-router-test-{tag}.sock");
        let leaked: &'static str = Box::leak(raw.into_boxed_str());
        Ok(leaked
            .to_fs_name::<GenericFilePath>()
            .context("failed to build filesystem socket name")?)
    }
}

struct TestServer {
    #[allow(dead_code)]
    name: interprocess::local_socket::Name<'static>,
    join: thread::JoinHandle<()>,
    ready: std::sync::mpsc::Receiver<()>,
}

impl TestServer {
    fn wait_ready(self) -> thread::JoinHandle<()> {
        self.ready
            .recv()
            .expect("test IPC server failed before signaling readiness");
        self.join
    }
}

fn spawn_stateful_server(
    name: interprocess::local_socket::Name<'static>,
    max_accepts: usize,
) -> TestServer {
    let (tx, rx) = std::sync::mpsc::channel::<()>();

    let name_for_thread = name.clone();

    let join = thread::spawn(move || {
        let listener = ListenerOptions::new()
            .name(name_for_thread)
            .create_sync()
            .expect("failed to create test IPC listener");

        // Listener is bound and ready now.
        let _ = tx.send(());

        let mut state = 0u32;

        for _ in 0..max_accepts {
            let mut conn = listener.accept().expect("failed to accept IPC connection");

            let req: Request =
                read_json_line(BufReader::new(&mut conn)).expect("failed to read request");

            let resp = match req {
                Request::Status => {
                    let kind = if state == 0 { "socks5" } else { "direct" };

                    Response::OkStatus(StatusResponse {
                        uptime_ms: 123,
                        config_path: "config.toml".to_owned(),
                        egress: vec![
                            EgressInfo {
                                id: "vpn".to_owned(),
                                kind: kind.to_owned(),
                                endpoint: Some("127.0.0.1:1080".to_owned()),
                            },
                            EgressInfo {
                                id: "direct".to_owned(),
                                kind: "direct".to_owned(),
                                endpoint: None,
                            },
                        ],
                    })
                }
                Request::Reload => {
                    state = 1;
                    Response::OkReload
                }
                Request::Stop => {
                    write_json_line(&mut conn, &Response::OkStop)
                        .expect("failed to write response");
                    return;
                }
                Request::Explain(x) => {
                    let proc = x.process.unwrap_or_else(|| "<none>".to_owned());
                    let dom = x.domain.unwrap_or_else(|| "<none>".to_owned());

                    Response::OkExplain(ExplainResponse {
                        decision: DecisionInfo {
                            egress: "vpn".to_owned(),
                            reason: format!("process={proc} domain={dom}"),
                            source: DecisionSource::Default,
                            rule_egress: Some("vpn".to_owned()),
                            matcher: Some(MatcherInfo {
                                kind: MatcherKind::Exact,
                                pattern: "example".to_owned(),
                            }),
                        },
                    })
                }
                Request::Diagnostics => Response::OkDiagnostics(DiagnosticsResponse {
                    uptime_ms: 123,
                    config_path: "config.toml".to_owned(),
                    socket: "test.sock".to_owned(),
                    egress_count: 2,
                    running: true,
                    ipc_requests: 1,
                    reload_ok: 0,
                    reload_err: 0,
                }),
            };

            write_json_line(&mut conn, &resp).expect("failed to write response");
        }
    });

    TestServer {
        name,
        join,
        ready: rx,
    }
}

#[test]
fn ipc_status_roundtrip() -> Result<()> {
    let name = make_name()?;
    let _server = spawn_stateful_server(name.clone(), 1).wait_ready();

    let mut conn = Stream::connect(name).context("failed to connect to test IPC server")?;
    let resp = client_roundtrip(&mut conn, &Request::Status)?;

    match resp {
        Response::OkStatus(s) => {
            assert_eq!(s.uptime_ms, 123);
            assert_eq!(s.config_path, "config.toml");
            assert_eq!(s.egress.len(), 2);
            assert_eq!(s.egress[0].id, "vpn");
            assert_eq!(s.egress[0].endpoint.as_deref(), Some("127.0.0.1:1080"));
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

#[test]
fn ipc_explain_roundtrip() -> Result<()> {
    let name = make_name()?;
    let _server = spawn_stateful_server(name.clone(), 1).wait_ready();

    let mut conn = Stream::connect(name).context("failed to connect to test IPC server")?;

    let req = Request::Explain(ExplainRequest {
        process: Some("chrome.exe".to_owned()),
        domain: Some("youtube.com".to_owned()),
    });

    let resp = client_roundtrip(&mut conn, &req)?;

    match resp {
        Response::OkExplain(x) => {
            assert_eq!(x.decision.egress, "vpn");
            assert!(x.decision.reason.contains("process=chrome.exe"));
            assert!(x.decision.reason.contains("domain=youtube.com"));
            assert_eq!(x.decision.rule_egress.as_deref(), Some("vpn"));
            assert!(x.decision.matcher.is_some());
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

#[test]
fn ipc_reload_roundtrip() -> Result<()> {
    let name = make_name()?;
    let _server = spawn_stateful_server(name.clone(), 3).wait_ready();

    // Status 1
    let mut conn1 =
        Stream::connect(name.clone()).context("failed to connect to test IPC server")?;
    let r1 = client_roundtrip(&mut conn1, &Request::Status)?;
    let k1 = match r1 {
        Response::OkStatus(s) => s.egress[0].kind.clone(),
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    // Reload
    let mut conn2 =
        Stream::connect(name.clone()).context("failed to connect to test IPC server")?;
    let r2 = client_roundtrip(&mut conn2, &Request::Reload)?;
    if !matches!(r2, Response::OkReload) {
        anyhow::bail!("unexpected response: {r2:?}");
    }

    // Status 2
    let mut conn3 = Stream::connect(name).context("failed to connect to test IPC server")?;
    let r3 = client_roundtrip(&mut conn3, &Request::Status)?;
    let k2 = match r3 {
        Response::OkStatus(s) => s.egress[0].kind.clone(),
        other => anyhow::bail!("unexpected response: {other:?}"),
    };

    assert_ne!(k1, k2);

    Ok(())
}

#[test]
fn ipc_stop_roundtrip() -> Result<()> {
    let name = make_name()?;
    let server = spawn_stateful_server(name.clone(), 1).wait_ready();

    let mut conn = Stream::connect(name.clone()).context("failed to connect to test IPC server")?;
    let resp = client_roundtrip(&mut conn, &Request::Stop)?;

    if !matches!(resp, Response::OkStop) {
        anyhow::bail!("unexpected response: {resp:?}");
    }

    // Make it deterministic: wait server exit.
    server.join().expect("test IPC server thread panicked");

    // Server exited, so a new connection should fail.
    assert!(Stream::connect(name).is_err());

    Ok(())
}

#[test]
fn ipc_diagnostics_roundtrip() -> Result<()> {
    let name = make_name()?;
    let _server = spawn_stateful_server(name.clone(), 1).wait_ready();

    let mut conn = Stream::connect(name).context("failed to connect to test IPC server")?;
    let resp = client_roundtrip(&mut conn, &Request::Diagnostics)?;

    match resp {
        Response::OkDiagnostics(d) => {
            assert_eq!(d.uptime_ms, 123);
            assert_eq!(d.config_path, "config.toml");
            assert_eq!(d.socket, "test.sock");
            assert_eq!(d.egress_count, 2);
            assert!(d.running);
            assert_eq!(d.ipc_requests, 1);
            assert_eq!(d.reload_ok, 0);
            assert_eq!(d.reload_err, 0);
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

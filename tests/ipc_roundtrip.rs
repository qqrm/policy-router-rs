use anyhow::{Context, Result};
use interprocess::local_socket::{prelude::*, ListenerOptions, Stream, GenericFilePath, GenericNamespaced};
use policy_router_rs::ipc::{
    client_roundtrip, read_json_line, write_json_line, DecisionInfo, EgressInfo, ErrorResponse,
    ExplainRequest, ExplainResponse, Request, Response, StatusResponse,
};
use std::io::BufReader;
use std::thread;
use std::time::Duration;

fn unique_tag() -> String {
    // No extra deps: uniqueness is sufficient for test isolation.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{pid}-{nanos}")
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

fn spawn_one_shot_server(name: interprocess::local_socket::Name<'static>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let listener = ListenerOptions::new()
            .name(name)
            .create_sync()
            .expect("failed to create test IPC listener");

        let mut conn = listener.accept().expect("failed to accept IPC connection");

        let req: Request = read_json_line(BufReader::new(&mut conn)).expect("failed to read request");

        let resp = match req {
            Request::Status => Response::OkStatus(StatusResponse {
                uptime_ms: 123,
                config_path: "config.toml".to_owned(),
                egress: vec![
                    EgressInfo {
                        id: "vpn".to_owned(),
                        kind: "socks5".to_owned(),
                        endpoint: Some("127.0.0.1:1080".to_owned()),
                    },
                    EgressInfo {
                        id: "direct".to_owned(),
                        kind: "direct".to_owned(),
                        endpoint: None,
                    },
                ],
            }),
            Request::Explain(x) => {
                let proc = x.process.unwrap_or_else(|| "<none>".to_owned());
                let dom = x.domain.unwrap_or_else(|| "<none>".to_owned());
                Response::OkExplain(ExplainResponse {
                    decision: DecisionInfo {
                        egress: "vpn".to_owned(),
                        reason: format!("process={proc} domain={dom}"),
                    },
                })
            }
            _ => Response::Err(ErrorResponse {
                message: "unsupported in test server".to_owned(),
            }),
        };

        write_json_line(&mut conn, &resp).expect("failed to write response");
    })
}

#[test]
fn ipc_status_roundtrip() -> Result<()> {
    let name = make_name()?;
    let _server = spawn_one_shot_server(name.clone());

    // Give the server a moment to bind.
    thread::sleep(Duration::from_millis(20));

    let mut conn = Stream::connect(name).context("failed to connect to test IPC server")?;
    let resp = client_roundtrip(&mut conn, &Request::Status)?;

    match resp {
        Response::OkStatus(s) => {
            assert_eq!(s.uptime_ms, 123);
            assert_eq!(s.config_path, "config.toml");
            assert_eq!(s.egress.len(), 2);
            assert_eq!(s.egress[0].id, "vpn");
            assert_eq!(s.egress[0].kind, "socks5");
            assert_eq!(s.egress[0].endpoint.as_deref(), Some("127.0.0.1:1080"));
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

#[test]
fn ipc_explain_roundtrip() -> Result<()> {
    let name = make_name()?;
    let _server = spawn_one_shot_server(name.clone());

    thread::sleep(Duration::from_millis(20));

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
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    Ok(())
}

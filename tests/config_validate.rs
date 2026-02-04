use policy_router_rs::policy::config::AppConfig;

fn base_config(egress_block: &str, rules_block: &str) -> String {
    format!(
        r#"[defaults]
egress = "main"

{egress_block}

{rules_block}
"#
    )
}

#[test]
fn validate_rejects_missing_endpoint_for_socks5() {
    let raw = base_config(
        r#"[egress.main]
type = "socks5"
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_missing_endpoint_for_singbox() {
    let raw = base_config(
        r#"[egress.main]
type = "singbox"
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_endpoint_for_direct() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"
endpoint = "socks5://127.0.0.1:1080"
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_endpoint_for_block() {
    let raw = base_config(
        r#"[egress.main]
type = "block"
endpoint = "socks5://127.0.0.1:1080"
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_bad_endpoint_format() {
    let endpoints = [
        "127.0.0.1:1080",
        "socks5://127.0.0.1",
        "socks5://127.0.0.1:70000",
    ];

    for endpoint in endpoints {
        let raw = base_config(
            &format!(
                r#"[egress.main]
type = "socks5"
endpoint = "{endpoint}"
"#
            ),
            "",
        );
        let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
        assert!(cfg.validate().is_err());
    }
}

#[test]
fn validate_rejects_empty_patterns() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"
"#,
        r#"
[[rules]]
egress = "main"
app = ""

[[rules]]
egress = "main"
domain = "   "
"#,
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_enabled_process_with_empty_program() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"

[egress.main.process]
enabled = true
program = "   "
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_enabled_process_with_bad_backoff() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"

[egress.main.process]
enabled = true
program = "worker"
backoff_ms = 0
max_backoff_ms = 10
max_restarts_per_minute = 1
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_enabled_process_with_zero_restart_limit() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"

[egress.main.process]
enabled = true
program = "worker"
backoff_ms = 10
max_backoff_ms = 10
max_restarts_per_minute = 0
"#,
        "",
    );
    let mut cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

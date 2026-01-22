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
        r"[rules.app]
main = []

[rules.domain]
main = []
",
    );
    let cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_missing_endpoint_for_singbox() {
    let raw = base_config(
        r#"[egress.main]
type = "singbox"
"#,
        r"[rules.app]
main = []

[rules.domain]
main = []
",
    );
    let cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_endpoint_for_direct() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"
endpoint = "socks5://127.0.0.1:1080"
"#,
        r"[rules.app]
main = []

[rules.domain]
main = []
",
    );
    let cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

#[test]
fn validate_rejects_endpoint_for_block() {
    let raw = base_config(
        r#"[egress.main]
type = "block"
endpoint = "socks5://127.0.0.1:1080"
"#,
        r"[rules.app]
main = []

[rules.domain]
main = []
",
    );
    let cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
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
            r"[rules.app]
main = []

[rules.domain]
main = []
",
        );
        let cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
        assert!(cfg.validate().is_err());
    }
}

#[test]
fn validate_rejects_empty_patterns() {
    let raw = base_config(
        r#"[egress.main]
type = "direct"
"#,
        r#"[rules.app]
main = [""]

[rules.domain]
main = ["   "]
"#,
    );
    let cfg = toml::from_str::<AppConfig>(&raw).expect("config must parse");
    assert!(cfg.validate().is_err());
}

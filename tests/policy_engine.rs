use policy_router_rs::policy::{
    config::{AppConfig, EgressId},
    engine::{DecisionReason, decide},
};

fn cfg_minimal() -> AppConfig {
    let toml = r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[egress.proxy]
type = "socks5"
endpoint = "socks5://127.0.0.1:1080"

[egress.direct]
type = "direct"

[egress.block]
type = "block"

[rules.domain]
vpn = ["chatgpt.com"]
proxy = ["youtube.com", "googlevideo.com"]
direct = ["ru"]
block = ["blocked.example"]

[rules.app]
vpn = ["zen.exe"]
proxy = ["curl.exe"]
direct = ["ciadpi.exe"]
block = ["bad.exe"]
"#;

    toml::from_str::<AppConfig>(toml).expect("test config TOML must parse")
}

fn eid(s: &str) -> EgressId {
    EgressId(s.to_string())
}

#[test]
fn domain_wins_over_app() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("youtube.com"));
    assert_eq!(d.egress, eid("proxy"));

    match d.reason {
        DecisionReason::DomainRule {
            pattern, egress, ..
        } => {
            assert_eq!(pattern, "youtube.com");
            assert_eq!(egress, eid("proxy"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn app_used_when_no_domain_match() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("unknown.example"));
    assert_eq!(d.egress, eid("vpn"));

    match d.reason {
        DecisionReason::AppRule { pattern, egress } => {
            assert_eq!(pattern, "zen.exe");
            assert_eq!(egress, eid("vpn"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn default_used_when_nothing_matches() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("notepad.exe"), Some("unknown.example"));
    assert_eq!(d.egress, eid("vpn"));

    match d.reason {
        DecisionReason::Default { egress } => {
            assert_eq!(egress, eid("vpn"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn block_by_app_has_top_priority() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("bad.exe"), Some("youtube.com"));
    assert_eq!(d.egress, eid("block"));

    match d.reason {
        DecisionReason::BlockByApp { pattern, egress } => {
            assert_eq!(pattern, "bad.exe");
            assert_eq!(egress, eid("block"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn block_by_domain_has_top_priority() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("blocked.example"));
    assert_eq!(d.egress, eid("block"));

    match d.reason {
        DecisionReason::BlockByDomain {
            pattern, egress, ..
        } => {
            assert_eq!(pattern, "blocked.example");
            assert_eq!(egress, eid("block"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn domain_suffix_matching_subdomains() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(
        &cfg,
        Some("zen.exe"),
        Some("r1---sn-abcdef.googlevideo.com"),
    );
    assert_eq!(d.egress, eid("proxy"));
}

#[test]
fn domain_matching_case_insensitive() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("YouTube.COM"));
    assert_eq!(d.egress, eid("proxy"));
}

#[test]
fn app_matching_case_insensitive() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("ZEN.EXE"), Some("unknown.example"));
    assert_eq!(d.egress, eid("vpn"));
}

#[test]
fn app_rule_matches_full_windows_path() {
    let toml = r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[rules.app]
vpn = ["zen.exe"]
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(
        &cfg,
        Some(r"C:\Program Files\Zen\zen.exe"),
        Some("unknown.example"),
    );
    assert_eq!(d.egress, eid("vpn"));

    match d.reason {
        DecisionReason::AppRule { pattern, egress } => {
            assert_eq!(pattern, "zen.exe");
            assert_eq!(egress, eid("vpn"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn block_app_matches_full_windows_path() {
    let toml = r#"
[defaults]
egress = "block"

[egress.block]
type = "block"

[rules.app]
block = ["bad.exe"]
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some(r"C:\bad.exe"), Some("youtube.com"));
    assert_eq!(d.egress, eid("block"));

    match d.reason {
        DecisionReason::BlockByApp { pattern, egress } => {
            assert_eq!(pattern, "bad.exe");
            assert_eq!(egress, eid("block"));
        }
        other => panic!("unexpected reason: {other:?}"),
    }
}

#[test]
fn reason_includes_suffix_domain_match_details() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(
        &cfg,
        Some("zen.exe"),
        Some("r1---sn-abcdef.googlevideo.com"),
    );
    let reason = d.reason.to_human();

    assert!(reason.contains("domain"));
    assert!(reason.contains("suffix"));
    assert!(reason.contains("googlevideo.com"));
}

#[test]
fn reason_includes_exact_app_match_details() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("curl.exe"), Some("unknown.example"));
    let reason = d.reason.to_human();

    assert!(reason.contains("app"));
    assert!(reason.contains("exact"));
    assert!(reason.contains("curl.exe"));
}

#[test]
fn explicit_direct_app_rule() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("ciadpi.exe"), Some("youtube.com"));
    // Domain wins over app, so still proxy due to youtube.com
    assert_eq!(d.egress, eid("proxy"));

    let d2 = decide(&cfg, Some("ciadpi.exe"), Some("unknown.example"));
    assert_eq!(d2.egress, eid("direct"));
}

#[test]
fn validate_rejects_unknown_rule_egress() {
    let toml = r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[rules.app]
unknown = ["bad.exe"]

[rules.domain]
vpn = ["example.com"]
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    let err = cfg.validate().err();
    assert!(err.is_some());
}

#[test]
fn domain_priority_prefers_singbox_over_direct() {
    let toml = r#"
[defaults]
egress = "direct"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[egress.direct]
type = "direct"

[rules.domain]
direct = ["example.com"]
vpn = ["example.com"]

[rules.app]
direct = []
vpn = []
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("example.com"));
    assert_eq!(d.egress, eid("vpn"));
}

#[test]
fn app_priority_prefers_singbox_over_direct() {
    let toml = r#"
[defaults]
egress = "direct"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[egress.direct]
type = "direct"

[rules.domain]
direct = []
vpn = []

[rules.app]
direct = ["zen.exe"]
vpn = ["zen.exe"]
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("example.com"));
    assert_eq!(d.egress, eid("vpn"));
}

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

[[rules]]
egress = "proxy"
domain = "youtube.com"

[[rules]]
egress = "proxy"
domain = "googlevideo.com"

[[rules]]
egress = "vpn"
domain = "chatgpt.com"

[[rules]]
egress = "block"
domain = "blocked.example"

[[rules]]
egress = "vpn"
app = "zen.exe"

[[rules]]
egress = "proxy"
app = "curl.exe"

[[rules]]
egress = "direct"
app = "ciadpi.exe"

[[rules]]
egress = "block"
app = "bad.exe"
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

    let d = decide(&cfg, Some("zen.exe"), Some("youtube.com"), None);
    assert_eq!(d.egress, eid("proxy"));

    match d.reason {
        DecisionReason::RuleMatch { tier, .. } => {
            assert_eq!(tier.as_str(), "domain");
        }
        DecisionReason::Default { .. } => {
            panic!("unexpected default reason")
        }
    }
}

#[test]
fn app_used_when_no_domain_match() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("unknown.example"), None);
    assert_eq!(d.egress, eid("vpn"));

    match d.reason {
        DecisionReason::RuleMatch { tier, .. } => {
            assert_eq!(tier.as_str(), "app");
        }
        DecisionReason::Default { .. } => {
            panic!("unexpected default reason")
        }
    }
}

#[test]
fn default_used_when_nothing_matches() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("notepad.exe"), Some("unknown.example"), None);
    assert_eq!(d.egress, eid("vpn"));

    match d.reason {
        DecisionReason::Default { egress } => {
            assert_eq!(egress, eid("vpn"));
        }
        DecisionReason::RuleMatch { .. } => {
            panic!("unexpected rule match")
        }
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
        None,
    );
    assert_eq!(d.egress, eid("proxy"));
}

#[test]
fn domain_matching_case_insensitive() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("YouTube.COM"), None);
    assert_eq!(d.egress, eid("proxy"));
}

#[test]
fn app_matching_case_insensitive() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("ZEN.EXE"), Some("unknown.example"), None);
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

[[rules]]
egress = "vpn"
app = "zen.exe"
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(
        &cfg,
        Some(r"C:\Program Files\Zen\zen.exe"),
        Some("unknown.example"),
        None,
    );
    assert_eq!(d.egress, eid("vpn"));

    match d.reason {
        DecisionReason::RuleMatch { tier, .. } => {
            assert_eq!(tier.as_str(), "app");
        }
        DecisionReason::Default { .. } => {
            panic!("unexpected default reason")
        }
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
        None,
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

    let d = decide(&cfg, Some("curl.exe"), Some("unknown.example"), None);
    let reason = d.reason.to_human();

    assert!(reason.contains("app"));
    assert!(reason.contains("exact"));
    assert!(reason.contains("curl.exe"));
}

#[test]
fn explicit_direct_app_rule() {
    let cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("ciadpi.exe"), Some("youtube.com"), None);
    assert_eq!(d.egress, eid("proxy"));

    let d2 = decide(&cfg, Some("ciadpi.exe"), Some("unknown.example"), None);
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

[[rules]]
egress = "unknown"
app = "bad.exe"

[[rules]]
egress = "vpn"
domain = "example.com"
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    let err = cfg.validate().err();
    assert!(err.is_some());
}

#[test]
fn app_domain_overrides_domain_and_app() {
    let toml = r#"
[defaults]
egress = "direct"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[egress.direct]
type = "direct"

[[rules]]
egress = "vpn"
domain = "example.com"

[[rules]]
egress = "direct"
app = "zen.exe"

[[rules]]
egress = "direct"
app = "zen.exe"
domain = "example.com"
"#;

    let cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("example.com"), None);
    assert_eq!(d.egress, eid("direct"));
}

use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

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

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards")
        .as_nanos();
    let mut path = std::env::temp_dir();
    path.push(format!(
        "policy-router-{prefix}-{nanos}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&path).expect("failed to create temp dir");
    path
}

#[test]
fn domain_wins_over_app() {
    let mut cfg = cfg_minimal();
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
    let mut cfg = cfg_minimal();
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
    let mut cfg = cfg_minimal();
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
    let mut cfg = cfg_minimal();
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
    let mut cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("YouTube.COM"), None);
    assert_eq!(d.egress, eid("proxy"));
}

#[test]
fn app_matching_case_insensitive() {
    let mut cfg = cfg_minimal();
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

    let mut cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
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
    let mut cfg = cfg_minimal();
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
    let mut cfg = cfg_minimal();
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("curl.exe"), Some("unknown.example"), None);
    let reason = d.reason.to_human();

    assert!(reason.contains("app"));
    assert!(reason.contains("exact"));
    assert!(reason.contains("curl.exe"));
}

#[test]
fn explicit_direct_app_rule() {
    let mut cfg = cfg_minimal();
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

    let mut cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
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

    let mut cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, Some("zen.exe"), Some("example.com"), None);
    assert_eq!(d.egress, eid("direct"));
}

#[test]
fn rule_name_and_index_propagate() {
    let toml = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"

[egress.proxy]
type = "socks5"
endpoint = "socks5://127.0.0.1:1080"

[[rules]]
egress = "direct"
domain = "example.com"

[[rules]]
egress = "proxy"
domain = "youtube.com"
name = "video"
"#;

    let mut cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    cfg.validate().expect("config must validate");

    let d = decide(&cfg, None, Some("youtube.com"), None);
    assert_eq!(d.egress, eid("proxy"));

    match d.reason {
        DecisionReason::RuleMatch {
            rule_index,
            rule_name,
            ..
        } => {
            assert_eq!(rule_index, 2);
            assert_eq!(rule_name.as_deref(), Some("video"));
        }
        DecisionReason::Default { .. } => {
            panic!("unexpected default reason")
        }
    }
}

#[test]
fn dst_ip_cidr_include_expands_in_order() {
    let temp_dir = unique_temp_dir("cidr-include");
    let cidr_path = temp_dir.join("cidrs.txt");
    let config_path = temp_dir.join("config.toml");

    fs::write(&cidr_path, "1.2.3.0/24\n5.6.7.8/32\n").expect("write cidrs");

    let toml = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"

[egress.proxy]
type = "socks5"
endpoint = "socks5://127.0.0.1:1080"

[[rules]]
egress = "proxy"
dst_ip_cidr = "@file:cidrs.txt"
"#;
    fs::write(&config_path, toml).expect("write config");

    let (cfg, deps) = AppConfig::load_from_path_with_deps(&config_path).expect("config must load");
    let expected_dep = fs::canonicalize(&cidr_path).unwrap_or_else(|_| cidr_path.clone());
    assert!(deps.contains(&expected_dep));

    let d1 = decide(&cfg, None, None, Some("1.2.3.4".parse().unwrap()));
    match d1.reason {
        DecisionReason::RuleMatch { rule_index, .. } => {
            assert_eq!(rule_index, 1);
        }
        DecisionReason::Default { .. } => panic!("unexpected default decision"),
    }

    let d2 = decide(&cfg, None, None, Some("5.6.7.8".parse().unwrap()));
    match d2.reason {
        DecisionReason::RuleMatch { rule_index, .. } => {
            assert_eq!(rule_index, 2);
        }
        DecisionReason::Default { .. } => panic!("unexpected default decision"),
    }

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[test]
fn dst_ip_cidr_include_rejects_app_include_cartesian() {
    let temp_dir = unique_temp_dir("cidr-include-cartesian");
    let cidr_path = temp_dir.join("cidrs.txt");
    let app_path = temp_dir.join("apps.txt");
    let config_path = temp_dir.join("config.toml");

    fs::write(&cidr_path, "1.2.3.0/24\n5.6.7.8/32\n").expect("write cidrs");
    fs::write(&app_path, "curl.exe\nzen.exe\n").expect("write apps");

    let toml = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"

[[rules]]
egress = "direct"
app = "@file:apps.txt"
dst_ip_cidr = "@file:cidrs.txt"
"#;
    fs::write(&config_path, toml).expect("write config");

    let err = AppConfig::load_from_path(&config_path).expect_err("cartesian include must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("dst_ip_cidr"));
    assert!(msg.contains("cartesian"));

    fs::remove_dir_all(&temp_dir).expect("cleanup temp dir");
}

#[test]
fn invalid_dst_ip_cidr_is_rejected() {
    let toml = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"

[[rules]]
egress = "direct"
dst_ip_cidr = "not-a-cidr"
"#;

    let mut cfg = toml::from_str::<AppConfig>(toml).expect("test config TOML must parse");
    let err = cfg.validate().expect_err("config must reject invalid CIDR");
    let msg = format!("{err:#}");
    assert!(msg.contains("dst_ip_cidr"));
    assert!(msg.contains("valid CIDR"));
}

use policy_router_rs::policy::config::AppConfig;

#[test]
fn config_example_parses() {
    let raw = include_str!("../config/config.example.toml");
    let cfg = toml::from_str::<AppConfig>(raw).expect("config.example.toml must parse");
    cfg.validate().expect("config.example.toml must validate");
}

#[test]
fn config_example_validate_ok() {
    let raw = include_str!("../config/config.example.toml");
    let cfg = toml::from_str::<AppConfig>(raw).expect("config.example.toml must parse");
    cfg.validate().expect("config.example.toml must validate");
}

#[test]
fn config_process_spec_parses() {
    let raw = r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[egress.vpn.process]
enabled = true
program = "sing-box"
args = ["run", "-c", "singbox.json"]
restart = "on-failure"
backoff_ms = 500
max_backoff_ms = 10_000
max_restarts_per_minute = 5

[rules.app]
vpn = []

[rules.domain]
vpn = []
"#;
    let cfg = toml::from_str::<AppConfig>(raw).expect("config must parse");
    cfg.validate().expect("config must validate");
    let process = cfg
        .egress
        .get(&policy_router_rs::policy::config::EgressId(
            "vpn".to_string(),
        ))
        .and_then(|spec| spec.process.as_ref())
        .expect("process spec should be present");
    assert!(process.enabled);
    assert_eq!(process.program.as_deref(), Some("sing-box"));
}

#[test]
fn config_process_spec_parses_when_program_missing() {
    let raw = r#"
[defaults]
egress = "direct"

[egress.direct]
type = "direct"

[egress.direct.process]
enabled = false

[rules.app]
direct = []

[rules.domain]
direct = []
"#;
    let cfg = toml::from_str::<AppConfig>(raw).expect("config must parse");
    cfg.validate().expect("config must validate");
    let process = cfg
        .egress
        .get(&policy_router_rs::policy::config::EgressId(
            "direct".to_string(),
        ))
        .and_then(|spec| spec.process.as_ref())
        .expect("process spec should be present");
    assert!(!process.enabled);
    assert!(process.program.is_none());
}

#[test]
fn config_includes_expand_and_validate() {
    use std::fs;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("policy-router-test-{tag}-{pid}-{nanos}"))
    }

    let dir = tmp_dir("includes");
    fs::create_dir_all(&dir).expect("create temp dir");

    // nested include: a.txt includes b.txt
    let include_b = dir.join("b.txt");
    fs::write(
        &include_b,
        r"
# comment
googlevideo.com
; another comment
ytimg.com
",
    )
    .expect("write b.txt");

    let include_a = dir.join("a.txt");
    fs::write(
        &include_a,
        format!(
            r"
# include b
@file:{b}
youtube.com ; inline comment
",
            b = include_b.file_name().unwrap().to_string_lossy()
        ),
    )
    .expect("write a.txt");

    let include_apps = dir.join("apps.txt");
    fs::write(
        &include_apps,
        r"
# apps
zen.exe
Telegram.exe
",
    )
    .expect("write apps.txt");

    let cfg_path = dir.join("config.toml");
    fs::write(
        &cfg_path,
        r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[egress.direct]
type = "direct"

[rules.domain]
vpn = ["@file:a.txt"]
direct = ["ru"]

[rules.app]
vpn = ["@file:apps.txt"]
direct = []
"#,
    )
    .expect("write config.toml");

    let (cfg, deps) =
        AppConfig::load_from_path_with_deps(&cfg_path).expect("load config with includes");

    let dep_names: Vec<String> = deps
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert_eq!(dep_names, vec!["a.txt", "b.txt", "apps.txt"]);

    let vpn_domains = cfg
        .rules
        .domain
        .get(&policy_router_rs::policy::config::EgressId(
            "vpn".to_string(),
        ))
        .expect("vpn domain rules exist");
    let got: Vec<&str> = vpn_domains
        .iter()
        .map(policy_router_rs::policy::config::DomainPattern::as_str)
        .collect();

    // Order matters: expanded in order: b.txt entries first (via @file), then youtube.com line
    assert_eq!(got, vec!["googlevideo.com", "ytimg.com", "youtube.com"]);

    let vpn_apps = cfg
        .rules
        .app
        .get(&policy_router_rs::policy::config::EgressId(
            "vpn".to_string(),
        ))
        .expect("vpn app rules exist");
    let got_apps: Vec<&str> = vpn_apps
        .iter()
        .map(policy_router_rs::policy::config::AppPattern::as_str)
        .collect();
    assert_eq!(got_apps, vec!["zen.exe", "Telegram.exe"]);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_includes_cycle_is_rejected() {
    use std::fs;
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("policy-router-test-{tag}-{pid}-{nanos}"))
    }
    let dir = tmp_dir("includes-cycle");
    fs::create_dir_all(&dir).expect("create temp dir");
    // a.txt includes b.txt, b.txt includes a.txt -> cycle
    let a = dir.join("a.txt");
    let b = dir.join("b.txt");
    fs::write(&a, "@file:b.txt\n").expect("write a.txt");
    fs::write(&b, "@file:a.txt\n").expect("write b.txt");
    let cfg_path = dir.join("config.toml");
    fs::write(
        &cfg_path,
        r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[rules.domain]
vpn = ["@file:a.txt"]

[rules.app]
vpn = []
"#,
    )
    .expect("write config.toml");
    let err = AppConfig::load_from_path(&cfg_path).expect_err("cycle must error");
    let ok = err
        .chain()
        .any(|e| e.to_string().contains("include cycle detected"));
    assert!(ok, "msg={err}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn config_includes_depth_is_rejected() {
    use std::fs;
    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        std::env::temp_dir().join(format!("policy-router-test-{tag}-{pid}-{nanos}"))
    }
    let dir = tmp_dir("includes-depth");
    fs::create_dir_all(&dir).expect("create temp dir");
    // Build a chain f0 -> f1 -> ... -> f20 to exceed MAX_INCLUDE_DEPTH (16)
    let chain_len = 20usize;
    for i in 0..chain_len {
        let cur = dir.join(format!("f{i}.txt"));
        if i + 1 < chain_len {
            fs::write(&cur, format!("@file:f{}.txt\n", i + 1)).expect("write chain link");
        } else {
            fs::write(&cur, "final.com\n").expect("write leaf");
        }
    }
    let cfg_path = dir.join("config.toml");
    fs::write(
        &cfg_path,
        r#"
[defaults]
egress = "vpn"

[egress.vpn]
type = "singbox"
endpoint = "socks5://127.0.0.1:1488"

[rules.domain]
vpn = ["@file:f0.txt"]

[rules.app]
vpn = []
"#,
    )
    .expect("write config.toml");
    let err = AppConfig::load_from_path(&cfg_path).expect_err("depth must error");
    let ok = err
        .chain()
        .any(|e| e.to_string().contains("include depth exceeded"));
    assert!(ok, "msg={err}");
    let _ = fs::remove_dir_all(&dir);
}

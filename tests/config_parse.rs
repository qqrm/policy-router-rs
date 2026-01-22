use policy_router_rs::policy::config::AppConfig;

#[test]
fn config_example_parses() {
    let raw = include_str!("../config/config.example.toml");
    let cfg = toml::from_str::<AppConfig>(raw).expect("config.example.toml must parse");
    cfg.validate().expect("config.example.toml must validate");
}

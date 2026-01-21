mod policy;

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use clap::Parser;
use tracing::{info, warn};

use crate::policy::{
    config::AppConfig,
    engine::{DecisionReason, decide},
};

#[derive(Debug, Parser)]
#[command(name = "policy-router-rs")]
struct Cli {
    /// Path to config.toml. If omitted, tries ./config.toml then ./config/config.example.toml
    #[arg(long)]
    config: Option<PathBuf>,

    /// Process name (example: zen.exe)
    #[arg(long)]
    process: Option<String>,

    /// Domain (example: youtube.com)
    #[arg(long)]
    domain: Option<String>,
}

fn main() -> Result<()> {
    init_logging();

    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.as_deref());
    info!(config = %config_path.display(), "using config");

    let cfg = load_config(&config_path)?;

    let decision = decide(&cfg, cli.process.as_deref(), cli.domain.as_deref());

    let egress_spec = cfg
        .egress_spec(&decision.egress)
        .with_context(|| format!("egress '{}' not found in config", decision.egress))?;

    info!(
        egress = %decision.egress,
        egress_type = %egress_spec.kind,
        endpoint = %egress_spec.endpoint.as_deref().unwrap_or("<none>"),
        reason = %format_reason(&decision.reason),
        "decision"
    );

    Ok(())
}

fn init_logging() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .compact()
        .init();
}

fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(p) = explicit {
        return p.to_path_buf();
    }

    let p1 = PathBuf::from("config.toml");
    if p1.exists() {
        return p1;
    }

    let p2 = PathBuf::from("config").join("config.example.toml");
    if p2.exists() {
        return p2;
    }

    warn!("config.toml not found, defaulting to config/config.example.toml");
    p2
}

fn load_config(path: &Path) -> Result<AppConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config: {}", path.display()))?;

    let cfg: AppConfig = toml::from_str(&text)
        .with_context(|| format!("failed to parse TOML: {}", path.display()))?;

    Ok(cfg)
}

fn format_reason(r: &DecisionReason) -> String {
    match r {
        DecisionReason::BlockByApp { process_name } => format!("block by app: {process_name}"),
        DecisionReason::BlockByDomain { domain } => format!("block by domain: {domain}"),
        DecisionReason::AppMatch {
            process_name,
            egress,
        } => {
            format!("app match: {process_name} -> {egress}")
        }
        DecisionReason::DomainMatch { domain, egress } => {
            format!("domain match: {domain} -> {egress}")
        }
        DecisionReason::Default { egress } => format!("default -> {egress}"),
    }
}

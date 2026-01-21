use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use policy_router_rs::policy::{config::AppConfig, engine};

#[derive(Debug, Parser)]
#[command(version, about = "Policy engine CLI (debug tool).")]
struct Args {
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
    tracing_subscriber::fmt().without_time().compact().init();

    let args = Args::parse();
    let config_path = resolve_config_path(args.config.as_deref())?;

    tracing::info!(config = %config_path.display(), "using config");
    let cfg = AppConfig::load_from_path(&config_path)?;

    let decision = engine::decide(&cfg, args.process.as_deref(), args.domain.as_deref());

    let egress_id = decision.egress.clone();
    let spec = cfg
        .egress
        .get(&egress_id)
        .with_context(|| format!("egress id {egress_id:?} not found in config"))?;

    tracing::info!(
        egress = %egress_id.0,
        egress_type = %spec.kind.as_str(),
        endpoint = %spec.endpoint.as_deref().unwrap_or(""),
        reason = %decision.reason.to_human(),
        "decision"
    );

    Ok(())
}

fn resolve_config_path(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }

    let p1 = PathBuf::from("config.toml");
    if p1.exists() {
        return Ok(p1);
    }

    let p2 = PathBuf::from("config").join("config.example.toml");
    if p2.exists() {
        return Ok(p2);
    }

    anyhow::bail!("no config found: tried ./config.toml and ./config/config.example.toml");
}

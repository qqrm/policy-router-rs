use std::{collections::BTreeMap, fmt, fs, path::Path};

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub defaults: Defaults,
    #[serde(default)]
    pub egress: BTreeMap<EgressId, EgressSpec>,
    pub rules: Rules,
}

impl AppConfig {
    /// Loads application configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the file cannot be read
    /// - the file contents are not valid UTF-8
    /// - the TOML cannot be parsed into [`AppConfig`]
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;

        let cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config: {}", path.display()))?;

        Ok(cfg)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub egress: EgressId,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    pub app: AppRules,
    pub domain: DomainRules,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppRules {
    #[serde(default)]
    pub vpn: Vec<String>,
    #[serde(default)]
    pub proxy: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainRules {
    #[serde(default)]
    pub vpn: Vec<String>,
    #[serde(default)]
    pub proxy: Vec<String>,
    #[serde(default)]
    pub direct: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(transparent)]
pub struct EgressId(pub String);

impl fmt::Display for EgressId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct EgressSpec {
    #[serde(rename = "type")]
    pub kind: EgressKind,
    pub endpoint: Option<String>,
}

use strum_macros::{Display, IntoStaticStr};

#[derive(Debug, Clone, Copy, Deserialize, IntoStaticStr, Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum EgressKind {
    Singbox,
    Socks5,
    Direct,
    Block,
}

impl EgressKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        self.into()
    }
}

use std::{collections::BTreeMap, fmt, fs, path::Path};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

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

        cfg.validate()?;

        Ok(cfg)
    }

    /// Validates configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns an error if defaults or rules reference unknown egress ids.
    pub fn validate(&self) -> Result<()> {
        if !self.egress.contains_key(&self.defaults.egress) {
            bail!(
                "defaults.egress '{}' is not declared under [egress.*]",
                self.defaults.egress
            );
        }

        for egress_id in self.rules.app.keys().chain(self.rules.domain.keys()) {
            if !self.egress.contains_key(egress_id) {
                bail!("rules reference unknown egress id '{egress_id}' (missing under [egress.*])");
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub egress: EgressId,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    #[serde(default)]
    pub app: BTreeMap<EgressId, Vec<AppPattern>>,
    #[serde(default)]
    pub domain: BTreeMap<EgressId, Vec<DomainPattern>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct AppPattern(pub String);

impl AppPattern {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct DomainPattern(pub String);

impl DomainPattern {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
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

use std::{collections::BTreeMap, fmt};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub defaults: Defaults,
    pub egress: BTreeMap<EgressId, EgressSpec>,
    pub rules: Rules,
}

impl AppConfig {
    #[must_use]
    pub fn egress_spec(&self, id: &EgressId) -> Option<&EgressSpec> {
        self.egress.get(id)
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressKind {
    Singbox,
    Socks5,
    Direct,
    Block,
}

impl fmt::Display for EgressKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Singbox => "singbox",
            Self::Socks5 => "socks5",
            Self::Direct => "direct",
            Self::Block => "block",
        };
        f.write_str(s)
    }
}

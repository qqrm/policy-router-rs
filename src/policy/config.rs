use std::{
    collections::{BTreeMap, HashSet},
    fmt, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
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

        let mut cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config: {}", path.display()))?;

        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        cfg.expand_includes(base_dir)
            .with_context(|| format!("failed to expand includes for config: {}", path.display()))?;

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

        for (egress_id, spec) in &self.egress {
            match spec.kind {
                EgressKind::Singbox | EgressKind::Socks5 => {
                    let endpoint = spec.endpoint.as_deref().ok_or_else(|| {
                        anyhow!(
                            "egress '{egress_id}' ({}) requires endpoint",
                            spec.kind.as_str()
                        )
                    })?;
                    let endpoint = endpoint.trim();
                    if endpoint.is_empty() {
                        bail!(
                            "egress '{egress_id}' ({}) has empty endpoint",
                            spec.kind.as_str()
                        );
                    }
                    let (scheme, _host, _port) = parse_endpoint(endpoint).with_context(|| {
                        format!(
                            "egress '{egress_id}' ({}) has invalid endpoint '{endpoint}'",
                            spec.kind.as_str()
                        )
                    })?;
                    if scheme != "socks5" {
                        bail!(
                            "egress '{egress_id}' ({}) must use socks5 scheme, got '{scheme}'",
                            spec.kind.as_str()
                        );
                    }
                }
                EgressKind::Direct | EgressKind::Block => {
                    if spec.endpoint.is_some() {
                        bail!(
                            "egress '{egress_id}' ({}) must not define endpoint",
                            spec.kind.as_str()
                        );
                    }
                }
            }
        }

        for (egress_id, patterns) in &self.rules.app {
            for (index, pattern) in patterns.iter().enumerate() {
                if pattern.as_str().trim().is_empty() {
                    bail!("rules.app entry at index {index} for egress '{egress_id}' is empty");
                }
            }
        }

        for (egress_id, patterns) in &self.rules.domain {
            for (index, pattern) in patterns.iter().enumerate() {
                if pattern.as_str().trim().is_empty() {
                    bail!("rules.domain entry at index {index} for egress '{egress_id}' is empty");
                }
            }
        }

        Ok(())
    }
}

const INCLUDE_PREFIX: &str = "@file:";
const MAX_INCLUDE_DEPTH: usize = 16;

impl AppConfig {
    fn expand_includes(&mut self, base_dir: &Path) -> Result<()> {
        expand_rule_map_app(&mut self.rules.app, base_dir)?;
        expand_rule_map_domain(&mut self.rules.domain, base_dir)?;
        Ok(())
    }
}

fn expand_rule_map_app(
    map: &mut BTreeMap<EgressId, Vec<AppPattern>>,
    base_dir: &Path,
) -> Result<()> {
    for patterns in map.values_mut() {
        let mut out: Vec<String> = Vec::new();
        let mut stack: HashSet<PathBuf> = HashSet::new();

        for p in patterns.iter() {
            expand_pattern_entry(p.as_str(), base_dir, &mut stack, 0, &mut out)?;
        }

        *patterns = out.into_iter().map(AppPattern).collect();
    }
    Ok(())
}

fn expand_rule_map_domain(
    map: &mut BTreeMap<EgressId, Vec<DomainPattern>>,
    base_dir: &Path,
) -> Result<()> {
    for patterns in map.values_mut() {
        let mut out: Vec<String> = Vec::new();
        let mut stack: HashSet<PathBuf> = HashSet::new();

        for p in patterns.iter() {
            expand_pattern_entry(p.as_str(), base_dir, &mut stack, 0, &mut out)?;
        }

        *patterns = out.into_iter().map(DomainPattern).collect();
    }
    Ok(())
}

fn expand_pattern_entry(
    raw: &str,
    base_dir: &Path,
    stack: &mut HashSet<PathBuf>,
    depth: usize,
    out: &mut Vec<String>,
) -> Result<()> {
    if depth >= MAX_INCLUDE_DEPTH {
        bail!("include depth exceeded (max depth {MAX_INCLUDE_DEPTH})");
    }

    let trimmed = raw.trim();
    if let Some(include_path) = trimmed.strip_prefix(INCLUDE_PREFIX).map(str::trim) {
        if include_path.is_empty() {
            bail!("include marker '{INCLUDE_PREFIX}' must be followed by a path");
        }

        let resolved = resolve_include_path(base_dir, include_path);
        let key = fs::canonicalize(&resolved).unwrap_or_else(|_| resolved.clone());

        if !stack.insert(key.clone()) {
            bail!("include cycle detected at {}", key.display());
        }

        let lines = read_patterns_file(&resolved).with_context(|| {
            format!(
                "failed to read include file {} (from base {})",
                resolved.display(),
                base_dir.display()
            )
        })?;

        let next_base = resolved.parent().unwrap_or(base_dir);

        for line in lines {
            expand_pattern_entry(&line, next_base, stack, depth + 1, out)?;
        }

        stack.remove(&key);
    } else {
        // Normal inline pattern (keep exactly as user wrote it, but trimmed)
        let value = trimmed.to_string();
        if !value.is_empty() {
            out.push(value);
        }
    }
    Ok(())
}

fn resolve_include_path(base_dir: &Path, raw: &str) -> PathBuf {
    let p = Path::new(raw);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base_dir.join(p)
    }
}

fn read_patterns_file(path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)?;
    let mut out = Vec::new();

    for line in raw.lines() {
        let mut s = line.trim();

        if s.is_empty() {
            continue;
        }
        if s.starts_with('#') || s.starts_with(';') || s.starts_with("//") {
            continue;
        }

        // Strip inline comments (# or ;)
        if let Some(idx) = s.find('#') {
            s = s[..idx].trim();
        }
        if let Some(idx) = s.find(';') {
            s = s[..idx].trim();
        }

        if s.is_empty() {
            continue;
        }
        if s.starts_with('#') || s.starts_with(';') || s.starts_with("//") {
            continue;
        }

        out.push(s.to_string());
    }

    Ok(out)
}

fn parse_endpoint(endpoint: &str) -> Result<(String, String, u16)> {
    let (scheme, rest) = endpoint
        .split_once("://")
        .ok_or_else(|| anyhow!("endpoint must contain '://', got '{endpoint}'"))?;
    if scheme.trim().is_empty() {
        bail!("endpoint has empty scheme");
    }

    let (host, port_str) = if let Some(rest) = rest.strip_prefix('[') {
        let close = rest
            .find(']')
            .ok_or_else(|| anyhow!("endpoint IPv6 host must have closing ']'"))?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        let port_str = after
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("endpoint IPv6 host must include port after ']'"))?;
        (host, port_str)
    } else {
        let (host, port_str) = rest
            .split_once(':')
            .ok_or_else(|| anyhow!("endpoint must include port after host"))?;
        (host, port_str)
    };

    if host.trim().is_empty() {
        bail!("endpoint has empty host");
    }

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow!("endpoint port must be a number, got '{port_str}'"))?;
    if port == 0 {
        bail!("endpoint port must be between 1 and 65535, got {port}");
    }

    Ok((scheme.to_string(), host.to_string(), port))
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

use std::{
    collections::{BTreeMap, HashSet},
    fmt, fs,
    ops::Deref,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, anyhow, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub defaults: Defaults,
    #[serde(default)]
    pub egress: BTreeMap<EgressId, EgressSpec>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct ValidatedAppConfig(pub AppConfig);

impl Deref for ValidatedAppConfig {
    type Target = AppConfig;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const INCLUDE_PREFIX: &str = "@file:";
const MAX_INCLUDE_DEPTH: usize = 16;

impl AppConfig {
    /// Loads configuration and returns a list of include file dependencies encountered
    /// during expansion (canonicalized best-effort).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the file cannot be read
    /// - the file contents are not valid UTF-8
    /// - the TOML cannot be parsed into [`AppConfig`]
    /// - include expansion fails (including cycle or depth errors)
    /// - validation fails
    pub fn load_from_path_with_deps(path: &Path) -> Result<(Self, Vec<PathBuf>)> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;

        let mut cfg: Self = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config: {}", path.display()))?;

        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));

        let mut deps: Vec<PathBuf> = Vec::new();
        cfg.expand_includes_collecting(base_dir, &mut deps)
            .with_context(|| format!("failed to expand includes for config: {}", path.display()))?;

        cfg.validate()?;
        Ok((cfg, deps))
    }

    /// Loads application configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - the file cannot be read
    /// - the file contents are not valid UTF-8
    /// - the TOML cannot be parsed into [`AppConfig`]
    /// - include expansion fails (including cycle or depth errors)
    /// - validation fails
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let (cfg, _deps) = Self::load_from_path_with_deps(path)?;
        Ok(cfg)
    }

    /// Validates configuration invariants and returns a validated wrapper.
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate_into(mut self) -> Result<ValidatedAppConfig> {
        self.validate()?;
        Ok(ValidatedAppConfig(self))
    }

    fn expand_includes_collecting(
        &mut self,
        base_dir: &Path,
        deps: &mut Vec<PathBuf>,
    ) -> Result<()> {
        expand_rule_list(&mut self.rules, base_dir, deps)?;
        Ok(())
    }
}

fn expand_rule_list(rules: &mut Vec<Rule>, base_dir: &Path, deps: &mut Vec<PathBuf>) -> Result<()> {
    let mut expanded = Vec::new();
    for (index, rule) in rules.iter().enumerate() {
        let app_values =
            expand_rule_field(rule.app.as_ref().map(AppPattern::as_str), base_dir, deps)
                .with_context(|| format!("failed to expand rules[{index}].app includes"))?;
        let domain_values = expand_rule_field(
            rule.domain.as_ref().map(DomainPattern::as_str),
            base_dir,
            deps,
        )
        .with_context(|| format!("failed to expand rules[{index}].domain includes"))?;
        let cidr_values = expand_rule_field(rule.dst_ip_cidr.as_deref(), base_dir, deps)
            .with_context(|| format!("failed to expand rules[{index}].dst_ip_cidr includes"))?;

        if app_values.is_empty() && rule.app.is_some() {
            bail!("rules[{index}].app include expanded to no patterns");
        }
        if domain_values.is_empty() && rule.domain.is_some() {
            bail!("rules[{index}].domain include expanded to no patterns");
        }
        if cidr_values.is_empty() && rule.dst_ip_cidr.is_some() {
            bail!("rules[{index}].dst_ip_cidr include expanded to no patterns");
        }

        if app_values.len() > 1 && domain_values.len() > 1 {
            bail!(
                "rules[{index}] contains includes for both app and domain; \
expand one field per rule to avoid cartesian expansion"
            );
        }
        if cidr_values.len() > 1 && (app_values.len() > 1 || domain_values.len() > 1) {
            bail!(
                "rules[{index}] contains includes for dst_ip_cidr and app/domain; \
expand one field per rule to avoid cartesian expansion"
            );
        }

        let app_values = if app_values.is_empty() {
            vec![None]
        } else {
            app_values
                .into_iter()
                .map(|value| Some(AppPattern(value)))
                .collect()
        };
        let domain_values = if domain_values.is_empty() {
            vec![None]
        } else {
            domain_values
                .into_iter()
                .map(|value| Some(DomainPattern(value)))
                .collect()
        };
        let cidr_values = if cidr_values.is_empty() {
            vec![None]
        } else {
            cidr_values.into_iter().map(Some).collect()
        };

        for app_value in &app_values {
            for domain_value in &domain_values {
                for cidr_value in &cidr_values {
                    expanded.push(Rule {
                        egress: rule.egress.clone(),
                        app: app_value.clone(),
                        domain: domain_value.clone(),
                        dst_ip_cidr: cidr_value.clone(),
                        dst_ip_cidr_parsed: None,
                        name: rule.name.clone(),
                    });
                }
            }
        }
    }
    *rules = expanded;
    Ok(())
}

fn expand_rule_field(
    raw: Option<&str>,
    base_dir: &Path,
    deps: &mut Vec<PathBuf>,
) -> Result<Vec<String>> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let mut out: Vec<String> = Vec::new();
    let mut stack: HashSet<PathBuf> = HashSet::new();
    expand_pattern_entry(raw, base_dir, &mut stack, 0, deps, &mut out)?;
    Ok(out)
}

fn expand_pattern_entry(
    raw: &str,
    base_dir: &Path,
    stack: &mut HashSet<PathBuf>,
    depth: usize,
    deps: &mut Vec<PathBuf>,
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

        // record deps once, in first-seen order
        if !deps.iter().any(|p| p == &key) {
            deps.push(key.clone());
        }

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
            expand_pattern_entry(&line, next_base, stack, depth + 1, deps, out)?;
        }

        stack.remove(&key);
    } else {
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

impl AppConfig {
    /// Validates configuration invariants.
    ///
    /// # Errors
    ///
    /// Returns an error if defaults or rules reference unknown egress ids.
    pub fn validate(&mut self) -> Result<()> {
        if !self.egress.contains_key(&self.defaults.egress) {
            bail!(
                "defaults.egress '{}' is not declared under [egress.*]",
                self.defaults.egress
            );
        }

        for (index, rule) in self.rules.iter().enumerate() {
            if !self.egress.contains_key(&rule.egress) {
                bail!(
                    "rules[{index}] references unknown egress id '{}' (missing under [egress.*])",
                    rule.egress
                );
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

            if let Some(process) = spec.process.as_ref().filter(|process| process.enabled) {
                let program = process.program.as_deref().unwrap_or_default().trim();
                if program.is_empty() {
                    bail!("egress '{egress_id}' has process enabled with empty program");
                }
                if process.backoff_ms == 0 {
                    bail!("egress '{egress_id}' has process backoff_ms set to 0");
                }
                if process.max_backoff_ms > 0 && process.backoff_ms > process.max_backoff_ms {
                    bail!(
                        "egress '{egress_id}' has process backoff_ms greater than max_backoff_ms"
                    );
                }
                if process.max_restarts_per_minute == 0 {
                    bail!("egress '{egress_id}' has process max_restarts_per_minute set to 0");
                }
            }
        }

        self.validate_rules()?;

        Ok(())
    }
}

impl AppConfig {
    fn validate_rules(&mut self) -> Result<()> {
        let mut app_domain_rules = Vec::new();
        let mut domain_rules = Vec::new();
        let mut dst_ip_rules = Vec::new();
        let mut app_rules = Vec::new();

        for (index, rule) in self.rules.iter_mut().enumerate() {
            let position = index + 1;

            if let Some(app) = rule.app.as_ref()
                && app.as_str().trim().is_empty()
            {
                bail!("rules[{index}].app is empty");
            }
            if let Some(domain) = rule.domain.as_ref()
                && domain.as_str().trim().is_empty()
            {
                bail!("rules[{index}].domain is empty");
            }

            if rule.dst_ip_cidr.is_some() && (rule.app.is_some() || rule.domain.is_some()) {
                bail!(
                    "rules[{index}] mixes dst_ip_cidr with app/domain matchers; \
use dst_ip_cidr alone or split into separate rules"
                );
            }

            if rule.app.is_none() && rule.domain.is_none() && rule.dst_ip_cidr.is_none() {
                bail!("rules[{index}] must set at least one matcher (app, domain, dst_ip_cidr)");
            }

            let app_normalized = rule
                .app
                .as_ref()
                .map(|app| normalize_process_name(app.as_str()));
            let domain_suffix = rule
                .domain
                .as_ref()
                .and_then(|domain| normalize_domain_pattern(domain.as_str()));
            let cidr_parsed = if let Some(raw) = rule.dst_ip_cidr.as_ref() {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    bail!("rules[{index}].dst_ip_cidr is empty");
                }
                let cidr = trimmed.parse::<IpNet>().map_err(|_| {
                    anyhow!("rules[{index}].dst_ip_cidr '{trimmed}' is not a valid CIDR")
                })?;
                Some(cidr)
            } else {
                None
            };
            rule.dst_ip_cidr_parsed = cidr_parsed;

            if rule.domain.is_some() && domain_suffix.is_none() {
                bail!("rules[{index}].domain is empty after normalization");
            }

            let tier = rule_tier(rule);
            let info = RuleInfo {
                index: position,
                rule,
                app_normalized,
                domain_suffix,
            };

            match tier {
                RuleTier::AppDomain => app_domain_rules.push(info),
                RuleTier::Domain => domain_rules.push(info),
                RuleTier::DstIp => dst_ip_rules.push(info),
                RuleTier::App => app_rules.push(info),
                RuleTier::Default => {
                    bail!(
                        "rules[{index}] is a catch-all; defaults.egress already defines the default"
                    );
                }
            }
        }

        detect_conflicts_app_domain(&app_domain_rules)?;
        detect_conflicts_domain(&domain_rules)?;
        detect_conflicts_app(&app_rules)?;
        detect_conflicts_dst_ip(&dst_ip_rules)?;

        Ok(())
    }
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
pub struct Rule {
    pub egress: EgressId,
    #[serde(default)]
    pub app: Option<AppPattern>,
    #[serde(default)]
    pub domain: Option<DomainPattern>,
    #[serde(default)]
    pub dst_ip_cidr: Option<String>,
    #[serde(skip)]
    #[serde(default)]
    pub dst_ip_cidr_parsed: Option<IpNet>,
    #[serde(default)]
    pub name: Option<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTier {
    AppDomain,
    Domain,
    DstIp,
    App,
    Default,
}

impl RuleTier {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppDomain => "app+domain",
            Self::Domain => "domain",
            Self::DstIp => "dst_ip_cidr",
            Self::App => "app",
            Self::Default => "default",
        }
    }
}

#[derive(Debug)]
struct RuleInfo<'a> {
    index: usize,
    rule: &'a Rule,
    app_normalized: Option<String>,
    domain_suffix: Option<String>,
}

const fn rule_tier(rule: &Rule) -> RuleTier {
    match (
        rule.app.is_some(),
        rule.domain.is_some(),
        rule.dst_ip_cidr.is_some(),
    ) {
        (true, true, false) => RuleTier::AppDomain,
        (false, true, false) => RuleTier::Domain,
        (false, false, true) => RuleTier::DstIp,
        (true, false, false) => RuleTier::App,
        _ => RuleTier::Default,
    }
}

pub(crate) fn normalize_process_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized_path = trimmed.replace('\\', "/");
    let base_name = normalized_path
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("");
    base_name.to_ascii_lowercase()
}

pub(crate) fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_domain_pattern(raw: &str) -> Option<String> {
    let suffix_raw = normalize_domain(raw);
    if suffix_raw.is_empty() {
        return None;
    }
    Some(
        suffix_raw
            .strip_prefix('.')
            .unwrap_or(suffix_raw.as_str())
            .to_string(),
    )
}

fn domain_suffix_overlaps(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    domain_is_suffix(left, right) || domain_is_suffix(right, left)
}

fn domain_is_suffix(domain: &str, suffix: &str) -> bool {
    if domain.len() <= suffix.len() {
        return false;
    }
    if !domain.ends_with(suffix) {
        return false;
    }
    let prefix_end = domain.len() - suffix.len();
    domain
        .as_bytes()
        .get(prefix_end - 1)
        .is_some_and(|b| *b == b'.')
}

fn detect_conflicts_app_domain(rules: &[RuleInfo<'_>]) -> Result<()> {
    for (i, left) in rules.iter().enumerate() {
        for right in rules.iter().skip(i + 1) {
            let Some(left_app) = left.app_normalized.as_ref() else {
                continue;
            };
            let Some(right_app) = right.app_normalized.as_ref() else {
                continue;
            };
            if left_app != right_app {
                continue;
            }
            let Some(left_domain) = left.domain_suffix.as_ref() else {
                continue;
            };
            let Some(right_domain) = right.domain_suffix.as_ref() else {
                continue;
            };
            if domain_suffix_overlaps(left_domain, right_domain) {
                bail_conflict(
                    RuleTier::AppDomain,
                    left,
                    right,
                    "make domain patterns non-overlapping or merge the rules",
                )?;
            }
        }
    }
    Ok(())
}

fn detect_conflicts_domain(rules: &[RuleInfo<'_>]) -> Result<()> {
    for (i, left) in rules.iter().enumerate() {
        for right in rules.iter().skip(i + 1) {
            let Some(left_domain) = left.domain_suffix.as_ref() else {
                continue;
            };
            let Some(right_domain) = right.domain_suffix.as_ref() else {
                continue;
            };
            if domain_suffix_overlaps(left_domain, right_domain) {
                bail_conflict(
                    RuleTier::Domain,
                    left,
                    right,
                    "make domain patterns non-overlapping or merge the rules",
                )?;
            }
        }
    }
    Ok(())
}

fn detect_conflicts_app(rules: &[RuleInfo<'_>]) -> Result<()> {
    for (i, left) in rules.iter().enumerate() {
        for right in rules.iter().skip(i + 1) {
            let Some(left_app) = left.app_normalized.as_ref() else {
                continue;
            };
            let Some(right_app) = right.app_normalized.as_ref() else {
                continue;
            };
            if left_app == right_app {
                bail_conflict(
                    RuleTier::App,
                    left,
                    right,
                    "remove or merge one of the duplicate app rules",
                )?;
            }
        }
    }
    Ok(())
}

fn detect_conflicts_dst_ip(rules: &[RuleInfo<'_>]) -> Result<()> {
    for (i, left) in rules.iter().enumerate() {
        let Some(left_net) = left.rule.dst_ip_cidr_parsed.as_ref() else {
            continue;
        };
        for right in rules.iter().skip(i + 1) {
            let Some(right_net) = right.rule.dst_ip_cidr_parsed.as_ref() else {
                continue;
            };
            if cidr_overlaps(left_net, right_net) {
                bail_conflict(
                    RuleTier::DstIp,
                    left,
                    right,
                    "use non-overlapping CIDRs or merge the rules",
                )?;
            }
        }
    }
    Ok(())
}

fn cidr_overlaps(left: &IpNet, right: &IpNet) -> bool {
    let left_v4 = matches!(left, IpNet::V4(_));
    let right_v4 = matches!(right, IpNet::V4(_));
    if left_v4 != right_v4 {
        return false;
    }
    left.contains(&right.network()) || right.contains(&left.network())
}

fn bail_conflict(
    tier: RuleTier,
    left: &RuleInfo<'_>,
    right: &RuleInfo<'_>,
    hint: &str,
) -> Result<()> {
    bail!(
        "conflicting rules in tier '{}':\n\
  - rule #{left_idx}: {left_rule}\n\
  - rule #{right_idx}: {right_rule}\n\
Hint: {hint}",
        tier.as_str(),
        left_idx = left.index,
        left_rule = format_rule(left.rule),
        right_idx = right.index,
        right_rule = format_rule(right.rule),
    );
}

fn format_rule(rule: &Rule) -> String {
    let mut parts = vec![format!("egress='{}'", rule.egress)];
    if let Some(name) = &rule.name {
        parts.push(format!("name='{name}'"));
    }
    if let Some(app) = &rule.app {
        parts.push(format!("app='{}'", app.as_str().trim()));
    }
    if let Some(domain) = &rule.domain {
        parts.push(format!("domain='{}'", domain.as_str().trim()));
    }
    if let Some(cidr) = &rule.dst_ip_cidr {
        parts.push(format!("dst_ip_cidr='{}'", cidr.trim()));
    }
    format!("{{ {} }}", parts.join(", "))
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
    #[serde(default)]
    pub process: Option<ProcessSpec>,
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

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_restart_policy")]
    pub restart: RestartPolicy,
    #[serde(default = "default_backoff_ms")]
    pub backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    #[serde(default = "default_max_restarts_per_minute")]
    pub max_restarts_per_minute: u32,
}

const fn default_restart_policy() -> RestartPolicy {
    RestartPolicy::OnFailure
}

const fn default_backoff_ms() -> u64 {
    500
}

const fn default_max_backoff_ms() -> u64 {
    10_000
}

const fn default_max_restarts_per_minute() -> u32 {
    30
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

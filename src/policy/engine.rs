use std::collections::{BTreeMap, HashMap};

use super::config::{AppConfig, AppPattern, DomainPattern, EgressId, EgressKind};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub egress: EgressId,
    pub reason: DecisionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    Exact,
    Suffix,
}

impl MatchKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Suffix => "suffix",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    BlockByApp {
        egress: EgressId,
        pattern: String,
    },
    BlockByDomain {
        egress: EgressId,
        pattern: String,
        match_kind: MatchKind,
    },
    AppRule {
        egress: EgressId,
        pattern: String,
    },
    DomainRule {
        egress: EgressId,
        pattern: String,
        match_kind: MatchKind,
    },
    Default {
        egress: EgressId,
    },
}

impl DecisionReason {
    #[must_use]
    pub fn to_human(&self) -> String {
        match self {
            Self::BlockByApp { pattern, egress } => {
                format!(
                    "blocked: app exact match '{pattern}' -> egress '{egress}' has highest priority"
                )
            }
            Self::BlockByDomain {
                pattern,
                match_kind,
                egress,
            } => {
                let mk = match_kind_to_str(*match_kind);
                format!(
                    "blocked: domain {mk} match '{pattern}' -> egress '{egress}' has highest priority"
                )
            }
            Self::AppRule { egress, pattern } => {
                format!("app rule: exact match '{pattern}' -> egress '{egress}'")
            }
            Self::DomainRule {
                egress,
                pattern,
                match_kind,
            } => {
                let mk = match_kind_to_str(*match_kind);
                format!("domain rule: {mk} match '{pattern}' -> egress '{egress}'")
            }
            Self::Default { egress } => {
                format!("default: egress '{egress}' (no rules matched)")
            }
        }
    }
}

const fn match_kind_to_str(k: MatchKind) -> &'static str {
    match k {
        MatchKind::Exact => "exact",
        MatchKind::Suffix => "suffix",
    }
}

#[derive(Debug, Clone)]
struct CompiledDomainPattern {
    suffix: String,
    original: String,
}

#[derive(Debug, Clone)]
pub struct CompiledEngine {
    block_app_map: HashMap<String, (EgressId, String)>,
    app_map: HashMap<String, (EgressId, String)>,
    block_domain_patterns: Vec<(EgressId, Vec<CompiledDomainPattern>)>,
    domain_patterns: Vec<(EgressId, Vec<CompiledDomainPattern>)>,
    default_egress: EgressId,
}

impl CompiledEngine {
    #[must_use]
    pub fn compile(cfg: &AppConfig) -> Self {
        let ordered_non_block_egresses_for_domain: Vec<EgressId> =
            ordered_non_block_rule_egresses(cfg, &cfg.rules.domain)
                .into_iter()
                .cloned()
                .collect();
        let ordered_non_block_egresses_for_app: Vec<EgressId> =
            ordered_non_block_rule_egresses(cfg, &cfg.rules.app)
                .into_iter()
                .cloned()
                .collect();

        let mut block_egresses: Vec<EgressId> = cfg
            .egress
            .iter()
            .filter(|(_id, spec)| matches!(spec.kind, EgressKind::Block))
            .map(|(id, _spec)| id.clone())
            .collect();
        block_egresses.sort();

        let block_app_map = compile_app_map(&block_egresses, &cfg.rules.app);
        let app_map = compile_app_map(&ordered_non_block_egresses_for_app, &cfg.rules.app);

        let block_domain_patterns = compile_domain_patterns(&block_egresses, &cfg.rules.domain);
        let domain_patterns =
            compile_domain_patterns(&ordered_non_block_egresses_for_domain, &cfg.rules.domain);

        Self {
            block_app_map,
            app_map,
            block_domain_patterns,
            domain_patterns,
            default_egress: cfg.defaults.egress.clone(),
        }
    }

    #[must_use]
    pub fn decide(&self, process_name: Option<&str>, domain: Option<&str>) -> Decision {
        if let Some(name) = process_name {
            let normalized = normalize_process_name(name);
            if let Some((egress, pattern)) = self.block_app_map.get(&normalized) {
                return Decision {
                    egress: egress.clone(),
                    reason: DecisionReason::BlockByApp {
                        egress: egress.clone(),
                        pattern: pattern.clone(),
                    },
                };
            }
        }

        if let Some(domain_value) = domain {
            let normalized_domain = normalize_domain(domain_value);
            if let Some((egress, pattern, match_kind)) =
                match_domain_patterns(&self.block_domain_patterns, &normalized_domain)
            {
                return Decision {
                    egress: egress.clone(),
                    reason: DecisionReason::BlockByDomain {
                        egress,
                        pattern,
                        match_kind,
                    },
                };
            }

            if let Some((egress, pattern, match_kind)) =
                match_domain_patterns(&self.domain_patterns, &normalized_domain)
            {
                return Decision {
                    egress: egress.clone(),
                    reason: DecisionReason::DomainRule {
                        egress,
                        pattern,
                        match_kind,
                    },
                };
            }
        }

        if let Some(name) = process_name {
            let normalized = normalize_process_name(name);
            if let Some((egress, pattern)) = self.app_map.get(&normalized) {
                return Decision {
                    egress: egress.clone(),
                    reason: DecisionReason::AppRule {
                        egress: egress.clone(),
                        pattern: pattern.clone(),
                    },
                };
            }
        }

        Decision {
            egress: self.default_egress.clone(),
            reason: DecisionReason::Default {
                egress: self.default_egress.clone(),
            },
        }
    }
}

#[must_use]
pub fn compile(cfg: &AppConfig) -> CompiledEngine {
    CompiledEngine::compile(cfg)
}

#[must_use]
pub fn decide(cfg: &AppConfig, process_name: Option<&str>, domain: Option<&str>) -> Decision {
    let engine = CompiledEngine::compile(cfg);
    engine.decide(process_name, domain)
}

fn normalize_process_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized_path = trimmed.replace('\\', "/");
    let base_name = normalized_path
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("");
    base_name.to_ascii_lowercase()
}

fn normalize_domain(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn compile_app_map(
    egresses: &[EgressId],
    rules: &BTreeMap<EgressId, Vec<AppPattern>>,
) -> HashMap<String, (EgressId, String)> {
    let mut map = HashMap::new();
    for egress in egresses {
        let Some(patterns) = rules.get(egress) else {
            continue;
        };
        for pattern in patterns {
            let normalized = normalize_process_name(pattern.as_str());
            if map.contains_key(&normalized) {
                continue;
            }
            map.insert(normalized, (egress.clone(), pattern.as_str().to_string()));
        }
    }

    map
}

fn compile_domain_patterns(
    egresses: &[EgressId],
    rules: &BTreeMap<EgressId, Vec<DomainPattern>>,
) -> Vec<(EgressId, Vec<CompiledDomainPattern>)> {
    let mut compiled = Vec::new();
    for egress in egresses {
        let Some(patterns) = rules.get(egress) else {
            continue;
        };
        let mut compiled_patterns = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            if let Some(compiled_pattern) = compile_domain_pattern(pattern.as_str()) {
                compiled_patterns.push(compiled_pattern);
            }
        }
        if !compiled_patterns.is_empty() {
            compiled.push((egress.clone(), compiled_patterns));
        }
    }
    compiled
}

fn compile_domain_pattern(raw: &str) -> Option<CompiledDomainPattern> {
    let original = raw.trim().to_string();
    let suffix_raw = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if suffix_raw.is_empty() {
        return None;
    }
    let suffix = suffix_raw
        .strip_prefix('.')
        .unwrap_or(suffix_raw.as_str())
        .to_string();
    Some(CompiledDomainPattern { suffix, original })
}

fn match_domain_patterns(
    patterns: &[(EgressId, Vec<CompiledDomainPattern>)],
    domain: &str,
) -> Option<(EgressId, String, MatchKind)> {
    for (egress, compiled_patterns) in patterns {
        for pattern in compiled_patterns {
            if domain == pattern.suffix {
                return Some((egress.clone(), pattern.original.clone(), MatchKind::Exact));
            }
            if domain_is_suffix(domain, &pattern.suffix) {
                return Some((egress.clone(), pattern.original.clone(), MatchKind::Suffix));
            }
        }
    }
    None
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

fn ordered_non_block_rule_egresses<'a, T>(
    cfg: &'a AppConfig,
    rules: &'a BTreeMap<EgressId, Vec<T>>,
) -> Vec<&'a EgressId> {
    let mut ordered: Vec<(&EgressId, usize)> = rules
        .keys()
        .filter_map(|id| {
            let spec = cfg.egress.get(id)?;
            let rank = match spec.kind {
                EgressKind::Singbox => 0,
                EgressKind::Socks5 => 1,
                EgressKind::Direct => 2,
                EgressKind::Block => return None,
            };
            Some((id, rank))
        })
        .collect();

    ordered.sort_by(|(left_id, left_rank), (right_id, right_rank)| {
        left_rank
            .cmp(right_rank)
            .then_with(|| left_id.cmp(right_id))
    });

    ordered.into_iter().map(|(id, _)| id).collect()
}

#[cfg(test)]
mod slow {
    use super::*;

    #[derive(Debug, Clone)]
    struct DomainSuffixMatch {
        pattern: String,
        match_kind: MatchKind,
    }

    #[must_use]
    pub(super) fn decide_slow_impl(
        cfg: &AppConfig,
        process_name: Option<&str>,
        domain: Option<&str>,
    ) -> Decision {
        decide_block(cfg, process_name, domain)
            .or_else(|| decide_domain(cfg, domain))
            .or_else(|| decide_app(cfg, process_name))
            .unwrap_or_else(|| decide_default(cfg))
    }

    fn decide_block(
        cfg: &AppConfig,
        process_name: Option<&str>,
        domain: Option<&str>,
    ) -> Option<Decision> {
        if let Some(name) = process_name
            && let Some((egress, pattern)) = choose_block_app(cfg, name)
        {
            return Some(Decision {
                egress: egress.clone(),
                reason: DecisionReason::BlockByApp { egress, pattern },
            });
        }

        if let Some(d) = domain
            && let Some((egress, m)) = choose_block_domain(cfg, d)
        {
            return Some(Decision {
                egress: egress.clone(),
                reason: DecisionReason::BlockByDomain {
                    egress,
                    pattern: m.pattern,
                    match_kind: m.match_kind,
                },
            });
        }

        None
    }

    fn decide_domain(cfg: &AppConfig, domain: Option<&str>) -> Option<Decision> {
        let d = domain?;

        choose_domain(d, cfg)
    }

    fn choose_domain(domain: &str, cfg: &AppConfig) -> Option<Decision> {
        let rules = &cfg.rules.domain;
        for egress in ordered_non_block_rule_egresses(cfg, rules) {
            let Some(patterns) = rules.get(egress) else {
                continue;
            };
            if let Some(m) = domain_matches_any(patterns, domain) {
                return Some(Decision {
                    egress: egress.clone(),
                    reason: DecisionReason::DomainRule {
                        pattern: m.pattern,
                        match_kind: m.match_kind,
                        egress: egress.clone(),
                    },
                });
            }
        }

        None
    }

    fn decide_app(cfg: &AppConfig, process_name: Option<&str>) -> Option<Decision> {
        let name = process_name?;

        choose_app(name, cfg)
    }

    fn choose_app(process_name: &str, cfg: &AppConfig) -> Option<Decision> {
        let normalized = normalize_process_name(process_name);
        let rules = &cfg.rules.app;
        for egress in ordered_non_block_rule_egresses(cfg, rules) {
            let Some(patterns) = rules.get(egress) else {
                continue;
            };
            if let Some(pattern) = find_matching_app_pattern(patterns, &normalized) {
                return Some(Decision {
                    egress: egress.clone(),
                    reason: DecisionReason::AppRule {
                        pattern,
                        egress: egress.clone(),
                    },
                });
            }
        }

        None
    }

    fn decide_default(cfg: &AppConfig) -> Decision {
        Decision {
            egress: cfg.defaults.egress.clone(),
            reason: DecisionReason::Default {
                egress: cfg.defaults.egress.clone(),
            },
        }
    }

    fn find_matching_app_pattern(list: &[AppPattern], normalized_value: &str) -> Option<String> {
        list.iter()
            .find(|pattern| normalize_process_name(pattern.as_str()) == normalized_value)
            .map(|pattern| pattern.as_str().to_string())
    }

    fn domain_matches_any(suffixes: &[DomainPattern], domain: &str) -> Option<DomainSuffixMatch> {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        suffixes
            .iter()
            .find_map(|raw| domain_matches_suffix(&d, raw.as_str()))
    }

    fn domain_matches_suffix(domain: &str, raw_suffix: &str) -> Option<DomainSuffixMatch> {
        let suffix_raw = raw_suffix.trim().trim_end_matches('.').to_ascii_lowercase();
        if suffix_raw.is_empty() {
            return None;
        }

        let suffix = suffix_raw.strip_prefix('.').unwrap_or(suffix_raw.as_str());

        if domain == suffix {
            return Some(DomainSuffixMatch {
                pattern: raw_suffix.trim().to_string(),
                match_kind: MatchKind::Exact,
            });
        }

        if domain.ends_with(&format!(".{suffix}")) {
            return Some(DomainSuffixMatch {
                pattern: raw_suffix.trim().to_string(),
                match_kind: MatchKind::Suffix,
            });
        }

        None
    }

    fn choose_block_app(cfg: &AppConfig, process_name: &str) -> Option<(EgressId, String)> {
        let normalized = normalize_process_name(process_name);
        for (egress, patterns) in cfg
            .rules
            .app
            .iter()
            .filter(|(id, _)| is_block_egress(cfg, id))
        {
            if let Some(pattern) = find_matching_app_pattern(patterns, &normalized) {
                return Some((egress.clone(), pattern));
            }
        }

        None
    }

    fn choose_block_domain(cfg: &AppConfig, domain: &str) -> Option<(EgressId, DomainSuffixMatch)> {
        for (egress, patterns) in cfg
            .rules
            .domain
            .iter()
            .filter(|(id, _)| is_block_egress(cfg, id))
        {
            if let Some(m) = domain_matches_any(patterns, domain) {
                return Some((egress.clone(), m));
            }
        }

        None
    }

    fn is_block_egress(cfg: &AppConfig, id: &EgressId) -> bool {
        cfg.egress
            .get(id)
            .is_some_and(|spec| matches!(spec.kind, EgressKind::Block))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_compiled_matrix() -> AppConfig {
        let toml = r#"
[defaults]
egress = "direct"

[egress.alpha]
type = "singbox"
endpoint = "socks5://127.0.0.1:1080"

[egress.beta]
type = "singbox"
endpoint = "socks5://127.0.0.1:1081"

[egress.proxy]
type = "socks5"
endpoint = "socks5://127.0.0.1:1082"

[egress.direct]
type = "direct"

[egress.block]
type = "block"

[egress.blocker]
type = "block"

[rules.domain]
alpha = ["example.com", ".shared.com", "Trailing.com."]
proxy = ["shared.com", "proxy.com"]
direct = ["direct.com"]
block = ["blocked.example", ".blocked.com"]
blocker = ["blocked.com"]

[rules.app]
alpha = ["Dupe.exe", "alpha.exe"]
proxy = ["dupe.exe", "proxy.exe"]
direct = ["direct.exe"]
block = ["bad.exe"]
blocker = ["bad.exe"]
"#;

        toml::from_str::<AppConfig>(toml).expect("test config TOML must parse")
    }

    #[test]
    fn compiled_engine_matches_slow_decisions() {
        let cfg = cfg_compiled_matrix();
        cfg.validate().expect("config must validate");

        let compiled = CompiledEngine::compile(&cfg);

        let cases = [
            (Some("Dupe.exe"), None),
            (Some(r"C:\Program Files\App\DUPE.EXE"), None),
            (Some("bad.exe"), Some("proxy.com")),
            (Some("unknown.exe"), Some("blocked.com")),
            (Some("alpha.exe"), Some("proxy.com")),
            (None, Some("shared.com")),
            (None, Some("sub.shared.com")),
            (None, Some("example.com.")),
            (None, Some("TRAILING.COM")),
            (None, Some("direct.com")),
        ];

        for (process, domain) in cases {
            let slow = slow::decide_slow_impl(&cfg, process, domain);
            let fast = compiled.decide(process, domain);
            assert_eq!(slow, fast);
        }
    }
}

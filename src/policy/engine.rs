use std::collections::BTreeMap;

use super::config::{AppConfig, AppPattern, DomainPattern, EgressId, EgressKind};

#[derive(Debug, Clone)]
pub struct Decision {
    pub egress: EgressId,
    pub reason: DecisionReason,
}

#[derive(Debug, Clone, Copy)]
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

#[derive(Debug, Clone)]
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
struct DomainSuffixMatch {
    pattern: String,
    match_kind: MatchKind,
}

#[must_use]
pub fn decide(cfg: &AppConfig, process_name: Option<&str>, domain: Option<&str>) -> Decision {
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

fn normalize_process_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let normalized_path = trimmed.replace('\\', "/");
    let base_name = normalized_path
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("");
    base_name.to_ascii_lowercase()
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

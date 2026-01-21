use super::config::{AppConfig, EgressId};

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
        pattern: String,
    },
    BlockByDomain {
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
            Self::BlockByApp { pattern } => {
                format!("blocked: app exact match '{pattern}' has highest priority")
            }
            Self::BlockByDomain {
                pattern,
                match_kind,
            } => {
                let mk = match_kind_to_str(*match_kind);
                format!("blocked: domain {mk} match '{pattern}' has highest priority")
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
        && let Some(pattern) = find_case_insensitive(&cfg.rules.app.block, name)
    {
        return Some(Decision {
            egress: EgressId("block".to_string()),
            reason: DecisionReason::BlockByApp { pattern },
        });
    }

    if let Some(d) = domain
        && let Some(m) = domain_matches_any(&cfg.rules.domain.block, d)
    {
        return Some(Decision {
            egress: EgressId("block".to_string()),
            reason: DecisionReason::BlockByDomain {
                pattern: m.pattern,
                match_kind: m.match_kind,
            },
        });
    }

    None
}

fn decide_domain(cfg: &AppConfig, domain: Option<&str>) -> Option<Decision> {
    let d = domain?;

    choose_domain(d, &cfg.rules.domain.vpn, "vpn")
        .or_else(|| choose_domain(d, &cfg.rules.domain.proxy, "proxy"))
        .or_else(|| choose_domain(d, &cfg.rules.domain.direct, "direct"))
}

fn choose_domain(domain: &str, suffixes: &[String], egress: &str) -> Option<Decision> {
    let m = domain_matches_any(suffixes, domain)?;

    let e = EgressId(egress.to_string());
    Some(Decision {
        egress: e.clone(),
        reason: DecisionReason::DomainRule {
            pattern: m.pattern,
            match_kind: m.match_kind,
            egress: e,
        },
    })
}

fn decide_app(cfg: &AppConfig, process_name: Option<&str>) -> Option<Decision> {
    let name = process_name?;

    choose_app(name, &cfg.rules.app.vpn, "vpn")
        .or_else(|| choose_app(name, &cfg.rules.app.proxy, "proxy"))
        .or_else(|| choose_app(name, &cfg.rules.app.direct, "direct"))
}

fn choose_app(process_name: &str, names: &[String], egress: &str) -> Option<Decision> {
    let pattern = find_case_insensitive(names, process_name)?;

    let e = EgressId(egress.to_string());
    Some(Decision {
        egress: e.clone(),
        reason: DecisionReason::AppRule { pattern, egress: e },
    })
}

fn decide_default(cfg: &AppConfig) -> Decision {
    Decision {
        egress: cfg.defaults.egress.clone(),
        reason: DecisionReason::Default {
            egress: cfg.defaults.egress.clone(),
        },
    }
}

fn find_case_insensitive(list: &[String], value: &str) -> Option<String> {
    list.iter()
        .find(|s| s.eq_ignore_ascii_case(value))
        .map(std::string::ToString::to_string)
}

fn domain_matches_any(suffixes: &[String], domain: &str) -> Option<DomainSuffixMatch> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    suffixes
        .iter()
        .find_map(|raw| domain_matches_suffix(&d, raw))
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

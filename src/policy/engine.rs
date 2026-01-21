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
        process_name: String,
        pattern: String,
    },
    BlockByDomain {
        domain: String,
        pattern: String,
        match_kind: MatchKind,
    },
    AppMatch {
        process_name: String,
        pattern: String,
        egress: EgressId,
    },
    DomainMatch {
        domain: String,
        pattern: String,
        match_kind: MatchKind,
        egress: EgressId,
    },
    Default {
        egress: EgressId,
    },
}

impl DecisionReason {
    #[must_use]
    pub fn to_human(&self) -> String {
        match self {
            Self::BlockByApp {
                process_name,
                pattern,
            } => {
                if pattern.eq_ignore_ascii_case(process_name) {
                    format!("block by app: {process_name}")
                } else {
                    format!("block by app: {process_name} (matched: {pattern})")
                }
            }
            Self::BlockByDomain {
                domain,
                pattern,
                match_kind,
            } => {
                format!(
                    "block by domain: {domain} (matched: {} {pattern})",
                    match_kind.as_str()
                )
            }
            Self::AppMatch {
                process_name,
                pattern,
                egress,
            } => {
                if pattern.eq_ignore_ascii_case(process_name) {
                    format!("app match: {process_name} -> {egress}")
                } else {
                    format!("app match: {process_name} -> {egress} (matched: {pattern})")
                }
            }
            Self::DomainMatch {
                domain,
                pattern,
                match_kind,
                egress,
            } => {
                format!(
                    "domain match: {domain} -> {egress} (matched: {} {pattern})",
                    match_kind.as_str()
                )
            }
            Self::Default { egress } => {
                format!("default: {egress}")
            }
        }
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
            reason: DecisionReason::BlockByApp {
                process_name: name.to_string(),
                pattern,
            },
        });
    }

    if let Some(d) = domain
        && let Some(m) = domain_matches_any(&cfg.rules.domain.block, d)
    {
        return Some(Decision {
            egress: EgressId("block".to_string()),
            reason: DecisionReason::BlockByDomain {
                domain: d.to_string(),
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
        reason: DecisionReason::DomainMatch {
            domain: domain.to_string(),
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
        reason: DecisionReason::AppMatch {
            process_name: process_name.to_string(),
            pattern,
            egress: e,
        },
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

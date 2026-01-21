use super::config::{AppConfig, EgressId};

#[derive(Debug, Clone)]
pub struct Decision {
    pub egress: EgressId,
    pub reason: DecisionReason,
}

#[derive(Debug, Clone)]
pub enum DecisionReason {
    BlockByApp {
        process_name: String,
    },
    BlockByDomain {
        domain: String,
    },
    AppMatch {
        process_name: String,
        egress: EgressId,
    },
    DomainMatch {
        domain: String,
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
            Self::BlockByApp { process_name } => {
                format!("block by app: {process_name}")
            }
            Self::BlockByDomain { domain } => {
                format!("block by domain: {domain}")
            }
            Self::AppMatch {
                process_name,
                egress,
            } => {
                format!("app match: {process_name} -> {egress}")
            }
            Self::DomainMatch { domain, egress } => {
                format!("domain match: {domain} -> {egress}")
            }
            Self::Default { egress } => {
                format!("default: {egress}")
            }
        }
    }
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
        .filter(|n| contains_case_insensitive(&cfg.rules.app.block, n))
        .map(str::to_string)
    {
        return Some(Decision {
            egress: EgressId("block".to_string()),
            reason: DecisionReason::BlockByApp { process_name: name },
        });
    }

    if let Some(d) = domain
        .filter(|d| domain_matches_any(&cfg.rules.domain.block, d))
        .map(str::to_string)
    {
        return Some(Decision {
            egress: EgressId("block".to_string()),
            reason: DecisionReason::BlockByDomain { domain: d },
        });
    }

    None
}

fn decide_domain(cfg: &AppConfig, domain: Option<&str>) -> Option<Decision> {
    let d = domain?;

    choose_domain(cfg, d, &cfg.rules.domain.vpn, "vpn")
        .or_else(|| choose_domain(cfg, d, &cfg.rules.domain.proxy, "proxy"))
        .or_else(|| choose_domain(cfg, d, &cfg.rules.domain.direct, "direct"))
}

fn choose_domain(
    _cfg: &AppConfig,
    domain: &str,
    suffixes: &[String],
    egress: &str,
) -> Option<Decision> {
    if !domain_matches_any(suffixes, domain) {
        return None;
    }

    let e = EgressId(egress.to_string());
    Some(Decision {
        egress: e.clone(),
        reason: DecisionReason::DomainMatch {
            domain: domain.to_string(),
            egress: e,
        },
    })
}

fn decide_app(cfg: &AppConfig, process_name: Option<&str>) -> Option<Decision> {
    let name = process_name?;

    choose_app(cfg, name, &cfg.rules.app.vpn, "vpn")
        .or_else(|| choose_app(cfg, name, &cfg.rules.app.proxy, "proxy"))
        .or_else(|| choose_app(cfg, name, &cfg.rules.app.direct, "direct"))
}

fn choose_app(
    _cfg: &AppConfig,
    process_name: &str,
    names: &[String],
    egress: &str,
) -> Option<Decision> {
    if !contains_case_insensitive(names, process_name) {
        return None;
    }

    let e = EgressId(egress.to_string());
    Some(Decision {
        egress: e.clone(),
        reason: DecisionReason::AppMatch {
            process_name: process_name.to_string(),
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

fn contains_case_insensitive(list: &[String], value: &str) -> bool {
    list.iter().any(|s| s.eq_ignore_ascii_case(value))
}

fn domain_matches_any(suffixes: &[String], domain: &str) -> bool {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    suffixes.iter().any(|raw| domain_matches_suffix(&d, raw))
}

fn domain_matches_suffix(domain: &str, raw_suffix: &str) -> bool {
    let suffix_raw = raw_suffix.trim().trim_end_matches('.').to_ascii_lowercase();
    if suffix_raw.is_empty() {
        return false;
    }

    let suffix = suffix_raw.strip_prefix('.').unwrap_or(suffix_raw.as_str());

    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

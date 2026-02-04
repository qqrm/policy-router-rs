use std::net::IpAddr;

use ipnet::IpNet;

use super::config::{
    AppConfig, EgressId, Rule, RuleTier, normalize_domain, normalize_process_name,
};

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
    RuleMatch {
        tier: RuleTier,
        rule_index: usize,
        rule_name: Option<String>,
        egress: EgressId,
        app: Option<String>,
        domain: Option<DomainMatch>,
        dst_ip_cidr: Option<IpNet>,
    },
    Default {
        egress: EgressId,
    },
}

impl DecisionReason {
    #[must_use]
    pub fn to_human(&self) -> String {
        match self {
            Self::RuleMatch {
                tier,
                rule_index,
                rule_name,
                egress,
                app,
                domain,
                dst_ip_cidr,
            } => {
                let mut parts = Vec::new();
                if let Some(app) = app {
                    parts.push(format!("app exact match '{app}'"));
                }
                if let Some(domain) = domain {
                    let mk = match_kind_to_str(domain.match_kind);
                    parts.push(format!("domain {mk} match '{}'", domain.pattern));
                }
                if let Some(cidr) = dst_ip_cidr {
                    parts.push(format!("dst_ip_cidr match '{cidr}'"));
                }
                let detail = if parts.is_empty() {
                    "no matchers".to_string()
                } else {
                    parts.join(", ")
                };
                let name = rule_name
                    .as_ref()
                    .map(|name| format!(", name '{name}'"))
                    .unwrap_or_default();
                format!(
                    "rule #{rule_index} (tier {}{name}): {detail} -> egress '{egress}'",
                    tier.as_str(),
                )
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMatch {
    pub pattern: String,
    pub match_kind: MatchKind,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    index: usize,
    tier: RuleTier,
    egress: EgressId,
    name: Option<String>,
    app_normalized: Option<String>,
    app_raw: Option<String>,
    domain: Option<CompiledDomainPattern>,
    dst_ip_cidr: Option<IpNet>,
}

#[derive(Debug, Clone)]
pub struct CompiledEngine {
    app_domain_rules: Vec<CompiledRule>,
    domain_rules: Vec<CompiledRule>,
    dst_ip_rules: Vec<CompiledRule>,
    app_rules: Vec<CompiledRule>,
    default_egress: EgressId,
}

impl CompiledEngine {
    #[must_use]
    pub fn compile(cfg: &AppConfig) -> Self {
        let mut app_domain_rules = Vec::new();
        let mut domain_rules = Vec::new();
        let mut dst_ip_rules = Vec::new();
        let mut app_rules = Vec::new();

        for (idx, rule) in cfg.rules.iter().enumerate() {
            if let Some(compiled) = compile_rule(rule, idx + 1) {
                match compiled.tier {
                    RuleTier::AppDomain => app_domain_rules.push(compiled),
                    RuleTier::Domain => domain_rules.push(compiled),
                    RuleTier::DstIp => dst_ip_rules.push(compiled),
                    RuleTier::App => app_rules.push(compiled),
                    RuleTier::Default => {}
                }
            }
        }

        Self {
            app_domain_rules,
            domain_rules,
            dst_ip_rules,
            app_rules,
            default_egress: cfg.defaults.egress.clone(),
        }
    }

    #[must_use]
    pub fn decide(
        &self,
        process_name: Option<&str>,
        domain: Option<&str>,
        dst_ip: Option<IpAddr>,
    ) -> Decision {
        let normalized_app = process_name.map(normalize_process_name);
        let normalized_domain = domain.map(normalize_domain);

        if let Some(decision) = match_rules(
            &self.app_domain_rules,
            normalized_app.as_deref(),
            normalized_domain.as_deref(),
            dst_ip,
        ) {
            return decision;
        }

        if let Some(decision) = match_rules(
            &self.domain_rules,
            normalized_app.as_deref(),
            normalized_domain.as_deref(),
            dst_ip,
        ) {
            return decision;
        }

        if let Some(decision) = match_rules(
            &self.dst_ip_rules,
            normalized_app.as_deref(),
            normalized_domain.as_deref(),
            dst_ip,
        ) {
            return decision;
        }

        if let Some(decision) = match_rules(
            &self.app_rules,
            normalized_app.as_deref(),
            normalized_domain.as_deref(),
            dst_ip,
        ) {
            return decision;
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
pub fn decide(
    cfg: &AppConfig,
    process_name: Option<&str>,
    domain: Option<&str>,
    dst_ip: Option<IpAddr>,
) -> Decision {
    let engine = CompiledEngine::compile(cfg);
    engine.decide(process_name, domain, dst_ip)
}

fn compile_rule(rule: &Rule, index: usize) -> Option<CompiledRule> {
    let tier = match (
        rule.app.is_some(),
        rule.domain.is_some(),
        rule.dst_ip_cidr.is_some(),
    ) {
        (true, true, false) => RuleTier::AppDomain,
        (false, true, false) => RuleTier::Domain,
        (false, false, true) => RuleTier::DstIp,
        (true, false, false) => RuleTier::App,
        _ => RuleTier::Default,
    };

    if matches!(tier, RuleTier::Default) {
        return None;
    }

    let app_normalized = rule
        .app
        .as_ref()
        .map(|app| normalize_process_name(app.as_str()));
    let app_raw = rule.app.as_ref().map(|app| app.as_str().trim().to_string());
    let domain = rule
        .domain
        .as_ref()
        .and_then(|domain| compile_domain_pattern(domain.as_str()));

    Some(CompiledRule {
        index,
        tier,
        egress: rule.egress.clone(),
        name: rule.name.clone(),
        app_normalized,
        app_raw,
        domain,
        dst_ip_cidr: rule.dst_ip_cidr_parsed,
    })
}

fn match_rules(
    rules: &[CompiledRule],
    app: Option<&str>,
    domain: Option<&str>,
    dst_ip: Option<IpAddr>,
) -> Option<Decision> {
    for rule in rules {
        let mut domain_match = None;

        if let Some(app_rule) = rule.app_normalized.as_ref() {
            let Some(app) = app else {
                continue;
            };
            if app != app_rule {
                continue;
            }
        }

        if let Some(domain_rule) = rule.domain.as_ref() {
            let Some(domain) = domain else {
                continue;
            };
            let Some(match_kind) = match_domain_pattern(domain_rule, domain) else {
                continue;
            };
            domain_match = Some(DomainMatch {
                pattern: domain_rule.original.clone(),
                match_kind,
            });
        }

        if let Some(cidr) = rule.dst_ip_cidr.as_ref() {
            let Some(ip) = dst_ip else {
                continue;
            };
            if !cidr.contains(&ip) {
                continue;
            }
        }

        return Some(Decision {
            egress: rule.egress.clone(),
            reason: DecisionReason::RuleMatch {
                tier: rule.tier,
                rule_index: rule.index,
                rule_name: rule.name.clone(),
                egress: rule.egress.clone(),
                app: rule.app_raw.clone(),
                domain: domain_match,
                dst_ip_cidr: rule.dst_ip_cidr,
            },
        });
    }
    None
}

fn compile_domain_pattern(raw: &str) -> Option<CompiledDomainPattern> {
    let original = raw.trim().to_string();
    let suffix_raw = normalize_domain(raw);
    if suffix_raw.is_empty() {
        return None;
    }
    let suffix = suffix_raw
        .strip_prefix('.')
        .unwrap_or(suffix_raw.as_str())
        .to_string();
    Some(CompiledDomainPattern { suffix, original })
}

fn match_domain_pattern(pattern: &CompiledDomainPattern, domain: &str) -> Option<MatchKind> {
    if domain == pattern.suffix {
        return Some(MatchKind::Exact);
    }
    if domain_is_suffix(domain, &pattern.suffix) {
        return Some(MatchKind::Suffix);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_for_rules(rules: &str) -> AppConfig {
        let toml = format!(
            r#"
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
{rules}
"#
        );

        toml::from_str::<AppConfig>(&toml).expect("test config TOML must parse")
    }

    #[test]
    fn order_is_preserved_within_tier() {
        let cfg = cfg_for_rules(
            r#"
[[rules]]
egress = "proxy"
domain = "example.com"

[[rules]]
egress = "direct"
domain = ".example.com"
"#,
        );

        let engine = CompiledEngine::compile(&cfg);
        let decision = engine.decide(None, Some("example.com"), None);

        assert_eq!(decision.egress, EgressId("proxy".to_string()));
    }

    #[test]
    fn app_domain_overrides_domain_and_app() {
        let mut cfg = cfg_for_rules(
            r#"
[[rules]]
egress = "proxy"
domain = "example.com"

[[rules]]
egress = "alpha"
app = "chat.exe"

[[rules]]
egress = "direct"
app = "chat.exe"
domain = "example.com"
"#,
        );
        cfg.validate().expect("config must validate");

        let engine = CompiledEngine::compile(&cfg);
        let decision = engine.decide(Some("chat.exe"), Some("example.com"), None);

        assert_eq!(decision.egress, EgressId("direct".to_string()));
    }

    #[test]
    fn unknown_domain_falls_back_to_app() {
        let mut cfg = cfg_for_rules(
            r#"
[[rules]]
egress = "proxy"
domain = "example.com"

[[rules]]
egress = "alpha"
app = "chat.exe"
"#,
        );
        cfg.validate().expect("config must validate");

        let engine = CompiledEngine::compile(&cfg);
        let decision = engine.decide(Some("chat.exe"), None, None);

        assert_eq!(decision.egress, EgressId("alpha".to_string()));
    }

    #[test]
    fn conflicting_domain_rules_are_rejected() {
        let mut cfg = cfg_for_rules(
            r#"
[[rules]]
egress = "proxy"
domain = "example.com"

[[rules]]
egress = "direct"
domain = ".com"
"#,
        );

        let err = cfg.validate().expect_err("config must reject overlaps");
        let msg = format!("{err:#}");
        assert!(msg.contains("tier 'domain'"));
        assert!(msg.contains("rule #1"));
        assert!(msg.contains("rule #2"));
    }

    #[test]
    fn dst_ip_cidr_matches_and_conflicts() {
        let mut cfg = cfg_for_rules(
            r#"
[[rules]]
egress = "proxy"
dst_ip_cidr = "10.0.0.0/24"

[[rules]]
egress = "direct"
app = "chat.exe"
"#,
        );
        cfg.validate().expect("config must validate");

        let engine = CompiledEngine::compile(&cfg);
        let decision = engine.decide(Some("chat.exe"), None, Some("10.0.0.42".parse().unwrap()));

        assert_eq!(decision.egress, EgressId("proxy".to_string()));

        let mut conflict_cfg = cfg_for_rules(
            r#"
[[rules]]
egress = "proxy"
dst_ip_cidr = "10.0.0.0/24"

[[rules]]
egress = "direct"
dst_ip_cidr = "10.0.0.0/16"
"#,
        );

        let err = conflict_cfg
            .validate()
            .expect_err("config must reject overlapping CIDRs");
        let msg = format!("{err:#}");
        assert!(msg.contains("tier 'dst_ip_cidr'"));
        assert!(msg.contains("rule #1"));
        assert!(msg.contains("rule #2"));
    }
}

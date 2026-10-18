// SPDX-License-Identifier: GPL-3.0-or-later
//! Domain matcher for DNS filtering (ADR-001).
//!
//! Syntax follows AdGuard's DNS filtering rules, restricted to what makes
//! sense without a full request:
//!
//! | Line | Meaning |
//! |---|---|
//! | `\|\|example.org^` | block `example.org` **and subdomains** |
//! | `@@\|\|example.org^` | allow `example.org` and subdomains |
//! | `0.0.0.0 example.org` (hosts) | block `example.org` **only** (exact) |
//! | `example.org` (bare domain) | block `example.org` **only** (exact) |
//! | `...$important` | beats non-important rules, including exceptions |
//! | `...$badfilter` | disables the same rule without `$badfilter` |
//!
//! Rules with any other modifier (`$client`, `$dnsrewrite`, `$dnstype`, ...),
//! regular expressions, wildcards and cosmetic rules are skipped entirely and
//! counted, never turned into a plain block. Hosts lines pointing to an
//! address other than `0.0.0.0`, `::` or loopback are rewrites in AdGuard
//! Home and are skipped too.
//!
//! Priority, strongest first: allowlist, then user rules, then filter lists;
//! within a group: `@@...$important`, `...$important`, `@@...`, plain blocks.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

/// Rule sources in priority order (lower value wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleGroup {
    /// "Don't filter this site": domain and subdomains are always allowed.
    Allowlist = 0,
    /// The user's own rules.
    User = 1,
    /// Subscribed filter lists.
    Lists = 2,
}

/// Location of a rule: source index (see [`Matcher::source_name`]) and
/// 1-based line number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleRef {
    pub source: u16,
    pub line: u32,
}

/// Result of matching a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Block(RuleRef),
    Allow(RuleRef),
    NoMatch,
}

impl Verdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, Self::Block(_))
    }
}

/// Per-source parsing counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParseStats {
    /// Rules added (a hosts line with several names counts once per name).
    pub rules: usize,
    /// Comments, blank lines and ignored hosts entries such as `localhost`.
    pub ignored: usize,
    /// Valid syntax we deliberately do not support (skipped, not applied).
    pub unsupported: usize,
    /// Lines that are not valid rules.
    pub invalid: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuleKey {
    exact: bool,
    domain: Box<str>,
    exception: bool,
    important: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedRule {
    key: RuleKey,
    badfilter: bool,
    /// Hosts-syntax rules are not affected by `$badfilter`.
    hosts: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Line {
    Rules(Vec<ParsedRule>),
    Ignored,
    Unsupported,
    Invalid,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    priority: u8,
    rule: RuleRef,
    allow: bool,
}

fn priority(group: RuleGroup, exception: bool, important: bool) -> u8 {
    let class = match (exception, important) {
        (true, true) => 0,
        (false, true) => 1,
        (true, false) => 2,
        (false, false) => 3,
    };
    group as u8 * 4 + class
}

/// Host names that hosts files map to loopback for system reasons.
const HOSTS_IGNORED_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Lowercases a DNS name and strips the trailing dot. Returns `None` for
/// names that cannot appear in rules (non-ASCII, empty labels, bad chars).
pub fn normalize_domain(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    is_valid_domain(&name).then_some(name)
}

fn is_valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        })
}

fn is_blocking_ip(ip: IpAddr) -> bool {
    ip.is_unspecified() || ip.is_loopback()
}

/// How a single line of a DNS filter list is treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineClass {
    Rule,
    Ignored,
    Unsupported,
    Invalid,
}

/// Classifies one list line (for `openshield-cli lists lint`).
pub fn classify_line(line: &str) -> LineClass {
    match parse_line(line) {
        Line::Rules(_) => LineClass::Rule,
        Line::Ignored => LineClass::Ignored,
        Line::Unsupported => LineClass::Unsupported,
        Line::Invalid => LineClass::Invalid,
    }
}

fn parse_line(raw: &str) -> Line {
    let line = raw.trim();
    if line.is_empty() || line.starts_with('!') || line.starts_with('#') || line.starts_with('[') {
        return Line::Ignored;
    }
    // Hosts syntax: "<ip> <name> [<name>...] [# comment]".
    let mut tokens = line.split_whitespace();
    if let Some(ip) = tokens.next().and_then(|t| t.parse::<IpAddr>().ok()) {
        if !is_blocking_ip(ip) {
            return Line::Unsupported; // a rewrite in AdGuard Home
        }
        let mut rules = Vec::new();
        for name in tokens.take_while(|t| !t.starts_with('#')) {
            let name = name.to_ascii_lowercase();
            if HOSTS_IGNORED_NAMES.contains(&name.as_str())
                || name.parse::<IpAddr>().is_ok()
                || !name.contains('.')
            {
                continue;
            }
            if !is_valid_domain(&name) {
                return Line::Invalid;
            }
            rules.push(ParsedRule {
                key: RuleKey {
                    exact: true,
                    domain: name.into(),
                    exception: false,
                    important: false,
                },
                badfilter: false,
                hosts: true,
            });
        }
        return if rules.is_empty() {
            Line::Ignored
        } else {
            Line::Rules(rules)
        };
    }

    // Cosmetic and HTML filtering rules from mixed lists.
    if ["##", "#@#", "#?#", "#$#", "$$"]
        .iter()
        .any(|m| line.contains(m))
    {
        return Line::Unsupported;
    }
    let (exception, rest) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    if rest.starts_with('/') {
        return Line::Unsupported; // regular expression
    }
    let (pattern, modifiers) = match rest.split_once('$') {
        Some((p, m)) => (p, Some(m)),
        None => (rest, None),
    };
    let mut important = false;
    let mut badfilter = false;
    if let Some(modifiers) = modifiers {
        for modifier in modifiers.split(',').map(str::trim) {
            match modifier {
                "important" => important = true,
                "badfilter" => badfilter = true,
                "" => return Line::Invalid,
                _ => return Line::Unsupported,
            }
        }
    }

    let (exact, domain) = if let Some(rest) = pattern.strip_prefix("||") {
        let domain = match rest.strip_suffix("^|").or_else(|| rest.strip_suffix('^')) {
            Some(domain) => domain,
            // "||example." is a wildcard over TLDs: not supported.
            None if rest.ends_with('.') => return Line::Unsupported,
            // "||example.org" without "^" also matches continuations such as
            // "example.org.cn" in AdGuard; we match it like "||example.org^",
            // which blocks a subset of what AdGuard blocks (never more).
            None => rest,
        };
        (false, domain)
    } else if pattern.starts_with('|') {
        return Line::Unsupported;
    } else {
        (true, pattern)
    };
    let domain = domain.to_ascii_lowercase();
    if domain.contains(['*', '^', '/', ':', '?', '=', '&', '|']) {
        return Line::Unsupported; // wildcards, URL parts
    }
    if !is_valid_domain(&domain) || (exact && !domain.contains('.')) {
        // A bare pattern made of host-name characters that is not a domain
        // ("-ad123-", ".stape.net") is an AdGuard substring pattern: valid
        // syntax, but not supported for DNS. Anything else is malformed.
        let host_chars = domain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b));
        return if exact && host_chars && !domain.is_empty() {
            Line::Unsupported
        } else {
            Line::Invalid
        };
    }
    Line::Rules(vec![ParsedRule {
        key: RuleKey {
            exact,
            domain: domain.into(),
            exception,
            important,
        },
        badfilter,
        hosts: false,
    }])
}

#[derive(Debug)]
struct Pending {
    key: RuleKey,
    hosts: bool,
    group: RuleGroup,
    rule: RuleRef,
}

#[derive(Debug, Clone)]
struct SourceInfo {
    name: String,
    group: RuleGroup,
}

/// Collects rules from all sources, then builds an immutable [`Matcher`].
#[derive(Debug, Default)]
pub struct MatcherBuilder {
    sources: Vec<SourceInfo>,
    pending: Vec<Pending>,
    badfilters: HashSet<RuleKey>,
}

impl MatcherBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_source(&mut self, name: &str, group: RuleGroup) -> u16 {
        let index = u16::try_from(self.sources.len()).unwrap_or(u16::MAX);
        self.sources.push(SourceInfo {
            name: name.to_owned(),
            group,
        });
        index
    }

    /// Adds a filter list or the user rules.
    pub fn add_rules(&mut self, name: &str, group: RuleGroup, text: &str) -> ParseStats {
        let source = self.next_source(name, group);
        let mut stats = ParseStats::default();
        for (index, raw) in text.lines().enumerate() {
            let rule = RuleRef {
                source,
                line: u32::try_from(index + 1).unwrap_or(u32::MAX),
            };
            match parse_line(raw) {
                Line::Rules(rules) => {
                    for parsed in rules {
                        stats.rules += 1;
                        if parsed.badfilter {
                            self.badfilters.insert(parsed.key);
                        } else {
                            self.pending.push(Pending {
                                key: parsed.key,
                                hosts: parsed.hosts,
                                group,
                                rule,
                            });
                        }
                    }
                }
                Line::Ignored => stats.ignored += 1,
                Line::Unsupported => stats.unsupported += 1,
                Line::Invalid => stats.invalid += 1,
            }
        }
        stats
    }

    /// Adds allowlisted domains (one per line, `#` comments). Each domain is
    /// allowed together with its subdomains.
    pub fn add_allowlist(&mut self, name: &str, text: &str) -> ParseStats {
        let source = self.next_source(name, RuleGroup::Allowlist);
        let mut stats = ParseStats::default();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                stats.ignored += 1;
                continue;
            }
            match normalize_domain(line) {
                Some(domain) => {
                    stats.rules += 1;
                    self.pending.push(Pending {
                        key: RuleKey {
                            exact: false,
                            domain: domain.into(),
                            exception: true,
                            important: false,
                        },
                        hosts: false,
                        group: RuleGroup::Allowlist,
                        rule: RuleRef {
                            source,
                            line: u32::try_from(index + 1).unwrap_or(u32::MAX),
                        },
                    });
                }
                None => stats.invalid += 1,
            }
        }
        stats
    }

    /// Applies `$badfilter` and builds the matcher. Also returns how many
    /// rules `$badfilter` disabled.
    pub fn build(self) -> (Matcher, usize) {
        let mut exact: HashMap<Box<str>, Entry> = HashMap::new();
        let mut subdomains: HashMap<Box<str>, Entry> = HashMap::new();
        let mut disabled = 0;
        for pending in self.pending {
            if !pending.hosts
                && pending.group != RuleGroup::Allowlist
                && self.badfilters.contains(&pending.key)
            {
                disabled += 1;
                continue;
            }
            let entry = Entry {
                priority: priority(pending.group, pending.key.exception, pending.key.important),
                rule: pending.rule,
                allow: pending.key.exception,
            };
            let map = if pending.key.exact {
                &mut exact
            } else {
                &mut subdomains
            };
            map.entry(pending.key.domain)
                .and_modify(|existing| {
                    if entry.priority < existing.priority {
                        *existing = entry;
                    }
                })
                .or_insert(entry);
        }
        exact.shrink_to_fit();
        subdomains.shrink_to_fit();
        let matcher = Matcher {
            sources: self.sources,
            exact,
            subdomains,
        };
        (matcher, disabled)
    }
}

/// Immutable domain matcher. Lookups do not allocate or lock.
#[derive(Debug, Default)]
pub struct Matcher {
    sources: Vec<SourceInfo>,
    exact: HashMap<Box<str>, Entry>,
    subdomains: HashMap<Box<str>, Entry>,
}

impl Matcher {
    /// Matches a normalized name (see [`normalize_domain`]).
    pub fn check(&self, name: &str) -> Verdict {
        let mut best = self.exact.get(name).copied();
        let mut suffix = name;
        loop {
            if let Some(entry) = self.subdomains.get(suffix)
                && best.is_none_or(|b| entry.priority < b.priority)
            {
                best = Some(*entry);
            }
            match suffix.find('.') {
                Some(dot) => suffix = &suffix[dot + 1..],
                None => break,
            }
        }
        match best {
            Some(entry) if entry.allow => Verdict::Allow(entry.rule),
            Some(entry) => Verdict::Block(entry.rule),
            None => Verdict::NoMatch,
        }
    }

    /// Display name of a rule source.
    pub fn source_name(&self, source: u16) -> Option<&str> {
        self.sources
            .get(usize::from(source))
            .map(|s| s.name.as_str())
    }

    /// Group of a rule source.
    pub fn source_group(&self, source: u16) -> Option<RuleGroup> {
        self.sources.get(usize::from(source)).map(|s| s.group)
    }

    /// Number of distinct domain entries.
    pub fn len(&self) -> usize {
        self.exact.len() + self.subdomains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(lists: &[&str], user: &str, allow: &str) -> Matcher {
        let mut b = MatcherBuilder::new();
        for (i, text) in lists.iter().enumerate() {
            b.add_rules(&format!("list{i}"), RuleGroup::Lists, text);
        }
        b.add_rules("user", RuleGroup::User, user);
        b.add_allowlist("allowlist", allow);
        b.build().0
    }

    fn blocked(m: &Matcher, name: &str) -> bool {
        m.check(name).is_blocked()
    }

    #[test]
    fn adblock_style_matches_subdomains() {
        let m = matcher(&["||ads.example.org^"], "", "");
        assert!(blocked(&m, "ads.example.org"));
        assert!(blocked(&m, "x.y.ads.example.org"));
        assert!(!blocked(&m, "example.org"));
        assert!(!blocked(&m, "badads.example.org"));
        assert!(!blocked(&m, "ads.example.org.evil"));
    }

    #[test]
    fn hosts_and_bare_domains_are_exact() {
        let m = matcher(
            &["0.0.0.0 tracker.example\n127.0.0.1 a.example b.example\nbare.example"],
            "",
            "",
        );
        assert!(blocked(&m, "tracker.example"));
        assert!(!blocked(&m, "sub.tracker.example"));
        assert!(blocked(&m, "a.example"));
        assert!(blocked(&m, "b.example"));
        assert!(blocked(&m, "bare.example"));
        assert!(!blocked(&m, "www.bare.example"));
    }

    #[test]
    fn hosts_special_names_and_rewrites_are_skipped() {
        let mut b = MatcherBuilder::new();
        let stats = b.add_rules(
            "hosts",
            RuleGroup::Lists,
            "127.0.0.1 localhost\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n1.2.3.4 rewrite.example\n# c\n\n0.0.0.0 ok.example # tail",
        );
        assert_eq!(stats.rules, 1);
        assert_eq!(stats.unsupported, 1);
        assert_eq!(stats.ignored, 5);
        let (m, _) = b.build();
        assert!(!blocked(&m, "localhost"));
        assert!(!blocked(&m, "rewrite.example"));
        assert!(blocked(&m, "ok.example"));
    }

    #[test]
    fn unsupported_modifiers_skip_the_whole_rule() {
        let mut b = MatcherBuilder::new();
        let stats = b.add_rules(
            "l",
            RuleGroup::Lists,
            "||client.example^$client=127.0.0.1\n||rw.example^$dnsrewrite=1.2.3.4\n||t.example^$dnstype=AAAA\n||ok.example^$important",
        );
        assert_eq!(stats.unsupported, 3);
        assert_eq!(stats.rules, 1);
        let (m, _) = b.build();
        assert!(!blocked(&m, "client.example"));
        assert!(!blocked(&m, "rw.example"));
        assert!(!blocked(&m, "t.example"));
        assert!(blocked(&m, "ok.example"));
    }

    #[test]
    fn regex_wildcards_and_cosmetics_are_unsupported() {
        let mut b = MatcherBuilder::new();
        let stats = b.add_rules(
            "l",
            RuleGroup::Lists,
            "/^ad[0-9]+\\.example$/\n||ad*.example^\nexample.org##.banner\n||anytld.\n|exact.example^\n.leading-dot.example^",
        );
        assert_eq!(stats.unsupported, 6);
        assert_eq!(stats.rules, 0);
    }

    #[test]
    fn missing_caret_matches_like_caret_rule() {
        let m = matcher(&["||noanchor.example"], "", "");
        assert!(blocked(&m, "noanchor.example"));
        assert!(blocked(&m, "sub.noanchor.example"));
        assert!(!blocked(&m, "noanchor.example.cn"));
        assert_eq!(classify_line("||noanchor.example"), LineClass::Rule);
        assert_eq!(classify_line("||anytld."), LineClass::Unsupported);
        assert_eq!(classify_line("! comment"), LineClass::Ignored);
        assert_eq!(classify_line("||bad..x^"), LineClass::Invalid);
    }

    #[test]
    fn exception_beats_block_and_important_beats_exception() {
        let m = matcher(
            &["||a.example^\n@@||a.example^\n||b.example^$important\n@@||b.example^"],
            "",
            "",
        );
        assert!(!blocked(&m, "a.example"));
        assert!(blocked(&m, "b.example"));

        let m = matcher(
            &["||c.example^$important\n@@||c.example^$important"],
            "",
            "",
        );
        assert!(!blocked(&m, "c.example"));
    }

    #[test]
    fn exception_on_parent_unblocks_subdomain_block() {
        let m = matcher(&["||ads.site.example^\n@@||site.example^"], "", "");
        assert!(!blocked(&m, "ads.site.example"));
    }

    #[test]
    fn badfilter_disables_matching_rule_across_lists() {
        let mut b = MatcherBuilder::new();
        b.add_rules(
            "l1",
            RuleGroup::Lists,
            "||x.example^\n||y.example^$important\n0.0.0.0 h.example",
        );
        b.add_rules(
            "l2",
            RuleGroup::Lists,
            "||x.example^$badfilter\n||y.example^$badfilter\nh.example$badfilter",
        );
        let (m, disabled) = b.build();
        assert_eq!(disabled, 1);
        assert!(!blocked(&m, "x.example"));
        // Different modifiers: not the same rule.
        assert!(blocked(&m, "y.example"));
        // Hosts rules are not affected by $badfilter.
        assert!(blocked(&m, "h.example"));
    }

    #[test]
    fn user_rules_beat_lists_and_allowlist_beats_everything() {
        let m = matcher(
            &["@@||u.example^$important\n||site.example^$important"],
            "||u.example^\n||site.example^",
            "site.example",
        );
        assert!(blocked(&m, "u.example"));
        assert!(!blocked(&m, "site.example"));
        assert!(!blocked(&m, "cdn.site.example"));
    }

    #[test]
    fn verdict_points_to_rule_line() {
        let m = matcher(&["! header\n||ads.example^"], "", "");
        match m.check("ads.example") {
            Verdict::Block(rule) => {
                assert_eq!(m.source_name(rule.source), Some("list0"));
                assert_eq!(rule.line, 2);
                assert_eq!(m.source_group(rule.source), Some(RuleGroup::Lists));
            }
            other => panic!("expected block, got {other:?}"),
        }
    }

    #[test]
    fn rules_are_case_insensitive() {
        let m = matcher(&["||Ads.Example^\n0.0.0.0 Tracker.EXAMPLE"], "", "");
        assert!(blocked(&m, "ads.example"));
        assert!(blocked(&m, "tracker.example"));
    }

    #[test]
    fn normalize_domain_handles_case_dot_and_garbage() {
        assert_eq!(
            normalize_domain("WWW.Example.ORG.").as_deref(),
            Some("www.example.org")
        );
        assert_eq!(
            normalize_domain("_dmarc.example").as_deref(),
            Some("_dmarc.example")
        );
        assert_eq!(normalize_domain("bad..name"), None);
        assert_eq!(normalize_domain("пример.рф"), None);
        assert_eq!(normalize_domain(""), None);
    }

    #[test]
    fn invalid_lines_are_counted() {
        let mut b = MatcherBuilder::new();
        let stats = b.add_rules(
            "l",
            RuleGroup::Lists,
            "||bad..example^\n||ok.example^$\nfoo bar\n-ad123-\n.stape.net\nnodot",
        );
        assert_eq!(stats.invalid, 3);
        // Substring patterns are valid AdGuard syntax we do not support.
        assert_eq!(stats.unsupported, 3);
    }

    #[test]
    fn single_label_adblock_rule_blocks_tld() {
        let m = matcher(&["||zip^"], "", "");
        assert!(blocked(&m, "evil.zip"));
        assert!(!blocked(&m, "zip.example"));
    }
}

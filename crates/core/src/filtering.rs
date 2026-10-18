// SPDX-License-Identifier: GPL-3.0-or-later
//! Glue between the data directory, filter lists and the [`Matcher`].

use crate::config::ListsConfig;
use crate::lists::{self, ListSource, Subscription, UpdateOutcome};
use crate::matcher::{Matcher, MatcherBuilder, ParseStats, RuleGroup, RuleRef};
use crate::paths::DataDir;

/// Where a matcher source came from, in source-index order.
#[derive(Debug, Clone)]
pub enum SourceKind {
    List(Subscription),
    UserRules,
    Allowlist,
}

#[derive(Debug, Clone)]
pub struct SourceReport {
    pub name: String,
    pub kind: SourceKind,
    pub stats: ParseStats,
    /// A subscribed list that has not been downloaded yet.
    pub missing: bool,
}

/// What went into a matcher.
#[derive(Debug, Clone, Default)]
pub struct LoadReport {
    pub sources: Vec<SourceReport>,
    pub disabled_by_badfilter: usize,
    /// Enabled ids that are not in the catalog, or invalid custom lists.
    pub invalid_subscriptions: Vec<String>,
}

impl LoadReport {
    /// Text of the rule a verdict points to (reads the source again).
    pub fn rule_text(&self, data_dir: &DataDir, rule: RuleRef) -> Option<String> {
        let source = self.sources.get(usize::from(rule.source))?;
        let text = match &source.kind {
            SourceKind::List(sub) => lists::read_cached(&data_dir.lists_dir(), sub)?,
            SourceKind::UserRules => std::fs::read_to_string(data_dir.user_rules_file()).ok()?,
            SourceKind::Allowlist => std::fs::read_to_string(data_dir.allowlist_file()).ok()?,
        };
        let index = usize::try_from(rule.line).ok()?.checked_sub(1)?;
        text.lines().nth(index).map(|l| l.trim().to_owned())
    }

    pub fn total_rules(&self) -> usize {
        self.sources.iter().map(|s| s.stats.rules).sum()
    }
}

/// Builds a matcher from cached lists, user rules and the allowlist.
/// Missing files are not errors: a list that was never downloaded is
/// reported as missing, absent user files mean "no rules".
pub fn build_matcher(data_dir: &DataDir, lists_config: &ListsConfig) -> (Matcher, LoadReport) {
    let (subs, invalid) = lists::subscriptions(lists_config);
    let mut builder = MatcherBuilder::new();
    let mut report = LoadReport {
        invalid_subscriptions: invalid,
        ..LoadReport::default()
    };
    let lists_dir = data_dir.lists_dir();
    for sub in subs {
        let (stats, missing) = match lists::read_cached(&lists_dir, &sub) {
            Some(text) => (builder.add_rules(&sub.name, RuleGroup::Lists, &text), false),
            None => (builder.add_rules(&sub.name, RuleGroup::Lists, ""), true),
        };
        report.sources.push(SourceReport {
            name: sub.name.clone(),
            kind: SourceKind::List(sub),
            stats,
            missing,
        });
    }
    let user = std::fs::read_to_string(data_dir.user_rules_file()).unwrap_or_default();
    report.sources.push(SourceReport {
        name: "User rules".to_owned(),
        kind: SourceKind::UserRules,
        stats: builder.add_rules("User rules", RuleGroup::User, &user),
        missing: false,
    });
    let allow = std::fs::read_to_string(data_dir.allowlist_file()).unwrap_or_default();
    report.sources.push(SourceReport {
        name: "Allowlist".to_owned(),
        kind: SourceKind::Allowlist,
        stats: builder.add_allowlist("Allowlist", &allow),
        missing: false,
    });
    let (matcher, disabled) = builder.build();
    report.disabled_by_badfilter = disabled;
    (matcher, report)
}

/// Updates all enabled downloadable lists. With `force`, every list gets a
/// conditional request; otherwise lists checked within the update interval
/// are skipped.
pub async fn update_lists(
    data_dir: &DataDir,
    lists_config: &ListsConfig,
    force: bool,
) -> Result<Vec<(Subscription, UpdateOutcome)>, reqwest::Error> {
    let client = lists::http_client()?;
    let (subs, _) = lists::subscriptions(lists_config);
    let max_age = (!force).then(|| lists_config.update_interval());
    let dir = data_dir.lists_dir();
    let mut results = Vec::with_capacity(subs.len());
    for sub in subs {
        if matches!(sub.source, ListSource::Embedded(_)) {
            continue;
        }
        let outcome = lists::update_list(&client, &dir, &sub, max_age).await;
        results.push((sub, outcome));
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::Verdict;

    #[test]
    fn builds_from_embedded_user_rules_and_allowlist() -> std::io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("openshield-filtering-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
        let data = DataDir::new(&root);
        std::fs::write(data.user_rules_file(), "! mine\n||mine.example^\n")?;
        std::fs::write(data.allowlist_file(), "dns.google\n")?;

        let (matcher, report) = build_matcher(&data, &ListsConfig::default());
        // Downloadable lists are missing in an empty data dir; embedded is not.
        assert!(report.sources.iter().any(|s| s.missing));
        assert!(matcher.check("cloudflare-dns.com").is_blocked());
        assert!(!matcher.check("dns.google").is_blocked());

        match matcher.check("x.mine.example") {
            Verdict::Block(rule) => {
                assert_eq!(
                    report.rule_text(&data, rule).as_deref(),
                    Some("||mine.example^")
                );
            }
            other => panic!("expected block, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }
}

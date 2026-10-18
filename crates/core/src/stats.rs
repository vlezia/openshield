// SPDX-License-Identifier: GPL-3.0-or-later
//! Query statistics, kept in memory only.
//!
//! Privacy: no query history is written to disk. Per-domain counters live in
//! a bounded in-memory table and disappear when the process exits.
//!
//! The packet loop calls [`StatsRecorder::record`], which only touches atomics
//! and does a non-blocking channel send; a collector thread aggregates.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// Maximum distinct domains tracked; least-seen entries are evicted beyond it.
pub const MAX_TRACKED_DOMAINS: usize = 20_000;
const CHANNEL_CAPACITY: usize = 8192;

#[derive(Debug, Default)]
struct Counters {
    total: AtomicU64,
    blocked: AtomicU64,
    dropped_events: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy)]
struct DomainCount {
    total: u64,
    blocked: u64,
}

type DomainTable = Arc<Mutex<HashMap<Box<str>, DomainCount>>>;

/// Cheap handle used by the packet loop.
#[derive(Debug, Clone)]
pub struct StatsRecorder {
    counters: Arc<Counters>,
    tx: SyncSender<(Box<str>, bool)>,
}

impl StatsRecorder {
    /// Records one query. Never blocks; if the collector lags, the per-domain
    /// event is dropped (totals stay exact).
    pub fn record(&self, domain: &str, blocked: bool) {
        self.counters.total.fetch_add(1, Ordering::Relaxed);
        if blocked {
            self.counters.blocked.fetch_add(1, Ordering::Relaxed);
        }
        match self.tx.try_send((domain.into(), blocked)) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                self.counters.dropped_events.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Point-in-time statistics.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub total: u64,
    pub blocked: u64,
    /// Per-domain events dropped because the collector lagged.
    pub dropped_events: u64,
    pub top_queried: Vec<(String, u64)>,
    pub top_blocked: Vec<(String, u64)>,
}

/// Owns the collector thread and the in-memory per-domain table.
#[derive(Debug)]
pub struct Stats {
    counters: Arc<Counters>,
    table: DomainTable,
    recorder: Option<StatsRecorder>,
    collector: Option<JoinHandle<()>>,
}

impl Stats {
    pub fn start() -> std::io::Result<Self> {
        let counters = Arc::new(Counters::default());
        let table: DomainTable = Arc::default();
        let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let collector_table = Arc::clone(&table);
        let collector = std::thread::Builder::new()
            .name("openshield-stats".to_owned())
            .spawn(move || collect(&rx, &collector_table))?;
        Ok(Self {
            recorder: Some(StatsRecorder {
                counters: Arc::clone(&counters),
                tx,
            }),
            counters,
            table,
            collector: Some(collector),
        })
    }

    pub fn recorder(&self) -> StatsRecorder {
        match &self.recorder {
            Some(r) => r.clone(),
            None => unreachable!("recorder exists until drop"),
        }
    }

    /// Current totals and the `top_n` most queried / most blocked domains.
    pub fn snapshot(&self, top_n: usize) -> StatsSnapshot {
        let mut snapshot = StatsSnapshot {
            total: self.counters.total.load(Ordering::Relaxed),
            blocked: self.counters.blocked.load(Ordering::Relaxed),
            dropped_events: self.counters.dropped_events.load(Ordering::Relaxed),
            ..StatsSnapshot::default()
        };
        if let Ok(table) = self.table.lock() {
            snapshot.top_queried = top(&table, top_n, |c| c.total);
            snapshot.top_blocked = top(&table, top_n, |c| c.blocked);
        }
        snapshot
    }
}

impl Drop for Stats {
    fn drop(&mut self) {
        // Dropping our sender lets the collector finish once all recorder
        // clones are gone; do not block shutdown waiting for stragglers.
        self.recorder = None;
        drop(self.collector.take());
    }
}

fn collect(rx: &Receiver<(Box<str>, bool)>, table: &DomainTable) {
    while let Ok((domain, blocked)) = rx.recv() {
        let Ok(mut table) = table.lock() else {
            return;
        };
        if table.len() >= MAX_TRACKED_DOMAINS && !table.contains_key(&domain) {
            evict(&mut table);
        }
        let count = table.entry(domain).or_default();
        count.total += 1;
        if blocked {
            count.blocked += 1;
        }
    }
}

/// Drops (at least) the least-seen half of the table. If all counts are
/// equal, the table is cleared.
fn evict(table: &mut HashMap<Box<str>, DomainCount>) {
    let mut totals: Vec<u64> = table.values().map(|c| c.total).collect();
    if totals.is_empty() {
        return;
    }
    let lower_half_end = (totals.len() / 2).saturating_sub(1);
    let (_, threshold, _) = totals.select_nth_unstable(lower_half_end);
    let threshold = *threshold;
    table.retain(|_, c| c.total > threshold);
}

fn top(
    table: &HashMap<Box<str>, DomainCount>,
    n: usize,
    key: impl Fn(&DomainCount) -> u64,
) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = table
        .iter()
        .map(|(domain, count)| (domain.to_string(), key(count)))
        .filter(|(_, value)| *value > 0)
        .collect();
    items.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    items.truncate(n);
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn wait_for(stats: &Stats, total_domains_events: u64) -> StatsSnapshot {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let snap = stats.snapshot(10);
            let seen: u64 = snap.top_queried.iter().map(|(_, n)| n).sum();
            if seen >= total_domains_events || Instant::now() > deadline {
                return snap;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn counts_totals_and_top_domains() -> std::io::Result<()> {
        let stats = Stats::start()?;
        let rec = stats.recorder();
        for _ in 0..3 {
            rec.record("ads.example", true);
        }
        rec.record("ok.example", false);
        rec.record("ok.example", false);
        let snap = wait_for(&stats, 5);
        assert_eq!(snap.total, 5);
        assert_eq!(snap.blocked, 3);
        assert_eq!(snap.top_queried[0], ("ads.example".to_owned(), 3));
        assert_eq!(snap.top_blocked, vec![("ads.example".to_owned(), 3)]);
        Ok(())
    }

    #[test]
    fn eviction_keeps_table_bounded() {
        let mut table = HashMap::new();
        for i in 0..MAX_TRACKED_DOMAINS {
            let count = DomainCount {
                total: if i % 2 == 0 { 5 } else { 1 },
                blocked: 0,
            };
            table.insert(format!("d{i}.example").into_boxed_str(), count);
        }
        evict(&mut table);
        assert_eq!(table.len(), MAX_TRACKED_DOMAINS / 2);
        assert!(table.values().all(|c| c.total == 5));
    }
}

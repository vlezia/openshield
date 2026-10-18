// SPDX-License-Identifier: GPL-3.0-or-later
//! The DNS packet loop.
//!
//! Hot path rules (ADR-004): no network or disk I/O and no locks. Policy is
//! read through `ArcSwap` (lock-free), statistics through atomics and a
//! non-blocking channel. Every packet is wrapped in heartbeat begin/end so the
//! watchdog can detect a hang and release capture.

use arc_swap::ArcSwap;
use openshield_core::stats::StatsRecorder;
use openshield_core::watchdog::Heartbeat;
use openshield_intercept::{InterceptError, Interceptor};

use crate::packet::{self, Action, Policy};

/// Large enough for any packet WinDivert can return.
pub const PACKET_BUFFER: usize = 40 + 0xFFFF;

/// Loop options. `stall_after` exists only with the `fault-injection`
/// feature, for testing the watchdog.
#[derive(Debug, Default, Clone)]
pub struct LoopOptions {
    /// Hang forever while processing the N-th packet (1-based).
    #[cfg(feature = "fault-injection")]
    pub stall_after: Option<u64>,
}

/// Counters returned when the loop ends.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LoopSummary {
    pub packets: u64,
    pub replies: u64,
    pub send_errors: u64,
}

/// Runs until the interceptor is shut down. Returns an error only if
/// capture fails for another reason.
pub fn run<I: Interceptor>(
    interceptor: &I,
    policy: &ArcSwap<Policy>,
    heartbeat: &Heartbeat,
    stats: &StatsRecorder,
    options: &LoopOptions,
) -> Result<LoopSummary, InterceptError> {
    let _ = options; // only read with fault injection
    let mut buf = vec![0u8; PACKET_BUFFER];
    let mut summary = LoopSummary::default();
    loop {
        let (len, meta) = match interceptor.recv(&mut buf) {
            Ok(received) => received,
            Err(InterceptError::Shutdown) => return Ok(summary),
            Err(e) => return Err(e),
        };
        heartbeat.begin();
        summary.packets += 1;

        #[cfg(feature = "fault-injection")]
        if options.stall_after == Some(summary.packets) {
            tracing::warn!(
                "fault injection: hanging on packet {} (watchdog should fire)",
                summary.packets
            );
            loop {
                std::thread::park();
            }
        }

        let packet = &buf[..len];
        let decision = packet::decide(packet, &policy.load());
        if let Some(query) = &decision.query {
            stats.record(&query.domain, query.blocked);
        }
        let sent = match &decision.action {
            Action::Pass => interceptor.reinject(packet, &meta),
            Action::Reply(reply) => {
                summary.replies += 1;
                // If the forged answer cannot be sent, let the original
                // query through rather than losing it (fail open).
                interceptor
                    .inject_reply(reply, &meta)
                    .or_else(|_| interceptor.reinject(packet, &meta))
            }
        };
        heartbeat.end();
        match sent {
            Ok(()) => {}
            Err(InterceptError::Shutdown) => return Ok(summary),
            Err(e) => {
                summary.send_errors += 1;
                tracing::debug!("packet send failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::{dns_query, policy, udp_v4};
    use hickory_proto::rr::RecordType;
    use openshield_core::config::DnsBlockingMode;
    use openshield_core::stats::Stats;
    use openshield_intercept::mock::MockInterceptor;
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn loop_answers_blocked_passes_allowed_and_stops_on_shutdown() -> std::io::Result<()> {
        let mock = Arc::new(MockInterceptor::new());
        let policy = Arc::new(ArcSwap::from_pointee(policy(DnsBlockingMode::NullIp)));
        let heartbeat = Heartbeat::new();
        let stats = Stats::start()?;
        let recorder = stats.recorder();

        let thread = {
            let (mock, policy, heartbeat) = (
                Arc::clone(&mock),
                Arc::clone(&policy),
                Arc::clone(&heartbeat),
            );
            std::thread::spawn(move || {
                run(
                    &*mock,
                    &policy,
                    &heartbeat,
                    &recorder,
                    &LoopOptions::default(),
                )
            })
        };

        let blocked = udp_v4(&dns_query("ads.example.", RecordType::A, 1));
        let allowed = udp_v4(&dns_query("example.org.", RecordType::A, 2));
        mock.push(blocked);
        mock.push(allowed.clone());
        mock.push(b"\x45garbage".to_vec());
        assert!(mock.wait_handled(3, Duration::from_secs(5)));

        assert_eq!(mock.replies().len(), 1);
        assert_eq!(mock.replies()[0].0, 0);
        assert_eq!(mock.reinjected()[0], allowed);
        assert_eq!(heartbeat.busy_for(), None);

        assert!(mock.shutdown().is_ok());
        let summary = thread
            .join()
            .map_err(|_| std::io::Error::other("loop panicked"))?
            .map_err(std::io::Error::other)?;
        assert_eq!(summary.packets, 3);
        assert_eq!(summary.replies, 1);

        let snap = stats.snapshot(5);
        assert_eq!(snap.total, 2);
        assert_eq!(snap.blocked, 1);
        Ok(())
    }

    #[test]
    fn policy_can_be_swapped_while_running() {
        let policy = ArcSwap::from_pointee(policy(DnsBlockingMode::NullIp));
        let packet = udp_v4(&dns_query("ads.example.", RecordType::A, 1));
        assert!(matches!(
            packet::decide(&packet, &policy.load()).action,
            Action::Reply(_)
        ));
        policy.store(Arc::new(Policy {
            matcher: Arc::default(),
            mode: DnsBlockingMode::NullIp,
            blocked_ttl: 10,
        }));
        assert_eq!(packet::decide(&packet, &policy.load()).action, Action::Pass);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS filtering.
//!
//! Stage 1: outgoing DNS queries are captured through an `Interceptor`; queries
//! for blocked domains get a forged answer (`0.0.0.0` / `::` or NXDOMAIN) and
//! the original packet is dropped. Everything else passes through unchanged.

/// Standard DNS port, captured for both UDP and TCP.
pub const DNS_PORT: u16 = 53;

/// How a blocked query is answered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BlockingMode {
    /// `A 0.0.0.0` / `AAAA ::` with a short TTL.
    #[default]
    NullIp,
    /// `NXDOMAIN` response code.
    NxDomain,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ip_is_default_mode() {
        assert_eq!(BlockingMode::default(), BlockingMode::NullIp);
    }
}

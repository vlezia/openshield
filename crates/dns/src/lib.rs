// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS filtering.
//!
//! Outgoing DNS queries are captured through an `Interceptor`. Queries for
//! blocked domains get a forged answer (`0.0.0.0` / `::`, or NXDOMAIN) over
//! UDP, or a TCP reset over TCP; the original packet is dropped. Everything
//! else is reinjected unchanged.

pub mod packet;
pub mod run;

/// Standard DNS port, captured for both UDP and TCP.
pub const DNS_PORT: u16 = 53;

/// WinDivert filter for outbound DNS. Loopback (local resolvers/proxies) and
/// our own injected packets are excluded; for TCP only data segments are
/// diverted, so handshakes are never touched.
pub const WINDIVERT_FILTER: &str = "outbound and !loopback and !impostor and \
     (udp.DstPort == 53 or (tcp.DstPort == 53 and tcp.PayloadLength > 0))";

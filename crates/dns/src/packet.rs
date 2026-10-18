// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-packet DNS decisions: parse a captured IP packet, match the queried
//! domain and build the forged answer.
//!
//! Pure functions over byte slices, so everything here is unit-testable
//! without a driver. Anything we do not understand is passed through
//! unchanged (fail open).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use openshield_core::config::DnsBlockingMode;
use openshield_core::matcher::{Matcher, normalize_domain};

use crate::DNS_PORT;

/// Firefox's DoH canary: an NXDOMAIN answer makes Firefox disable its own
/// DNS-over-HTTPS (ADR-002). A `0.0.0.0` answer would not.
pub const FIREFOX_CANARY: &str = "use-application-dns.net";

/// TTL / hop limit of forged packets.
const FORGED_TTL: u8 = 64;

/// What the packet loop needs to answer blocked queries.
#[derive(Debug)]
pub struct Policy {
    pub matcher: Arc<Matcher>,
    pub mode: DnsBlockingMode,
    /// TTL of forged DNS records, seconds.
    pub blocked_ttl: u32,
}

/// What to do with a captured packet.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Reinject the packet unchanged.
    Pass,
    /// Drop the packet and send this one back to its sender instead.
    Reply(Vec<u8>),
}

/// The queried domain, for statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfo {
    pub domain: String,
    pub blocked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Decision {
    pub action: Action,
    pub query: Option<QueryInfo>,
}

impl Decision {
    fn pass() -> Self {
        Self {
            action: Action::Pass,
            query: None,
        }
    }
}

/// Decides what to do with one outbound packet.
pub fn decide(packet: &[u8], policy: &Policy) -> Decision {
    let Ok(sliced) = SlicedPacket::from_ip(packet) else {
        return Decision::pass();
    };
    let (src, dst) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(v6)) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
        _ => return Decision::pass(),
    };
    match &sliced.transport {
        Some(TransportSlice::Udp(udp)) if udp.destination_port() == DNS_PORT => {
            let Some((query, response)) = evaluate(udp.payload(), policy) else {
                return Decision::pass();
            };
            let action = match response {
                Some(dns) => match build_udp(dst, src, DNS_PORT, udp.source_port(), &dns) {
                    Some(reply) => Action::Reply(reply),
                    None => Action::Pass,
                },
                None => Action::Pass,
            };
            Decision {
                action,
                query: Some(query),
            }
        }
        Some(TransportSlice::Tcp(tcp)) if tcp.destination_port() == DNS_PORT => {
            // DNS over TCP: 2-byte length prefix. We only look at segments
            // that carry exactly one whole query; anything else passes.
            let payload = tcp.payload();
            if payload.len() < 2 {
                return Decision::pass();
            }
            let declared = usize::from(u16::from_be_bytes([payload[0], payload[1]]));
            if declared + 2 != payload.len() {
                return Decision::pass();
            }
            let Some((query, response)) = evaluate(&payload[2..], policy) else {
                return Decision::pass();
            };
            let action = if response.is_some() {
                // Forging an answer inside the stream is fragile; reset the
                // connection instead, the resolver then fails for this name.
                let seq = tcp.acknowledgment_number();
                let payload_len = u32::try_from(payload.len()).unwrap_or(0);
                let ack = tcp.sequence_number().wrapping_add(payload_len);
                match build_tcp_rst(dst, src, DNS_PORT, tcp.source_port(), seq, ack) {
                    Some(rst) => Action::Reply(rst),
                    None => Action::Pass,
                }
            } else {
                Action::Pass
            };
            Decision {
                action,
                query: Some(query),
            }
        }
        _ => Decision::pass(),
    }
}

/// Parses a DNS query and, if blocked, builds the response message bytes.
/// Returns `None` for anything that is not a standard query.
fn evaluate(dns: &[u8], policy: &Policy) -> Option<(QueryInfo, Option<Vec<u8>>)> {
    let request = Message::from_vec(dns).ok()?;
    if request.metadata.message_type != MessageType::Query
        || request.metadata.op_code != OpCode::Query
    {
        return None;
    }
    let question = request.queries.first()?;
    let domain = normalize_domain(&question.name().to_ascii())?;
    let blocked = policy.matcher.check(&domain).is_blocked();
    let response = if blocked {
        Some(blocked_response(&request, &domain, policy)?)
    } else {
        None
    };
    Some((QueryInfo { domain, blocked }, response))
}

fn blocked_response(request: &Message, domain: &str, policy: &Policy) -> Option<Vec<u8>> {
    let question = request.queries.first()?;
    let nxdomain = policy.mode == DnsBlockingMode::Nxdomain || domain == FIREFOX_CANARY;
    let mut response = Message::response(request.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.checking_disabled = request.metadata.checking_disabled;
    response.queries = request.queries.clone();
    if nxdomain {
        response.metadata.response_code = ResponseCode::NXDomain;
    } else {
        response.metadata.response_code = ResponseCode::NoError;
        let rdata = match question.query_type() {
            RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
            // HTTPS, SVCB, CNAME, TXT, ...: empty answer (NODATA).
            _ => None,
        };
        if let Some(rdata) = rdata {
            response.add_answer(Record::from_rdata(
                question.name().clone(),
                policy.blocked_ttl,
                rdata,
            ));
        }
    }
    response.to_vec().ok()
}

fn build_udp(src: IpAddr, dst: IpAddr, sport: u16, dport: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let builder = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), FORGED_TTL),
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), FORGED_TTL),
        _ => return None,
    }
    .udp(sport, dport);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}

fn build_tcp_rst(
    src: IpAddr,
    dst: IpAddr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
) -> Option<Vec<u8>> {
    let builder = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => PacketBuilder::ipv4(s.octets(), d.octets(), FORGED_TTL),
        (IpAddr::V6(s), IpAddr::V6(d)) => PacketBuilder::ipv6(s.octets(), d.octets(), FORGED_TTL),
        _ => return None,
    }
    .tcp(sport, dport, seq, 0)
    .rst()
    .ack(ack);
    let mut out = Vec::with_capacity(builder.size(0));
    builder.write(&mut out, &[]).ok()?;
    Some(out)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use openshield_core::matcher::{MatcherBuilder, RuleGroup};

    pub(crate) const CLIENT_V4: [u8; 4] = [192, 168, 1, 10];
    pub(crate) const SERVER_V4: [u8; 4] = [8, 8, 8, 8];

    pub(crate) fn policy(mode: DnsBlockingMode) -> Policy {
        let mut b = MatcherBuilder::new();
        b.add_rules(
            "test",
            RuleGroup::Lists,
            "||ads.example^\n||use-application-dns.net^",
        );
        Policy {
            matcher: Arc::new(b.build().0),
            mode,
            blocked_ttl: 10,
        }
    }

    pub(crate) fn dns_query(name: &str, rtype: RecordType, id: u16) -> Vec<u8> {
        let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        msg.add_query(Query::query(Name::from_ascii(name).expect("name"), rtype));
        msg.to_vec().expect("encode")
    }

    pub(crate) fn udp_v4(dns: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ipv4(CLIENT_V4, SERVER_V4, 128).udp(50000, 53);
        let mut out = Vec::new();
        builder.write(&mut out, dns).expect("build");
        out
    }

    fn reply_dns(reply: &[u8]) -> (SlicedPacket<'_>, Message) {
        let sliced = SlicedPacket::from_ip(reply).expect("valid reply");
        let payload = match &sliced.transport {
            Some(TransportSlice::Udp(udp)) => udp.payload(),
            other => panic!("expected UDP, got {other:?}"),
        };
        let msg = Message::from_vec(payload).expect("dns");
        (sliced, msg)
    }

    fn expect_reply(decision: &Decision) -> &[u8] {
        match &decision.action {
            Action::Reply(bytes) => bytes,
            Action::Pass => panic!("expected a reply"),
        }
    }

    #[test]
    fn blocked_a_query_gets_null_ip_from_the_server_address() {
        let p = policy(DnsBlockingMode::NullIp);
        let packet = udp_v4(&dns_query("x.ads.example.", RecordType::A, 0x1234));
        let decision = decide(&packet, &p);
        assert_eq!(
            decision.query,
            Some(QueryInfo {
                domain: "x.ads.example".to_owned(),
                blocked: true
            })
        );
        let (sliced, msg) = reply_dns(expect_reply(&decision));
        match &sliced.net {
            Some(NetSlice::Ipv4(v4)) => {
                assert_eq!(v4.header().source_addr().octets(), SERVER_V4);
                assert_eq!(v4.header().destination_addr().octets(), CLIENT_V4);
            }
            other => panic!("expected IPv4, got {other:?}"),
        }
        match &sliced.transport {
            Some(TransportSlice::Udp(udp)) => {
                assert_eq!(udp.source_port(), 53);
                assert_eq!(udp.destination_port(), 50000);
            }
            other => panic!("expected UDP, got {other:?}"),
        }
        assert_eq!(msg.metadata.id, 0x1234);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.metadata.recursion_desired);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].ttl, 10);
        assert_eq!(msg.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
    }

    #[test]
    fn blocked_aaaa_gets_unspecified_v6() {
        let p = policy(DnsBlockingMode::NullIp);
        let decision = decide(&udp_v4(&dns_query("ads.example.", RecordType::AAAA, 1)), &p);
        let (_, msg) = reply_dns(expect_reply(&decision));
        assert_eq!(
            msg.answers[0].data,
            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))
        );
    }

    #[test]
    fn blocked_https_query_gets_empty_answer() {
        let p = policy(DnsBlockingMode::NullIp);
        let decision = decide(
            &udp_v4(&dns_query("ads.example.", RecordType::HTTPS, 1)),
            &p,
        );
        let (_, msg) = reply_dns(expect_reply(&decision));
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.answers.is_empty());
    }

    #[test]
    fn nxdomain_mode_and_firefox_canary() {
        let p = policy(DnsBlockingMode::Nxdomain);
        let decision = decide(&udp_v4(&dns_query("ads.example.", RecordType::A, 1)), &p);
        let (_, msg) = reply_dns(expect_reply(&decision));
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);

        let p = policy(DnsBlockingMode::NullIp);
        let decision = decide(
            &udp_v4(&dns_query("use-application-dns.net.", RecordType::A, 1)),
            &p,
        );
        let (_, msg) = reply_dns(expect_reply(&decision));
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn allowed_query_passes_with_info() {
        let p = policy(DnsBlockingMode::NullIp);
        let decision = decide(&udp_v4(&dns_query("Example.ORG.", RecordType::A, 1)), &p);
        assert_eq!(decision.action, Action::Pass);
        assert_eq!(
            decision.query,
            Some(QueryInfo {
                domain: "example.org".to_owned(),
                blocked: false
            })
        );
    }

    #[test]
    fn ipv6_query_is_answered_over_ipv6() {
        let p = policy(DnsBlockingMode::NullIp);
        let client = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let server = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        let builder = PacketBuilder::ipv6(client, server, 64).udp(40000, 53);
        let mut packet = Vec::new();
        builder
            .write(&mut packet, &dns_query("ads.example.", RecordType::A, 7))
            .expect("build");
        let decision = decide(&packet, &p);
        let sliced = SlicedPacket::from_ip(expect_reply(&decision)).expect("reply");
        match &sliced.net {
            Some(NetSlice::Ipv6(v6)) => {
                assert_eq!(v6.header().source_addr().octets(), server);
                assert_eq!(v6.header().destination_addr().octets(), client);
            }
            other => panic!("expected IPv6, got {other:?}"),
        }
    }

    fn tcp_query(dns: &[u8], seq: u32, ack: u32) -> Vec<u8> {
        let mut payload = u16::try_from(dns.len())
            .expect("len")
            .to_be_bytes()
            .to_vec();
        payload.extend_from_slice(dns);
        let builder = PacketBuilder::ipv4(CLIENT_V4, SERVER_V4, 128)
            .tcp(50001, 53, seq, 64240)
            .ack(ack)
            .psh();
        let mut out = Vec::new();
        builder.write(&mut out, &payload).expect("build");
        out
    }

    #[test]
    fn blocked_tcp_query_gets_rst() {
        let p = policy(DnsBlockingMode::NullIp);
        let dns = dns_query("ads.example.", RecordType::A, 9);
        let packet = tcp_query(&dns, 1000, 5000);
        let decision = decide(&packet, &p);
        let sliced = SlicedPacket::from_ip(expect_reply(&decision)).expect("reply");
        match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                assert!(tcp.rst());
                assert!(tcp.ack());
                assert_eq!(tcp.source_port(), 53);
                assert_eq!(tcp.destination_port(), 50001);
                assert_eq!(tcp.sequence_number(), 5000);
                assert_eq!(
                    tcp.acknowledgment_number(),
                    1000 + u32::try_from(dns.len() + 2).expect("len")
                );
            }
            other => panic!("expected TCP, got {other:?}"),
        }
    }

    #[test]
    fn partial_tcp_segment_passes() {
        let p = policy(DnsBlockingMode::NullIp);
        let dns = dns_query("ads.example.", RecordType::A, 9);
        let mut packet = tcp_query(&dns, 1, 1);
        packet.truncate(packet.len() - 3); // cut the query
        // Fix up the IPv4 total length so the packet still parses.
        let total = u16::try_from(packet.len()).expect("len").to_be_bytes();
        packet[2] = total[0];
        packet[3] = total[1];
        assert_eq!(decide(&packet, &p), Decision::pass());
    }

    #[test]
    fn garbage_and_non_dns_pass() {
        let p = policy(DnsBlockingMode::NullIp);
        assert_eq!(decide(&[0x45, 0, 0], &p), Decision::pass());
        assert_eq!(decide(&udp_v4(b"not dns"), &p), Decision::pass());
        // A DNS response (not a query) passes too.
        let mut msg = Message::response(1, OpCode::Query);
        msg.add_query(Query::query(
            Name::from_ascii("ads.example.").expect("n"),
            RecordType::A,
        ));
        assert_eq!(
            decide(&udp_v4(&msg.to_vec().expect("enc")), &p),
            Decision::pass()
        );
    }
}

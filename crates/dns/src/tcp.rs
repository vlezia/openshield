// SPDX-License-Identifier: GPL-3.0-or-later
//! Reassembly of DNS-over-TCP queries split across segments (ADR-011).
//!
//! A DNS client may send the 2-byte length prefix and the message in
//! separate segments (e.g. two `send()` calls with Nagle's algorithm). We
//! keep the bytes seen so far per flow until a whole query is available.
//! State is owned by the packet-loop thread (no locks) and bounded.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Flows with a partial query kept at most.
pub const MAX_FLOWS: usize = 256;
/// Largest query we reassemble; larger ones pass unfiltered.
pub const MAX_QUERY: usize = 4096;
/// A partial query older than this is dropped when space is needed.
const FLOW_TTL: Duration = Duration::from_secs(10);

/// Client → server direction of a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: IpAddr,
    pub sport: u16,
    pub dst: IpAddr,
    pub dport: u16,
}

#[derive(Debug)]
struct Partial {
    next_seq: u32,
    buf: Vec<u8>,
    last_seen: Instant,
}

/// Result of feeding one segment.
#[derive(Debug, PartialEq, Eq)]
pub enum Feed<'a> {
    /// More segments are needed; let this one pass.
    Incomplete,
    /// A whole DNS message (without the length prefix).
    Complete(Cow<'a, [u8]>),
    /// Not something we reassemble (too large, empty); let it pass.
    GiveUp,
}

/// Per-flow partial queries.
#[derive(Debug, Default)]
pub struct TcpReassembly {
    flows: HashMap<FlowKey, Partial>,
}

/// Length-prefixed message at the start of `buf`, if complete.
fn split_message(buf: &[u8]) -> Option<Result<&[u8], ()>> {
    if buf.len() < 2 {
        return None;
    }
    let declared = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
    if declared == 0 || declared > MAX_QUERY {
        return Some(Err(()));
    }
    buf.get(2..2 + declared).map(Ok)
}

impl TcpReassembly {
    /// Feeds a client → server segment with payload starting at `seq`.
    pub fn feed<'a>(&mut self, key: FlowKey, seq: u32, payload: &'a [u8]) -> Feed<'a> {
        let next_seq = seq.wrapping_add(u32::try_from(payload.len()).unwrap_or(u32::MAX));
        let buf = match self.flows.remove(&key) {
            Some(partial) if partial.next_seq == seq => {
                let mut buf = partial.buf;
                buf.extend_from_slice(payload);
                buf
            }
            // No state, or out of order / retransmission: start over here.
            _ => match split_message(payload) {
                Some(Ok(message)) => return Feed::Complete(Cow::Borrowed(message)),
                Some(Err(())) => return Feed::GiveUp,
                None => payload.to_vec(),
            },
        };
        match split_message(&buf) {
            Some(Ok(message)) => Feed::Complete(Cow::Owned(message.to_vec())),
            Some(Err(())) => Feed::GiveUp,
            None if buf.len() > MAX_QUERY + 2 => Feed::GiveUp,
            None => {
                self.store(key, next_seq, buf);
                Feed::Incomplete
            }
        }
    }

    fn store(&mut self, key: FlowKey, next_seq: u32, buf: Vec<u8>) {
        let now = Instant::now();
        if self.flows.len() >= MAX_FLOWS {
            self.flows
                .retain(|_, p| now.duration_since(p.last_seen) < FLOW_TTL);
            if self.flows.len() >= MAX_FLOWS {
                self.flows.clear();
            }
        }
        self.flows.insert(
            key,
            Partial {
                next_seq,
                buf,
                last_seen: now,
            },
        );
    }

    /// Flows with a partial query.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(sport: u16) -> FlowKey {
        FlowKey {
            src: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            sport,
            dst: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            dport: 53,
        }
    }

    fn framed(msg: &[u8]) -> Vec<u8> {
        let mut out = u16::try_from(msg.len())
            .expect("len")
            .to_be_bytes()
            .to_vec();
        out.extend_from_slice(msg);
        out
    }

    #[test]
    fn whole_message_needs_no_state() {
        let mut r = TcpReassembly::default();
        let data = framed(b"hello");
        assert_eq!(
            r.feed(key(1), 100, &data),
            Feed::Complete(Cow::Borrowed(b"hello"))
        );
        assert!(r.is_empty());
    }

    #[test]
    fn length_prefix_and_message_in_separate_segments() {
        let mut r = TcpReassembly::default();
        let data = framed(b"hello");
        assert_eq!(r.feed(key(1), 100, &data[..2]), Feed::Incomplete);
        assert_eq!(r.len(), 1);
        assert_eq!(
            r.feed(key(1), 102, &data[2..]),
            Feed::Complete(Cow::Owned(b"hello".to_vec()))
        );
        assert!(r.is_empty());
    }

    #[test]
    fn three_way_split_and_independent_flows() {
        let mut r = TcpReassembly::default();
        let data = framed(b"abcdef");
        assert_eq!(r.feed(key(1), 0, &data[..1]), Feed::Incomplete);
        assert_eq!(r.feed(key(2), 50, &data[..3]), Feed::Incomplete);
        assert_eq!(r.feed(key(1), 1, &data[1..4]), Feed::Incomplete);
        assert_eq!(
            r.feed(key(1), 4, &data[4..]),
            Feed::Complete(Cow::Owned(b"abcdef".to_vec()))
        );
        assert_eq!(r.len(), 1); // flow 2 still waiting
    }

    #[test]
    fn out_of_order_segment_restarts() {
        let mut r = TcpReassembly::default();
        let data = framed(b"hello");
        assert_eq!(r.feed(key(1), 100, &data[..2]), Feed::Incomplete);
        // Unexpected sequence number: treated as a new message start; its
        // first bytes ("he") read as an oversized length, so it just passes.
        assert_eq!(r.feed(key(1), 500, &data[2..4]), Feed::GiveUp);
        // Retransmission of the first part, then the rest.
        assert_eq!(r.feed(key(1), 100, &data[..2]), Feed::Incomplete);
        assert_eq!(
            r.feed(key(1), 102, &data[2..]),
            Feed::Complete(Cow::Owned(b"hello".to_vec()))
        );
    }

    #[test]
    fn oversized_and_empty_messages_give_up() {
        let mut r = TcpReassembly::default();
        let big = u16::try_from(MAX_QUERY + 1).expect("len").to_be_bytes();
        assert_eq!(r.feed(key(1), 0, &big), Feed::GiveUp);
        assert_eq!(r.feed(key(2), 0, &[0, 0]), Feed::GiveUp);
        assert!(r.is_empty());
    }

    #[test]
    fn state_is_bounded() {
        let mut r = TcpReassembly::default();
        for port in 0..(MAX_FLOWS as u16 + 10) {
            assert_eq!(r.feed(key(port), 0, &[0]), Feed::Incomplete);
        }
        assert!(r.len() <= MAX_FLOWS);
    }
}

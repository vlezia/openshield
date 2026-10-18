// SPDX-License-Identifier: GPL-3.0-or-later
//! In-memory [`Interceptor`] for testing packet loops without a driver.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::{InterceptError, Interceptor};

#[derive(Debug, Default)]
struct State {
    inbound: VecDeque<Vec<u8>>,
    next_id: u64,
    reinjected: Vec<Vec<u8>>,
    replies: Vec<(u64, Vec<u8>)>,
    shut_down: bool,
}

/// Metadata of a mock packet: its sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockMeta(pub u64);

/// Queue-backed interceptor. Push packets in, read decisions out.
#[derive(Debug, Default)]
pub struct MockInterceptor {
    state: Mutex<State>,
    changed: Condvar,
}

impl MockInterceptor {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queues a captured packet.
    pub fn push(&self, packet: Vec<u8>) {
        self.lock().inbound.push_back(packet);
        self.changed.notify_all();
    }

    /// Packets passed through unchanged.
    pub fn reinjected(&self) -> Vec<Vec<u8>> {
        self.lock().reinjected.clone()
    }

    /// Injected replies with the sequence number of the packet they answer.
    pub fn replies(&self) -> Vec<(u64, Vec<u8>)> {
        self.lock().replies.clone()
    }

    pub fn is_shut_down(&self) -> bool {
        self.lock().shut_down
    }

    /// Waits until `n` packets have been handled (reinjected or answered).
    pub fn wait_handled(&self, n: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock();
        while state.reinjected.len() + state.replies.len() < n {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            state = match self.changed.wait_timeout(state, left) {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        true
    }
}

impl Interceptor for MockInterceptor {
    type Meta = MockMeta;

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, MockMeta), InterceptError> {
        let mut state = self.lock();
        loop {
            if state.shut_down {
                return Err(InterceptError::Shutdown);
            }
            if let Some(packet) = state.inbound.pop_front() {
                let len = packet.len().min(buf.len());
                buf[..len].copy_from_slice(&packet[..len]);
                let id = state.next_id;
                state.next_id += 1;
                return Ok((len, MockMeta(id)));
            }
            state = match self.changed.wait(state) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn reinject(&self, packet: &[u8], _meta: &MockMeta) -> Result<(), InterceptError> {
        self.lock().reinjected.push(packet.to_vec());
        self.changed.notify_all();
        Ok(())
    }

    fn inject_reply(&self, packet: &[u8], original: &MockMeta) -> Result<(), InterceptError> {
        self.lock().replies.push((original.0, packet.to_vec()));
        self.changed.notify_all();
        Ok(())
    }

    fn shutdown(&self) -> Result<(), InterceptError> {
        self.lock().shut_down = true;
        self.changed.notify_all();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn recv_returns_queued_packets_then_shutdown() -> Result<(), InterceptError> {
        let mock = MockInterceptor::new();
        mock.push(vec![1, 2, 3]);
        let mut buf = [0u8; 16];
        let (len, meta) = mock.recv(&mut buf)?;
        assert_eq!(&buf[..len], &[1, 2, 3]);
        mock.reinject(&buf[..len], &meta)?;
        mock.inject_reply(&[9], &meta)?;
        assert_eq!(mock.reinjected(), vec![vec![1, 2, 3]]);
        assert_eq!(mock.replies(), vec![(0, vec![9])]);
        mock.shutdown()?;
        assert!(matches!(mock.recv(&mut buf), Err(InterceptError::Shutdown)));
        Ok(())
    }

    #[test]
    fn shutdown_unblocks_waiting_recv() {
        let mock = Arc::new(MockInterceptor::new());
        let waiter = Arc::clone(&mock);
        let thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4];
            waiter.recv(&mut buf).map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(mock.shutdown().is_ok());
        let result = thread.join().map_err(|_| "panicked");
        assert!(matches!(result, Ok(Err(InterceptError::Shutdown))));
    }
}

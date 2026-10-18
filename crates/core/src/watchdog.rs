// SPDX-License-Identifier: GPL-3.0-or-later
//! Hang detection for packet loops (ADR-004).
//!
//! The packet loop marks each packet with [`Heartbeat::begin`] /
//! [`Heartbeat::end`] (two atomic stores, no locks). A [`Watchdog`] thread
//! notices when a packet has been "in progress" longer than the stall timeout
//! and calls the stall handler once, which releases capture (fail open).
//! An idle loop blocked waiting for packets is not a stall.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Progress marker shared between a packet loop and its watchdog.
#[derive(Debug)]
pub struct Heartbeat {
    origin: Instant,
    /// Milliseconds since `origin` + 1 when a packet started; 0 when idle.
    busy_since: AtomicU64,
}

impl Default for Heartbeat {
    fn default() -> Self {
        Self {
            origin: Instant::now(),
            busy_since: AtomicU64::new(0),
        }
    }
}

impl Heartbeat {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1)
    }

    /// A packet has been received and is being processed.
    pub fn begin(&self) {
        self.busy_since.store(self.now_ms() + 1, Ordering::Release);
    }

    /// The current packet has been handled.
    pub fn end(&self) {
        self.busy_since.store(0, Ordering::Release);
    }

    /// How long the current packet has been in progress, if any.
    pub fn busy_for(&self) -> Option<Duration> {
        match self.busy_since.load(Ordering::Acquire) {
            0 => None,
            since => Some(Duration::from_millis(
                self.now_ms().saturating_sub(since - 1),
            )),
        }
    }
}

/// Background thread that calls a handler once if the heartbeat stalls.
#[derive(Debug)]
pub struct Watchdog {
    stop: Arc<(Mutex<bool>, Condvar)>,
    thread: Option<JoinHandle<()>>,
}

impl Watchdog {
    /// Starts watching. `on_stall` runs at most once, on the watchdog thread,
    /// with the stall duration; the watchdog exits afterwards.
    pub fn spawn<F>(
        heartbeat: Arc<Heartbeat>,
        timeout: Duration,
        on_stall: F,
    ) -> std::io::Result<Self>
    where
        F: FnOnce(Duration) + Send + 'static,
    {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_thread = Arc::clone(&stop);
        let tick = (timeout / 4).max(Duration::from_millis(10));
        let thread = std::thread::Builder::new()
            .name("openshield-watchdog".to_owned())
            .spawn(move || {
                let (lock, cvar) = &*stop_thread;
                let Ok(mut stopped) = lock.lock() else {
                    return;
                };
                loop {
                    if *stopped {
                        return;
                    }
                    if let Some(busy) = heartbeat.busy_for()
                        && busy >= timeout
                    {
                        drop(stopped);
                        on_stall(busy);
                        return;
                    }
                    stopped = match cvar.wait_timeout(stopped, tick) {
                        Ok((guard, _)) => guard,
                        Err(_) => return,
                    };
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Stops the watchdog and waits for its thread.
    pub fn stop(mut self) {
        self.signal_stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    fn signal_stop(&self) {
        let (lock, cvar) = &*self.stop;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
            cvar.notify_all();
        }
    }
}

impl Drop for Watchdog {
    fn drop(&mut self) {
        self.signal_stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn stall_triggers_handler_once() -> std::io::Result<()> {
        let hb = Heartbeat::new();
        let (tx, rx) = mpsc::channel();
        let dog = Watchdog::spawn(Arc::clone(&hb), Duration::from_millis(100), move |busy| {
            let _ = tx.send(busy);
        })?;
        hb.begin(); // never ends: simulated hang
        let busy = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(std::io::Error::other)?;
        assert!(busy >= Duration::from_millis(100));
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
        dog.stop();
        Ok(())
    }

    #[test]
    fn idle_and_fast_packets_do_not_trigger() -> std::io::Result<()> {
        let hb = Heartbeat::new();
        let (tx, rx) = mpsc::channel::<Duration>();
        let dog = Watchdog::spawn(Arc::clone(&hb), Duration::from_millis(100), move |busy| {
            let _ = tx.send(busy);
        })?;
        for _ in 0..20 {
            hb.begin();
            hb.end();
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(rx.recv_timeout(Duration::from_millis(200)).is_err());
        dog.stop();
        Ok(())
    }

    #[test]
    fn busy_for_reports_progress_state() {
        let hb = Heartbeat::new();
        assert_eq!(hb.busy_for(), None);
        hb.begin();
        assert!(hb.busy_for().is_some());
        hb.end();
        assert_eq!(hb.busy_for(), None);
    }
}

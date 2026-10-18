// SPDX-License-Identifier: GPL-3.0-or-later
//! Traffic interception abstraction.
//!
//! The rest of OpenShield talks to the network stack only through
//! [`Interceptor`], so Linux and macOS backends can be added later without
//! touching the filtering code. The WinDivert backend arrives in stage 1.
//!
//! Every implementation must fail open: when an interceptor stops, errors out
//! or its process dies, traffic must keep flowing unfiltered.

use std::error::Error;
use std::fmt;

/// What an interceptor captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterceptKind {
    /// Outgoing DNS queries (UDP/TCP 53) of all processes.
    Dns,
    /// TCP 80/443 of selected processes, redirected to the local proxy.
    Https,
}

/// Errors reported by an [`Interceptor`].
#[derive(Debug)]
pub enum InterceptError {
    /// The backend is not available on this platform or build.
    Unsupported,
    /// The packet capture driver reported an error.
    Driver(String),
}

impl fmt::Display for InterceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("interception is not supported on this platform"),
            Self::Driver(msg) => write!(f, "packet capture driver error: {msg}"),
        }
    }
}

impl Error for InterceptError {}

/// A source of intercepted traffic.
///
/// The interface is provisional and will be refined when the WinDivert backend
/// is implemented in stage 1.
pub trait Interceptor: Send {
    /// What this interceptor captures.
    fn kind(&self) -> InterceptKind;

    /// Starts capturing. On error nothing may stay captured.
    fn start(&mut self) -> Result<(), InterceptError>;

    /// Stops capturing and releases the driver handle. Must be idempotent.
    fn stop(&mut self) -> Result<(), InterceptError>;

    /// Whether capture is currently active.
    fn is_running(&self) -> bool;
}

/// Interceptor that captures nothing. Used on unsupported platforms and in tests.
#[derive(Debug)]
pub struct NoopInterceptor {
    kind: InterceptKind,
    running: bool,
}

impl NoopInterceptor {
    /// Creates a stopped no-op interceptor of the given kind.
    pub fn new(kind: InterceptKind) -> Self {
        Self {
            kind,
            running: false,
        }
    }
}

impl Interceptor for NoopInterceptor {
    fn kind(&self) -> InterceptKind {
        self.kind
    }

    fn start(&mut self) -> Result<(), InterceptError> {
        self.running = true;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), InterceptError> {
        self.running = false;
        Ok(())
    }

    fn is_running(&self) -> bool {
        self.running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_start_stop_is_idempotent() -> Result<(), InterceptError> {
        let mut i = NoopInterceptor::new(InterceptKind::Dns);
        assert!(!i.is_running());
        i.start()?;
        assert!(i.is_running());
        i.stop()?;
        i.stop()?;
        assert!(!i.is_running());
        assert_eq!(i.kind(), InterceptKind::Dns);
        Ok(())
    }

    #[test]
    fn interceptor_is_object_safe() {
        let boxed: Box<dyn Interceptor> = Box::new(NoopInterceptor::new(InterceptKind::Https));
        assert_eq!(boxed.kind(), InterceptKind::Https);
    }
}

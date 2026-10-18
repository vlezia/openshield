// SPDX-License-Identifier: GPL-3.0-or-later
//! Traffic interception abstraction.
//!
//! Packet loops talk to the network stack only through [`Interceptor`], so
//! Linux and macOS backends can be added later without touching filtering
//! code. The Windows backend is [`windivert::WinDivert`].
//!
//! Every implementation must fail open: after [`Interceptor::shutdown`], an
//! error, or the death of the process, traffic keeps flowing unfiltered.

#[cfg(any(test, feature = "mock"))]
pub mod mock;
#[cfg(windows)]
pub mod windivert;

/// Errors reported by an [`Interceptor`].
#[derive(Debug, thiserror::Error)]
pub enum InterceptError {
    /// [`Interceptor::shutdown`] was called; the loop should exit.
    #[error("capture was shut down")]
    Shutdown,
    /// No backend for this platform.
    #[error("interception is not supported on this platform")]
    Unsupported,
    /// The capture library could not be loaded.
    #[error("cannot load {path}: {message}")]
    Load { path: String, message: String },
    /// An OS or driver call failed.
    #[error("{op} failed: {message} (os error {code})")]
    Os {
        op: &'static str,
        code: i32,
        message: String,
    },
}

/// A source of intercepted packets.
///
/// Methods take `&self` so one thread can block in [`recv`](Self::recv)
/// while another (the watchdog) calls [`shutdown`](Self::shutdown).
pub trait Interceptor: Send + Sync {
    /// Per-packet metadata needed to reinject or answer a packet.
    type Meta: Send;

    /// Blocks until a packet is captured; returns its length in `buf`.
    /// Returns [`InterceptError::Shutdown`] once the capture is shut down.
    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Self::Meta), InterceptError>;

    /// Lets a captured packet continue unchanged.
    fn reinject(&self, packet: &[u8], meta: &Self::Meta) -> Result<(), InterceptError>;

    /// Sends `packet` in the opposite direction of `original`, e.g. a forged
    /// DNS answer to the application that sent the query. Checksums are
    /// recomputed by the backend.
    fn inject_reply(&self, packet: &[u8], original: &Self::Meta) -> Result<(), InterceptError>;

    /// Stops capturing new packets; traffic flows unfiltered from now on.
    /// Safe to call from any thread, more than once.
    fn shutdown(&self) -> Result<(), InterceptError>;
}

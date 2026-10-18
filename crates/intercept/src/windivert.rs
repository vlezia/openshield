// SPDX-License-Identifier: GPL-3.0-or-later
//! WinDivert 2.x backend, loaded at runtime (ADR-009).
//!
//! `WinDivert.dll` is loaded from an explicit directory by absolute path
//! (never through the DLL search path), and `WinDivert64.sys` must sit next
//! to it. Nothing of WinDivert is linked into our binaries.
//!
//! When the handle is shut down or closed, or our process dies, the driver
//! stops diverting packets for it: traffic flows unfiltered (fail open).

// FFI to the official WinDivert DLL. Each unsafe block states its invariant.
#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_void};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use libloading::os::windows::{
    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, Library,
};

use crate::{InterceptError, Interceptor};

/// Largest packet WinDivert can return (40-byte IPv6 header + 0xFFFF).
pub const MTU_MAX: usize = 40 + 0xFFFF;

/// Supported WinDivert major version.
pub const SUPPORTED_MAJOR: u64 = 2;

/// `WINDIVERT_LAYER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Layer {
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4,
}

const SHUTDOWN_BOTH: i32 = 3;
const PARAM_VERSION_MAJOR: i32 = 3;
const PARAM_VERSION_MINOR: i32 = 4;
const INVALID_HANDLE: isize = -1;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_INVALID_PARAMETER: i32 = 87;
const ERROR_NO_DATA: i32 = 232;
const ERROR_INVALID_IMAGE_HASH: i32 = 577;
const ERROR_DRIVER_FAILED_PRIOR_UNLOAD: i32 = 654;
const ERROR_DRIVER_BLOCKED: i32 = 1275;
const EPT_S_NOT_REGISTERED: i32 = 1753;

/// `WINDIVERT_ADDRESS` (80 bytes). Bitfields are packed into `flags` in
/// MSVC order: Layer:8, Event:8, Sniffed, Outbound, Loopback, Impostor,
/// IPv6, IPChecksum, TCPChecksum, UDPChecksum, Reserved1:8.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    timestamp: i64,
    flags: u32,
    reserved2: u32,
    /// Union of layer-specific data; for the network layer the first 8 bytes
    /// are the interface and sub-interface indexes.
    data: [u8; 64],
}

const _: () = assert!(std::mem::size_of::<Address>() == 80);

const FLAG_OUTBOUND: u32 = 1 << 17;
const FLAG_LOOPBACK: u32 = 1 << 18;
const FLAG_IMPOSTOR: u32 = 1 << 19;
const FLAG_IPV6: u32 = 1 << 20;

impl Address {
    fn zeroed() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            data: [0; 64],
        }
    }

    pub fn is_outbound(&self) -> bool {
        self.flags & FLAG_OUTBOUND != 0
    }

    pub fn is_loopback(&self) -> bool {
        self.flags & FLAG_LOOPBACK != 0
    }

    pub fn is_impostor(&self) -> bool {
        self.flags & FLAG_IMPOSTOR != 0
    }

    pub fn is_ipv6(&self) -> bool {
        self.flags & FLAG_IPV6 != 0
    }

    fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.flags |= FLAG_OUTBOUND;
        } else {
            self.flags &= !FLAG_OUTBOUND;
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Address")
            .field("outbound", &self.is_outbound())
            .field("loopback", &self.is_loopback())
            .field("impostor", &self.is_impostor())
            .field("ipv6", &self.is_ipv6())
            .finish_non_exhaustive()
    }
}

type OpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> isize;
type RecvFn = unsafe extern "C" fn(isize, *mut c_void, u32, *mut u32, *mut Address) -> i32;
type SendFn = unsafe extern "C" fn(isize, *const c_void, u32, *mut u32, *const Address) -> i32;
type ShutdownFn = unsafe extern "C" fn(isize, i32) -> i32;
type CloseFn = unsafe extern "C" fn(isize) -> i32;
type GetParamFn = unsafe extern "C" fn(isize, i32, *mut u64) -> i32;
type CalcChecksumsFn = unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32;

/// The loaded `WinDivert.dll`.
#[derive(Debug)]
pub struct WinDivertLib {
    path: PathBuf,
    open: OpenFn,
    recv: RecvFn,
    send: SendFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    get_param: GetParamFn,
    calc_checksums: CalcChecksumsFn,
    // Keeps the DLL mapped while the function pointers above are in use.
    _library: Library,
}

fn last_os_error(op: &'static str) -> InterceptError {
    let err = std::io::Error::last_os_error();
    let code = err.raw_os_error().unwrap_or(0);
    let hint = match code {
        ERROR_ACCESS_DENIED => "administrator rights are required to start packet capture",
        ERROR_FILE_NOT_FOUND => "WinDivert64.sys was not found next to WinDivert.dll",
        ERROR_INVALID_PARAMETER => "invalid filter or parameter",
        ERROR_INVALID_IMAGE_HASH => {
            "Windows rejected the WinDivert driver signature (check Memory integrity / Secure Boot policy)"
        }
        ERROR_DRIVER_FAILED_PRIOR_UNLOAD => {
            "another WinDivert version is loaded; stop the program using it or reboot"
        }
        ERROR_DRIVER_BLOCKED => "the WinDivert driver is blocked by security software or policy",
        EPT_S_NOT_REGISTERED => "the Base Filtering Engine service is not running",
        _ => "",
    };
    let message = if hint.is_empty() {
        err.to_string()
    } else {
        format!("{hint} ({err})")
    };
    InterceptError::Os { op, code, message }
}

impl WinDivertLib {
    /// Loads `WinDivert.dll` from `dir`.
    pub fn load(dir: &Path) -> Result<Arc<Self>, InterceptError> {
        let dll = dir.join("WinDivert.dll");
        let load_err = |message: String| InterceptError::Load {
            path: dll.display().to_string(),
            message,
        };
        let dll = std::path::absolute(&dll).map_err(|e| load_err(e.to_string()))?;
        if !dll.is_file() {
            return Err(load_err(
                "file not found (run scripts\\dev-setup.ps1)".to_owned(),
            ));
        }
        if !dir.join("WinDivert64.sys").is_file() {
            return Err(load_err(
                "WinDivert64.sys is missing next to the DLL".to_owned(),
            ));
        }
        // SAFETY: loading a DLL runs its DllMain. We load the official
        // WinDivert DLL by absolute path; its dependencies may only come from
        // its own directory or System32.
        let library = unsafe {
            Library::load_with_flags(
                &dll,
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        }
        .map_err(|e| load_err(e.to_string()))?;

        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                // SAFETY: the symbol type matches the WinDivert 2.x C
                // declaration in windivert.h.
                let sym = unsafe { library.get::<$ty>($name) }
                    .map_err(|e| load_err(format!("{}: {e}", stringify!($name))))?;
                *sym
            }};
        }
        let lib = Self {
            open: symbol!(b"WinDivertOpen\0", OpenFn),
            recv: symbol!(b"WinDivertRecv\0", RecvFn),
            send: symbol!(b"WinDivertSend\0", SendFn),
            shutdown: symbol!(b"WinDivertShutdown\0", ShutdownFn),
            close: symbol!(b"WinDivertClose\0", CloseFn),
            get_param: symbol!(b"WinDivertGetParam\0", GetParamFn),
            calc_checksums: symbol!(b"WinDivertHelperCalcChecksums\0", CalcChecksumsFn),
            path: dll,
            _library: library,
        };
        Ok(Arc::new(lib))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// An open WinDivert handle.
#[derive(Debug)]
pub struct WinDivert {
    lib: Arc<WinDivertLib>,
    handle: isize,
}

impl WinDivert {
    /// Opens a handle. Requires administrator rights; installs and starts
    /// the WinDivert driver service on first use.
    pub fn open(
        lib: Arc<WinDivertLib>,
        filter: &str,
        layer: Layer,
        priority: i16,
        flags: u64,
    ) -> Result<Self, InterceptError> {
        let filter = CString::new(filter).map_err(|_| InterceptError::Os {
            op: "WinDivertOpen",
            code: ERROR_INVALID_PARAMETER,
            message: "filter contains a NUL byte".to_owned(),
        })?;
        // SAFETY: `filter` is a valid NUL-terminated string that outlives the
        // call; the other arguments are plain values.
        let handle = unsafe { (lib.open)(filter.as_ptr(), layer as i32, priority, flags) };
        if handle == INVALID_HANDLE {
            return Err(last_os_error("WinDivertOpen"));
        }
        let divert = Self { lib, handle };
        let (major, minor) = divert.version()?;
        if major != SUPPORTED_MAJOR {
            return Err(InterceptError::Os {
                op: "WinDivertOpen",
                code: 0,
                message: format!("unsupported WinDivert driver {major}.{minor}"),
            });
        }
        Ok(divert)
    }

    fn get_param(&self, param: i32) -> Result<u64, InterceptError> {
        let mut value = 0u64;
        // SAFETY: `handle` is open (closed only in Drop); `value` is a valid
        // out-pointer for the duration of the call.
        let ok = unsafe { (self.lib.get_param)(self.handle, param, &mut value) };
        if ok == 0 {
            return Err(last_os_error("WinDivertGetParam"));
        }
        Ok(value)
    }

    /// Driver version `(major, minor)`.
    pub fn version(&self) -> Result<(u64, u64), InterceptError> {
        Ok((
            self.get_param(PARAM_VERSION_MAJOR)?,
            self.get_param(PARAM_VERSION_MINOR)?,
        ))
    }

    fn send_raw(&self, packet: &[u8], addr: &Address) -> Result<(), InterceptError> {
        let len = u32::try_from(packet.len()).map_err(|_| InterceptError::Os {
            op: "WinDivertSend",
            code: ERROR_INVALID_PARAMETER,
            message: "packet too large".to_owned(),
        })?;
        // SAFETY: `packet` and `addr` are valid for reads of `len` bytes and
        // one address for the duration of the call; the send-length
        // out-pointer is optional (null).
        let ok = unsafe {
            (self.lib.send)(
                self.handle,
                packet.as_ptr().cast(),
                len,
                std::ptr::null_mut(),
                addr,
            )
        };
        if ok == 0 {
            return Err(last_os_error("WinDivertSend"));
        }
        Ok(())
    }
}

impl Interceptor for WinDivert {
    type Meta = Address;

    fn recv(&self, buf: &mut [u8]) -> Result<(usize, Address), InterceptError> {
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let mut len = 0u32;
        let mut addr = Address::zeroed();
        // SAFETY: `buf` is valid for writes of `cap` bytes, `len` and `addr`
        // are valid out-pointers; the driver writes at most `cap` bytes.
        let ok = unsafe {
            (self.lib.recv)(
                self.handle,
                buf.as_mut_ptr().cast(),
                cap,
                &mut len,
                &mut addr,
            )
        };
        if ok == 0 {
            let err = last_os_error("WinDivertRecv");
            if let InterceptError::Os {
                code: ERROR_NO_DATA,
                ..
            } = err
            {
                return Err(InterceptError::Shutdown);
            }
            return Err(err);
        }
        Ok((len as usize, addr))
    }

    fn reinject(&self, packet: &[u8], meta: &Address) -> Result<(), InterceptError> {
        self.send_raw(packet, meta)
    }

    fn inject_reply(&self, packet: &[u8], original: &Address) -> Result<(), InterceptError> {
        let mut addr = *original;
        addr.set_outbound(!original.is_outbound());
        let mut copy = packet.to_vec();
        let len = u32::try_from(copy.len()).unwrap_or(u32::MAX);
        // SAFETY: `copy` is valid for reads and writes of `len` bytes and
        // `addr` is a valid address; the helper fixes checksums in place and
        // updates the checksum flags in `addr`.
        unsafe {
            (self.lib.calc_checksums)(copy.as_mut_ptr().cast(), len, &mut addr, 0);
        }
        self.send_raw(&copy, &addr)
    }

    fn shutdown(&self) -> Result<(), InterceptError> {
        // SAFETY: `handle` stays valid until Drop; WinDivertShutdown may be
        // called concurrently with a blocked WinDivertRecv on another thread.
        let ok = unsafe { (self.lib.shutdown)(self.handle, SHUTDOWN_BOTH) };
        if ok == 0 {
            return Err(last_os_error("WinDivertShutdown"));
        }
        Ok(())
    }
}

impl Drop for WinDivert {
    fn drop(&mut self) {
        // SAFETY: `handle` was returned by WinDivertOpen and is closed exactly
        // once; `&mut self` guarantees no concurrent use.
        unsafe {
            (self.lib.close)(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_flags_follow_msvc_bitfield_layout() {
        let mut addr = Address::zeroed();
        assert!(!addr.is_outbound());
        addr.set_outbound(true);
        assert_eq!(addr.flags, 1 << 17);
        addr.flags |= 1 << 20;
        assert!(addr.is_ipv6());
        addr.set_outbound(false);
        assert!(!addr.is_outbound());
        assert!(addr.is_ipv6());
    }

    #[test]
    fn missing_dll_is_a_load_error() {
        let err = WinDivertLib::load(Path::new("no-such-dir"));
        assert!(matches!(err, Err(InterceptError::Load { .. })));
    }
}

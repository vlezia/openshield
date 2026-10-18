// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows helpers for the service: DNS cache flush and system DoH detection.

use windows_registry::LOCAL_MACHINE;

const DNSCACHE: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache";
const DOH_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";

/// Flushes the Windows DNS resolver cache so answers cached before filtering
/// was toggled do not linger. Failures are logged, not fatal.
#[allow(unsafe_code)]
pub fn flush_dns_cache() {
    use libloading::os::windows::{LOAD_LIBRARY_SEARCH_SYSTEM32, Library};
    type FlushFn = unsafe extern "system" fn() -> i32;

    // SAFETY: dnsapi.dll is a system library loaded only from System32;
    // DnsFlushResolverCache takes no arguments and returns a BOOL.
    let result = unsafe {
        Library::load_with_flags("dnsapi.dll", LOAD_LIBRARY_SEARCH_SYSTEM32).and_then(|lib| {
            let flush = *lib.get::<FlushFn>(b"DnsFlushResolverCache\0")?;
            Ok(flush())
        })
    };
    match result {
        Ok(0) => tracing::warn!("DnsFlushResolverCache reported failure"),
        Ok(_) => tracing::debug!("DNS resolver cache flushed"),
        Err(e) => tracing::warn!("cannot flush DNS cache: {e}"),
    }
}

/// Best-effort detection of Windows' built-in DNS-over-HTTPS (ADR-002).
/// Returns human-readable reasons; empty means "no sign of system DoH".
/// There is no official API for this, so false negatives are possible.
pub fn system_doh_indicators() -> Vec<String> {
    let mut reasons = Vec::new();

    if let Ok(key) = LOCAL_MACHINE.open(DOH_POLICY_KEY)
        && let Ok(policy) = key.get_u32("DoHPolicy")
    {
        match policy {
            2 => reasons.push("Group Policy allows DNS over HTTPS (DoHPolicy=2)".to_owned()),
            3 => reasons.push("Group Policy requires DNS over HTTPS (DoHPolicy=3)".to_owned()),
            _ => {}
        }
    }

    if let Ok(key) = LOCAL_MACHINE.open(format!(r"{DNSCACHE}\Parameters")) {
        if key.get_u32("EnableAutoDoh").is_ok_and(|v| v == 2) {
            reasons.push("automatic DoH is enabled (EnableAutoDoh=2)".to_owned());
        }
        if let Ok(servers) = key.open("DohWellKnownServers")
            && let Ok(names) = servers.keys()
        {
            for ip in names {
                let flags = servers.open(&ip).and_then(|k| k.get_u64("DohFlags"));
                if flags.is_ok_and(|f| f != 0) {
                    reasons.push(format!("DoH auto-upgrade is set for DNS server {ip}"));
                }
            }
        }
    }

    if let Ok(interfaces) = LOCAL_MACHINE.open(format!(r"{DNSCACHE}\InterfaceSpecificParameters"))
        && let Ok(guids) = interfaces.keys()
    {
        for guid in guids {
            for family in ["Doh", "Doh6"] {
                let path = format!(r"{guid}\DohInterfaceSettings\{family}");
                let Ok(settings) = interfaces.open(&path) else {
                    continue;
                };
                let Ok(servers) = settings.keys() else {
                    continue;
                };
                for ip in servers {
                    // DohFlags 0 would mean "unencrypted only"; a missing
                    // value is treated as a possible DoH configuration.
                    let flags = settings.open(&ip).and_then(|k| k.get_u64("DohFlags"));
                    if flags.is_err() || flags.is_ok_and(|f| f != 0) {
                        reasons.push(format!("network interface {guid} may use DoH for {ip}"));
                    }
                }
            }
        }
    }
    reasons
}

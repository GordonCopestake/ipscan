//! Reverse DNS.
//!
//! `ToSocketAddrs` looks *forward*, and given a bare address it just parses it,
//! so it cannot answer this. Each platform therefore gets the call it actually
//! has: `getnameinfo` on Unix, `GetAddrInfoW` on Windows.
//!
//! Every lookup here is a blocking call to a resolver that may be slow or
//! absent, so callers must run them somewhere they cannot stall the scan.

use std::net::Ipv4Addr;

#[cfg(unix)]
mod imp {
    use std::ffi::{CStr, c_char};
    use std::net::Ipv4Addr;

    /// Reverse-resolve `ip`, returning `None` if there is no PTR record.
    pub fn lookup(ip: Ipv4Addr) -> Option<String> {
        let sa = sockaddr_in(ip);
        // NI_NAMEREQD makes this fail rather than fall back to echoing the
        // numeric address back, which would be useless in the output.
        let mut host = [0 as c_char; NI_MAXHOST as usize];
        let rc = unsafe {
            getnameinfo(
                &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of_sockaddr(),
                host.as_mut_ptr(),
                host.len() as u32,
                std::ptr::null_mut(),
                0,
                NI_NAMEREQD,
            )
        };
        if rc != 0 {
            return None;
        }
        let name = unsafe { CStr::from_ptr(host.as_ptr()) };
        Some(name.to_string_lossy().into_owned())
    }

    /// A `sockaddr_in` for the address to look up.
    ///
    /// Zeroed rather than built with a literal, because BSD and macOS carry an
    /// extra `sin_len` field that Linux does not have.
    fn sockaddr_in(ip: Ipv4Addr) -> libc::sockaddr_in {
        let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr = libc::in_addr {
            s_addr: u32::from_ne_bytes(ip.octets()),
        };
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        {
            sa.sin_len = size_of_sockaddr() as u8;
        }
        sa
    }

    fn size_of_sockaddr() -> u32 {
        std::mem::size_of::<libc::sockaddr_in>() as u32
    }

    const NI_MAXHOST: libc::c_int = 1025;
    const NI_NAMEREQD: libc::c_int = 8;

    unsafe extern "C" {
        fn getnameinfo(
            sa: *const libc::sockaddr,
            salen: u32,
            host: *mut c_char,
            hostlen: u32,
            serv: *mut c_char,
            servlen: u32,
            flags: libc::c_int,
        ) -> libc::c_int;
    }
}

#[cfg(windows)]
mod imp {
    use std::net::Ipv4Addr;

    use windows::Win32::Networking::WinSock::{
        ADDRINFOW, AF_INET, AI_CANONNAME, GetAddrInfoW, WSACleanup, WSADATA, WSAStartup,
    };

    /// Reverse-resolve `ip`, returning `None` if there is no PTR record.
    pub fn lookup(ip: Ipv4Addr) -> Option<String> {
        // Winsock has to be started before any of its calls, including the ones
        // used purely for name resolution.
        let _guard = WinsockGuard::start()?;

        let node: Vec<u16> = ip.to_string().encode_utf16().chain([0]).collect();
        // A numeric node with AI_CANONNAME is how Winsock is asked for the PTR
        // record rather than for another forward lookup.
        let hints = ADDRINFOW {
            ai_flags: AI_CANONNAME as i32,
            ai_family: AF_INET.0 as i32,
            ..Default::default()
        };
        let mut result: *mut ADDRINFOW = std::ptr::null_mut();
        let rc = unsafe {
            GetAddrInfoW(
                windows::core::PCWSTR::from_raw(node.as_ptr()),
                windows::core::PCWSTR::null(),
                Some(&raw const hints),
                &raw mut result,
            )
        };
        if rc != 0 || result.is_null() {
            return None;
        }

        let found = (|| {
            let canon = unsafe { (*result).ai_canonname };
            if canon.is_null() {
                return None;
            }
            let name = unsafe { canon.to_string().ok()? };
            // Without a PTR record Winsock echoes the address back, which would
            // just be noise in a column of its own.
            if name.is_empty() || name == ip.to_string() {
                return None;
            }
            Some(name)
        })();

        // The block chain is only released once the name has been copied out.
        unsafe {
            free_addr_info(result);
        }
        found
    }

    // `FreeAddrInfo` is not in the `windows` bindings, which only carry the `Ex`
    // variants, so it is declared here. `ws2_32.dll` is the same library every
    // other Winsock call here comes from.
    #[link(name = "ws2_32")]
    unsafe extern "system" {
        #[link_name = "FreeAddrInfo"]
        fn free_addr_info(addr_info: *mut ADDRINFOW) -> i32;
    }

    /// Starts Winsock for the lifetime of the guard and undoes it on drop.
    struct WinsockGuard;

    impl WinsockGuard {
        fn start() -> Option<Self> {
            // MAKEWORD(2, 2): ask for Winsock 2.2, which every supported Windows
            // release provides.
            let mut data = WSADATA::default();
            if unsafe { WSAStartup(0x0202, &mut data) } != 0 {
                return None;
            }
            Some(WinsockGuard)
        }
    }

    impl Drop for WinsockGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = WSACleanup();
            }
        }
    }
}

/// Reverse-resolve `ip`, or `None` when there is no PTR record for it.
pub fn lookup(ip: Ipv4Addr) -> Option<String> {
    imp::lookup(ip)
}

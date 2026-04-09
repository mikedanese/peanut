//! Network setup helpers.

use crate::error::{Errno, Result};
use crate::fd::OwnedFd;

/// Bring up the loopback interface in the current network namespace.
pub fn bring_up_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Errno::last());
    }

    let sock = OwnedFd::new(sock);
    bring_up_loopback_with_socket(sock.as_raw())
}

fn bring_up_loopback_with_socket(sock: libc::c_int) -> Result<()> {
    let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
    let name = b"lo\0";

    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.iter().copied()) {
        *dst = src as libc::c_char;
    }

    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;

    let ret = unsafe { libc::ioctl(sock, libc::SIOCSIFFLAGS as libc::c_ulong, &ifr) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

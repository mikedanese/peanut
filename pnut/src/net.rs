//! Network loopback interface bring-up for the sandbox.
//!
//! When a new network namespace is created, all interfaces start in the
//! DOWN state. This module brings up the `lo` (loopback) interface so
//! that processes can communicate via 127.0.0.1.
//!
//! Called at step 11 in the ARCHITECTURE.md child setup sequence:
//! after hostname (step 10), before rlimits (step 12).

use crate::error::{Error, Stage};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use std::os::unix::io::AsRawFd;

/// Bring up the loopback (lo) interface in the current network namespace.
///
/// Creates a temporary UDP socket, constructs an `ifreq` struct for "lo",
/// and uses `ioctl(SIOCSIFFLAGS)` to set `IFF_UP | IFF_RUNNING`.
/// The socket is closed when the function returns (RAII via OwnedFd).
pub fn bring_up_loopback() -> Result<(), Error> {
    // Create a UDP socket for ioctl — any socket type works, UDP is cheapest.
    let _sock_fd = socket(
        AddressFamily::Inet,
        SockType::Datagram,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| Error::Setup {
        stage: Stage::Network,
        context: "failed to create socket for loopback setup".into(),
        source: e.into(),
    })?;

    // Build ifreq for "lo" with IFF_UP | IFF_RUNNING.
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Copy interface name "lo\0" into ifr_name.
    let name = b"lo\0";
    ifr.ifr_name[..name.len()].copy_from_slice(
        // Safety: i8 and u8 have the same layout on Linux.
        unsafe { &*(name.as_slice() as *const [u8] as *const [i8]) },
    );

    // Set IFF_UP | IFF_RUNNING flags.
    ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;

    // Apply the flags via ioctl.
    let ret = unsafe {
        libc::ioctl(
            _sock_fd.as_raw_fd(),
            libc::SIOCSIFFLAGS as libc::c_ulong,
            &ifr,
        )
    };
    if ret < 0 {
        return Err(Error::Setup {
            stage: Stage::Network,
            context: "ioctl(SIOCSIFFLAGS) failed to bring up loopback interface".into(),
            source: std::io::Error::last_os_error(),
        });
    }

    Ok(())
}

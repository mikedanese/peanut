//! Parent-side supervision (post-fork, monitors child).
//!
//! This code runs in the parent process after `clone3`. It manages:
//! - UID/GID map writes
//! - Signal forwarding via signalfd + pidfd
//! - Child exit status collection

use crate::error::{Error, Stage};
use crate::idmap;
use crate::idmap::Map as IdMap;
use crate::namespace;

use super::Sandbox;
use super::child;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use std::os::fd::AsFd;
use std::os::unix::io::OwnedFd;

/// Signals forwarded to the sandboxed child (or that trigger SIGKILL when
/// `forward_signals` is false).
const FORWARDED_SIGNALS: &[Signal] = &[
    Signal::SIGTERM,
    Signal::SIGINT,
    Signal::SIGHUP,
    Signal::SIGQUIT,
    Signal::SIGUSR1,
    Signal::SIGUSR2,
];

/// Build the signal mask used by both `run_once_mode` (to block before clone3)
/// and `wait_for_child` (to create the signalfd).
fn supervision_signal_mask() -> SigSet {
    let mut mask = SigSet::empty();
    for &sig in FORWARDED_SIGNALS {
        mask.add(sig);
    }
    mask.add(Signal::SIGCHLD);
    mask
}

/// STANDALONE_ONCE mode: clone3 a child, supervise it, propagate exit status.
pub(super) fn run_once_mode(sandbox: &Sandbox) -> Result<i32, Error> {
    let uid_map = sandbox
        .uid_map
        .as_ref()
        .ok_or_else(|| Error::Other("uid_map is required when user namespace is enabled".into()))?;
    let gid_map = sandbox
        .gid_map
        .as_ref()
        .ok_or_else(|| Error::Other("gid_map is required when user namespace is enabled".into()))?;

    // Create sync pipe: parent writes after UID/GID maps are set, child reads to proceed.
    let (sync_read_fd, sync_write_fd) = pipe_pair()?;

    // Block forwarded signals + SIGCHLD before clone3 so that no signals
    // are lost between clone3 and the signalfd loop.
    let mask = supervision_signal_mask();
    mask.thread_block()
        .map_err(|e| Error::Other(format!("failed to block signals: {e}")))?;

    let flags = namespace::clone_flags(&sandbox.namespaces);
    let child = namespace::do_clone3(flags)?;

    let child = match child {
        None => {
            // === CHILD PROCESS ===
            // Unblock signals inherited from parent's signalfd setup.
            let _ = mask.thread_unblock();
            drop(sync_write_fd);
            child::child_main(sync_read_fd, sandbox);
        }
        Some(cr) => cr,
    };

    // === PARENT PROCESS ===
    let child_pid = child.pid;
    let child_pidfd = child.pidfd;
    drop(sync_read_fd);

    // All parent exit paths must go through cleanup.
    let result = run_parent_setup(
        child_pid,
        &child_pidfd,
        sync_write_fd,
        uid_map,
        gid_map,
        sandbox,
    );

    // Restore signal mask for library callers.
    let _ = mask.thread_unblock();

    result
}

/// Parent-side logic after clone3. Extracted so all error paths are cleaned up
/// by the caller (`run_once_mode`).
fn run_parent_setup(
    child_pid: Pid,
    pidfd: &OwnedFd,
    sync_write_fd: OwnedFd,
    uid_map: &IdMap,
    gid_map: &IdMap,
    sandbox: &Sandbox,
) -> Result<i32, Error> {
    if let Err(e) = idmap::write_id_maps(child_pid, uid_map, gid_map) {
        drop(sync_write_fd);
        let _ = waitpid(child_pid, None);
        return Err(e);
    }

    nix::unistd::write(&sync_write_fd, &[0u8]).map_err(|e| Error::Setup {
        stage: Stage::Clone,
        context: "failed to signal child via sync pipe".into(),
        source: e.into(),
    })?;
    drop(sync_write_fd);

    wait_for_child(child_pid, pidfd, sandbox.process.forward_signals)
}

fn wait_for_child(child_pid: Pid, pidfd: &OwnedFd, forward_signals: bool) -> Result<i32, Error> {
    // Signals are already blocked before clone3. Create signalfd to receive them.
    // We detect child exit via the pidfd (becomes readable), not SIGCHLD —
    // this avoids SIGCHLD races in multi-threaded processes.
    let mask = supervision_signal_mask();
    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)
        .map_err(|e| Error::Other(format!("signalfd creation failed: {e}")))?;

    // Poll on both:
    // - pidfd: becomes readable when child exits (race-free, no SIGCHLD needed)
    // - signalfd: delivers forwarded signals (SIGTERM, SIGINT, etc.)
    loop {
        let mut fds = [
            PollFd::new(pidfd.as_fd(), PollFlags::POLLIN),
            PollFd::new(sfd.as_fd(), PollFlags::POLLIN),
        ];
        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(Error::Other(format!("poll failed: {e}"))),
        }

        // Check pidfd — child exited.
        if fds[0]
            .revents()
            .is_some_and(|r: PollFlags| r.contains(PollFlags::POLLIN))
        {
            match waitpid(child_pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => return Ok(code),
                Ok(WaitStatus::Signaled(_, signal, _)) => return Ok(128 + signal as i32),
                _ => continue,
            }
        }

        // Drain signalfd — forward or kill.
        while let Ok(Some(siginfo)) = sfd.read_signal() {
            if siginfo.ssi_signo == libc::SIGCHLD as u32 {
                continue;
            }
            if forward_signals {
                pidfd_send_signal(pidfd, siginfo.ssi_signo as i32);
            } else {
                pidfd_send_signal(pidfd, libc::SIGKILL);
            }
        }
    }
}

/// Send a signal to a process via its pidfd. Race-free: the signal is
/// always delivered to the intended process even if its PID has been recycled.
/// ESRCH (child already exited) is silently ignored; other errors are logged.
fn pidfd_send_signal(pidfd: &OwnedFd, sig: i32) {
    use std::os::fd::AsRawFd;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd() as libc::c_long,
            sig as libc::c_long,
            std::ptr::null::<libc::siginfo_t>() as libc::c_long,
            0 as libc::c_long,
        )
    };
    if ret == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            eprintln!("pnut: pidfd_send_signal({sig}) failed: {err}");
        }
    }
}

fn pipe_pair() -> Result<(OwnedFd, OwnedFd), Error> {
    let (read_fd, write_fd) = nix::unistd::pipe().map_err(|e| Error::Setup {
        stage: Stage::Clone,
        context: "pipe() failed".into(),
        source: e.into(),
    })?;
    Ok((read_fd, write_fd))
}

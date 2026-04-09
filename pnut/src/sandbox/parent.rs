//! Parent-side supervision (post-fork, monitors child).
//!
//! This code runs in the parent process after `clone3`. It manages:
//! - UID/GID map writes
//! - Signal forwarding via signalfd + pidfd
//! - Child exit status collection
//! - Status pipe reading for ChildFailure decoding

use crate::config::{IdMap, Namespaces};
use crate::error::{Error, Stage};
use std::os::fd::FromRawFd;

use super::Sandbox;

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
    // Validated by TryFrom<SandboxBuilder>.
    let uid_map = sandbox.uid_map.as_ref().unwrap();
    let gid_map = sandbox.gid_map.as_ref().unwrap();

    // Allocate all child data into an arena before clone3.
    // The child inherits COW copies of the arena after fork.
    let arena = bumpalo::Bump::new();
    let mut spec = sandbox.prepare(&arena).map_err(Error::from)?;

    // Create sync pipe: parent writes after UID/GID maps are set, child reads to proceed.
    let (sync_read_fd, sync_write_fd) = pipe_pair()?;

    // Create status pipe with CLOEXEC: child writes ChildFailure on setup failure,
    // write end auto-closes on successful execve (parent reads 0 bytes = success).
    let (status_read_fd, status_write_fd) = pipe_pair_cloexec()?;

    // Block forwarded signals + SIGCHLD before clone3 so that no signals
    // are lost between clone3 and the signalfd loop.
    let mask = supervision_signal_mask();
    mask.thread_block()
        .map_err(|e| Error::Other(format!("failed to block signals: {e}")))?;

    let flags = clone_flags(&sandbox.namespaces);
    let child = do_clone3(flags)?;

    let child = match child {
        None => {
            // === CHILD PROCESS ===
            let _ = mask.thread_unblock();

            // Close parent ends of both pipes (raw close, no allocation).
            unsafe {
                use std::os::fd::IntoRawFd;
                libc::close(sync_write_fd.into_raw_fd());
                libc::close(status_read_fd.into_raw_fd());
            }

            use std::os::fd::AsRawFd;
            spec.sync_fd = Some(sync_read_fd.as_raw_fd());
            spec.status_fd = Some(status_write_fd.as_raw_fd());

            // This never returns — it execs or exits.
            pnut_child::run(&mut spec);
        }
        Some(cr) => cr,
    };

    // === PARENT PROCESS ===
    let child_pid = child.pid;
    let child_pidfd = child.pidfd;
    drop(sync_read_fd);
    drop(status_write_fd);

    // All parent exit paths must go through cleanup.
    let result = run_parent_setup(
        child_pid,
        &child_pidfd,
        sync_write_fd,
        uid_map,
        gid_map,
        sandbox,
        status_read_fd,
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
    status_read_fd: OwnedFd,
) -> Result<i32, Error> {
    if let Err(e) = write_id_maps(child_pid, uid_map, gid_map) {
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

    let exit_code = wait_for_child(child_pid, pidfd, sandbox.process.forward_signals)?;

    // Read status pipe — if ChildFailure present, return structured error.
    if let Some(err) = decode_child_failure(&status_read_fd, sandbox) {
        return Err(err);
    }

    Ok(exit_code)
}

/// Read a ChildFailure from the status pipe and convert to a structured Error.
/// Returns None if the child exec'd successfully (CLOEXEC closed the write end).
fn decode_child_failure(status_read_fd: &OwnedFd, sandbox: &Sandbox) -> Option<Error> {
    use std::os::fd::AsRawFd;

    let mut buf = [0u8; core::mem::size_of::<pnut_child::ChildFailure>()];
    let n = unsafe {
        libc::read(
            status_read_fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };

    if n != buf.len() as isize {
        return None;
    }

    let failure: pnut_child::ChildFailure =
        unsafe { core::ptr::read_unaligned(buf.as_ptr().cast()) };

    if failure.version != pnut_child::ChildFailure::VERSION {
        return None;
    }

    let message = format_child_failure(&failure, sandbox);
    let stage = pnut_child::Stage::from_u16(failure.stage);

    Some(Error::ChildSetup {
        stage: stage.unwrap_or(pnut_child::Stage::Exec),
        errno: failure.errno,
        detail: failure.detail,
        exit_code: failure.exit_code,
        message,
    })
}

/// Format a ChildFailure into a human-readable error message.
fn format_child_failure(failure: &pnut_child::ChildFailure, sandbox: &Sandbox) -> String {
    use pnut_child::Stage;

    let errno = failure.errno;
    let detail = failure.detail;

    let errno_desc = if errno != 0 {
        std::io::Error::from_raw_os_error(errno).to_string()
    } else {
        String::new()
    };

    let command_path = sandbox
        .command
        .args
        .first()
        .map(|s| s.as_str())
        .unwrap_or("<unknown>");

    let Some(stage) = Stage::from_u16(failure.stage) else {
        return format!("child setup failed (stage {}): {errno_desc}", failure.stage);
    };

    match stage {
        Stage::Exec => {
            if errno == libc::ENOENT {
                format!("command not found: {command_path}")
            } else if errno == libc::EACCES {
                format!("permission denied: {command_path}")
            } else {
                format!("exec failed: {errno_desc}")
            }
        }
        Stage::Mount => {
            if detail >= 0 {
                format!("mount setup failed (entry {detail}): {errno_desc}")
            } else {
                format!("mount setup failed: {errno_desc}")
            }
        }
        Stage::ParentDeathSignal => format!("failed to set PR_SET_PDEATHSIG: {errno_desc}"),
        Stage::ParentCheck => "parent already exited".to_string(),
        Stage::SyncWait => "parent failed during setup".to_string(),
        Stage::Dumpable => format!("failed to set PR_SET_DUMPABLE: {errno_desc}"),
        Stage::Hostname => format!("failed to set hostname: {errno_desc}"),
        Stage::Network => format!("loopback setup failed: {errno_desc}"),
        Stage::Rlimit => format!("rlimits setup failed: {errno_desc}"),
        Stage::Landlock => format!("landlock setup failed: {errno_desc}"),
        Stage::Env => format!("environment setup failed: {errno_desc}"),
        Stage::Capabilities => format!("capability setup failed: {errno_desc}"),
        Stage::Setsid => format!("setsid failed: {errno_desc}"),
        Stage::Fd => format!("fd setup failed: {errno_desc}"),
        Stage::Tsc => format!("failed to set TSC: {errno_desc}"),
        Stage::NoNewPrivs => format!("failed to set NO_NEW_PRIVS: {errno_desc}"),
        Stage::Mdwe => format!("failed to set PR_SET_MDWE: {errno_desc}"),
        Stage::Seccomp => format!("seccomp filter installation failed: {errno_desc}"),
        Stage::Cwd => format!("failed to set working directory: {errno_desc}"),
    }
}

fn wait_for_child(child_pid: Pid, pidfd: &OwnedFd, forward_signals: bool) -> Result<i32, Error> {
    // Signals are already blocked before clone3. Create signalfd to receive them.
    // We detect child exit via the pidfd (becomes readable), not SIGCHLD --
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

        // Check pidfd -- child exited.
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

        // Drain signalfd -- forward or kill.
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

fn pipe_pair_cloexec() -> Result<(OwnedFd, OwnedFd), Error> {
    use nix::fcntl::OFlag;
    let (read_fd, write_fd) = nix::unistd::pipe2(OFlag::O_CLOEXEC).map_err(|e| Error::Setup {
        stage: Stage::Clone,
        context: "pipe2(O_CLOEXEC) failed".into(),
        source: e.into(),
    })?;
    Ok((read_fd, write_fd))
}

/// Write setgroups deny, uid_map, and gid_map for the given child process.
///
/// Order matters: setgroups must be written before gid_map for unprivileged
/// user namespaces (kernel requirement since Linux 3.19).
pub(super) fn write_id_maps(
    child_pid: nix::unistd::Pid,
    uid_map: &IdMap,
    gid_map: &IdMap,
) -> Result<(), Error> {
    let pid = child_pid.as_raw();

    let setgroups_path = format!("/proc/{pid}/setgroups");
    std::fs::write(&setgroups_path, "deny").map_err(|e| Error::Setup {
        stage: Stage::IdMap,
        context: format!("failed to write {setgroups_path}"),
        source: e,
    })?;

    let uid_map_path = format!("/proc/{pid}/uid_map");
    let uid_map_content = format!("{} {} {}\n", uid_map.inside, uid_map.outside, uid_map.count);
    std::fs::write(&uid_map_path, &uid_map_content).map_err(|e| Error::Setup {
        stage: Stage::IdMap,
        context: format!("failed to write {uid_map_path}"),
        source: e,
    })?;

    let gid_map_path = format!("/proc/{pid}/gid_map");
    let gid_map_content = format!("{} {} {}\n", gid_map.inside, gid_map.outside, gid_map.count);
    std::fs::write(&gid_map_path, &gid_map_content).map_err(|e| Error::Setup {
        stage: Stage::IdMap,
        context: format!("failed to write {gid_map_path}"),
        source: e,
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// clone3 + namespace flags
// ---------------------------------------------------------------------------

pub(super) fn clone_flags(ns: &Namespaces) -> u64 {
    let table: &[(bool, i32)] = &[
        (ns.user, libc::CLONE_NEWUSER),
        (ns.pid, libc::CLONE_NEWPID),
        (ns.mount, libc::CLONE_NEWNS),
        (ns.uts, libc::CLONE_NEWUTS),
        (ns.ipc, libc::CLONE_NEWIPC),
        (ns.net, libc::CLONE_NEWNET),
        (ns.cgroup, libc::CLONE_NEWCGROUP),
        (ns.time, libc::CLONE_NEWTIME),
    ];
    table
        .iter()
        .filter(|(enabled, _)| *enabled)
        .fold(0u64, |flags, &(_, flag)| flags | flag as u64)
}

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

struct ChildHandle {
    pid: nix::unistd::Pid,
    pidfd: std::os::fd::OwnedFd,
}

fn do_clone3(flags: u64) -> Result<Option<ChildHandle>, Error> {
    let mut pidfd_raw: i32 = -1;
    let args = CloneArgs {
        flags: flags | libc::CLONE_PIDFD as u64,
        exit_signal: nix::sys::signal::Signal::SIGCHLD as u64,
        pidfd: &mut pidfd_raw as *mut i32 as u64,
        child_tid: 0,
        parent_tid: 0,
        stack: 0,
        stack_size: 0,
        tls: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &args as *const CloneArgs,
            core::mem::size_of::<CloneArgs>(),
        )
    };
    if ret == -1 {
        return Err(Error::Setup {
            stage: Stage::Clone,
            context: "clone3 failed".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    if ret == 0 {
        return Ok(None);
    }
    if pidfd_raw < 0 {
        return Err(Error::Setup {
            stage: Stage::Clone,
            context: "clone3 succeeded but CLONE_PIDFD did not return a valid fd".into(),
            source: std::io::Error::from_raw_os_error(libc::EBADF),
        });
    }
    let pidfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd_raw) };
    Ok(Some(ChildHandle {
        pid: nix::unistd::Pid::from_raw(ret as i32),
        pidfd,
    }))
}

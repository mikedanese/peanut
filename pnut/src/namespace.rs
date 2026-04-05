//! Namespace selection and `clone3` process creation.
//!
//! This module owns namespace configuration plus the low-level helpers that
//! translate namespace toggles into `clone3` flags.

use crate::error::{Error, Stage};
use nix::sys::signal::Signal;
use nix::unistd::Pid;

/// Controls which Linux namespaces are created via `clone3` flags.
///
/// Defaults: user, PID, and mount are enabled. UTS, IPC, net, and cgroup
/// are disabled. Setting `net = false` (the default) means the sandbox
/// inherits the host network stack.
#[derive(Debug)]
pub struct Config {
    /// User namespace. Required for unprivileged sandboxing. Default: `true`.
    pub user: bool,

    /// PID namespace. Child becomes PID 1. Default: `true`.
    pub pid: bool,

    /// Mount namespace. Required for filesystem isolation. Default: `true`.
    pub mount: bool,

    /// UTS namespace. Required for `sandbox.hostname`. Default: `false`.
    pub uts: bool,

    /// IPC namespace. Isolates System V IPC and POSIX message queues.
    /// Default: `false`.
    pub ipc: bool,

    /// Network namespace. `true` = loopback only, `false` = inherit host
    /// network. Default: `false`.
    pub net: bool,

    /// Cgroup namespace. Isolates cgroup view. Default: `false`.
    pub cgroup: bool,

    /// Time namespace. Virtualizes `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`.
    /// Requires kernel 5.6+. Default: `false`.
    pub time: bool,

    /// Hostname seen inside the sandbox. Requires `uts = true`.
    /// Default: `None` (inherit host hostname).
    pub hostname: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            user: true,
            pid: true,
            mount: true,
            uts: false,
            ipc: false,
            net: false,
            cgroup: false,
            time: false,
            hostname: None,
        }
    }
}

impl Config {
    /// Enable or disable the user namespace.
    pub fn user(&mut self, enabled: bool) -> &mut Self {
        self.user = enabled;
        self
    }

    /// Enable or disable the PID namespace.
    pub fn pid(&mut self, enabled: bool) -> &mut Self {
        self.pid = enabled;
        self
    }

    /// Enable or disable the mount namespace.
    pub fn mount(&mut self, enabled: bool) -> &mut Self {
        self.mount = enabled;
        self
    }

    /// Enable or disable the UTS namespace.
    pub fn uts(&mut self, enabled: bool) -> &mut Self {
        self.uts = enabled;
        self
    }

    /// Enable or disable the IPC namespace.
    pub fn ipc(&mut self, enabled: bool) -> &mut Self {
        self.ipc = enabled;
        self
    }

    /// Enable or disable the network namespace.
    pub fn net(&mut self, enabled: bool) -> &mut Self {
        self.net = enabled;
        self
    }

    /// Enable or disable the cgroup namespace.
    pub fn cgroup(&mut self, enabled: bool) -> &mut Self {
        self.cgroup = enabled;
        self
    }

    /// Enable or disable the time namespace.
    pub fn time(&mut self, enabled: bool) -> &mut Self {
        self.time = enabled;
        self
    }

    /// Set the hostname seen inside the sandbox. Requires `uts = true`.
    pub fn hostname(&mut self, hostname: impl Into<String>) -> &mut Self {
        self.hostname = Some(hostname.into());
        self
    }
}

/// Build clone3 flags from the namespace config.
pub(crate) fn clone_flags(ns: &Config) -> u64 {
    let mut flags: u64 = 0;
    if ns.user {
        flags |= libc::CLONE_NEWUSER as u64;
    }
    if ns.pid {
        flags |= libc::CLONE_NEWPID as u64;
    }
    if ns.mount {
        flags |= libc::CLONE_NEWNS as u64;
    }
    if ns.uts {
        flags |= libc::CLONE_NEWUTS as u64;
    }
    if ns.ipc {
        flags |= libc::CLONE_NEWIPC as u64;
    }
    if ns.net {
        flags |= libc::CLONE_NEWNET as u64;
    }
    if ns.cgroup {
        flags |= libc::CLONE_NEWCGROUP as u64;
    }
    if ns.time {
        flags |= libc::CLONE_NEWTIME as u64;
    }
    flags
}

/// Low-level clone3 struct matching the kernel's `struct clone_args`.
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

/// Create a new process via the clone3 syscall with the given namespace flags.
///
/// Returns the child PID to the parent and `Pid::from_raw(0)` to the child.
///
/// # Safety
///
/// This is a thin wrapper around `SYS_clone3`. The caller must ensure that
/// post-fork invariants are maintained (e.g., no multi-threaded forking hazards,
/// proper pipe synchronization).
pub(crate) fn do_clone3(flags: u64) -> Result<Pid, Error> {
    let args = CloneArgs {
        flags,
        exit_signal: Signal::SIGCHLD as u64,
        pidfd: 0,
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
        Err(Error::Setup {
            stage: Stage::Clone,
            context: "clone3 failed".into(),
            source: std::io::Error::last_os_error(),
        })
    } else if ret == 0 {
        Ok(Pid::from_raw(0))
    } else {
        Ok(Pid::from_raw(ret as i32))
    }
}

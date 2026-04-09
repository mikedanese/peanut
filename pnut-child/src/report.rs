//! Structured child failure reporting.

use crate::error::Errno;
use crate::io::{write_all, write_stderr};

/// Child-runtime stage identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Stage {
    ParentDeathSignal = 1,
    ParentCheck = 2,
    SyncWait = 3,
    Dumpable = 4,
    Mount = 5,
    Hostname = 6,
    Network = 7,
    Rlimit = 8,
    Landlock = 9,
    Env = 10,
    Capabilities = 11,
    Setsid = 12,
    Fd = 13,
    Tsc = 14,
    NoNewPrivs = 15,
    Mdwe = 16,
    Seccomp = 17,
    Cwd = 18,
    Exec = 19,
}

impl Stage {
    pub const fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::ParentDeathSignal),
            2 => Some(Self::ParentCheck),
            3 => Some(Self::SyncWait),
            4 => Some(Self::Dumpable),
            5 => Some(Self::Mount),
            6 => Some(Self::Hostname),
            7 => Some(Self::Network),
            8 => Some(Self::Rlimit),
            9 => Some(Self::Landlock),
            10 => Some(Self::Env),
            11 => Some(Self::Capabilities),
            12 => Some(Self::Setsid),
            13 => Some(Self::Fd),
            14 => Some(Self::Tsc),
            15 => Some(Self::NoNewPrivs),
            16 => Some(Self::Mdwe),
            17 => Some(Self::Seccomp),
            18 => Some(Self::Cwd),
            19 => Some(Self::Exec),
            _ => None,
        }
    }
}

/// Fixed-layout fatal child failure record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct ChildFailure {
    pub version: u16,
    pub stage: u16,
    pub errno: i32,
    pub detail: i32,
    pub exit_code: i32,
}

impl ChildFailure {
    pub const VERSION: u16 = 1;

    pub const fn new(stage: Stage, errno: i32, detail: i32, exit_code: i32) -> Self {
        Self {
            version: Self::VERSION,
            stage: stage as u16,
            errno,
            detail,
            exit_code,
        }
    }
}

/// Status-fd writer for fatal child failures.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reporter {
    status_fd: Option<libc::c_int>,
}

impl Reporter {
    pub(crate) const fn new(status_fd: Option<libc::c_int>) -> Self {
        Self { status_fd }
    }

    pub(crate) fn report_errno(
        &self,
        stage: Stage,
        err: Errno,
        detail: i32,
        exit_code: i32,
    ) -> ChildFailure {
        let failure = ChildFailure::new(stage, err.0, detail, exit_code);
        self.send_and_stderr(&failure, stage);
        failure
    }

    pub(crate) fn report_logic(&self, stage: Stage, detail: i32, exit_code: i32) -> ChildFailure {
        let failure = ChildFailure::new(stage, 0, detail, exit_code);
        self.send_and_stderr(&failure, stage);
        failure
    }

    pub(crate) fn report_exec_errno(
        &self,
        err: Errno,
        exit_code: i32,
        path: &core::ffi::CStr,
    ) -> ChildFailure {
        let failure = ChildFailure::new(Stage::Exec, err.0, 0, exit_code);
        let sent = self.send_failure(&failure);

        if !sent {
            let prefix = if err.0 == libc::ENOENT {
                &b"pnut: command not found: "[..]
            } else if err.0 == libc::EACCES {
                &b"pnut: permission denied: "[..]
            } else {
                &b"pnut: exec failed: "[..]
            };
            let _ = write_stderr(prefix);
            let _ = write_stderr(path.to_bytes());
            let _ = write_stderr(b"\n");
        }

        failure
    }

    /// Write the binary failure record to status_fd. Returns true if sent.
    fn send_failure(&self, failure: &ChildFailure) -> bool {
        if let Some(fd) = self.status_fd {
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (failure as *const ChildFailure).cast::<u8>(),
                    core::mem::size_of::<ChildFailure>(),
                )
            };
            if write_all(fd, bytes).is_ok() {
                return true;
            }
        }
        false
    }

    /// Send the failure record and, if not sent, write a fallback message to stderr.
    fn send_and_stderr(&self, failure: &ChildFailure, stage: Stage) {
        if self.send_failure(failure) {
            return;
        }
        let msg: &[u8] = match stage {
            Stage::ParentDeathSignal => b"pnut: failed to set PR_SET_PDEATHSIG\n",
            Stage::ParentCheck => b"pnut: parent already exited\n",
            Stage::SyncWait => b"pnut: parent failed during setup\n",
            Stage::Dumpable => b"pnut: failed to set PR_SET_DUMPABLE\n",
            Stage::Mount => b"pnut: mount setup failed\n",
            Stage::Hostname => b"pnut: failed to set hostname\n",
            Stage::Network => b"pnut: loopback setup failed\n",
            Stage::Rlimit => b"pnut: rlimits setup failed\n",
            Stage::Landlock => b"pnut: landlock setup failed\n",
            Stage::Env => b"pnut: environment setup failed\n",
            Stage::Capabilities => b"pnut: capability setup failed\n",
            Stage::Setsid => b"pnut: setsid failed\n",
            Stage::Fd => b"pnut: fd setup failed\n",
            Stage::Tsc => b"pnut: failed to set TSC\n",
            Stage::NoNewPrivs => b"pnut: failed to set NO_NEW_PRIVS\n",
            Stage::Mdwe => b"pnut: failed to set PR_SET_MDWE\n",
            Stage::Seccomp => b"pnut: seccomp filter installation failed\n",
            Stage::Cwd => b"pnut: failed to set working directory\n",
            Stage::Exec => b"pnut: exec failed\n",
        };
        let _ = write_stderr(msg);
    }
}

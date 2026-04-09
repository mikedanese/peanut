//! Child-side sandbox setup (post-fork, pre-exec).
//!
//! **Constraints**: This code runs after `clone3` in the child process.
//! - No `tracing` or structured logging — only `eprintln!` for errors.
//! - All failures exit via `std::process::exit(126)` (or 127 for command not found).
//! - No panics — use `unwrap_or_else` with exit, not `.unwrap()`.
//! - Minimal heap allocation.

use super::Sandbox;
use crate::caps as capmod;
use crate::env;
use crate::fd;
use crate::landlock;
use crate::mount;
use crate::net;
use crate::rlimit;

use nix::sys::signal::Signal;
use nix::unistd::Pid;
use std::ffi::CString;
use std::io::Read;
use std::os::unix::io::OwnedFd;

fn last_os_error() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// Print an error and exit the child process.
///
/// Used throughout child setup where returning errors is not possible
/// (we're past fork, the only option is exit with a status code).
macro_rules! exit {
    ($code:expr, $($arg:tt)*) => {{
        eprintln!("pnut: {}", format_args!($($arg)*));
        std::process::exit($code);
    }};
}

/// prctl options used during child setup.
enum Prctl {
    Dumpable,
    NoNewPrivs,
    Mdwe,
    Tsc,
}

impl Prctl {
    fn option(&self) -> libc::c_int {
        match self {
            Self::Dumpable => libc::PR_SET_DUMPABLE,
            Self::NoNewPrivs => libc::PR_SET_NO_NEW_PRIVS,
            Self::Mdwe => libc::PR_SET_MDWE,
            Self::Tsc => libc::PR_SET_TSC,
        }
    }
}

impl std::fmt::Display for Prctl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Dumpable => "PR_SET_DUMPABLE",
            Self::NoNewPrivs => "PR_SET_NO_NEW_PRIVS",
            Self::Mdwe => "PR_SET_MDWE",
            Self::Tsc => "PR_SET_TSC",
        })
    }
}

/// Call `prctl` via the [`Prctl`] enum. Exits on failure.
fn apply_prctl_or_die(p: Prctl, arg: libc::c_ulong) {
    let ret = unsafe { libc::prctl(p.option(), arg, 0, 0, 0) };
    if ret != 0 {
        exit!(126, "failed to set {p}: {}", last_os_error());
    }
}

/// Child process entry point for `once` mode.
///
/// Waits for the parent to signal (via sync pipe) that UID/GID maps are
/// written, then proceeds to sandbox setup and exec.
pub(super) fn child_main(sync_read_fd: OwnedFd, sandbox: &Sandbox) -> ! {
    if sandbox.process.die_with_parent {
        if let Err(e) = nix::sys::prctl::set_pdeathsig(Signal::SIGKILL) {
            exit!(126, "failed to set PR_SET_PDEATHSIG: {e}");
        }
        if nix::unistd::getppid() == Pid::from_raw(1) {
            exit!(126, "parent already exited");
        }
    }

    {
        let file = std::fs::File::from(sync_read_fd);
        let mut pipe = std::io::BufReader::new(file);
        let mut buf = [0u8; 1];
        if pipe.read_exact(&mut buf).is_err() {
            exit!(126, "parent failed during setup");
        }
    }

    run_child_setup(sandbox);
}

/// Shared child setup sequence used by both execution modes.
///
/// Applies all sandbox restrictions in order, then execs the target command.
pub(super) fn run_child_setup(sandbox: &Sandbox) -> ! {
    let dumpable = u64::from(sandbox.process.dumpable);
    apply_prctl_or_die(Prctl::Dumpable, dumpable);

    if sandbox.namespaces.mount
        && !sandbox.mounts.is_empty()
        && let Err(e) = mount::setup_filesystem(sandbox)
    {
        exit!(126, "filesystem setup failed: {e}");
    }

    if let Some(ref hostname) = sandbox.namespaces.hostname
        && sandbox.namespaces.uts
        && let Err(e) = nix::unistd::sethostname(hostname)
    {
        exit!(126, "failed to set hostname to '{hostname}': {e}");
    }

    if sandbox.namespaces.net
        && let Err(e) = net::bring_up_loopback()
    {
        exit!(126, "loopback setup failed: {e}");
    }

    if let Some(ref rlimits_config) = sandbox.rlimits
        && let Err(e) = rlimit::apply_rlimits(rlimits_config)
    {
        exit!(126, "rlimits setup failed: {e}");
    }

    if let Some(ref landlock_config) = sandbox.landlock
        && let Err(e) = landlock::apply_landlock(landlock_config)
    {
        exit!(126, "landlock setup failed: {e}");
    }

    if let Some(ref env_config) = sandbox.env {
        env::setup_environment(env_config);
    }

    if let Some(ref caps_config) = sandbox.capabilities
        && let Err(e) = capmod::apply_capabilities(caps_config)
    {
        exit!(126, "capability setup failed: {e}");
    }

    if sandbox.process.new_session
        && let Err(e) = nix::unistd::setsid()
    {
        exit!(126, "setsid failed: {e}");
    }

    {
        let fd_config = sandbox.fd.as_ref();
        let default_config = fd::Config::default();
        let config = fd_config.unwrap_or(&default_config);
        if let Err(e) = fd::apply_fd_config(config) {
            exit!(126, "fd setup failed: {e}");
        }
    }

    if sandbox.process.disable_tsc {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        apply_prctl_or_die(Prctl::Tsc, libc::PR_TSC_SIGSEGV as libc::c_ulong);
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        exit!(126, "disable_tsc is only supported on x86/x86_64");
    }

    if sandbox.process.no_new_privs {
        apply_prctl_or_die(Prctl::NoNewPrivs, 1);
    }

    if sandbox.process.mdwe {
        apply_prctl_or_die(Prctl::Mdwe, libc::PR_MDWE_REFUSE_EXEC_GAIN as libc::c_ulong);
    }

    if let Some(program) = sandbox.seccomp_program.as_ref()
        && let Err(e) = kafel::install_filter(program)
    {
        exit!(126, "seccomp filter installation failed: {e}");
    }

    do_exec(sandbox);
}

/// Build argv and execv the target command.
fn do_exec(sandbox: &Sandbox) -> ! {
    let command = &sandbox.command.args;
    let path = CString::new(command[0].as_str()).unwrap_or_else(|_| {
        exit!(126, "command path contains null byte");
    });

    let mut args: Vec<CString> = command
        .iter()
        .map(|a| {
            CString::new(a.as_str()).unwrap_or_else(|_| {
                exit!(126, "argument contains null byte");
            })
        })
        .collect();

    if let Some(ref argv0) = sandbox.command.argv0 {
        args[0] = CString::new(argv0.as_str()).unwrap_or_else(|_| {
            exit!(126, "argv0 contains null byte");
        });
    }

    let err = nix::unistd::execv(&path, &args);
    match err {
        Err(nix::errno::Errno::ENOENT) => exit!(127, "command not found: {}", command[0]),
        Err(nix::errno::Errno::EACCES) => exit!(126, "permission denied: {}", command[0]),
        Err(e) => exit!(126, "exec failed: {e}"),
        Ok(_) => unreachable!(),
    }
}

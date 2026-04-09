//! Ordered child-runtime execution.

use crate::caps;
use crate::env;
use crate::fd;
use crate::io::read_byte;
use crate::landlock;
use crate::mount;
use crate::net;
use crate::process::{self, Prctl};
use crate::report::{Reporter, Stage};
use crate::rlimit;
use crate::seccomp;
use crate::spec::ChildSpec;

const EXIT_SETUP_FAILED: libc::c_int = 126;
const EXIT_COMMAND_NOT_FOUND: libc::c_int = 127;

pub fn run(spec: &mut ChildSpec<'_>) -> ! {
    let reporter = Reporter::new(spec.status_fd);

    if let Some(sig) = spec.process.pdeathsig
        && let Err(err) =
            process::prctl_set(Prctl::ParentDeathSignal, sig as libc::c_ulong, 0, 0, 0)
    {
        let _ = reporter.report_errno(Stage::ParentDeathSignal, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if spec.process.verify_parent_alive && process::getppid() == 1 {
        let _ = reporter.report_logic(Stage::ParentCheck, 1, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(sync_fd) = spec.sync_fd {
        let sync_result = read_byte(sync_fd).and_then(|_| fd::close(sync_fd));
        if let Err(err) = sync_result {
            let _ = reporter.report_errno(Stage::SyncWait, err, 0, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
    }

    if let Err(err) = process::prctl_set(
        Prctl::Dumpable,
        spec.process.dumpable as libc::c_ulong,
        0,
        0,
        0,
    ) {
        let _ = reporter.report_errno(Stage::Dumpable, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    // Filesystem setup has to happen before any later path-based operations
    // such as hostname-specific proc views, cwd changes, or exec.
    if let Some(mounts) = spec.mounts.as_ref()
        && let Err(err) = mount::setup(mounts)
    {
        let _ = reporter.report_errno(Stage::Mount, err.errno, err.detail, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(hostname) = spec.hostname
        && let Err(err) = process::sethostname(hostname)
    {
        let _ = reporter.report_errno(Stage::Hostname, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if spec.bring_up_loopback
        && let Err(err) = net::bring_up_loopback()
    {
        let _ = reporter.report_errno(Stage::Network, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(rlimits) = spec.rlimits.as_ref()
        && let Err(err) = rlimit::apply(rlimits)
    {
        let _ = reporter.report_errno(Stage::Rlimit, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(landlock_spec) = spec.landlock.as_ref()
        && let Err(err) = landlock::apply(landlock_spec)
    {
        let _ = reporter.report_errno(Stage::Landlock, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    let envp = if let Some(env_spec) = spec.env.as_mut() {
        match env::prepare(env_spec) {
            Ok(envp) => envp,
            Err(err) => {
                let _ = reporter.report_errno(Stage::Env, err, 0, EXIT_SETUP_FAILED);
                process::exit_immediately(EXIT_SETUP_FAILED);
            }
        }
    } else {
        process::current_environ()
    };

    if let Some(caps_spec) = spec.caps.as_ref()
        && let Err(err) = caps::apply(caps_spec)
    {
        let _ = reporter.report_errno(Stage::Capabilities, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if spec.process.new_session
        && let Err(err) = process::setsid()
    {
        let _ = reporter.report_errno(Stage::Setsid, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Err(err) = fd::apply_actions(spec.fds.actions) {
        let _ = reporter.report_errno(Stage::Fd, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
    if spec.fds.close_fds {
        let extra_keep = [spec.status_fd.unwrap_or(-1)];
        if let Err(err) = fd::close_other_fds(spec.fds.keep, &extra_keep) {
            let _ = reporter.report_errno(Stage::Fd, err, 1, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
    }

    if spec.process.disable_tsc {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let tsc_result =
            process::prctl_set(Prctl::Tsc, libc::PR_TSC_SIGSEGV as libc::c_ulong, 0, 0, 0);
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let tsc_result = Err(crate::error::Errno::new(libc::EOPNOTSUPP));

        if let Err(err) = tsc_result {
            let _ = reporter.report_errno(Stage::Tsc, err, 0, EXIT_SETUP_FAILED);
            process::exit_immediately(EXIT_SETUP_FAILED);
        }
    }

    if spec.process.no_new_privs
        && let Err(err) = process::prctl_set(Prctl::NoNewPrivs, 1, 0, 0, 0)
    {
        let _ = reporter.report_errno(Stage::NoNewPrivs, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(mdwe_flags) = spec.process.mdwe_flags
        && let Err(err) = process::prctl_set(Prctl::Mdwe, mdwe_flags, 0, 0, 0)
    {
        let _ = reporter.report_errno(Stage::Mdwe, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(seccomp_spec) = spec.seccomp.as_ref()
        && let Err(err) = seccomp::install(seccomp_spec)
    {
        let _ = reporter.report_errno(Stage::Seccomp, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    if let Some(cwd) = spec.cwd
        && let Err(err) = process::chdir(cwd)
    {
        let _ = reporter.report_errno(Stage::Cwd, err, 0, EXIT_SETUP_FAILED);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }

    let err = process::execve(&spec.exec, envp);
    if err.0 == libc::ENOENT {
        let _ = reporter.report_exec_errno(err, EXIT_COMMAND_NOT_FOUND, spec.exec.path);
        process::exit_immediately(EXIT_COMMAND_NOT_FOUND);
    } else {
        let _ = reporter.report_exec_errno(err, EXIT_SETUP_FAILED, spec.exec.path);
        process::exit_immediately(EXIT_SETUP_FAILED);
    }
}

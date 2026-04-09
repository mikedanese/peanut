//! Process-control helpers for the post-`clone3`, pre-`execve` phase.

use core::ffi::CStr;

use crate::error::{Errno, Result};
use crate::spec::ExecSpec;

unsafe extern "C" {
    static mut environ: *mut *mut libc::c_char;
}

/// A small subset of `prctl` options commonly used during child setup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Prctl {
    Dumpable,
    NoNewPrivs,
    Mdwe,
    Tsc,
    ParentDeathSignal,
}

impl Prctl {
    fn option(self) -> libc::c_int {
        match self {
            Self::Dumpable => libc::PR_SET_DUMPABLE,
            Self::NoNewPrivs => libc::PR_SET_NO_NEW_PRIVS,
            Self::Mdwe => libc::PR_SET_MDWE,
            Self::Tsc => libc::PR_SET_TSC,
            Self::ParentDeathSignal => libc::PR_SET_PDEATHSIG,
        }
    }
}

/// Call `prctl(option, arg2, arg3, arg4, arg5)`.
pub fn prctl_set(
    option: Prctl,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
) -> Result<()> {
    prctl_raw(option.option(), arg2, arg3, arg4, arg5)
}

/// Call `prctl(option, arg2, arg3, arg4, arg5)` with a raw option code.
pub fn prctl_raw(
    option: libc::c_int,
    arg2: libc::c_ulong,
    arg3: libc::c_ulong,
    arg4: libc::c_ulong,
    arg5: libc::c_ulong,
) -> Result<()> {
    let ret = unsafe { libc::prctl(option, arg2, arg3, arg4, arg5) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

/// Return the current parent pid.
pub fn getppid() -> libc::pid_t {
    unsafe { libc::getppid() }
}

/// Create a new session with `setsid()`.
pub fn setsid() -> Result<libc::pid_t> {
    let ret = unsafe { libc::setsid() };
    if ret >= 0 {
        Ok(ret)
    } else {
        Err(Errno::last())
    }
}

/// Set the hostname in the current UTS namespace.
pub fn sethostname(hostname: &CStr) -> Result<()> {
    let bytes = hostname.to_bytes();
    let ret = unsafe {
        libc::sethostname(
            bytes.as_ptr().cast::<libc::c_char>(),
            bytes.len() as libc::size_t,
        )
    };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

/// Change the current working directory.
pub fn chdir(path: &CStr) -> Result<()> {
    let ret = unsafe { libc::chdir(path.as_ptr()) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

/// Borrow the current process environment pointer.
pub fn current_environ() -> *const *const libc::c_char {
    unsafe { environ.cast::<*const libc::c_char>() }
}

/// Replace the current process image via `execve`.
///
/// On success execve never returns, so this function always returns an error.
pub fn execve(spec: &ExecSpec<'_>, envp: *const *const libc::c_char) -> Errno {
    unsafe { libc::execve(spec.path.as_ptr(), spec.argv.as_ptr(), envp.cast_mut()) };
    Errno::last()
}

/// Exit immediately without running destructors or stdio cleanup.
pub fn exit_immediately(code: libc::c_int) -> ! {
    unsafe { libc::_exit(code) }
}

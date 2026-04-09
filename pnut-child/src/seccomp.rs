//! Raw seccomp filter installation.

use crate::error::{Errno, Result};
use crate::spec::SeccompSpec;

pub fn install(spec: &SeccompSpec) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            spec.flags,
            &spec.program as *const libc::sock_fprog,
        )
    };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

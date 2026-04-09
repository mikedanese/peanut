//! Raw Linux capability application.

use crate::error::{Errno, Result};
use crate::process::prctl_raw;
use crate::spec::CapsSpec;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct UserCapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
struct UserCapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

pub fn apply(spec: &CapsSpec<'_>) -> Result<()> {
    if spec.clear_ambient {
        prctl_raw(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0,
            0,
            0,
        )?;
    }

    for &cap in spec.bounding_drop {
        prctl_raw(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0)?;
    }

    let header = UserCapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        UserCapData {
            effective: spec.effective[0],
            permitted: spec.permitted[0],
            inheritable: spec.inheritable[0],
        },
        UserCapData {
            effective: spec.effective[1],
            permitted: spec.permitted[1],
            inheritable: spec.inheritable[1],
        },
    ];

    let ret = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &header as *const UserCapHeader,
            data.as_ptr(),
        )
    };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

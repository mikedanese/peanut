//! `/dev` setup inside the sandbox filesystem.

use core::ffi::CStr;

use super::{report_fsconfig_failure, syscall};

const DEV: &CStr = c"dev";
const SHM: &CStr = c"shm";
const PTS: &CStr = c"pts";

fn mount_fs(
    fs_type: &CStr,
    root_fd: libc::c_int,
    rel_dst: &CStr,
    attr_flags: u64,
    options: &[(&CStr, &CStr)],
    flags: &[&CStr],
) -> crate::error::Result<()> {
    let fs_fd = syscall::fsopen(fs_type)?;

    for &(key, value) in options {
        syscall::fsconfig_set_string(fs_fd.as_raw(), key, value)?;
    }
    for &key in flags {
        syscall::fsconfig_set_flag(fs_fd.as_raw(), key)?;
    }

    let mut log_buf = [0u8; 1024];
    if let Err(err) = syscall::fsconfig_create(fs_fd.as_raw(), &mut log_buf) {
        return Err(report_fsconfig_failure(err, &log_buf, b"/dev"));
    }

    let mnt_fd = syscall::fsmount(fs_fd.as_raw(), attr_flags)?;
    syscall::move_mount_to_fd(mnt_fd.as_raw(), root_fd, rel_dst)
}

pub(super) fn setup_dev(root_fd: libc::c_int) -> crate::error::Result<()> {
    syscall::mkdirat_all(root_fd, DEV)?;

    // Start with an isolated tmpfs-backed /dev so only explicitly attached
    // nodes and submounts are visible inside the sandbox.
    mount_fs(
        c"tmpfs",
        root_fd,
        DEV,
        libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NOEXEC,
        &[(c"mode", c"0755")],
        &[],
    )?;

    let dev_fd = syscall::openat_dir(root_fd, DEV)?;

    for &(name, host_path) in &[
        (c"null", c"/dev/null"),
        (c"zero", c"/dev/zero"),
        (c"full", c"/dev/full"),
        (c"random", c"/dev/random"),
        (c"urandom", c"/dev/urandom"),
        (c"tty", c"/dev/tty"),
    ] {
        // Device nodes are bind-mounted from the host /dev. The sandbox only
        // receives the specific nodes we attach here.
        syscall::create_file_at(dev_fd.as_raw(), name)?;
        let mnt_fd = syscall::open_tree(
            libc::AT_FDCWD,
            host_path,
            libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
        )?;
        syscall::move_mount_to_fd(mnt_fd.as_raw(), dev_fd.as_raw(), name)?;
    }

    syscall::mkdirat_all(dev_fd.as_raw(), SHM)?;
    mount_fs(
        c"tmpfs",
        dev_fd.as_raw(),
        SHM,
        libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NODEV,
        &[(c"mode", c"1777")],
        &[],
    )?;

    // devpts must be a distinct instance so PTY allocation is scoped to the
    // sandbox rather than sharing the host's /dev/pts mount.
    syscall::mkdirat_all(dev_fd.as_raw(), PTS)?;
    mount_fs(
        c"devpts",
        dev_fd.as_raw(),
        PTS,
        libc::MOUNT_ATTR_NOSUID | libc::MOUNT_ATTR_NOEXEC,
        &[(c"ptmxmode", c"0666"), (c"mode", c"620")],
        &[c"newinstance"],
    )?;

    syscall::symlinkat(c"pts/ptmx", dev_fd.as_raw(), c"ptmx")?;
    syscall::symlinkat(c"/proc/self/fd", dev_fd.as_raw(), c"fd")?;
    syscall::symlinkat(c"/proc/self/fd/0", dev_fd.as_raw(), c"stdin")?;
    syscall::symlinkat(c"/proc/self/fd/1", dev_fd.as_raw(), c"stdout")?;
    syscall::symlinkat(c"/proc/self/fd/2", dev_fd.as_raw(), c"stderr")?;

    Ok(())
}

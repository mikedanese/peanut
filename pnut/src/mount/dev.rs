//! `/dev` setup inside the sandbox filesystem.

use crate::error::Error;
use std::ffi::CString;
use std::os::fd::{AsFd, BorrowedFd};

use super::syscall;
use super::{mnt, mnt_nix};

/// Mount a filesystem using the new mount API: fsopen -> fsconfig -> fsmount -> move_mount.
///
/// `fs_type`: filesystem type (e.g., c"tmpfs", c"devpts")
/// `root_fd`: directory fd to mount relative to
/// `rel_dst`: relative path under root_fd to mount at
/// `attr_flags`: fsmount attr_flags (MOUNT_ATTR_NOSUID, etc.)
/// `options`: list of (key, value) pairs for fsconfig_set_string
/// `flags`: list of keys for fsconfig_set_flag
/// `label`: human-readable label for error messages
fn mount_fs(
    fs_type: &std::ffi::CStr,
    root_fd: BorrowedFd<'_>,
    rel_dst: &str,
    attr_flags: u64,
    options: &[(&std::ffi::CStr, &std::ffi::CStr)],
    flags: &[&std::ffi::CStr],
    label: &str,
) -> Result<(), Error> {
    let fs_fd =
        syscall::fsopen(fs_type).map_err(|e| mnt_nix(format!("fsopen for {label} failed"), e))?;

    for (key, value) in options {
        syscall::fsconfig_set_string(fs_fd.as_fd(), key, value)
            .map_err(|e| mnt_nix(format!("fsconfig for {label} failed"), e))?;
    }
    for key in flags {
        syscall::fsconfig_set_flag(fs_fd.as_fd(), key)
            .map_err(|e| mnt_nix(format!("fsconfig flag for {label} failed"), e))?;
    }

    syscall::fsconfig_create(fs_fd.as_fd()).map_err(|(errno, log)| {
        let mut ctx = format!("fsconfig(CMD_CREATE) for {label} failed");
        if let Some(msg) = log {
            ctx.push_str(": ");
            ctx.push_str(&msg);
        }
        mnt_nix(ctx, errno)
    })?;

    let mnt_fd = syscall::fsmount(fs_fd.as_fd(), attr_flags)
        .map_err(|e| mnt_nix(format!("fsmount for {label} failed"), e))?;

    let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
        mnt(
            format!("invalid path for {label}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::move_mount_to_fd(mnt_fd.as_fd(), root_fd, &rel_dst_cstr)
        .map_err(|e| mnt_nix(format!("move_mount for {label} failed"), e))?;

    Ok(())
}

/// Set up `/dev` with device nodes, shm, pts, and standard symlinks.
///
/// Called in the child process after fork. All operations are fd-relative
/// using the provided `root_fd`.
pub(super) fn setup_dev(root_fd: BorrowedFd<'_>) -> Result<(), Error> {
    syscall::mkdirat_all(root_fd, "dev").map_err(|e| mnt_nix("failed to create /dev", e))?;

    // tmpfs at /dev with MS_NOSUID|MS_NOEXEC, mode=0755
    mount_fs(
        c"tmpfs",
        root_fd,
        "dev",
        syscall::MOUNT_ATTR_NOSUID | syscall::MOUNT_ATTR_NOEXEC,
        &[(c"mode", c"0755")],
        &[],
        "tmpfs at /dev",
    )?;

    // Open the /dev directory fd for creating mount points inside it
    let dev_cstr = CString::new("dev").unwrap();
    let dev_fd = syscall::openat_dir(root_fd, &dev_cstr)
        .map_err(|e| mnt_nix("failed to open /dev as directory fd", e))?;

    // Bind mount device nodes from host using open_tree + move_mount
    let at_fdcwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
    let devices = ["null", "zero", "full", "random", "urandom", "tty"];
    for dev in &devices {
        // Create mount point file relative to dev_fd
        let dev_cstr = CString::new(*dev).unwrap();
        syscall::create_file_at(dev_fd.as_fd(), &dev_cstr)
            .map_err(|e| mnt_nix(format!("failed to create mount point for /dev/{dev}"), e))?;

        let host_path = format!("/dev/{dev}");
        let src_cstr = CString::new(host_path.as_str()).map_err(|e| {
            mnt(
                format!("invalid path for /dev/{dev}: {e}"),
                std::io::Error::other(e),
            )
        })?;
        let mnt_fd = syscall::open_tree(
            at_fdcwd,
            &src_cstr,
            syscall::OPEN_TREE_CLONE | syscall::OPEN_TREE_CLOEXEC,
        )
        .map_err(|e| mnt_nix(format!("open_tree for /dev/{dev} failed"), e))?;

        // Attach relative to dev_fd
        syscall::move_mount_to_fd(mnt_fd.as_fd(), dev_fd.as_fd(), &dev_cstr)
            .map_err(|e| mnt_nix(format!("move_mount for /dev/{dev} failed"), e))?;
    }

    // /dev/shm — shared memory tmpfs with MS_NOSUID|MS_NODEV, mode=1777
    syscall::mkdirat_all(dev_fd.as_fd(), "shm")
        .map_err(|e| mnt_nix("failed to create /dev/shm", e))?;
    mount_fs(
        c"tmpfs",
        dev_fd.as_fd(),
        "shm",
        syscall::MOUNT_ATTR_NOSUID | syscall::MOUNT_ATTR_NODEV,
        &[(c"mode", c"1777")],
        &[],
        "tmpfs at /dev/shm",
    )?;

    // /dev/pts — isolated devpts instance with MS_NOSUID|MS_NOEXEC
    syscall::mkdirat_all(dev_fd.as_fd(), "pts")
        .map_err(|e| mnt_nix("failed to create /dev/pts", e))?;
    mount_fs(
        c"devpts",
        dev_fd.as_fd(),
        "pts",
        syscall::MOUNT_ATTR_NOSUID | syscall::MOUNT_ATTR_NOEXEC,
        &[(c"ptmxmode", c"0666"), (c"mode", c"620")],
        &[c"newinstance"],
        "devpts at /dev/pts",
    )?;

    // /dev/ptmx -> pts/ptmx (standard devpts setup)
    syscall::symlinkat(c"pts/ptmx", dev_fd.as_fd(), c"ptmx")
        .map_err(|e| mnt_nix("failed to create /dev/ptmx symlink", e))?;

    syscall::symlinkat(c"/proc/self/fd", dev_fd.as_fd(), c"fd")
        .map_err(|e| mnt_nix("failed to create /dev/fd symlink", e))?;
    syscall::symlinkat(c"/proc/self/fd/0", dev_fd.as_fd(), c"stdin")
        .map_err(|e| mnt_nix("failed to create /dev/stdin symlink", e))?;
    syscall::symlinkat(c"/proc/self/fd/1", dev_fd.as_fd(), c"stdout")
        .map_err(|e| mnt_nix("failed to create /dev/stdout symlink", e))?;
    syscall::symlinkat(c"/proc/self/fd/2", dev_fd.as_fd(), c"stderr")
        .map_err(|e| mnt_nix("failed to create /dev/stderr symlink", e))?;

    Ok(())
}

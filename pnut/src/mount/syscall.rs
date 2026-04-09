//! Raw syscall wrappers for the new mount API (Linux 5.2+).
//!
//! Provides safe Rust wrappers around `fsopen`, `fsconfig`, `fsmount`,
//! `move_mount`, `open_tree`, and `mount_setattr`. These syscalls are not
//! yet wrapped by the `nix` or `libc` crates, so we use raw `libc::syscall()`
//! following the same pattern as `clone3` in `namespace.rs`.
//!
//! All fd-returning functions use [`OwnedFd`] for RAII cleanup — fds are
//! automatically closed when dropped, even on error paths.

use nix::errno::Errno;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

// ---------------------------------------------------------------------------
// Syscall numbers (x86_64). These are stable ABI.
// ---------------------------------------------------------------------------
const SYS_FSOPEN: libc::c_long = 430;
const SYS_FSCONFIG: libc::c_long = 431;
const SYS_FSMOUNT: libc::c_long = 432;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOUNT_SETATTR: libc::c_long = 442;
const SYS_PIVOT_ROOT: libc::c_long = 155;
const SYS_UMOUNT2: libc::c_long = 166;

// ---------------------------------------------------------------------------
// Constants not yet in the `libc` crate.
// Values from <linux/mount.h> and <linux/fs.h>.
// ---------------------------------------------------------------------------

/// `fsopen()` flag: set `O_CLOEXEC` on the returned fs_fd.
pub const FSOPEN_CLOEXEC: libc::c_uint = 0x0000_0001;

/// `fsmount()` flag: set `O_CLOEXEC` on the returned mount fd.
pub const FSMOUNT_CLOEXEC: libc::c_uint = 0x0000_0001;

// fsconfig commands
pub const FSCONFIG_SET_FLAG: libc::c_uint = 0;
pub const FSCONFIG_SET_STRING: libc::c_uint = 1;
#[allow(dead_code)]
pub const FSCONFIG_SET_BINARY: libc::c_uint = 2;
#[allow(dead_code)]
pub const FSCONFIG_SET_PATH: libc::c_uint = 3;
#[allow(dead_code)]
pub const FSCONFIG_SET_PATH_EMPTY: libc::c_uint = 4;
#[allow(dead_code)]
pub const FSCONFIG_SET_FD: libc::c_uint = 5;
pub const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
#[allow(dead_code)]
pub const FSCONFIG_CMD_RECONFIGURE: libc::c_uint = 7;

// move_mount flags
pub const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
#[allow(dead_code)]
pub const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;

// open_tree flags
pub const OPEN_TREE_CLONE: libc::c_uint = 0x0000_0001;
pub const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;

// mount_setattr flags (struct mount_attr.attr_set / attr_clr)
pub const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
pub const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
pub const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
pub const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;
#[allow(dead_code)]
pub const MOUNT_ATTR_NOSYMFOLLOW: u64 = 0x0020_0000;

// mount_attr.propagation values (from <linux/mount.h>)
/// Make mount point private — changes don't propagate.
pub const MS_PRIVATE: u64 = 1 << 18; // 0x40000

// umount2 flags
/// Detach the filesystem lazily — make it invisible, clean up when last ref drops.
pub const MNT_DETACH: libc::c_int = 2;

// AT_* flags used with mount_setattr and open_tree
pub const AT_EMPTY_PATH: libc::c_uint = 0x1000;
pub const AT_RECURSIVE: libc::c_uint = 0x8000;

// ---------------------------------------------------------------------------
// mount_attr struct for mount_setattr(2)
// ---------------------------------------------------------------------------

/// Kernel `struct mount_attr` — used with `mount_setattr(2)`.
#[repr(C)]
pub struct MountAttr {
    pub attr_set: u64,
    pub attr_clr: u64,
    pub propagation: u64,
    pub userns_fd: u64,
}

impl MountAttr {
    /// Create a zeroed `mount_attr`.
    pub fn new() -> Self {
        Self {
            attr_set: 0,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Syscall wrappers
// ---------------------------------------------------------------------------

/// Open a filesystem context for configuration.
///
/// Returns an fd that can be used with `fsconfig()` to set options,
/// then `fsmount()` to create a detached mount. On error, the kernel
/// may write a human-readable error message to this fd (readable via
/// `read_fs_error_log()`).
///
/// Always passes `FSOPEN_CLOEXEC`.
pub fn fsopen(fs_name: &CStr) -> Result<OwnedFd, Errno> {
    let ret = unsafe { libc::syscall(SYS_FSOPEN, fs_name.as_ptr(), FSOPEN_CLOEXEC) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Read the kernel error log from an fs_fd after a failed `fsconfig()`.
///
/// The kernel writes human-readable error descriptions to the fs_fd.
/// Returns `None` if nothing is available to read.
pub fn read_fs_error_log(fs_fd: BorrowedFd<'_>) -> Option<String> {
    let mut buf = [0u8; 1024];
    let n = unsafe { libc::read(fs_fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n <= 0 {
        return None;
    }
    let s = String::from_utf8_lossy(&buf[..n as usize]);
    // Trim trailing newlines/nulls
    let trimmed = s.trim_end_matches(['\n', '\0']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Set a string option on a filesystem context.
///
/// Equivalent to `fsconfig(fd, FSCONFIG_SET_STRING, key, value, 0)`.
pub fn fsconfig_set_string(fs_fd: BorrowedFd<'_>, key: &CStr, value: &CStr) -> Result<(), Errno> {
    let ret = unsafe {
        libc::syscall(
            SYS_FSCONFIG,
            fs_fd.as_raw_fd(),
            FSCONFIG_SET_STRING,
            key.as_ptr(),
            value.as_ptr(),
            0,
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// Set a boolean flag on a filesystem context.
///
/// Equivalent to `fsconfig(fd, FSCONFIG_SET_FLAG, key, NULL, 0)`.
pub fn fsconfig_set_flag(fs_fd: BorrowedFd<'_>, key: &CStr) -> Result<(), Errno> {
    let ret = unsafe {
        libc::syscall(
            SYS_FSCONFIG,
            fs_fd.as_raw_fd(),
            FSCONFIG_SET_FLAG,
            key.as_ptr(),
            std::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// Finalize the filesystem configuration and create a superblock.
///
/// Equivalent to `fsconfig(fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0)`.
/// After this, the fs_fd can be passed to `fsmount()`.
///
/// On failure, reads the kernel error log from `fs_fd` and returns it
/// as part of the error string via the second element of the tuple.
pub fn fsconfig_create(fs_fd: BorrowedFd<'_>) -> Result<(), (Errno, Option<String>)> {
    let ret = unsafe {
        libc::syscall(
            SYS_FSCONFIG,
            fs_fd.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if ret < 0 {
        let errno = Errno::last();
        let log = read_fs_error_log(fs_fd);
        return Err((errno, log));
    }
    Ok(())
}

/// Create a detached mount from a configured filesystem context.
///
/// `fs_fd` must have been finalized with `fsconfig_create()`.
/// `mount_attr_flags` is a bitmask of `MOUNT_ATTR_*` flags.
///
/// Always passes `FSMOUNT_CLOEXEC`.
pub fn fsmount(fs_fd: BorrowedFd<'_>, mount_attr_flags: u64) -> Result<OwnedFd, Errno> {
    let ret = unsafe {
        libc::syscall(
            SYS_FSMOUNT,
            fs_fd.as_raw_fd(),
            FSMOUNT_CLOEXEC,
            mount_attr_flags as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Move a mount from one location to another.
///
/// This is the new API equivalent of the "attach" step: it takes a
/// detached mount fd (from `fsmount()` or `open_tree(OPEN_TREE_CLONE)`)
/// and attaches it at the target path.
///
/// Common usage: `move_mount(mnt_fd, "", to_dir_fd, "relative/path", MOVE_MOUNT_F_EMPTY_PATH)`
pub fn move_mount(
    from_fd: BorrowedFd<'_>,
    from_path: &CStr,
    to_fd: BorrowedFd<'_>,
    to_path: &CStr,
    flags: libc::c_uint,
) -> Result<(), Errno> {
    let ret = unsafe {
        libc::syscall(
            SYS_MOVE_MOUNT,
            from_fd.as_raw_fd(),
            from_path.as_ptr(),
            to_fd.as_raw_fd(),
            to_path.as_ptr(),
            flags,
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// Convenience wrapper: move a detached mount (from fsmount) to an absolute path.
///
/// Uses `AT_FDCWD` as the target directory and `MOVE_MOUNT_F_EMPTY_PATH`
/// for the source (since the fd *is* the mount).
pub fn move_mount_to_path(mnt_fd: BorrowedFd<'_>, target: &CStr) -> Result<(), Errno> {
    let at_fdcwd_fd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
    move_mount(mnt_fd, c"", at_fdcwd_fd, target, MOVE_MOUNT_F_EMPTY_PATH)
}

/// Clone or reference an existing mount subtree.
///
/// With `OPEN_TREE_CLONE`, creates a detached copy of the mount at `path`.
/// The returned fd can be passed to `move_mount()` or `mount_setattr()`.
///
/// Typically combined with `OPEN_TREE_CLOEXEC` and optionally `AT_RECURSIVE`.
pub fn open_tree(
    dir_fd: BorrowedFd<'_>,
    path: &CStr,
    flags: libc::c_uint,
) -> Result<OwnedFd, Errno> {
    let ret = unsafe { libc::syscall(SYS_OPEN_TREE, dir_fd.as_raw_fd(), path.as_ptr(), flags) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Set mount attributes on an existing mount.
///
/// Can atomically apply read-only, nosuid, nodev, noexec in a single call,
/// replacing the old mount-then-remount pattern.
///
/// `flags` is typically `AT_EMPTY_PATH` (when operating on `dir_fd` itself)
/// or `AT_RECURSIVE` (to apply to all submounts).
pub fn mount_setattr(
    dir_fd: BorrowedFd<'_>,
    path: &CStr,
    flags: libc::c_uint,
    attr: &MountAttr,
) -> Result<(), Errno> {
    let ret = unsafe {
        libc::syscall(
            SYS_MOUNT_SETATTR,
            dir_fd.as_raw_fd(),
            path.as_ptr(),
            flags,
            attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// Convenience wrapper: move a detached mount to a relative path under a directory fd.
///
/// Uses `MOVE_MOUNT_F_EMPTY_PATH` for the source (since the fd *is* the mount)
/// and the provided `to_fd` + `rel_path` for the target.
pub fn move_mount_to_fd(
    mnt_fd: BorrowedFd<'_>,
    to_fd: BorrowedFd<'_>,
    rel_path: &CStr,
) -> Result<(), Errno> {
    move_mount(mnt_fd, c"", to_fd, rel_path, MOVE_MOUNT_F_EMPTY_PATH)
}

/// Create nested directories relative to a directory fd.
///
/// Equivalent to `mkdir -p` but using `mkdirat` relative to `dir_fd`.
/// Each component is created with mode `0o755`. Ignores `EEXIST`.
pub fn mkdirat_all(dir_fd: BorrowedFd<'_>, path: &str) -> Result<(), Errno> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Ok(());
    }

    let mut cumulative = String::new();
    for component in path.split('/') {
        if component.is_empty() {
            continue;
        }
        if !cumulative.is_empty() {
            cumulative.push('/');
        }
        cumulative.push_str(component);

        let c_path = std::ffi::CString::new(cumulative.as_str()).map_err(|_| Errno::EINVAL)?;
        let ret = unsafe { libc::mkdirat(dir_fd.as_raw_fd(), c_path.as_ptr(), 0o755) };
        if ret < 0 {
            let err = Errno::last();
            if err != Errno::EEXIST {
                return Err(err);
            }
        }
    }
    Ok(())
}

/// Create a file mount point (empty file) relative to a directory fd.
///
/// Uses `openat` with `O_CREAT | O_WRONLY | O_CLOEXEC`. The returned fd is
/// wrapped in [`OwnedFd`] for RAII cleanup — it is closed on drop.
pub fn create_file_at(dir_fd: BorrowedFd<'_>, rel_path: &CStr) -> Result<(), Errno> {
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            rel_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(Errno::last());
    }
    // Wrap in OwnedFd so it is closed on drop, even if this function grows
    // additional fallible steps in the future.
    let _owned = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(())
}

/// Write content to a file relative to a directory fd.
///
/// Creates (or truncates) the file and writes `content` to it. The fd is
/// wrapped in [`OwnedFd`] for RAII cleanup — it is closed on drop even if
/// the write loop encounters an error partway through.
pub fn write_file_at(dir_fd: BorrowedFd<'_>, rel_path: &CStr, content: &[u8]) -> Result<(), Errno> {
    let raw_fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            rel_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC,
            0o644,
        )
    };
    if raw_fd < 0 {
        return Err(Errno::last());
    }
    // OwnedFd ensures close-on-drop for all exit paths (success, error, panic).
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let mut written = 0usize;
    while written < content.len() {
        let n = unsafe {
            libc::write(
                fd.as_raw_fd(),
                content[written..].as_ptr().cast(),
                content.len() - written,
            )
        };
        if n < 0 {
            return Err(Errno::last());
        }
        written += n as usize;
    }
    Ok(())
}

/// Open a directory relative to a directory fd.
///
/// Returns an `OwnedFd` with `O_RDONLY | O_DIRECTORY | O_CLOEXEC`.
pub fn openat_dir(dir_fd: BorrowedFd<'_>, path: &CStr) -> Result<OwnedFd, Errno> {
    let fd = unsafe {
        libc::openat(
            dir_fd.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(Errno::last());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `pivot_root(new_root, put_old)` via raw syscall.
pub fn pivot_root(new_root: &CStr, put_old: &CStr) -> Result<(), Errno> {
    let ret = unsafe { libc::syscall(SYS_PIVOT_ROOT, new_root.as_ptr(), put_old.as_ptr()) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// `umount2(target, flags)` via raw syscall.
pub fn umount2(target: &CStr, flags: libc::c_int) -> Result<(), Errno> {
    let ret = unsafe { libc::syscall(SYS_UMOUNT2, target.as_ptr(), flags) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// `fchdir(fd)` — change working directory to an open directory fd.
pub fn fchdir(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    let ret = unsafe { libc::fchdir(fd.as_raw_fd()) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// `symlinkat(target, dirfd, linkpath)` — create a symlink relative to a directory fd.
pub fn symlinkat(target: &CStr, dir_fd: BorrowedFd<'_>, link_path: &CStr) -> Result<(), Errno> {
    let ret = unsafe { libc::symlinkat(target.as_ptr(), dir_fd.as_raw_fd(), link_path.as_ptr()) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

/// Check if a path relative to `dir_fd` is a directory (using `fstatat`).
pub fn is_dir_at(dir_fd: BorrowedFd<'_>, path: &CStr) -> bool {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstatat(dir_fd.as_raw_fd(), path.as_ptr(), &mut stat, 0) };
    ret == 0 && (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

/// `unlinkat(dirfd, path, flags)` — remove a file or directory relative to a directory fd.
pub fn unlinkat(dir_fd: BorrowedFd<'_>, path: &CStr, flags: libc::c_int) -> Result<(), Errno> {
    let ret = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), path.as_ptr(), flags) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    #[test]
    fn fsopen_nonexistent_fs_returns_error() {
        let err = fsopen(c"definitely_not_a_real_fs").unwrap_err();
        // In a user namespace or unprivileged context, the kernel may return
        // EPERM (no privilege to create the fs context) before even checking
        // the fs type. Both ENODEV and EPERM are valid outcomes.
        assert!(
            err == Errno::ENODEV || err == Errno::EPERM,
            "fsopen with bogus fs type should return ENODEV or EPERM, got {err}"
        );
    }

    #[test]
    fn fsopen_tmpfs_succeeds() {
        // This test requires running in a user namespace or as root,
        // but fsopen("tmpfs") should work in most test environments.
        // If it fails with EPERM, that's a capability issue, not a code bug.
        match fsopen(c"tmpfs") {
            Ok(fd) => {
                // fd is valid and will be closed on drop
                assert!(fd.as_raw_fd() >= 0);
            }
            Err(Errno::EPERM) => {
                // Running without sufficient privileges — skip gracefully
            }
            Err(e) => panic!("unexpected error from fsopen(\"tmpfs\"): {e}"),
        }
    }

    #[test]
    fn fsconfig_create_on_tmpfs() {
        let fs_fd = match fsopen(c"tmpfs") {
            Ok(fd) => fd,
            Err(Errno::EPERM) => return, // skip
            Err(e) => panic!("fsopen failed: {e}"),
        };

        // Create the superblock — should succeed with default config
        fsconfig_create(fs_fd.as_fd()).expect("fsconfig CMD_CREATE should succeed");

        // Now fsmount should work
        let mnt_fd = fsmount(fs_fd.as_fd(), 0).expect("fsmount should succeed");
        assert!(mnt_fd.as_raw_fd() >= 0);
        // Both fds closed on drop
    }

    #[test]
    fn fsconfig_set_string_on_tmpfs() {
        let fs_fd = match fsopen(c"tmpfs") {
            Ok(fd) => fd,
            Err(Errno::EPERM) => return,
            Err(e) => panic!("fsopen failed: {e}"),
        };

        // Set size option
        fsconfig_set_string(fs_fd.as_fd(), c"size", c"4096")
            .expect("fsconfig SET_STRING size should succeed");

        fsconfig_create(fs_fd.as_fd())
            .expect("fsconfig CMD_CREATE should succeed after setting size");
    }

    #[test]
    fn fsconfig_invalid_key_returns_error() {
        let fs_fd = match fsopen(c"tmpfs") {
            Ok(fd) => fd,
            Err(Errno::EPERM) => return,
            Err(e) => panic!("fsopen failed: {e}"),
        };

        let err =
            fsconfig_set_string(fs_fd.as_fd(), c"nonexistent_option_xyz", c"value").unwrap_err();
        // The kernel returns EINVAL for unknown options
        assert_eq!(
            err,
            Errno::EINVAL,
            "bad fsconfig key should return EINVAL, got {err}"
        );
    }

    #[test]
    fn read_fs_error_log_after_bad_config() {
        let fs_fd = match fsopen(c"tmpfs") {
            Ok(fd) => fd,
            Err(Errno::EPERM) => return,
            Err(e) => panic!("fsopen failed: {e}"),
        };

        // Set an invalid option to trigger an error log entry
        let _ = fsconfig_set_string(fs_fd.as_fd(), c"nonexistent_option_xyz", c"value");

        // The kernel should have written an error message to the fs_fd
        let log = read_fs_error_log(fs_fd.as_fd());
        // The log may or may not be present depending on kernel version,
        // but if present it should contain something meaningful
        if let Some(msg) = log {
            assert!(!msg.is_empty(), "error log should not be empty");
        }
    }

    #[test]
    fn fsmount_without_create_fails() {
        let fs_fd = match fsopen(c"tmpfs") {
            Ok(fd) => fd,
            Err(Errno::EPERM) => return,
            Err(e) => panic!("fsopen failed: {e}"),
        };

        // fsmount without CMD_CREATE should fail
        let err = fsmount(fs_fd.as_fd(), 0).unwrap_err();
        assert_eq!(
            err,
            Errno::EINVAL,
            "fsmount without CMD_CREATE should return EINVAL, got {err}"
        );
    }

    #[test]
    fn mount_setattr_on_non_mount_fd() {
        // Use a pipe fd — valid fd but not a mount, so mount_setattr should fail.
        // In unprivileged context, may return EPERM instead of EINVAL.
        let (read_fd, _write_fd) = nix::unistd::pipe().expect("pipe");
        let attr = MountAttr::new();
        let err = mount_setattr(read_fd.as_fd(), c"", AT_EMPTY_PATH, &attr).unwrap_err();
        assert!(
            err == Errno::EBADF || err == Errno::EINVAL || err == Errno::EPERM,
            "mount_setattr on non-mount fd should fail, got {err}"
        );
    }

    #[test]
    fn open_tree_nonexistent_path() {
        let at_fdcwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
        let err = open_tree(
            at_fdcwd,
            c"/nonexistent/path/for/open_tree_test",
            OPEN_TREE_CLOEXEC,
        )
        .unwrap_err();
        assert_eq!(
            err,
            Errno::ENOENT,
            "open_tree on nonexistent path should return ENOENT, got {err}"
        );
    }

    #[test]
    fn move_mount_non_mount_source_fd() {
        // Use a pipe fd — valid fd but not a mount, so move_mount should fail.
        // In unprivileged context, may return EPERM instead of EINVAL.
        let (read_fd, _write_fd) = nix::unistd::pipe().expect("pipe");
        let at_fdcwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
        let err = move_mount(
            read_fd.as_fd(),
            c"",
            at_fdcwd,
            c"/tmp",
            MOVE_MOUNT_F_EMPTY_PATH,
        )
        .unwrap_err();
        assert!(
            err == Errno::EBADF
                || err == Errno::EINVAL
                || err == Errno::ENOENT
                || err == Errno::EPERM,
            "move_mount with non-mount fd should fail, got {err}"
        );
    }
}

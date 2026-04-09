//! Raw syscall wrappers for the new mount API (Linux 5.2+).

use core::ffi::CStr;

use crate::error::{Errno, Result};
use crate::fd::OwnedFd;

pub(crate) const FSOPEN_CLOEXEC: libc::c_uint = 0x0000_0001;
pub(crate) const FSMOUNT_CLOEXEC: libc::c_uint = 0x0000_0001;
pub(crate) const FSCONFIG_SET_FLAG: libc::c_uint = 0;
pub(crate) const FSCONFIG_SET_STRING: libc::c_uint = 1;
pub(crate) const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
pub(crate) const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
pub(crate) const MNT_DETACH: libc::c_int = 2;
pub(crate) const MS_PRIVATE: u64 = 1 << 18;

#[repr(C)]
pub(crate) struct MountAttr {
    pub(crate) attr_set: u64,
    pub(crate) attr_clr: u64,
    pub(crate) propagation: u64,
    pub(crate) userns_fd: u64,
}

impl MountAttr {
    pub(crate) const fn new() -> Self {
        Self {
            attr_set: 0,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FsConfigCreateError {
    pub(crate) errno: Errno,
    pub(crate) log_len: usize,
}

pub(crate) fn fsopen(fs_name: &CStr) -> Result<OwnedFd> {
    let ret = unsafe { libc::syscall(libc::SYS_fsopen, fs_name.as_ptr(), FSOPEN_CLOEXEC) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(OwnedFd::new(ret as libc::c_int))
}

pub(crate) fn fsconfig_set_string(fs_fd: libc::c_int, key: &CStr, value: &CStr) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_fd,
            FSCONFIG_SET_STRING,
            key.as_ptr(),
            value.as_ptr(),
            0,
        )
    };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn fsconfig_set_flag(fs_fd: libc::c_int, key: &CStr) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_fd,
            FSCONFIG_SET_FLAG,
            key.as_ptr(),
            core::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn fsconfig_create(
    fs_fd: libc::c_int,
    log_buf: &mut [u8; 1024],
) -> core::result::Result<(), FsConfigCreateError> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_fd,
            FSCONFIG_CMD_CREATE,
            core::ptr::null::<libc::c_char>(),
            core::ptr::null::<libc::c_char>(),
            0,
        )
    };
    if ret >= 0 {
        return Ok(());
    }

    let errno = Errno::last();
    // The kernel writes human-readable setup errors back to the fs fd. Capture
    // them now while the fd still points at the failed filesystem context.
    let log_len = read_fs_error_log(fs_fd, log_buf);
    Err(FsConfigCreateError { errno, log_len })
}

pub(crate) fn fsmount(fs_fd: libc::c_int, mount_attr_flags: u64) -> Result<OwnedFd> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            fs_fd,
            FSMOUNT_CLOEXEC,
            mount_attr_flags as libc::c_uint,
        )
    };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(OwnedFd::new(ret as libc::c_int))
}

pub(crate) fn move_mount(
    from_fd: libc::c_int,
    from_path: &CStr,
    to_fd: libc::c_int,
    to_path: &CStr,
    flags: libc::c_uint,
) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            from_fd,
            from_path.as_ptr(),
            to_fd,
            to_path.as_ptr(),
            flags,
        )
    };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn move_mount_to_path(mnt_fd: libc::c_int, target: &CStr) -> Result<()> {
    move_mount(mnt_fd, c"", libc::AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH)
}

pub(crate) fn open_tree(dir_fd: libc::c_int, path: &CStr, flags: libc::c_uint) -> Result<OwnedFd> {
    let ret = unsafe { libc::syscall(libc::SYS_open_tree, dir_fd, path.as_ptr(), flags) };
    if ret < 0 {
        return Err(Errno::last());
    }
    Ok(OwnedFd::new(ret as libc::c_int))
}

pub(crate) fn mount_setattr(
    dir_fd: libc::c_int,
    path: &CStr,
    flags: libc::c_uint,
    attr: &MountAttr,
) -> Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            dir_fd,
            path.as_ptr(),
            flags,
            attr as *const MountAttr,
            core::mem::size_of::<MountAttr>(),
        )
    };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn move_mount_to_fd(
    mnt_fd: libc::c_int,
    to_fd: libc::c_int,
    rel_path: &CStr,
) -> Result<()> {
    move_mount(mnt_fd, c"", to_fd, rel_path, MOVE_MOUNT_F_EMPTY_PATH)
}

pub(crate) fn mkdirat_all(dir_fd: libc::c_int, path: &CStr) -> Result<()> {
    let bytes = path.to_bytes();
    if bytes.is_empty() {
        return Ok(());
    }

    // Build one cumulative relative path and issue mkdirat on each prefix.
    // That keeps directory creation fd-relative without allocating path
    // components or temporary strings in the child.
    let mut cumulative = [0u8; 4096];
    let mut cumulative_len = 0usize;
    let mut component_start = 0usize;
    let mut idx = 0usize;

    while idx <= bytes.len() {
        if idx == bytes.len() || bytes[idx] == b'/' {
            if idx > component_start {
                let component = &bytes[component_start..idx];
                if cumulative_len != 0 {
                    if cumulative_len + 1 >= cumulative.len() {
                        return Err(Errno::new(libc::ENAMETOOLONG));
                    }
                    cumulative[cumulative_len] = b'/';
                    cumulative_len += 1;
                }
                if cumulative_len + component.len() + 1 > cumulative.len() {
                    return Err(Errno::new(libc::ENAMETOOLONG));
                }
                cumulative[cumulative_len..cumulative_len + component.len()]
                    .copy_from_slice(component);
                cumulative_len += component.len();
                cumulative[cumulative_len] = 0;
                let c_path =
                    unsafe { CStr::from_bytes_with_nul_unchecked(&cumulative[..=cumulative_len]) };
                let ret = unsafe { libc::mkdirat(dir_fd, c_path.as_ptr(), 0o755) };
                if ret < 0 {
                    let err = Errno::last();
                    if err.0 != libc::EEXIST {
                        return Err(err);
                    }
                }
            }
            component_start = idx + 1;
        }
        idx += 1;
    }

    Ok(())
}

pub(crate) fn create_file_at(dir_fd: libc::c_int, rel_path: &CStr) -> Result<()> {
    let fd = unsafe {
        libc::openat(
            dir_fd,
            rel_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_CLOEXEC,
            0o644,
        )
    };
    if fd < 0 {
        return Err(Errno::last());
    }
    let _owned = OwnedFd::new(fd);
    Ok(())
}

pub(crate) fn write_file_at(dir_fd: libc::c_int, rel_path: &CStr, content: &[u8]) -> Result<()> {
    let raw_fd = unsafe {
        libc::openat(
            dir_fd,
            rel_path.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC,
            0o644,
        )
    };
    if raw_fd < 0 {
        return Err(Errno::last());
    }
    let fd = OwnedFd::new(raw_fd);
    let mut written = 0usize;
    while written < content.len() {
        let n = unsafe {
            libc::write(
                fd.as_raw(),
                content[written..].as_ptr().cast::<libc::c_void>(),
                content.len() - written,
            )
        };
        if n < 0 {
            let err = Errno::last();
            if err.0 == libc::EINTR {
                continue;
            }
            return Err(err);
        }
        written += n as usize;
    }
    Ok(())
}

pub(crate) fn openat_dir(dir_fd: libc::c_int, path: &CStr) -> Result<OwnedFd> {
    let fd = unsafe {
        libc::openat(
            dir_fd,
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(Errno::last());
    }
    Ok(OwnedFd::new(fd))
}

pub(crate) fn pivot_root(new_root: &CStr, put_old: &CStr) -> Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn umount2(target: &CStr, flags: libc::c_int) -> Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_umount2, target.as_ptr(), flags) };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn fchdir(fd: libc::c_int) -> Result<()> {
    let ret = unsafe { libc::fchdir(fd) };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn symlinkat(target: &CStr, dir_fd: libc::c_int, link_path: &CStr) -> Result<()> {
    let ret = unsafe { libc::symlinkat(target.as_ptr(), dir_fd, link_path.as_ptr()) };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

pub(crate) fn unlinkat(dir_fd: libc::c_int, path: &CStr, flags: libc::c_int) -> Result<()> {
    let ret = unsafe { libc::unlinkat(dir_fd, path.as_ptr(), flags) };
    if ret < 0 { Err(Errno::last()) } else { Ok(()) }
}

fn read_fs_error_log(fs_fd: libc::c_int, buf: &mut [u8; 1024]) -> usize {
    let n = unsafe { libc::read(fs_fd, buf.as_mut_ptr().cast::<libc::c_void>(), buf.len()) };
    if n <= 0 { 0 } else { n as usize }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::ffi::CString;
    use std::format;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd as StdOwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};

    fn unique_tempdir(tag: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("pnut-child-{tag}-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn path_cstr(path: &Path) -> CString {
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }

    fn open_dir(path: &Path) -> StdOwnedFd {
        let c_path = path_cstr(path);
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(
            fd >= 0,
            "open directory failed: {}",
            std::io::Error::last_os_error()
        );
        unsafe { StdOwnedFd::from_raw_fd(fd) }
    }

    #[test]
    fn fsopen_nonexistent_fs_returns_error() {
        let err = fsopen(c"definitely_not_a_real_fs").unwrap_err();
        assert!(
            err.0 == libc::ENODEV || err.0 == libc::EPERM,
            "fsopen with bogus fs type should return ENODEV or EPERM, got {:?}",
            err
        );
    }

    #[test]
    fn fsopen_tmpfs_succeeds() {
        match fsopen(c"tmpfs") {
            Ok(fd) => assert!(fd.as_raw() >= 0),
            Err(err) if err.0 == libc::EPERM => {}
            Err(err) => panic!("unexpected error from fsopen(\"tmpfs\"): {:?}", err),
        }
    }

    #[test]
    fn fsconfig_create_on_tmpfs() {
        let fs_fd = match fsopen(c"tmpfs") {
            Ok(fd) => fd,
            Err(err) if err.0 == libc::EPERM => return,
            Err(err) => panic!("fsopen failed: {:?}", err),
        };

        let mut log = [0u8; 1024];
        fsconfig_create(fs_fd.as_raw(), &mut log).expect("fsconfig create should succeed");
        let mnt_fd = fsmount(fs_fd.as_raw(), 0).expect("fsmount should succeed");
        assert!(mnt_fd.as_raw() >= 0);
    }

    #[test]
    fn open_tree_nonexistent_path() {
        let err = open_tree(
            libc::AT_FDCWD,
            c"/nonexistent/path/for/open_tree_test",
            libc::OPEN_TREE_CLOEXEC,
        )
        .unwrap_err();
        assert_eq!(err.0, libc::ENOENT);
    }

    #[test]
    fn mkdirat_all_creates_nested_directories() {
        let dir = unique_tempdir("mkdirat");
        let dir_fd = open_dir(&dir);

        mkdirat_all(dir_fd.as_raw_fd(), c"a/b/c").expect("mkdirat_all should succeed");
        assert!(dir.join("a").is_dir());
        assert!(dir.join("a/b").is_dir());
        assert!(dir.join("a/b/c").is_dir());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn create_and_write_file_at_populate_expected_paths() {
        let dir = unique_tempdir("file-at");
        let dir_fd = open_dir(&dir);

        mkdirat_all(dir_fd.as_raw_fd(), c"nested").expect("mkdir nested");
        create_file_at(dir_fd.as_raw_fd(), c"nested/empty.txt").expect("create empty file");
        write_file_at(dir_fd.as_raw_fd(), c"nested/data.txt", b"hello world").expect("write file");

        assert!(dir.join("nested/empty.txt").is_file());
        assert_eq!(
            std::fs::read(dir.join("nested/data.txt")).unwrap(),
            b"hello world"
        );

        std::fs::remove_dir_all(dir).unwrap();
    }
}

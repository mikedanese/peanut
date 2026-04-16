//! Filesystem staging, mount setup, and pivot-root support.

mod dev;
mod syscall;

use core::ffi::CStr;

use crate::error::Errno;
use crate::fd::OwnedFd;
use crate::io::write_stderr;
use crate::process;
use crate::spec::{
    BindMount, FileMount, HidePid, MountEntry, MountPlan, MqueueMount, ProcMount, ProcSubset,
    TmpfsMount,
};

const NEW_ROOT_ABS: &CStr = c"/tmp/pnut-newroot";
const ROOT_SLASH: &CStr = c"/";
const DOT: &CStr = c".";
const EMPTY_PATH: &CStr = c"";
const PUT_OLD: &CStr = c".old_root";
const PUT_OLD_ABS: &CStr = c"/.old_root";
const CONTENT_STAGING: &CStr = c".pnut-content";
const CONTENT_STAGING_ABS: &CStr = c"/.pnut-content";
const MAX_PATH_BYTES: usize = 4096;
const FSCONFIG_LOG_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountError {
    pub(crate) errno: Errno,
    pub(crate) detail: i32,
}

impl MountError {
    fn new(errno: Errno, detail: i32) -> Self {
        Self { errno, detail }
    }
}

pub(crate) fn setup(plan: &MountPlan<'_>) -> core::result::Result<(), MountError> {
    let root_fd = setup_root().map_err(|err| MountError::new(err, 0))?;
    syscall::mkdirat_all(root_fd.as_raw(), PUT_OLD).map_err(|err| MountError::new(err, 0))?;
    syscall::mkdirat_all(root_fd.as_raw(), CONTENT_STAGING)
        .map_err(|err| MountError::new(err, 0))?;
    let staging_fd = syscall::openat_dir(root_fd.as_raw(), CONTENT_STAGING)
        .map_err(|err| MountError::new(err, 0))?;

    // Lay down the managed /dev tmpfs first so user bind-mounts under /dev
    // (e.g. /dev/nvidia0) land on top and aren't shadowed.
    dev::setup_dev(root_fd.as_raw()).map_err(|err| MountError::new(err, 2000))?;

    let mut content_count = 0usize;
    for (idx, entry) in plan.entries.iter().enumerate() {
        process_mount_entry(
            entry,
            root_fd.as_raw(),
            staging_fd.as_raw(),
            &mut content_count,
        )
        .map_err(|err| MountError::new(err, 1000 + idx as i32))?;
    }
    pivot_and_cleanup(root_fd.as_raw(), staging_fd.as_raw(), content_count)
        .map_err(|err| MountError::new(err, 3000))?;
    Ok(())
}

fn setup_root() -> crate::error::Result<OwnedFd> {
    let mut prop_attr = syscall::MountAttr::new();
    prop_attr.propagation = syscall::MS_PRIVATE;
    // Make the whole mount tree private up front so nothing from this child
    // leaks back into the parent namespace through shared propagation.
    syscall::mount_setattr(
        libc::AT_FDCWD,
        ROOT_SLASH,
        libc::AT_RECURSIVE as libc::c_uint,
        &prop_attr,
    )?;

    let ret = unsafe { libc::mkdir(NEW_ROOT_ABS.as_ptr(), 0o755) };
    if ret < 0 {
        let err = Errno::last();
        if err.0 != libc::EEXIST {
            return Err(err);
        }
    }

    // Build the new root as a detached tmpfs, then attach it at the temporary
    // staging path so the rest of the tree can be assembled fd-relatively.
    let fs_fd = syscall::fsopen(c"tmpfs")?;
    let mut log_buf = [0u8; FSCONFIG_LOG_BYTES];
    if let Err(err) = syscall::fsconfig_create(fs_fd.as_raw(), &mut log_buf) {
        return Err(report_fsconfig_failure(err, &log_buf, b"mount"));
    }

    let mnt_fd = syscall::fsmount(fs_fd.as_raw(), 0)?;
    syscall::move_mount_to_path(mnt_fd.as_raw(), NEW_ROOT_ABS)?;
    syscall::openat_dir(libc::AT_FDCWD, NEW_ROOT_ABS)
}

fn pivot_and_cleanup(
    root_fd: libc::c_int,
    staging_fd: libc::c_int,
    content_count: usize,
) -> crate::error::Result<()> {
    // The fd-based pivot keeps the child path free of path lookups against the
    // old root once the new filesystem tree is ready.
    syscall::fchdir(root_fd)?;
    syscall::pivot_root(DOT, DOT)?;
    syscall::umount2(DOT, syscall::MNT_DETACH)?;

    cleanup_staging(staging_fd, content_count)?;
    let _ = syscall::unlinkat(libc::AT_FDCWD, PUT_OLD_ABS, libc::AT_REMOVEDIR);
    let _ = syscall::unlinkat(libc::AT_FDCWD, CONTENT_STAGING_ABS, libc::AT_REMOVEDIR);

    process::chdir(ROOT_SLASH)
}

fn cleanup_staging(staging_fd: libc::c_int, content_count: usize) -> crate::error::Result<()> {
    let mut name_buf = [0u8; 64];
    for idx in 0..content_count {
        let name = staging_name_cstr(idx, &mut name_buf)?;
        syscall::unlinkat(staging_fd, name, 0)?;
    }
    Ok(())
}

fn process_mount_entry(
    entry: &MountEntry<'_>,
    root_fd: libc::c_int,
    staging_fd: libc::c_int,
    content_count: &mut usize,
) -> crate::error::Result<()> {
    match *entry {
        MountEntry::Bind(bind) => process_bind_mount(&bind, root_fd),
        MountEntry::Tmpfs(tmpfs) => process_tmpfs_mount(&tmpfs, root_fd),
        MountEntry::Proc(proc_mount) => process_proc_mount(&proc_mount, root_fd),
        MountEntry::Mqueue(mqueue) => process_mqueue_mount(&mqueue, root_fd),
        MountEntry::File(file) => process_file_mount(&file, root_fd, staging_fd, content_count),
    }
}

fn process_bind_mount(entry: &BindMount<'_>, root_fd: libc::c_int) -> crate::error::Result<()> {
    ensure_mount_point(root_fd, entry.dst_rel, entry.src_is_dir)?;

    let flags =
        libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC | libc::AT_RECURSIVE as libc::c_uint;
    let mnt_fd = syscall::open_tree(libc::AT_FDCWD, entry.src, flags)?;

    if entry.read_only {
        let mut attr = syscall::MountAttr::new();
        attr.attr_set = libc::MOUNT_ATTR_RDONLY;
        // Apply read-only while the mount is still detached so the target is
        // never visible as writable inside the sandbox.
        syscall::mount_setattr(
            mnt_fd.as_raw(),
            EMPTY_PATH,
            libc::AT_EMPTY_PATH as libc::c_uint,
            &attr,
        )?;
    }

    syscall::move_mount_to_fd(mnt_fd.as_raw(), root_fd, entry.dst_rel)
}

fn process_tmpfs_mount(entry: &TmpfsMount<'_>, root_fd: libc::c_int) -> crate::error::Result<()> {
    syscall::mkdirat_all(root_fd, entry.dst_rel)?;

    let fs_fd = syscall::fsopen(c"tmpfs")?;
    let mut size_buf = [0u8; 32];
    let mut mode_buf = [0u8; 16];

    if let Some(size_bytes) = entry.size_bytes {
        let size_cstr = decimal_cstr(size_bytes, &mut size_buf)?;
        syscall::fsconfig_set_string(fs_fd.as_raw(), c"size", size_cstr)?;
    }
    if let Some(mode) = entry.mode {
        let mode_cstr = octal_cstr(mode, &mut mode_buf)?;
        syscall::fsconfig_set_string(fs_fd.as_raw(), c"mode", mode_cstr)?;
    }

    let mut log_buf = [0u8; FSCONFIG_LOG_BYTES];
    if let Err(err) = syscall::fsconfig_create(fs_fd.as_raw(), &mut log_buf) {
        return Err(report_fsconfig_failure(err, &log_buf, b"mount"));
    }

    let mnt_fd = syscall::fsmount(fs_fd.as_raw(), 0)?;
    if entry.read_only {
        let mut attr = syscall::MountAttr::new();
        attr.attr_set = libc::MOUNT_ATTR_RDONLY;
        // Like bind mounts, tmpfs becomes read-only before attach so there is
        // no writable window after move_mount().
        syscall::mount_setattr(
            mnt_fd.as_raw(),
            EMPTY_PATH,
            libc::AT_EMPTY_PATH as libc::c_uint,
            &attr,
        )?;
    }

    syscall::move_mount_to_fd(mnt_fd.as_raw(), root_fd, entry.dst_rel)
}

fn process_proc_mount(entry: &ProcMount<'_>, root_fd: libc::c_int) -> crate::error::Result<()> {
    syscall::mkdirat_all(root_fd, entry.dst_rel)?;

    let fs_fd = syscall::fsopen(c"proc")?;
    if let Some(subset) = entry.subset {
        let value = match subset {
            ProcSubset::Pid => c"pid",
        };
        syscall::fsconfig_set_string(fs_fd.as_raw(), c"subset", value)?;
    }
    if let Some(hidepid) = entry.hidepid {
        let value = match hidepid {
            HidePid::Visible => c"0",
            HidePid::Hidden => c"1",
            HidePid::Invisible => c"invisible",
        };
        syscall::fsconfig_set_string(fs_fd.as_raw(), c"hidepid", value)?;
    }

    let mut log_buf = [0u8; FSCONFIG_LOG_BYTES];
    if let Err(err) = syscall::fsconfig_create(fs_fd.as_raw(), &mut log_buf) {
        return Err(report_fsconfig_failure(err, &log_buf, b"mount"));
    }

    let mnt_fd = syscall::fsmount(fs_fd.as_raw(), 0)?;
    syscall::move_mount_to_fd(mnt_fd.as_raw(), root_fd, entry.dst_rel)
}

fn process_mqueue_mount(entry: &MqueueMount<'_>, root_fd: libc::c_int) -> crate::error::Result<()> {
    syscall::mkdirat_all(root_fd, entry.dst_rel)?;

    let fs_fd = syscall::fsopen(c"mqueue")?;
    let mut log_buf = [0u8; FSCONFIG_LOG_BYTES];
    if let Err(err) = syscall::fsconfig_create(fs_fd.as_raw(), &mut log_buf) {
        return Err(report_fsconfig_failure(err, &log_buf, b"mount"));
    }

    let mnt_fd = syscall::fsmount(fs_fd.as_raw(), 0)?;
    syscall::move_mount_to_fd(mnt_fd.as_raw(), root_fd, entry.dst_rel)
}

fn process_file_mount(
    entry: &FileMount<'_>,
    root_fd: libc::c_int,
    staging_fd: libc::c_int,
    content_count: &mut usize,
) -> crate::error::Result<()> {
    let mut staging_name_buf = [0u8; 64];
    let staging_name = staging_name_cstr(*content_count, &mut staging_name_buf)?;
    *content_count += 1;

    // Content mounts are assembled as ordinary files inside the root tmpfs and
    // then cloned into detached mounts. That keeps injected file bytes out of
    // the mount protocol itself.
    syscall::write_file_at(staging_fd, staging_name, entry.content)?;
    ensure_parent_dirs(root_fd, entry.dst_rel)?;
    syscall::create_file_at(root_fd, entry.dst_rel)?;

    let mnt_fd = syscall::open_tree(
        staging_fd,
        staging_name,
        libc::OPEN_TREE_CLONE | libc::OPEN_TREE_CLOEXEC,
    )?;

    if entry.read_only {
        let mut attr = syscall::MountAttr::new();
        attr.attr_set = libc::MOUNT_ATTR_RDONLY;
        syscall::mount_setattr(
            mnt_fd.as_raw(),
            EMPTY_PATH,
            libc::AT_EMPTY_PATH as libc::c_uint,
            &attr,
        )?;
    }

    syscall::move_mount_to_fd(mnt_fd.as_raw(), root_fd, entry.dst_rel)
}

fn ensure_mount_point(
    root_fd: libc::c_int,
    dst_rel: &CStr,
    src_is_dir: bool,
) -> crate::error::Result<()> {
    if src_is_dir {
        syscall::mkdirat_all(root_fd, dst_rel)
    } else {
        ensure_parent_dirs(root_fd, dst_rel)?;
        syscall::create_file_at(root_fd, dst_rel)
    }
}

fn ensure_parent_dirs(root_fd: libc::c_int, rel_path: &CStr) -> crate::error::Result<()> {
    let bytes = rel_path.to_bytes();
    let Some(parent_end) = bytes.iter().rposition(|&b| b == b'/') else {
        return Ok(());
    };
    if parent_end == 0 {
        return Ok(());
    }
    let mut buf = [0u8; MAX_PATH_BYTES];
    if parent_end + 1 > buf.len() {
        return Err(Errno::new(libc::ENAMETOOLONG));
    }
    buf[..parent_end].copy_from_slice(&bytes[..parent_end]);
    buf[parent_end] = 0;
    let parent = unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..=parent_end]) };
    syscall::mkdirat_all(root_fd, parent)
}

fn staging_name_cstr(index: usize, buf: &mut [u8; 64]) -> crate::error::Result<&CStr> {
    const PREFIX: &[u8] = b"content-";
    buf[..PREFIX.len()].copy_from_slice(PREFIX);

    let mut digits = [0u8; 20];
    let digits_len = decimal_digits(index as u64, &mut digits);
    let total = PREFIX.len() + digits_len;
    if total + 1 > buf.len() {
        return Err(Errno::new(libc::ENAMETOOLONG));
    }
    buf[PREFIX.len()..total].copy_from_slice(&digits[..digits_len]);
    buf[total] = 0;
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..=total]) })
}

fn decimal_cstr(value: u64, buf: &mut [u8; 32]) -> crate::error::Result<&CStr> {
    let digits_len = decimal_digits(value, buf);
    if digits_len + 1 > buf.len() {
        return Err(Errno::new(libc::ENAMETOOLONG));
    }
    buf[digits_len] = 0;
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..=digits_len]) })
}

fn octal_cstr(value: u32, buf: &mut [u8; 16]) -> crate::error::Result<&CStr> {
    let digits_len = octal_digits(value, buf);
    if digits_len + 1 > buf.len() {
        return Err(Errno::new(libc::ENAMETOOLONG));
    }
    buf[digits_len] = 0;
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..=digits_len]) })
}

fn decimal_digits(mut value: u64, buf: &mut [u8]) -> usize {
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while value != 0 {
        tmp[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    for idx in 0..len {
        buf[idx] = tmp[len - 1 - idx];
    }
    len
}

fn octal_digits(mut value: u32, buf: &mut [u8]) -> usize {
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut tmp = [0u8; 16];
    let mut len = 0usize;
    while value != 0 {
        tmp[len] = b'0' + (value & 7) as u8;
        value >>= 3;
        len += 1;
    }
    for idx in 0..len {
        buf[idx] = tmp[len - 1 - idx];
    }
    len
}

fn report_fsconfig_failure(
    err: syscall::FsConfigCreateError,
    log_buf: &[u8],
    label: &[u8],
) -> Errno {
    let _ = write_stderr(b"pnut-child: ");
    let _ = write_stderr(label);
    let _ = write_stderr(b" fsconfig failed\n");
    if err.log_len != 0 {
        let _ = write_stderr(&log_buf[..err.log_len]);
        let _ = write_stderr(b"\n");
    }
    err.errno
}

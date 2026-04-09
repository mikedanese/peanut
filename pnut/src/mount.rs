//! Filesystem staging, mount setup, and pivot-root support.

mod dev;
mod syscall;

use crate::error::{Error, Stage};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsFd, BorrowedFd};
use std::slice;

use crate::Sandbox;

/// Proc mount `subset=` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcSubset {
    /// `subset=pid` — only PID-related entries are visible.
    /// Hides `/proc/sys`, `/proc/kallsyms`, `/proc/modules`, etc.
    Pid,
}

/// Proc mount `hidepid=` option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidePid {
    /// `hidepid=0` — all `/proc/<pid>` directories are visible to everyone.
    Visible,
    /// `hidepid=1` — users cannot access other users' `/proc/<pid>` contents.
    Hidden,
    /// `hidepid=2` / `hidepid=invisible` — other users' `/proc/<pid>` directories
    /// are completely invisible.
    Invisible,
}

/// One filesystem mount operation.
#[derive(Debug, Clone)]
pub struct Entry {
    pub src: Option<String>,
    pub dst: Option<String>,
    pub bind: bool,
    pub read_only: bool,
    pub mount_type: Option<String>,
    pub content: Option<String>,
    pub size: Option<u64>,
    pub perms: Option<String>,
    /// Proc mount: `subset=` option. Default: `Some(ProcSubset::Pid)`.
    /// Set to `None` to mount full proc.
    pub proc_subset: Option<ProcSubset>,
    /// Proc mount: `hidepid=` option. Default: `Some(HidePid::Invisible)`.
    /// Set to `None` to use kernel default (`hidepid=0`).
    pub hidepid: Option<HidePid>,
}

/// Ordered filesystem mount operations for a sandbox.
#[derive(Debug, Default)]
pub struct Table {
    entries: Vec<Entry>,
}

impl Table {
    /// Create an empty mount table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one mount entry.
    pub fn push(&mut self, entry: Entry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Append many mount entries.
    pub fn extend<I>(&mut self, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = Entry>,
    {
        self.entries.extend(entries);
        self
    }

    /// Add a recursive bind mount.
    pub fn bind(&mut self, src: impl Into<String>, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: Some(src.into()),
            dst: Some(dst.into()),
            bind: true,
            read_only: false,
            mount_type: None,
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a read-only recursive bind mount.
    pub fn bind_read_only(&mut self, src: impl Into<String>, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: Some(src.into()),
            dst: Some(dst.into()),
            bind: true,
            read_only: true,
            mount_type: None,
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a tmpfs mount at the destination path.
    pub fn tmpfs(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("tmpfs".to_string()),
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a tmpfs mount with explicit size and permissions.
    pub fn tmpfs_with_options<P>(
        &mut self,
        dst: impl Into<String>,
        size: Option<u64>,
        perms: Option<P>,
    ) -> &mut Self
    where
        P: Into<String>,
    {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("tmpfs".to_string()),
            content: None,
            size,
            perms: perms.map(Into::into),
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Add a procfs mount at the destination path with default hardening
    /// (`subset=pid`, `hidepid=invisible`).
    pub fn proc(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("proc".to_string()),
            content: None,
            size: None,
            perms: None,
            proc_subset: Some(ProcSubset::Pid),
            hidepid: Some(HidePid::Invisible),
        })
    }

    /// Add an mqueue mount at the destination path.
    pub fn mqueue(&mut self, dst: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: Some("mqueue".to_string()),
            content: None,
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Inject a file into the sandbox filesystem.
    pub fn inject_file(&mut self, dst: impl Into<String>, content: impl Into<String>) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: false,
            mount_type: None,
            content: Some(content.into()),
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Inject a read-only file into the sandbox filesystem.
    pub fn inject_read_only_file(
        &mut self,
        dst: impl Into<String>,
        content: impl Into<String>,
    ) -> &mut Self {
        self.push(Entry {
            src: None,
            dst: Some(dst.into()),
            bind: false,
            read_only: true,
            mount_type: None,
            content: Some(content.into()),
            size: None,
            perms: None,
            proc_subset: None,
            hidepid: None,
        })
    }

    /// Iterate over mount entries in insertion order.
    pub fn iter(&self) -> slice::Iter<'_, Entry> {
        self.entries.iter()
    }

    /// Return whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<'a> IntoIterator for &'a Table {
    type Item = &'a Entry;
    type IntoIter = slice::Iter<'a, Entry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

const PUT_OLD: &str = ".old_root";
const CONTENT_STAGING: &str = ".pnut-content";

fn mnt(context: impl Into<String>, source: impl Into<std::io::Error>) -> Error {
    Error::Setup {
        stage: Stage::Mount,
        context: context.into(),
        source: source.into(),
    }
}

fn mnt_nix(context: impl Into<String>, e: nix::errno::Errno) -> Error {
    Error::Setup {
        stage: Stage::Mount,
        context: context.into(),
        source: e.into(),
    }
}

/// Set up the isolated filesystem and pivot_root into it.
///
/// Called in the child process after fork.
pub(crate) fn setup_filesystem(sandbox: &Sandbox) -> Result<(), Error> {
    // Make the entire mount tree recursively private so that mount changes
    // in this namespace don't propagate to the parent. Uses mount_setattr()
    // with the propagation field set to MS_PRIVATE and AT_RECURSIVE to apply
    // to all mount points.
    let at_fdcwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
    let mut prop_attr = syscall::MountAttr::new();
    prop_attr.propagation = syscall::MS_PRIVATE;
    syscall::mount_setattr(at_fdcwd, c"/", syscall::AT_RECURSIVE, &prop_attr)
        .map_err(|e| mnt_nix("failed to make mount tree recursively private", e))?;

    let new_root = "/tmp/pnut-newroot";
    let new_root_cstr = CString::new(new_root).unwrap();

    // Create the new root directory using mkdir(2)
    let ret = unsafe { libc::mkdir(new_root_cstr.as_ptr(), 0o755) };
    if ret < 0 {
        let err = nix::errno::Errno::last();
        if err != nix::errno::Errno::EEXIST {
            return Err(mnt_nix("failed to create new root directory", err));
        }
    }

    // Create the root tmpfs using the new mount API:
    // fsopen("tmpfs") -> fsconfig(CMD_CREATE) -> fsmount() -> move_mount()
    let fs_fd = syscall::fsopen(c"tmpfs").map_err(|e| mnt_nix("fsopen(\"tmpfs\") failed", e))?;

    syscall::fsconfig_create(fs_fd.as_fd()).map_err(|(errno, log)| {
        let mut ctx = "fsconfig(CMD_CREATE) for root tmpfs failed".to_string();
        if let Some(msg) = log {
            ctx.push_str(": ");
            ctx.push_str(&msg);
        }
        mnt_nix(ctx, errno)
    })?;

    let mnt_fd = syscall::fsmount(fs_fd.as_fd(), 0)
        .map_err(|e| mnt_nix("fsmount() for root tmpfs failed", e))?;

    // move_mount the detached tmpfs to the new_root path
    syscall::move_mount_to_path(mnt_fd.as_fd(), &new_root_cstr)
        .map_err(|e| mnt_nix("move_mount() for root tmpfs failed", e))?;

    // Open the root tmpfs as a directory fd for fd-relative operations
    let root_fd = syscall::openat_dir(at_fdcwd, &new_root_cstr)
        .map_err(|e| mnt_nix("failed to open root tmpfs as directory fd", e))?;

    // Create .old_root and content staging directories relative to root_fd
    syscall::mkdirat_all(root_fd.as_fd(), PUT_OLD)
        .map_err(|e| mnt_nix("failed to create put_old directory", e))?;
    syscall::mkdirat_all(root_fd.as_fd(), CONTENT_STAGING)
        .map_err(|e| mnt_nix("failed to create content staging directory", e))?;

    // Open the staging directory for content injection
    let staging_cstr = CString::new(CONTENT_STAGING).unwrap();
    let staging_fd = syscall::openat_dir(root_fd.as_fd(), &staging_cstr)
        .map_err(|e| mnt_nix("failed to open staging directory", e))?;

    let mut content_idx: usize = 0;
    for (i, entry) in sandbox.mount_table().iter().enumerate() {
        process_mount_entry(entry, root_fd.as_fd(), staging_fd.as_fd(), &mut content_idx)
            .map_err(|e| Error::Other(format!("failed to process mount entry {i}: {e}")))?;
    }

    dev::setup_dev(root_fd.as_fd())?;

    // fd-based pivot_root: fchdir(root_fd) + pivot_root(".", ".")
    // This avoids path-based operations entirely.
    syscall::fchdir(root_fd.as_fd()).map_err(|e| Error::Setup {
        stage: Stage::Pivot,
        context: "fchdir to new root failed".into(),
        source: e.into(),
    })?;

    syscall::pivot_root(c".", c".").map_err(|e| Error::Setup {
        stage: Stage::Pivot,
        context: "pivot_root failed".into(),
        source: e.into(),
    })?;

    // After pivot_root(".", "."), the old root is stacked on top of the new root.
    // Unmount it with MNT_DETACH to lazily clean up.
    syscall::umount2(c".", syscall::MNT_DETACH)
        .map_err(|e| mnt_nix("failed to unmount old root", e))?;

    // Remove the put_old directory (it's now at /.old_root in the new root)
    let _ = syscall::unlinkat(
        at_fdcwd,
        &CString::new(format!("/{PUT_OLD}")).unwrap(),
        libc::AT_REMOVEDIR,
    );

    // Clean up the staging directory
    clean_staging_dir();

    let cwd = sandbox.working_dir();
    std::env::set_current_dir(cwd).map_err(|e| mnt(format!("failed to chdir to {cwd}"), e))?;

    Ok(())
}

/// Remove the content staging directory and its contents.
fn clean_staging_dir() {
    let staging = format!("/{CONTENT_STAGING}");
    // Best-effort cleanup — ignore errors
    let _ = fs::remove_dir_all(&staging);
}

fn process_mount_entry(
    entry: &Entry,
    root_fd: BorrowedFd<'_>,
    staging_fd: BorrowedFd<'_>,
    content_idx: &mut usize,
) -> Result<(), Error> {
    if let Some(ref content) = entry.content {
        return process_content_entry(entry, content, root_fd, staging_fd, content_idx);
    }

    if entry.bind {
        return process_bind_mount(entry, root_fd);
    }

    if let Some(ref mount_type) = entry.mount_type {
        return match mount_type.as_str() {
            "tmpfs" => process_tmpfs_mount(entry, root_fd),
            "proc" => process_proc_mount(entry, root_fd),
            "mqueue" => process_mqueue_mount(entry, root_fd),
            other => Err(Error::Other(format!("unsupported mount type: {other}"))),
        };
    }

    Err(Error::Other(
        "mount entry has no bind, type, or content field".into(),
    ))
}

fn process_bind_mount(entry: &Entry, root_fd: BorrowedFd<'_>) -> Result<(), Error> {
    let src = entry
        .src
        .as_deref()
        .ok_or_else(|| Error::Other("bind mount requires a src field".into()))?;
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("bind mount requires a dst field".into()))?;

    let rel_dst = dst.trim_start_matches('/');
    ensure_mount_point(root_fd, rel_dst, src)?;

    // Clone the source mount tree using open_tree
    let at_fdcwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
    let src_cstr = CString::new(src).map_err(|e| {
        mnt(
            format!("invalid source path for bind mount {src}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    let mnt_fd = syscall::open_tree(
        at_fdcwd,
        &src_cstr,
        syscall::OPEN_TREE_CLONE | syscall::OPEN_TREE_CLOEXEC | syscall::AT_RECURSIVE,
    )
    .map_err(|e| mnt_nix(format!("open_tree for bind mount {src} -> {dst} failed"), e))?;

    // Apply read-only on the detached mount BEFORE attaching — atomic, never visible as writable
    if entry.read_only {
        let mut attr = syscall::MountAttr::new();
        attr.attr_set = syscall::MOUNT_ATTR_RDONLY;
        syscall::mount_setattr(mnt_fd.as_fd(), c"", syscall::AT_EMPTY_PATH, &attr)
            .map_err(|e| mnt_nix(format!("mount_setattr(RDONLY) for {dst} failed"), e))?;
    }

    // Attach at the target path relative to root_fd
    let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
        mnt(
            format!("invalid target path for bind mount {dst}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::move_mount_to_fd(mnt_fd.as_fd(), root_fd, &rel_dst_cstr).map_err(|e| {
        mnt_nix(
            format!("move_mount for bind mount {src} -> {dst} failed"),
            e,
        )
    })?;

    Ok(())
}

fn process_tmpfs_mount(entry: &Entry, root_fd: BorrowedFd<'_>) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("tmpfs mount requires a dst field".into()))?;

    let rel_dst = dst.trim_start_matches('/');
    syscall::mkdirat_all(root_fd, rel_dst)
        .map_err(|e| mnt_nix(format!("failed to create directory for tmpfs at {dst}"), e))?;

    let fs_fd = syscall::fsopen(c"tmpfs")
        .map_err(|e| mnt_nix(format!("fsopen(\"tmpfs\") for {dst} failed"), e))?;

    if let Some(size) = entry.size {
        let size_str = CString::new(size.to_string()).unwrap();
        syscall::fsconfig_set_string(fs_fd.as_fd(), c"size", &size_str)
            .map_err(|e| mnt_nix(format!("fsconfig size for tmpfs at {dst} failed"), e))?;
    }
    if let Some(ref perms) = entry.perms {
        let mode = u32::from_str_radix(perms.trim_start_matches('0'), 8)
            .map_err(|e| Error::Other(format!("invalid permissions: {perms}: {e}")))?;
        let mode_str = CString::new(format!("{mode:04o}")).unwrap();
        syscall::fsconfig_set_string(fs_fd.as_fd(), c"mode", &mode_str)
            .map_err(|e| mnt_nix(format!("fsconfig mode for tmpfs at {dst} failed"), e))?;
    }

    syscall::fsconfig_create(fs_fd.as_fd()).map_err(|(errno, log)| {
        let mut ctx = format!("fsconfig(CMD_CREATE) for tmpfs at {dst} failed");
        if let Some(msg) = log {
            ctx.push_str(": ");
            ctx.push_str(&msg);
        }
        mnt_nix(ctx, errno)
    })?;

    let mnt_fd = syscall::fsmount(fs_fd.as_fd(), 0)
        .map_err(|e| mnt_nix(format!("fsmount() for tmpfs at {dst} failed"), e))?;

    // Apply read-only on the detached mount before attaching — atomic, never visible as writable
    if entry.read_only {
        let mut attr = syscall::MountAttr::new();
        attr.attr_set = syscall::MOUNT_ATTR_RDONLY;
        syscall::mount_setattr(mnt_fd.as_fd(), c"", syscall::AT_EMPTY_PATH, &attr).map_err(
            |e| {
                mnt_nix(
                    format!("mount_setattr(RDONLY) for tmpfs at {dst} failed"),
                    e,
                )
            },
        )?;
    }

    let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
        mnt(
            format!("invalid path for tmpfs at {dst}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::move_mount_to_fd(mnt_fd.as_fd(), root_fd, &rel_dst_cstr)
        .map_err(|e| mnt_nix(format!("move_mount() for tmpfs at {dst} failed"), e))?;

    Ok(())
}

fn process_proc_mount(entry: &Entry, root_fd: BorrowedFd<'_>) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("proc mount requires a dst field".into()))?;

    let rel_dst = dst.trim_start_matches('/');
    syscall::mkdirat_all(root_fd, rel_dst)
        .map_err(|e| mnt_nix(format!("failed to create directory for proc at {dst}"), e))?;

    let fs_fd = syscall::fsopen(c"proc")
        .map_err(|e| mnt_nix(format!("fsopen(\"proc\") for {dst} failed"), e))?;

    if let Some(subset) = &entry.proc_subset {
        let value = match subset {
            ProcSubset::Pid => c"pid",
        };
        syscall::fsconfig_set_string(fs_fd.as_fd(), c"subset", value)
            .map_err(|e| mnt_nix(format!("fsconfig subset for proc at {dst} failed"), e))?;
    }
    if let Some(hidepid) = &entry.hidepid {
        let value: &std::ffi::CStr = match hidepid {
            HidePid::Visible => c"0",
            HidePid::Hidden => c"1",
            HidePid::Invisible => c"invisible",
        };
        syscall::fsconfig_set_string(fs_fd.as_fd(), c"hidepid", value)
            .map_err(|e| mnt_nix(format!("fsconfig hidepid for proc at {dst} failed"), e))?;
    }

    syscall::fsconfig_create(fs_fd.as_fd()).map_err(|(errno, log)| {
        let mut ctx = format!("fsconfig(CMD_CREATE) for proc at {dst} failed");
        if let Some(msg) = log {
            ctx.push_str(": ");
            ctx.push_str(&msg);
        }
        mnt_nix(ctx, errno)
    })?;

    let mnt_fd = syscall::fsmount(fs_fd.as_fd(), 0)
        .map_err(|e| mnt_nix(format!("fsmount() for proc at {dst} failed"), e))?;

    let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
        mnt(
            format!("invalid path for proc at {dst}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::move_mount_to_fd(mnt_fd.as_fd(), root_fd, &rel_dst_cstr)
        .map_err(|e| mnt_nix(format!("move_mount() for proc at {dst} failed"), e))?;

    Ok(())
}

fn process_mqueue_mount(entry: &Entry, root_fd: BorrowedFd<'_>) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("mqueue mount requires a dst field".into()))?;

    let rel_dst = dst.trim_start_matches('/');
    syscall::mkdirat_all(root_fd, rel_dst)
        .map_err(|e| mnt_nix(format!("failed to create directory for mqueue at {dst}"), e))?;

    let fs_fd = syscall::fsopen(c"mqueue")
        .map_err(|e| mnt_nix(format!("fsopen(\"mqueue\") for {dst} failed"), e))?;

    syscall::fsconfig_create(fs_fd.as_fd()).map_err(|(errno, log)| {
        let mut ctx = format!("fsconfig(CMD_CREATE) for mqueue at {dst} failed");
        if let Some(msg) = log {
            ctx.push_str(": ");
            ctx.push_str(&msg);
        }
        mnt_nix(ctx, errno)
    })?;

    let mnt_fd = syscall::fsmount(fs_fd.as_fd(), 0)
        .map_err(|e| mnt_nix(format!("fsmount() for mqueue at {dst} failed"), e))?;

    let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
        mnt(
            format!("invalid path for mqueue at {dst}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::move_mount_to_fd(mnt_fd.as_fd(), root_fd, &rel_dst_cstr)
        .map_err(|e| mnt_nix(format!("move_mount() for mqueue at {dst} failed"), e))?;

    Ok(())
}

fn process_content_entry(
    entry: &Entry,
    content: &str,
    root_fd: BorrowedFd<'_>,
    staging_fd: BorrowedFd<'_>,
    content_idx: &mut usize,
) -> Result<(), Error> {
    let dst = entry
        .dst
        .as_deref()
        .ok_or_else(|| Error::Other("content mount requires a dst field".into()))?;

    // Write content to a staging file on the root tmpfs
    let staging_name = format!("content-{content_idx}");
    *content_idx += 1;
    let staging_cstr = CString::new(staging_name.as_str()).map_err(|e| {
        mnt(
            format!("invalid staging path for {dst}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::write_file_at(staging_fd, &staging_cstr, content.as_bytes())
        .map_err(|e| mnt_nix(format!("failed to write content for {dst}"), e))?;

    // Create mount point for the content at the destination, relative to root_fd
    let rel_dst = dst.trim_start_matches('/');
    // Create parent directories
    if let Some(parent_end) = rel_dst.rfind('/') {
        let parent = &rel_dst[..parent_end];
        if !parent.is_empty() {
            syscall::mkdirat_all(root_fd, parent)
                .map_err(|e| mnt_nix(format!("failed to create parent dirs for {dst}"), e))?;
        }
    }
    let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
        mnt(
            format!("invalid path for content at {dst}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    syscall::create_file_at(root_fd, &rel_dst_cstr)
        .map_err(|e| mnt_nix(format!("failed to create mount point file for {dst}"), e))?;

    // Clone the staging file mount using open_tree.
    // We need the absolute path of the staging file for open_tree since it works on
    // mount-visible paths, not fd-relative. Build it from the staging dir fd.
    // Actually, open_tree accepts dir_fd + relative path, so use staging_fd.
    let mnt_fd = syscall::open_tree(
        staging_fd,
        &staging_cstr,
        syscall::OPEN_TREE_CLONE | syscall::OPEN_TREE_CLOEXEC,
    )
    .map_err(|e| mnt_nix(format!("open_tree for content at {dst} failed"), e))?;

    // Apply read-only on the detached mount before attaching
    if entry.read_only {
        let mut attr = syscall::MountAttr::new();
        attr.attr_set = syscall::MOUNT_ATTR_RDONLY;
        syscall::mount_setattr(mnt_fd.as_fd(), c"", syscall::AT_EMPTY_PATH, &attr).map_err(
            |e| {
                mnt_nix(
                    format!("mount_setattr(RDONLY) for content at {dst} failed"),
                    e,
                )
            },
        )?;
    }

    // Attach at the target path relative to root_fd
    syscall::move_mount_to_fd(mnt_fd.as_fd(), root_fd, &rel_dst_cstr)
        .map_err(|e| mnt_nix(format!("move_mount for content at {dst} failed"), e))?;

    Ok(())
}

/// Create a mount point (directory or file) relative to `root_fd` based on whether
/// the source is a directory or file.
fn ensure_mount_point(root_fd: BorrowedFd<'_>, rel_dst: &str, source: &str) -> Result<(), Error> {
    let source_cstr = CString::new(source).map_err(|e| {
        mnt(
            format!("invalid source path: {source}: {e}"),
            std::io::Error::other(e),
        )
    })?;
    let at_fdcwd = unsafe { BorrowedFd::borrow_raw(libc::AT_FDCWD) };
    let is_dir = syscall::is_dir_at(at_fdcwd, &source_cstr);

    if is_dir {
        syscall::mkdirat_all(root_fd, rel_dst).map_err(|e| {
            mnt_nix(
                format!("failed to create directory mount point: {rel_dst}"),
                e,
            )
        })?;
    } else {
        // Create parent directories first
        if let Some(parent_end) = rel_dst.rfind('/') {
            let parent = &rel_dst[..parent_end];
            if !parent.is_empty() {
                syscall::mkdirat_all(root_fd, parent).map_err(|e| {
                    mnt_nix(format!("failed to create parent dirs for {rel_dst}"), e)
                })?;
            }
        }
        let rel_dst_cstr = CString::new(rel_dst).map_err(|e| {
            mnt(
                format!("invalid path: {rel_dst}: {e}"),
                std::io::Error::other(e),
            )
        })?;
        syscall::create_file_at(root_fd, &rel_dst_cstr)
            .map_err(|e| mnt_nix(format!("failed to create file mount point: {rel_dst}"), e))?;
    }

    Ok(())
}

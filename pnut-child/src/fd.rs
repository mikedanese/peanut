//! File-descriptor helpers for child-runtime setup.

use crate::error::{Errno, Result};

/// Minimal internal fd guard for child-runtime error paths.
#[derive(Debug)]
pub(crate) struct OwnedFd(libc::c_int);

impl OwnedFd {
    pub(crate) const fn new(fd: libc::c_int) -> Self {
        Self(fd)
    }

    pub(crate) const fn as_raw(&self) -> libc::c_int {
        self.0
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            unsafe {
                libc::close(self.0);
            }
        }
    }
}

/// One precomputed fd action for the child runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FdAction {
    Dup2 { src: libc::c_int, dst: libc::c_int },
    Close(libc::c_int),
}

/// Close one file descriptor.
///
/// On Linux the fd is always released regardless of the return value, so
/// EINTR is not retried.
pub fn close(fd: libc::c_int) -> Result<()> {
    let ret = unsafe { libc::close(fd) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

/// Duplicate `src` onto `dst`.
pub fn dup2(src: libc::c_int, dst: libc::c_int) -> Result<()> {
    loop {
        let ret = unsafe { libc::dup2(src, dst) };
        if ret >= 0 {
            return Ok(());
        }
        let err = Errno::last();
        if err.0 == libc::EINTR {
            continue;
        }
        return Err(err);
    }
}

/// Apply all fd actions in order.
pub fn apply_actions(actions: &[FdAction]) -> Result<()> {
    for action in actions {
        match *action {
            FdAction::Dup2 { src, dst } if src != dst => dup2(src, dst)?,
            FdAction::Dup2 { .. } => {}
            FdAction::Close(fd) => close(fd)?,
        }
    }
    Ok(())
}

/// Close all fds >= 3 that are not in `keep_sorted` or `extra_keep`.
///
/// `keep_sorted` should be sorted ascending and contain no duplicates. This
/// function does not require that property for correctness, but it keeps the
/// close-range scan deterministic and cheap.
pub fn close_other_fds(keep_sorted: &[libc::c_int], extra_keep: &[libc::c_int]) -> Result<()> {
    let mut cursor = 3u32;

    loop {
        let next_keep = next_keep_fd(cursor, keep_sorted, extra_keep);
        if next_keep == u32::MAX {
            close_range(cursor, u32::MAX)?;
            return Ok(());
        }
        if next_keep > cursor {
            close_range(cursor, next_keep - 1)?;
        }
        cursor = next_keep.saturating_add(1);
    }
}

fn next_keep_fd(cursor: u32, keep_sorted: &[libc::c_int], extra_keep: &[libc::c_int]) -> u32 {
    let mut next = u32::MAX;

    // keep_sorted is ascending, so the first fd >= cursor is the answer.
    for &fd in keep_sorted {
        let fd = fd as u32;
        if fd >= cursor {
            next = fd;
            break;
        }
    }

    for &fd in extra_keep {
        if fd < 3 {
            continue;
        }
        let fd = fd as u32;
        if fd >= cursor && fd < next {
            next = fd;
        }
    }

    next
}

fn close_range(first: u32, last: u32) -> Result<()> {
    if first > last {
        return Ok(());
    }

    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

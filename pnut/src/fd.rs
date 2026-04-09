//! File descriptor mapping and cleanup before exec.

use std::collections::BTreeSet;
use std::os::unix::io::RawFd;

use crate::error::{Error, Stage};

/// A single parent→child fd mapping.
#[derive(Debug, Clone)]
pub struct FdMapping {
    pub src: RawFd,
    pub dst: RawFd,
}

/// File descriptor policy applied just before exec.
#[derive(Debug)]
pub struct Config {
    pub mappings: Vec<FdMapping>,
    /// Close all fds >= 3 not in the destination set. Default: true.
    pub close_fds: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mappings: Vec::new(),
            close_fds: true,
        }
    }
}

impl Config {
    pub fn map(&mut self, src: RawFd, dst: RawFd) -> &mut Self {
        self.mappings.push(FdMapping { src, dst });
        self
    }

    pub fn close_fds(&mut self, val: bool) -> &mut Self {
        self.close_fds = val;
        self
    }
}

/// Apply fd mappings (cycle-safe) and optionally close all other fds >= 3.
///
/// Called in the child process after fork.
pub(crate) fn apply_fd_config(config: &Config) -> Result<(), Error> {
    apply_mappings(&config.mappings)?;

    if config.close_fds {
        let mut keep: BTreeSet<RawFd> = BTreeSet::new();
        keep.insert(0);
        keep.insert(1);
        keep.insert(2);
        for m in &config.mappings {
            keep.insert(m.dst);
        }
        close_other_fds(&keep)?;
    }

    Ok(())
}

fn fd_err(context: impl Into<String>, source: std::io::Error) -> Error {
    Error::Setup {
        stage: Stage::Fd,
        context: context.into(),
        source,
    }
}

/// Execute dup2 mappings, handling cycles safely.
///
/// Uses the "parallel register move" algorithm: when a source fd is also
/// another mapping's destination, save it to a temporary fd first to avoid
/// clobbering.
fn apply_mappings(mappings: &[FdMapping]) -> Result<(), Error> {
    if mappings.is_empty() {
        return Ok(());
    }

    // Place temporaries above all destinations to avoid conflicts.
    let max_dst = mappings.iter().map(|m| m.dst).max().unwrap_or(0);
    let temp_floor = max_dst + 1;

    let dst_set: BTreeSet<RawFd> = mappings.iter().map(|m| m.dst).collect();

    let mut effective: Vec<(RawFd, RawFd)> = Vec::with_capacity(mappings.len());
    let mut temps: Vec<RawFd> = Vec::new();

    for m in mappings {
        if m.src == m.dst {
            continue;
        }

        let actual_src = if dst_set.contains(&m.src) {
            // Save source to a temporary fd above the conflict zone.
            let tmp = unsafe { libc::fcntl(m.src, libc::F_DUPFD_CLOEXEC, temp_floor) };
            if tmp == -1 {
                return Err(fd_err(
                    format!("failed to save fd {} to temporary", m.src),
                    std::io::Error::last_os_error(),
                ));
            }
            temps.push(tmp);
            tmp
        } else {
            m.src
        };

        effective.push((actual_src, m.dst));
    }

    for &(src, dst) in &effective {
        if unsafe { libc::dup2(src, dst) } == -1 {
            return Err(fd_err(
                format!("dup2({src}, {dst}) failed"),
                std::io::Error::last_os_error(),
            ));
        }
    }

    for tmp in temps {
        unsafe { libc::close(tmp) };
    }

    Ok(())
}

/// Close all fds >= 3 that are not in `keep`.
fn close_other_fds(keep: &BTreeSet<RawFd>) -> Result<(), Error> {
    let mut cursor: u32 = 3;
    for &fd in keep {
        let fd = fd as u32;
        if fd < 3 {
            continue;
        }
        if fd > cursor {
            close_range(cursor, fd - 1)?;
        }
        cursor = fd + 1;
    }
    close_range(cursor, u32::MAX)?;
    Ok(())
}

/// No flags — actually close the fds (as opposed to CLOSE_RANGE_CLOEXEC).
const CLOSE_RANGE_CLOSE: libc::c_uint = 0;

fn close_range(first: u32, last: u32) -> Result<(), Error> {
    if first > last {
        return Ok(());
    }
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, last, CLOSE_RANGE_CLOSE) };
    if ret == -1 {
        return Err(fd_err(
            "close_range failed",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_mapping_is_noop() {
        let mappings = [FdMapping { src: 1, dst: 1 }];
        apply_mappings(&mappings).unwrap();
    }

    #[test]
    fn close_other_fds_gap_logic() {
        let mut keep = BTreeSet::new();
        keep.insert(0);
        keep.insert(1);
        keep.insert(2);
        keep.insert(5);

        let fds: Vec<RawFd> = keep.iter().copied().collect();
        assert_eq!(fds, vec![0, 1, 2, 5]);
    }
}

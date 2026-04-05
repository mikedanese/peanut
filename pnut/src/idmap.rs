//! UID/GID mapping support for user namespaces.

use crate::error::{Error, Stage};
use nix::unistd::Pid;
use std::fs;

/// One `/proc/<pid>/(uid|gid)_map` entry.
#[derive(Debug, Clone)]
pub struct Map {
    /// First ID inside the namespace. Default: `0` (root).
    pub inside: u32,

    /// First host ID visible outside the namespace.
    pub outside: u32,

    /// Number of consecutive IDs to map. Default: `1`.
    pub count: u32,
}

impl Map {
    /// Create one contiguous ID map.
    pub fn new(inside: u32, outside: u32, count: u32) -> Self {
        Self {
            inside,
            outside,
            count,
        }
    }
}

impl Default for Map {
    fn default() -> Self {
        Self {
            inside: 0,
            outside: 0,
            count: 1,
        }
    }
}

/// Write setgroups deny, uid_map, and gid_map for the given child process.
///
/// This must be called from the parent process after clone3 and before
/// signaling the child via the sync pipe.
///
/// Order matters: setgroups must be written before gid_map for unprivileged
/// user namespaces (kernel requirement since Linux 3.19).
pub(crate) fn write_id_maps(child_pid: Pid, uid_map: &Map, gid_map: &Map) -> Result<(), Error> {
    let pid = child_pid.as_raw();

    let setgroups_path = format!("/proc/{pid}/setgroups");
    fs::write(&setgroups_path, "deny").map_err(|e| Error::Setup {
        stage: Stage::IdMap,
        context: format!("failed to write {setgroups_path}"),
        source: e,
    })?;

    let uid_map_path = format!("/proc/{pid}/uid_map");
    let uid_map_content = format!("{} {} {}\n", uid_map.inside, uid_map.outside, uid_map.count);
    fs::write(&uid_map_path, &uid_map_content).map_err(|e| Error::Setup {
        stage: Stage::IdMap,
        context: format!("failed to write {uid_map_path}"),
        source: e,
    })?;

    let gid_map_path = format!("/proc/{pid}/gid_map");
    let gid_map_content = format!("{} {} {}\n", gid_map.inside, gid_map.outside, gid_map.count);
    fs::write(&gid_map_path, &gid_map_content).map_err(|e| Error::Setup {
        stage: Stage::IdMap,
        context: format!("failed to write {gid_map_path}"),
        source: e,
    })?;

    Ok(())
}

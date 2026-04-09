//! Execve (standalone) mode: unshare namespaces in-process, then exec.

use crate::error::{Error, Stage};

use super::Sandbox;

/// Execve mode: unshare, write id maps, then replace this process.
pub(super) fn run_execve_mode(sandbox: &Sandbox) -> Result<i32, Error> {
    // Validated by TryFrom<SandboxBuilder>.
    let uid_map = sandbox.uid_map.as_ref().unwrap();
    let gid_map = sandbox.gid_map.as_ref().unwrap();

    let mut flags = super::parent::clone_flags(&sandbox.namespaces);
    // Execve mode can't use PID namespace (validated at build time, but strip anyway).
    flags &= !(libc::CLONE_NEWPID as u64);

    let ret = unsafe { libc::unshare(flags as i32) };
    if ret != 0 {
        return Err(Error::Setup {
            stage: Stage::Clone,
            context: "unshare failed".into(),
            source: std::io::Error::last_os_error(),
        });
    }

    let my_pid = nix::unistd::Pid::this();
    super::parent::write_id_maps(my_pid, uid_map, gid_map)?;

    let arena = bumpalo::Bump::new();
    let mut spec = sandbox.prepare(&arena).map_err(Error::from)?;
    pnut_child::run(&mut spec);
}

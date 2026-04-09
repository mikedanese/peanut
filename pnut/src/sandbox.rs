//! Validated sandbox and execution logic.

mod parent;
mod prepare;
mod seccomp;
mod standalone;

use std::path::Path;

use crate::config::{
    Capabilities, Command, Environment, FileDescriptors, IdMap, Landlock, Namespaces,
    ProcessOptions, ResourceLimits, RunMode, SandboxBuilder,
};
use crate::error::{BuildError, Error};
use crate::mount;

/// A validated, ready-to-run Linux sandbox.
///
/// Produced by [`SandboxBuilder::build`] or `Sandbox::try_from(builder)`.
/// All configuration has been validated and any seccomp policy has been
/// compiled to BPF.
pub struct Sandbox {
    mode: RunMode,
    pub(crate) command: Command,
    pub(crate) process: ProcessOptions,
    pub(crate) namespaces: Namespaces,
    pub(crate) mounts: mount::Table,
    pub(crate) uid_map: Option<IdMap>,
    pub(crate) gid_map: Option<IdMap>,
    pub(crate) env: Option<Environment>,
    pub(crate) rlimits: Option<ResourceLimits>,
    pub(crate) landlock: Option<Landlock>,
    pub(crate) capabilities: Option<Capabilities>,
    pub(crate) fd: Option<FileDescriptors>,
    pub(crate) seccomp_program: Option<kafel::BpfProgram>,
}

impl TryFrom<SandboxBuilder> for Sandbox {
    type Error = BuildError;

    fn try_from(builder: SandboxBuilder) -> Result<Self, BuildError> {
        // Command is required.
        if builder.command.args.is_empty() {
            return Err(BuildError::InvalidConfig("no command specified".into()));
        }

        // UID/GID maps are required (user namespace is always enabled).
        if builder.uid_map.is_none() {
            return Err(BuildError::InvalidConfig("uid_map is required".into()));
        }
        if builder.gid_map.is_none() {
            return Err(BuildError::InvalidConfig("gid_map is required".into()));
        }

        // Hostname requires UTS namespace.
        if builder.namespaces.hostname.is_some() && !builder.namespaces.uts {
            return Err(BuildError::InvalidConfig(
                "hostname is set but UTS namespace is not enabled; set [namespaces] uts = true"
                    .into(),
            ));
        }

        // Mounts require mount namespace.
        if !builder.mounts.is_empty() && !builder.namespaces.mount {
            return Err(BuildError::InvalidConfig(
                "mount entries configured but mount namespace is not enabled; set [namespaces] mount = true".into(),
            ));
        }

        // Execve mode cannot provide PID namespace isolation.
        if builder.mode == RunMode::Execve && builder.namespaces.pid {
            return Err(BuildError::InvalidConfig(
                "execve mode cannot use PID namespace (unshare(CLONE_NEWPID) only affects children, not the calling process)".into(),
            ));
        }

        for (i, entry) in builder.mounts.iter().enumerate() {
            if let mount::MountEntry::Bind { src, .. } = entry
                && !Path::new(src).exists()
            {
                return Err(BuildError::InvalidConfig(format!(
                    "mount entry {i}: bind mount source path does not exist: {src}"
                )));
            }
        }

        if let Some(fd_config) = builder.fd.as_ref() {
            let mut dst_set = std::collections::HashSet::new();
            for m in &fd_config.mappings {
                if !dst_set.insert(m.dst) {
                    return Err(BuildError::InvalidConfig(format!(
                        "duplicate fd mapping destination: {}",
                        m.dst
                    )));
                }
            }
        }

        let seccomp_program =
            seccomp::prepare_program(builder.seccomp.as_ref(), &builder.namespaces)?;

        Ok(Sandbox {
            mode: builder.mode,
            command: builder.command,
            process: builder.process,
            namespaces: builder.namespaces,
            mounts: builder.mounts,
            uid_map: builder.uid_map,
            gid_map: builder.gid_map,
            env: builder.env,
            rlimits: builder.rlimits,
            landlock: builder.landlock,
            capabilities: builder.capabilities,
            fd: builder.fd,
            seccomp_program,
        })
    }
}

impl Sandbox {
    /// Execute the sandboxed command.
    pub fn run(&self) -> Result<i32, Error> {
        match self.mode {
            RunMode::Execve => standalone::run_execve_mode(self),
            RunMode::Once => parent::run_once_mode(self),
        }
    }
}

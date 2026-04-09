//! Sandbox configuration types and builder.
//!
//! [`SandboxBuilder`] is the top-level mutable builder. Subsystem config types
//! (capabilities, environment, fd, rlimits, landlock) live alongside it.
//! The preparation layer (`prepare.rs`) translates these into `pnut-child`
//! spec types before fork.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

pub use caps::Capability;

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// Linux capabilities to keep after dropping all others.
#[derive(Debug, Default)]
pub struct Capabilities {
    pub keep: Vec<Capability>,
}

impl Capabilities {
    /// Keep one capability after dropping all others.
    pub fn keep(&mut self, capability: Capability) -> &mut Self {
        self.keep.push(capability);
        self
    }
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

/// Environment handling for the sandboxed process.
#[derive(Debug, Default)]
pub struct Environment {
    /// Clear all environment variables before applying `set` and `keep`.
    pub clear: bool,
    /// Variables to set or override inside the sandbox.
    pub set: HashMap<String, String>,
    /// Host variables to preserve when `clear = true`.
    pub keep: Vec<String>,
}

impl Environment {
    /// Control whether the host environment is cleared before applying this policy.
    pub fn clear(&mut self, clear: bool) -> &mut Self {
        self.clear = clear;
        self
    }

    /// Set or override one environment variable inside the sandbox.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.set.insert(key.into(), value.into());
        self
    }

    /// Preserve one host environment variable when `clear = true`.
    pub fn keep(&mut self, key: impl Into<String>) -> &mut Self {
        self.keep.push(key.into());
        self
    }
}

// ---------------------------------------------------------------------------
// File Descriptors
// ---------------------------------------------------------------------------

/// A single parent-to-child fd mapping.
#[derive(Debug, Clone)]
pub struct FdMapping {
    pub src: RawFd,
    pub dst: RawFd,
}

/// File descriptor policy applied just before exec.
#[derive(Debug)]
pub struct FileDescriptors {
    pub mappings: Vec<FdMapping>,
    /// Close all fds >= 3 not in the destination set. Default: true.
    pub close_fds: bool,
}

impl Default for FileDescriptors {
    fn default() -> Self {
        Self {
            mappings: Vec::new(),
            close_fds: true,
        }
    }
}

impl FileDescriptors {
    pub fn map(&mut self, src: RawFd, dst: RawFd) -> &mut Self {
        self.mappings.push(FdMapping { src, dst });
        self
    }

    pub fn close_fds(&mut self, val: bool) -> &mut Self {
        self.close_fds = val;
        self
    }
}

// ---------------------------------------------------------------------------
// Resource Limits
// ---------------------------------------------------------------------------

/// Resource limits applied inside the sandbox.
#[derive(Debug, Default)]
pub struct ResourceLimits {
    pub nofile: Option<u64>,
    pub nproc: Option<u64>,
    pub fsize_mb: Option<u64>,
    pub stack_mb: Option<u64>,
    pub as_mb: Option<u64>,
    pub core_mb: Option<u64>,
    pub cpu_seconds: Option<u64>,
}

impl ResourceLimits {
    pub fn nofile(&mut self, value: u64) -> &mut Self {
        self.nofile = Some(value);
        self
    }
    pub fn nproc(&mut self, value: u64) -> &mut Self {
        self.nproc = Some(value);
        self
    }
    pub fn fsize_mb(&mut self, value: u64) -> &mut Self {
        self.fsize_mb = Some(value);
        self
    }
    pub fn stack_mb(&mut self, value: u64) -> &mut Self {
        self.stack_mb = Some(value);
        self
    }
    pub fn as_mb(&mut self, value: u64) -> &mut Self {
        self.as_mb = Some(value);
        self
    }
    pub fn core_mb(&mut self, value: u64) -> &mut Self {
        self.core_mb = Some(value);
        self
    }
    pub fn cpu_seconds(&mut self, value: u64) -> &mut Self {
        self.cpu_seconds = Some(value);
        self
    }
}

// ---------------------------------------------------------------------------
// Landlock
// ---------------------------------------------------------------------------

/// Landlock filesystem and network allow-lists.
#[derive(Debug, Default)]
pub struct Landlock {
    pub allowed_read: Vec<String>,
    pub allowed_write: Vec<String>,
    pub allowed_execute: Vec<String>,
    /// Paths allowed to be the source or destination of cross-directory renames/links (V2+).
    pub allowed_refer: Vec<String>,
    /// Paths where file truncation is allowed (V3+).
    pub allowed_truncate: Vec<String>,
    /// TCP ports the sandboxed process is allowed to bind (V4+).
    pub allowed_bind: Vec<u16>,
    /// TCP ports the sandboxed process is allowed to connect to (V4+).
    pub allowed_connect: Vec<u16>,
    /// Paths where device ioctl commands are allowed (V5+).
    pub allowed_ioctl_dev: Vec<String>,
}

impl Landlock {
    pub fn allow_read(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_read.push(path.into());
        self
    }
    pub fn allow_write(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_write.push(path.into());
        self
    }
    pub fn allow_execute(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_execute.push(path.into());
        self
    }
    pub fn allow_refer(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_refer.push(path.into());
        self
    }
    pub fn allow_truncate(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_truncate.push(path.into());
        self
    }
    pub fn allow_bind(&mut self, port: u16) -> &mut Self {
        self.allowed_bind.push(port);
        self
    }
    pub fn allow_connect(&mut self, port: u16) -> &mut Self {
        self.allowed_connect.push(port);
        self
    }
    pub fn allow_ioctl_dev(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_ioctl_dev.push(path.into());
        self
    }
}

// ---------------------------------------------------------------------------
// Namespaces
// ---------------------------------------------------------------------------

/// Controls which Linux namespaces are created via `clone3` flags.
///
/// Defaults: all namespaces enabled except time.
#[derive(Debug)]
#[non_exhaustive]
pub struct Namespaces {
    pub user: bool,
    pub pid: bool,
    pub mount: bool,
    pub uts: bool,
    pub ipc: bool,
    pub net: bool,
    pub cgroup: bool,
    pub time: bool,
    pub hostname: Option<String>,
    pub allow_nested_userns: bool,
}

impl Default for Namespaces {
    fn default() -> Self {
        Self {
            user: true,
            pid: true,
            mount: true,
            uts: true,
            ipc: true,
            net: true,
            cgroup: true,
            time: false,
            hostname: None,
            allow_nested_userns: false,
        }
    }
}

impl Namespaces {
    pub fn user(&mut self, enabled: bool) -> &mut Self {
        self.user = enabled;
        self
    }
    pub fn pid(&mut self, enabled: bool) -> &mut Self {
        self.pid = enabled;
        self
    }
    pub fn mount(&mut self, enabled: bool) -> &mut Self {
        self.mount = enabled;
        self
    }
    pub fn uts(&mut self, enabled: bool) -> &mut Self {
        self.uts = enabled;
        self
    }
    pub fn ipc(&mut self, enabled: bool) -> &mut Self {
        self.ipc = enabled;
        self
    }
    pub fn net(&mut self, enabled: bool) -> &mut Self {
        self.net = enabled;
        self
    }
    pub fn cgroup(&mut self, enabled: bool) -> &mut Self {
        self.cgroup = enabled;
        self
    }
    pub fn time(&mut self, enabled: bool) -> &mut Self {
        self.time = enabled;
        self
    }
    pub fn hostname(&mut self, hostname: impl Into<String>) -> &mut Self {
        self.hostname = Some(hostname.into());
        self
    }
}

// ---------------------------------------------------------------------------
// ID Maps
// ---------------------------------------------------------------------------

/// One `/proc/<pid>/(uid|gid)_map` entry for user namespace ID mapping.
#[derive(Debug, Clone)]
pub struct IdMap {
    /// First ID inside the namespace. Default: `0` (root).
    pub inside: u32,
    /// First host ID visible outside the namespace.
    pub outside: u32,
    /// Number of consecutive IDs to map. Default: `1`.
    pub count: u32,
}

impl IdMap {
    pub fn new(inside: u32, outside: u32, count: u32) -> Self {
        Self {
            inside,
            outside,
            count,
        }
    }
}

impl Default for IdMap {
    fn default() -> Self {
        Self {
            inside: 0,
            outside: 0,
            count: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Run mode, command, process options
// ---------------------------------------------------------------------------

/// Run mode for the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunMode {
    #[default]
    Once,
    Execve,
}

/// What to execute inside the sandbox.
///
/// `args[0]` is the binary path. `argv0` optionally overrides what the
/// child sees as argv\[0\] (defaults to args\[0\]).
#[derive(Debug, Default)]
pub struct Command {
    pub(crate) args: Vec<String>,
    pub(crate) argv0: Option<String>,
    pub(crate) cwd: String,
}

impl Command {
    fn new() -> Self {
        Self {
            args: Vec::new(),
            argv0: None,
            cwd: "/".to_string(),
        }
    }
}

/// Process lifecycle options applied inside the sandbox.
#[derive(Debug)]
#[non_exhaustive]
pub struct ProcessOptions {
    pub new_session: bool,
    pub die_with_parent: bool,
    pub no_new_privs: bool,
    pub disable_tsc: bool,
    pub dumpable: bool,
    pub forward_signals: bool,
    pub mdwe: bool,
}

impl Default for ProcessOptions {
    fn default() -> Self {
        Self {
            new_session: true,
            die_with_parent: true,
            no_new_privs: true,
            disable_tsc: false,
            dumpable: false,
            forward_signals: true,
            mdwe: false,
        }
    }
}

/// Source of a seccomp policy.
#[derive(Debug)]
pub enum SeccompSource {
    /// Inline Kafel policy string.
    Inline(String),
    /// Path to a Kafel policy file.
    File(PathBuf),
}

// ---------------------------------------------------------------------------
// SandboxBuilder
// ---------------------------------------------------------------------------

/// A mutable builder for configuring a Linux sandbox.
///
/// Configure the subsystems you need, then call [`SandboxBuilder::build`]
/// to validate and produce a [`Sandbox`](crate::sandbox::Sandbox).
///
/// ```no_run
/// use pnut::{SandboxBuilder, Sandbox};
///
/// let mut sb = SandboxBuilder::new();
/// sb.uid_map(0, 1000, 1)
///   .gid_map(0, 1000, 1)
///   .command("/bin/echo")
///   .arg("hello");
/// let exit_code = sb.build().unwrap().run().unwrap();
/// ```
#[derive(Debug)]
pub struct SandboxBuilder {
    pub(crate) mode: RunMode,
    pub(crate) command: Command,
    pub(crate) process: ProcessOptions,
    pub(crate) namespaces: Namespaces,
    pub(crate) mounts: crate::mount::Table,
    pub(crate) uid_map: Option<IdMap>,
    pub(crate) gid_map: Option<IdMap>,
    pub(crate) env: Option<Environment>,
    pub(crate) rlimits: Option<ResourceLimits>,
    pub(crate) landlock: Option<Landlock>,
    pub(crate) capabilities: Option<Capabilities>,
    pub(crate) fd: Option<FileDescriptors>,
    pub(crate) seccomp: Option<SeccompSource>,
}

impl Default for SandboxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxBuilder {
    /// Create a builder with the same defaults as an empty TOML config.
    pub fn new() -> Self {
        Self {
            mode: RunMode::default(),
            command: Command::new(),
            process: ProcessOptions::default(),
            namespaces: Namespaces::default(),
            mounts: crate::mount::Table::default(),
            uid_map: None,
            gid_map: None,
            env: None,
            rlimits: None,
            landlock: None,
            capabilities: None,
            fd: None,
            seccomp: None,
        }
    }

    pub fn command(&mut self, path: impl Into<String>) -> &mut Self {
        self.command.args.clear();
        self.command.args.push(path.into());
        self
    }

    pub fn command_with_args<I, S>(&mut self, command: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command.args = command.into_iter().map(Into::into).collect();
        self
    }

    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.command.args.push(arg.into());
        self
    }

    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn argv0(&mut self, argv0: impl Into<String>) -> &mut Self {
        self.command.argv0 = Some(argv0.into());
        self
    }

    pub fn cwd(&mut self, cwd: impl Into<String>) -> &mut Self {
        self.command.cwd = cwd.into();
        self
    }

    pub fn mode(&mut self, mode: RunMode) -> &mut Self {
        self.mode = mode;
        self
    }

    pub fn process(&mut self) -> &mut ProcessOptions {
        &mut self.process
    }

    pub fn uid_map(&mut self, inside: u32, outside: u32, count: u32) -> &mut Self {
        self.uid_map = Some(IdMap::new(inside, outside, count));
        self
    }

    pub fn gid_map(&mut self, inside: u32, outside: u32, count: u32) -> &mut Self {
        self.gid_map = Some(IdMap::new(inside, outside, count));
        self
    }

    pub fn namespaces(&mut self) -> &mut Namespaces {
        &mut self.namespaces
    }

    pub fn mounts(&mut self) -> &mut crate::mount::Table {
        &mut self.mounts
    }

    pub fn env(&mut self) -> &mut Environment {
        self.env.get_or_insert_default()
    }

    pub fn rlimits(&mut self) -> &mut ResourceLimits {
        self.rlimits.get_or_insert_default()
    }

    pub fn landlock(&mut self) -> &mut Landlock {
        self.landlock.get_or_insert_default()
    }

    pub fn capabilities(&mut self) -> &mut Capabilities {
        self.capabilities.get_or_insert_default()
    }

    pub fn fd(&mut self) -> &mut FileDescriptors {
        self.fd.get_or_insert_default()
    }

    pub fn seccomp(&mut self, source: SeccompSource) -> &mut Self {
        self.seccomp = Some(source);
        self
    }

    /// Validate configuration and produce a ready-to-run [`Sandbox`](crate::sandbox::Sandbox).
    pub fn build(self) -> Result<crate::sandbox::Sandbox, crate::error::BuildError> {
        crate::sandbox::Sandbox::try_from(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn landlock_config_accumulates_paths() {
        let mut builder = SandboxBuilder::new();
        builder
            .landlock()
            .allow_read("/usr")
            .allow_write("/tmp")
            .allow_execute("/usr/bin");

        let landlock = builder.landlock.as_ref().unwrap();
        assert_eq!(landlock.allowed_read, vec!["/usr"]);
        assert_eq!(landlock.allowed_write, vec!["/tmp"]);
        assert_eq!(landlock.allowed_execute, vec!["/usr/bin"]);
    }

    #[test]
    fn command_builder_replaces_then_appends_args() {
        let mut builder = SandboxBuilder::new();
        builder.command("/bin/echo").arg("hello").arg("world");
        assert_eq!(builder.command.args, vec!["/bin/echo", "hello", "world"]);

        builder.command_with_args(["/bin/true"]);
        assert_eq!(builder.command.args, vec!["/bin/true"]);
    }

    #[test]
    fn seccomp_source_inline_round_trips() {
        let mut builder = SandboxBuilder::new();
        builder.seccomp(SeccompSource::Inline(
            "USE allow_default_policy DEFAULT KILL".to_string(),
        ));

        assert!(matches!(
            builder.seccomp,
            Some(SeccompSource::Inline(ref s)) if s == "USE allow_default_policy DEFAULT KILL"
        ));
    }
}

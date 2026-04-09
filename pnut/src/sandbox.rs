mod child;
mod parent;

use crate::error::{BuildError, Error, Stage};
use std::path::{Path, PathBuf};

use crate::caps::Config as CapsConfig;
use crate::env::Config as EnvConfig;
use crate::fd::Config as FdConfig;
use crate::idmap::Map as IdMap;
use crate::landlock::Config as LandlockConfig;
use crate::mount;
use crate::namespace;
use crate::rlimit::Config as RlimitsConfig;
use crate::seccomp;

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

    fn has_command(&self) -> bool {
        !self.args.is_empty()
    }
}

/// Process lifecycle options applied inside the sandbox.
#[derive(Debug)]
pub struct ProcessOptions {
    pub new_session: bool,
    pub die_with_parent: bool,
    /// Set `PR_SET_NO_NEW_PRIVS` before exec. Prevents `execve` from
    /// granting privileges (setuid, file capabilities). Required for
    /// unprivileged seccomp filter installation. Default: `true`.
    pub no_new_privs: bool,
    /// Disable RDTSC/RDTSCP instructions (x86/x86_64 only).
    /// Causes SIGSEGV on RDTSC. Default: `false`.
    pub disable_tsc: bool,
    /// Set `PR_SET_DUMPABLE` to 0 (non-dumpable). Prevents same-UID ptrace
    /// and `/proc/<pid>/mem` access from outside the sandbox. Default: `false`
    /// (i.e. non-dumpable by default).
    pub dumpable: bool,
    /// Forward signals received by the supervisor to the sandboxed child.
    /// When `false`, any signal to the supervisor kills the child with
    /// SIGKILL. Default: `true`.
    pub forward_signals: bool,
    /// Set `PR_SET_MDWE` (Memory-Deny-Write-Execute). Denies creating
    /// writable+executable mappings and converting writable mappings to
    /// executable. Breaks JIT workloads. Requires kernel >= 6.3.
    /// Default: `false`.
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

/// A mutable builder for configuring a Linux sandbox.
///
/// Build it directly in Rust, configure the subsystems you need, and then
/// call [`SandboxBuilder::build`] to validate and produce a [`Sandbox`],
/// or [`SandboxBuilder::run`] as a shortcut to build and run.
///
/// ```no_run
/// use pnut::SandboxBuilder;
///
/// let mut sb = SandboxBuilder::new();
/// sb.uid_map(0, 1000, 1)
///   .gid_map(0, 1000, 1)
///   .command("/bin/echo")
///   .arg("hello");
/// let exit_code = sb.run().unwrap();
/// ```
#[derive(Debug)]
pub struct SandboxBuilder {
    mode: RunMode,
    command: Command,
    process: ProcessOptions,
    namespaces: namespace::Config,
    mounts: mount::Table,
    uid_map: Option<IdMap>,
    gid_map: Option<IdMap>,
    env: Option<EnvConfig>,
    rlimits: Option<RlimitsConfig>,
    landlock: Option<LandlockConfig>,
    capabilities: Option<CapsConfig>,
    fd: Option<FdConfig>,
    seccomp: Option<SeccompSource>,
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
            namespaces: namespace::Config::default(),
            mounts: mount::Table::default(),
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

    /// Replace the command path and clear any existing arguments.
    pub fn command(&mut self, path: impl Into<String>) -> &mut Self {
        self.command.args.clear();
        self.command.args.push(path.into());
        self
    }

    /// Replace the full command vector, including the path.
    pub fn command_with_args<I, S>(&mut self, command: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command.args = command.into_iter().map(Into::into).collect();
        self
    }

    /// Append one argument to the current command vector.
    pub fn arg(&mut self, arg: impl Into<String>) -> &mut Self {
        self.command.args.push(arg.into());
        self
    }

    /// Append multiple arguments to the current command vector.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.command.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Override `argv[0]` for the executed command.
    pub fn argv0(&mut self, argv0: impl Into<String>) -> &mut Self {
        self.command.argv0 = Some(argv0.into());
        self
    }

    /// Set the working directory inside the sandbox.
    pub fn cwd(&mut self, cwd: impl Into<String>) -> &mut Self {
        self.command.cwd = cwd.into();
        self
    }

    /// Set the sandbox run mode.
    pub fn mode(&mut self, mode: RunMode) -> &mut Self {
        self.mode = mode;
        self
    }

    /// Access the process lifecycle options.
    pub fn process(&mut self) -> &mut ProcessOptions {
        &mut self.process
    }

    /// Set the UID mapping for the user namespace.
    pub fn uid_map(&mut self, inside: u32, outside: u32, count: u32) -> &mut Self {
        self.uid_map = Some(IdMap::new(inside, outside, count));
        self
    }

    /// Set the GID mapping for the user namespace.
    pub fn gid_map(&mut self, inside: u32, outside: u32, count: u32) -> &mut Self {
        self.gid_map = Some(IdMap::new(inside, outside, count));
        self
    }

    /// Access the namespace configuration.
    pub fn namespaces(&mut self) -> &mut crate::namespace::Config {
        &mut self.namespaces
    }

    /// Access the ordered mount table.
    pub fn mounts(&mut self) -> &mut crate::mount::Table {
        &mut self.mounts
    }

    /// Access the environment policy, creating one if needed.
    pub fn env(&mut self) -> &mut crate::env::Config {
        self.env.get_or_insert_with(Default::default)
    }

    /// Access the resource limit configuration, creating one if needed.
    pub fn rlimits(&mut self) -> &mut crate::rlimit::Config {
        self.rlimits.get_or_insert_with(Default::default)
    }

    /// Access the Landlock policy, creating one if needed.
    pub fn landlock(&mut self) -> &mut crate::landlock::Config {
        self.landlock.get_or_insert_with(Default::default)
    }

    /// Access the capability policy, creating one if needed.
    pub fn capabilities(&mut self) -> &mut crate::caps::Config {
        self.capabilities.get_or_insert_with(Default::default)
    }

    /// Access the fd policy, creating one if needed.
    pub fn fd(&mut self) -> &mut crate::fd::Config {
        self.fd.get_or_insert_with(Default::default)
    }

    /// Set the seccomp policy source.
    pub fn seccomp(&mut self, source: SeccompSource) -> &mut Self {
        self.seccomp = Some(source);
        self
    }

    /// Validate configuration and produce a ready-to-run [`Sandbox`].
    pub fn build(self) -> std::result::Result<Sandbox, BuildError> {
        if self.namespaces.hostname.is_some() && !self.namespaces.uts {
            return Err(BuildError::InvalidConfig(
                "hostname is set but UTS namespace is not enabled; set [namespaces] uts = true to use hostname".to_string(),
            ));
        }

        for (i, entry) in self.mounts.iter().enumerate() {
            if entry.dst.is_none() {
                return Err(BuildError::InvalidConfig(format!(
                    "mount entry {i} is missing the required 'dst' field"
                )));
            }

            if entry.bind {
                let Some(src) = entry.src.as_deref() else {
                    return Err(BuildError::InvalidConfig(format!(
                        "mount entry {i}: bind mount requires a 'src' field"
                    )));
                };
                if !Path::new(src).exists() {
                    return Err(BuildError::InvalidConfig(format!(
                        "mount entry {i}: bind mount source path does not exist: {src}"
                    )));
                }
            }

            if !entry.bind && entry.mount_type.is_none() && entry.content.is_none() {
                return Err(BuildError::InvalidConfig(format!(
                    "mount entry {i}: must specify at least one of 'bind', 'type', or 'content'"
                )));
            }
        }

        if let Some(fd_config) = self.fd.as_ref() {
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

        let seccomp_program = seccomp::prepare_program(self.seccomp.as_ref(), &self.namespaces)?;

        Ok(Sandbox {
            mode: self.mode,
            command: self.command,
            process: self.process,
            namespaces: self.namespaces,
            mounts: self.mounts,
            uid_map: self.uid_map,
            gid_map: self.gid_map,
            env: self.env,
            rlimits: self.rlimits,
            landlock: self.landlock,
            capabilities: self.capabilities,
            fd: self.fd,
            seccomp_program,
        })
    }

    /// Validate, build, and execute the sandboxed command.
    ///
    /// Convenience method equivalent to `build()?.run()`.
    pub fn run(self) -> Result<i32, Error> {
        if !self.command.has_command() {
            return Err(Error::Other(
                "no command specified. Usage: pnut --config <path> -- <command> [args...]".into(),
            ));
        }
        let sandbox = self.build()?;
        sandbox.run()
    }
}

/// A validated, ready-to-run Linux sandbox.
///
/// Produced by [`SandboxBuilder::build`]. All configuration has been validated
/// and any seccomp policy has been compiled to BPF.
pub struct Sandbox {
    mode: RunMode,
    command: Command,
    process: ProcessOptions,
    pub(crate) namespaces: namespace::Config,
    pub(crate) mounts: mount::Table,
    uid_map: Option<IdMap>,
    gid_map: Option<IdMap>,
    env: Option<EnvConfig>,
    rlimits: Option<RlimitsConfig>,
    landlock: Option<LandlockConfig>,
    capabilities: Option<CapsConfig>,
    fd: Option<FdConfig>,
    seccomp_program: Option<kafel::BpfProgram>,
}

impl Sandbox {
    /// Execute the sandboxed command.
    ///
    /// Returns the propagated exit code from the sandboxed program,
    /// following the same conventions as the `pnut` CLI.
    pub fn run(&self) -> Result<i32, Error> {
        match self.mode {
            RunMode::Execve => run_execve_mode(self),
            RunMode::Once => parent::run_once_mode(self),
        }
    }

    pub(crate) fn working_dir(&self) -> &str {
        &self.command.cwd
    }

    pub(crate) fn mount_table(&self) -> &crate::mount::Table {
        &self.mounts
    }
}

/// STANDALONE_EXECVE mode: the calling process sets up the sandbox itself and
/// replaces itself with the target command.
fn run_execve_mode(sandbox: &Sandbox) -> Result<i32, Error> {
    let uid_map = sandbox
        .uid_map
        .as_ref()
        .ok_or_else(|| Error::Other("uid_map is required when user namespace is enabled".into()))?;
    let gid_map = sandbox
        .gid_map
        .as_ref()
        .ok_or_else(|| Error::Other("gid_map is required when user namespace is enabled".into()))?;

    let mut flags = crate::namespace::clone_flags(&sandbox.namespaces);
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
    crate::idmap::write_id_maps(my_pid, uid_map, gid_map)?;

    child::run_child_setup(sandbox);
}

#[cfg(test)]
mod tests {
    use super::SandboxBuilder;

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
        builder.seccomp(super::SeccompSource::Inline(
            "USE allow_default_policy DEFAULT KILL".to_string(),
        ));

        assert!(matches!(
            builder.seccomp,
            Some(super::SeccompSource::Inline(ref s)) if s == "USE allow_default_policy DEFAULT KILL"
        ));
    }
}

//! Resource limit (rlimit) enforcement for the sandbox.

use crate::error::{Error, Stage};
use nix::sys::resource::{Resource, getrlimit, setrlimit};

const MIB: u64 = 1024 * 1024;

/// Resource limits applied inside the sandbox.
#[derive(Debug, Default)]
pub struct Config {
    pub nofile: Option<u64>,
    pub nproc: Option<u64>,
    pub fsize_mb: Option<u64>,
    pub stack_mb: Option<u64>,
    pub as_mb: Option<u64>,
    pub core_mb: Option<u64>,
    pub cpu: Option<u64>,
}

impl Config {
    /// Set `RLIMIT_NOFILE`.
    pub fn nofile(&mut self, value: u64) -> &mut Self {
        self.nofile = Some(value);
        self
    }

    /// Set `RLIMIT_NPROC`.
    pub fn nproc(&mut self, value: u64) -> &mut Self {
        self.nproc = Some(value);
        self
    }

    /// Set `RLIMIT_FSIZE` in MiB.
    pub fn fsize_mb(&mut self, value: u64) -> &mut Self {
        self.fsize_mb = Some(value);
        self
    }

    /// Set `RLIMIT_STACK` in MiB.
    pub fn stack_mb(&mut self, value: u64) -> &mut Self {
        self.stack_mb = Some(value);
        self
    }

    /// Set `RLIMIT_AS` in MiB.
    pub fn as_mb(&mut self, value: u64) -> &mut Self {
        self.as_mb = Some(value);
        self
    }

    /// Set `RLIMIT_CORE` in MiB.
    pub fn core_mb(&mut self, value: u64) -> &mut Self {
        self.core_mb = Some(value);
        self
    }

    /// Set `RLIMIT_CPU` in seconds.
    pub fn cpu(&mut self, value: u64) -> &mut Self {
        self.cpu = Some(value);
        self
    }
}

/// Apply all configured resource limits.
pub(crate) fn apply_rlimits(config: &Config) -> Result<(), Error> {
    if let Some(nofile) = config.nofile {
        set_limit(Resource::RLIMIT_NOFILE, nofile, "RLIMIT_NOFILE")?;
    }
    if let Some(nproc) = config.nproc {
        set_limit(Resource::RLIMIT_NPROC, nproc, "RLIMIT_NPROC")?;
    }
    if let Some(fsize_mb) = config.fsize_mb {
        set_limit(
            Resource::RLIMIT_FSIZE,
            fsize_mb.saturating_mul(MIB),
            "RLIMIT_FSIZE",
        )?;
    }
    if let Some(stack_mb) = config.stack_mb {
        set_limit(
            Resource::RLIMIT_STACK,
            stack_mb.saturating_mul(MIB),
            "RLIMIT_STACK",
        )?;
    }
    if let Some(as_mb) = config.as_mb {
        set_limit(Resource::RLIMIT_AS, as_mb.saturating_mul(MIB), "RLIMIT_AS")?;
    }
    if let Some(core_mb) = config.core_mb {
        set_limit(
            Resource::RLIMIT_CORE,
            core_mb.saturating_mul(MIB),
            "RLIMIT_CORE",
        )?;
    }
    if let Some(cpu) = config.cpu {
        set_limit(Resource::RLIMIT_CPU, cpu, "RLIMIT_CPU")?;
    }
    Ok(())
}

fn set_limit(resource: Resource, value: u64, name: &str) -> Result<(), Error> {
    let (_current_soft, current_hard) = getrlimit(resource).map_err(|e| Error::Setup {
        stage: Stage::Rlimit,
        context: format!("getrlimit({name}) failed"),
        source: e.into(),
    })?;
    let effective = value.min(current_hard);
    setrlimit(resource, effective, effective).map_err(|e| Error::Setup {
        stage: Stage::Rlimit,
        context: format!("failed to set {name}"),
        source: e.into(),
    })?;
    Ok(())
}

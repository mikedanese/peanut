//! Landlock LSM filesystem access control for the sandbox.

use crate::error::Error;
use landlock::{
    ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, NetPort, PathBeneath, PathFd,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus, make_bitflags,
};

/// Landlock filesystem and network allow-lists.
#[derive(Debug, Default)]
pub struct Config {
    pub allowed_read: Vec<String>,
    pub allowed_write: Vec<String>,
    pub allowed_execute: Vec<String>,
    /// Paths allowed to be the source or destination of cross-directory renames/links.
    /// Requires Landlock ABI V2 (kernel 5.19+).
    pub allowed_refer: Vec<String>,
    /// Paths where file truncation is allowed.
    /// Requires Landlock ABI V3 (kernel 6.2+).
    pub allowed_truncate: Vec<String>,
    /// TCP ports the sandboxed process is allowed to bind.
    /// When non-empty, all other TCP bind attempts are denied.
    /// Requires Landlock ABI V4 (kernel 6.7+).
    pub allowed_bind: Vec<u16>,
    /// TCP ports the sandboxed process is allowed to connect to.
    /// When non-empty, all other TCP connect attempts are denied.
    /// Requires Landlock ABI V4 (kernel 6.7+).
    pub allowed_connect: Vec<u16>,
    /// Paths where device ioctl commands are allowed.
    /// Requires Landlock ABI V5 (kernel 6.10+).
    pub allowed_ioctl_dev: Vec<String>,
}

impl Config {
    /// Allow read access beneath one path.
    pub fn allow_read(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_read.push(path.into());
        self
    }

    /// Allow write access beneath one path.
    pub fn allow_write(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_write.push(path.into());
        self
    }

    /// Allow execute access beneath one path.
    pub fn allow_execute(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_execute.push(path.into());
        self
    }

    /// Allow cross-directory rename/link beneath one path (V2+).
    pub fn allow_refer(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_refer.push(path.into());
        self
    }

    /// Allow file truncation beneath one path (V3+).
    pub fn allow_truncate(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_truncate.push(path.into());
        self
    }

    /// Allow TCP bind on one port (V4+).
    pub fn allow_bind(&mut self, port: u16) -> &mut Self {
        self.allowed_bind.push(port);
        self
    }

    /// Allow TCP connect to one port (V4+).
    pub fn allow_connect(&mut self, port: u16) -> &mut Self {
        self.allowed_connect.push(port);
        self
    }

    /// Allow device ioctl commands beneath one path (V5+).
    pub fn allow_ioctl_dev(&mut self, path: impl Into<String>) -> &mut Self {
        self.allowed_ioctl_dev.push(path.into());
        self
    }
}

/// Compute the minimum Landlock ABI required by the given config.
fn required_abi(config: &Config) -> ABI {
    if !config.allowed_ioctl_dev.is_empty() {
        ABI::V5
    } else if !config.allowed_bind.is_empty() || !config.allowed_connect.is_empty() {
        ABI::V4
    } else if !config.allowed_truncate.is_empty() {
        ABI::V3
    } else if !config.allowed_refer.is_empty() {
        ABI::V2
    } else {
        ABI::V1
    }
}

fn read_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn write_access() -> landlock::BitFlags<AccessFs> {
    // Core V1 write rights only. V2+ rights (Refer, Truncate, IoctlDev) are
    // granted through their own dedicated config fields.
    AccessFs::from_all(ABI::V1) & !AccessFs::Execute
}

fn execute_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir})
}

fn refer_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Refer})
}

fn truncate_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Truncate})
}

fn ioctl_dev_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{IoctlDev})
}

fn add_path_rule(
    ruleset: RulesetCreated,
    path: &str,
    access: landlock::BitFlags<AccessFs>,
    label: &str,
) -> Result<RulesetCreated, Error> {
    let fd = PathFd::new(path)
        .map_err(|e| Error::Other(format!("failed to open Landlock {label} path: {path}: {e}")))?;
    let ruleset = ruleset
        .add_rule(PathBeneath::new(fd, access))
        .map_err(|e| {
            Error::Other(format!(
                "failed to add Landlock {label} rule for: {path}: {e}"
            ))
        })?;
    Ok(ruleset)
}

/// Apply Landlock filesystem and network restrictions based on the config.
///
/// Called in the child process after fork.
pub(crate) fn apply_landlock(config: &Config) -> Result<(), Error> {
    let abi = required_abi(config);

    let mut pre_ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::Other(format!("failed to handle Landlock access rights: {e}")))?;

    // Only govern the specific network access rights that are configured.
    // This way, configuring allowed_connect without allowed_bind does not
    // implicitly deny all binds (and vice versa).
    if !config.allowed_bind.is_empty() {
        pre_ruleset = pre_ruleset.handle_access(AccessNet::BindTcp).map_err(|e| {
            Error::Other(format!(
                "failed to handle Landlock BindTcp access right: {e}"
            ))
        })?;
    }
    if !config.allowed_connect.is_empty() {
        pre_ruleset = pre_ruleset
            .handle_access(AccessNet::ConnectTcp)
            .map_err(|e| {
                Error::Other(format!(
                    "failed to handle Landlock ConnectTcp access right: {e}"
                ))
            })?;
    }

    let mut ruleset = pre_ruleset.create().map_err(|e| {
        Error::Other(format!(
            "failed to create Landlock ruleset (is Landlock supported by this kernel?): {e}"
        ))
    })?;

    // Filesystem rules.
    for path in &config.allowed_read {
        ruleset = add_path_rule(ruleset, path, read_access(), "read")?;
    }
    for path in &config.allowed_write {
        ruleset = add_path_rule(ruleset, path, write_access(), "write")?;
    }
    for path in &config.allowed_execute {
        ruleset = add_path_rule(ruleset, path, execute_access(), "execute")?;
    }
    for path in &config.allowed_refer {
        ruleset = add_path_rule(ruleset, path, refer_access(), "refer")?;
    }
    for path in &config.allowed_truncate {
        ruleset = add_path_rule(ruleset, path, truncate_access(), "truncate")?;
    }
    for path in &config.allowed_ioctl_dev {
        ruleset = add_path_rule(ruleset, path, ioctl_dev_access(), "ioctl_dev")?;
    }

    // Network rules.
    for &port in &config.allowed_bind {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::BindTcp))
            .map_err(|e| {
                Error::Other(format!(
                    "failed to add Landlock bind rule for port {port}: {e}"
                ))
            })?;
    }
    for &port in &config.allowed_connect {
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(|e| {
                Error::Other(format!(
                    "failed to add Landlock connect rule for port {port}: {e}"
                ))
            })?;
    }

    let status = ruleset
        .restrict_self()
        .map_err(|e| Error::Other(format!("failed to enforce Landlock restrictions: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {}
        RulesetStatus::PartiallyEnforced => {
            eprintln!("pnut: warning: Landlock rules only partially enforced");
        }
        RulesetStatus::NotEnforced => {
            return Err(Error::Other(
                "Landlock rules were not enforced — kernel may not support Landlock".into(),
            ));
        }
    }

    Ok(())
}

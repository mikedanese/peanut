//! Landlock LSM filesystem access control for the sandbox.

use crate::error::Error;
use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
    RulesetCreated, RulesetCreatedAttr, RulesetStatus, make_bitflags,
};

/// Landlock filesystem allow-lists.
#[derive(Debug, Default)]
pub struct Config {
    pub allowed_read: Vec<String>,
    pub allowed_write: Vec<String>,
    pub allowed_execute: Vec<String>,
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
}

fn read_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{ReadFile | ReadDir})
}

fn write_access() -> landlock::BitFlags<AccessFs> {
    AccessFs::from_all(ABI::V1) & !AccessFs::Execute
}

fn execute_access() -> landlock::BitFlags<AccessFs> {
    make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir})
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

/// Apply Landlock filesystem restrictions based on the config.
pub(crate) fn apply_landlock(config: &Config) -> Result<(), Error> {
    let abi = ABI::V1;

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| Error::Other(format!("failed to handle Landlock access rights: {e}")))?
        .create()
        .map_err(|e| {
            Error::Other(format!(
                "failed to create Landlock ruleset (is Landlock supported by this kernel?): {e}"
            ))
        })?;

    for path in &config.allowed_read {
        ruleset = add_path_rule(ruleset, path, read_access(), "read")?;
    }
    for path in &config.allowed_write {
        ruleset = add_path_rule(ruleset, path, write_access(), "write")?;
    }
    for path in &config.allowed_execute {
        ruleset = add_path_rule(ruleset, path, execute_access(), "execute")?;
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

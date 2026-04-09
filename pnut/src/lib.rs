//! Public library API for building and running `pnut` sandboxes.
//!
//! [`SandboxBuilder`] is the mutable configuration builder. Call
//! [`SandboxBuilder::build`] to validate and produce a [`Sandbox`],
//! or use `Sandbox::try_from(builder)`.

mod config;
mod error;
mod mount;
mod sandbox;

pub use config::{
    Capabilities, Capability, Environment, FdMapping, FileDescriptors, IdMap, Landlock, Namespaces,
    ProcessOptions, ResourceLimits, RunMode, SandboxBuilder, SeccompSource,
};
pub use error::{BuildError, ChildStage, Error, Stage};
pub use mount::{HidePid, MountEntry, ProcSubset, Table as MountTable};
pub use sandbox::Sandbox;

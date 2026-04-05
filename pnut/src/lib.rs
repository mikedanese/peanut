//! Public library API for building and running `pnut` sandboxes.
//!
//! [`SandboxBuilder`] is the mutable configuration builder. Call
//! [`SandboxBuilder::build`] to validate and produce a [`Sandbox`],
//! or [`SandboxBuilder::run`] to build and execute in one step.

pub mod caps;
pub mod env;
pub mod error;
pub mod fd;
pub mod idmap;
pub mod landlock;
pub mod mount;
pub mod namespace;
mod net;
pub mod rlimit;
pub mod sandbox;
mod seccomp;

pub use error::{BuildError, Error, Stage};
pub use sandbox::{Command, ProcessOptions, RunMode, Sandbox, SandboxBuilder, SeccompSource};

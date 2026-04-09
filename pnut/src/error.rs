//! Error types for the pnut sandbox library.

use std::fmt;

/// Re-export pnut-child's Stage for child failure decoding.
pub use pnut_child::Stage as ChildStage;

/// Which phase of sandbox setup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// clone3 or unshare syscall failed (parent-side).
    Clone,
    /// UID/GID map writing failed (parent-side).
    IdMap,
    /// The child process reported a failure via the status pipe.
    Child(ChildStage),
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stage::Clone => write!(f, "clone"),
            Stage::IdMap => write!(f, "idmap"),
            Stage::Child(s) => write!(f, "child:{s:?}"),
        }
    }
}

/// Runtime errors from sandbox setup and execution.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A syscall or IO operation failed during sandbox setup.
    #[error("{stage}: {context}: {source}")]
    Setup {
        stage: Stage,
        context: String,
        source: std::io::Error,
    },

    /// The child process failed during sandbox setup.
    /// Contains the decoded failure from the status pipe.
    #[error("child setup failed at {stage:?}: {message}")]
    ChildSetup {
        stage: ChildStage,
        errno: i32,
        detail: i32,
        exit_code: i32,
        message: String,
    },

    /// A logical error with no underlying OS error.
    #[error("{0}")]
    Other(String),

    /// Configuration validation failed.
    #[error(transparent)]
    Build(#[from] BuildError),
}

/// Errors from sandbox configuration validation (pre-run).
///
/// Returned by [`SandboxBuilder::build`](crate::SandboxBuilder::build).
/// These should map to CLI exit code 126.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// A generic validation message.
    #[error("{0}")]
    InvalidConfig(String),

    /// Failed to read a seccomp policy file.
    #[error("failed to read seccomp policy file {path}: {source}")]
    SeccompFileRead {
        path: String,
        source: std::io::Error,
    },

    /// Seccomp policy compilation failed.
    #[error("seccomp policy error: {0}")]
    SeccompCompile(String),
}

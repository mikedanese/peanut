//! Error types for the pnut sandbox library.

use std::fmt;

/// Which phase of sandbox setup failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Clone,
    IdMap,
    Mount,
    Pivot,
    Network,
    Rlimit,
    Landlock,
    Capabilities,
    Fd,
    Exec,
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Stage::Clone => write!(f, "clone"),
            Stage::IdMap => write!(f, "idmap"),
            Stage::Mount => write!(f, "mount"),
            Stage::Pivot => write!(f, "pivot"),
            Stage::Network => write!(f, "network"),
            Stage::Rlimit => write!(f, "rlimit"),
            Stage::Landlock => write!(f, "landlock"),
            Stage::Capabilities => write!(f, "capabilities"),
            Stage::Fd => write!(f, "fd"),
            Stage::Exec => write!(f, "exec"),
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

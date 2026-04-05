//! Error types for the kafel policy compiler.

/// The sole error type for policy compilation.
///
/// All failure paths in parsing, resolution, include processing, and
/// BPF codegen produce this error. It implements [`std::fmt::Display`]
/// and [`std::error::Error`] for ergonomic error handling and chaining.
///
/// Parse errors include line and column information in their display output.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The policy text failed to parse.
    #[error("parse: {message}")]
    Parse {
        /// Human-readable description including line/column.
        message: String,
    },
    /// A syscall name in the policy has no known number.
    #[error("unknown syscall: '{name}'")]
    UnknownSyscall {
        /// The unrecognized syscall name.
        name: String,
    },
    /// An identifier in an expression could not be resolved to a `#define` constant.
    #[error("undefined identifier: '{name}'")]
    UndefinedIdentifier {
        /// The unresolved identifier.
        name: String,
    },
    /// An argument name used in a filter was not declared in the syscall's
    /// argument list.
    #[error("undeclared argument '{name}' in syscall '{syscall}'")]
    UndeclaredArgument {
        /// The undeclared argument name.
        name: String,
        /// The syscall rule it appeared in.
        syscall: String,
    },
    /// A `USE` reference forms a cycle.
    #[error("circular USE reference involving policy '{policy}'")]
    CircularUse {
        /// The policy name where the cycle was detected.
        policy: String,
    },
    /// A `USE` reference names a policy that does not exist.
    #[error("USE references undefined policy '{name}'")]
    UndefinedPolicy {
        /// The missing policy name.
        name: String,
    },
    /// An error occurred during BPF code generation.
    #[error("codegen error: {message}")]
    Codegen {
        /// Human-readable description of the codegen failure.
        message: String,
    },
    /// An `#include` directive referenced a file that the resolver could not find.
    #[error("include file not found: '{filename}'")]
    IncludeNotFound {
        /// The filename from the `#include` directive.
        filename: String,
    },
    /// Recursive `#include` directives exceeded the configured depth limit.
    #[error("include depth exceeded maximum limit")]
    IncludeDepthExceeded,
    /// A circular `#include` chain was detected.
    #[error("circular include detected: '{filename}'")]
    CircularInclude {
        /// The filename that completed the cycle.
        filename: String,
    },
}

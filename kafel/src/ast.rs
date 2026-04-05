//! AST data types for the seccomp policy DSL.

/// A parsed seccomp policy file.
#[derive(Debug, Default)]
pub struct PolicyFile {
    /// `#include` directives (filenames to resolve).
    pub(crate) include_directives: Vec<String>,
    /// `#define` constants (name -> value).
    pub(crate) defines: Vec<(String, Expr)>,
    /// Named policies.
    pub(crate) policies: Vec<Policy>,
    /// Top-level `USE ... DEFAULT ...` statement.
    pub(crate) use_stmt: Option<UseStmt>,
}

impl PolicyFile {
    /// Number of `#define` directives in the file.
    #[cfg(test)]
    pub fn define_count(&self) -> usize {
        self.defines.len()
    }

    /// Number of named policies in the file.
    #[cfg(test)]
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Whether a top-level `USE ... DEFAULT ...` statement is present.
    #[cfg(test)]
    pub fn has_use_stmt(&self) -> bool {
        self.use_stmt.is_some()
    }
}

/// A named policy containing action blocks and references to other policies.
#[derive(Debug)]
pub(crate) struct Policy {
    pub(crate) name: String,
    pub(crate) entries: Vec<PolicyEntry>,
}

/// An entry within a policy: either an action block or a `USE` reference.
#[derive(Debug)]
pub(crate) enum PolicyEntry {
    ActionBlock(ActionBlock),
    UseRef(String),
}

/// An action block mapping an action to a set of syscall rules.
#[derive(Debug)]
pub(crate) struct ActionBlock {
    pub(crate) action: Action,
    pub(crate) rules: Vec<SyscallRule>,
}

/// A seccomp return action.
#[derive(Debug, Clone)]
pub(crate) enum Action {
    Allow,
    Kill,
    KillProcess,
    Log,
    UserNotif,
    Errno(Expr),
    Trap(Expr),
    Trace(Expr),
}

/// A syscall rule with optional argument names and filter expression.
#[derive(Debug)]
pub(crate) struct SyscallRule {
    /// Syscall name (e.g., "write", "mmap").
    pub(crate) name: String,
    /// Named arguments, if declared (e.g., ["fd", "buf", "count"]).
    pub(crate) args: Vec<String>,
    /// Optional boolean filter on arguments.
    pub(crate) filter: Option<BoolExpr>,
}

/// Boolean expression tree for argument filtering.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum BoolExpr {
    /// Comparison: lhs op rhs
    Compare(CmpLhs, CmpOp, Expr),
    /// Logical AND
    And(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical OR (includes comma-separated OR)
    Or(Box<BoolExpr>, Box<BoolExpr>),
    /// Logical NOT
    Not(Box<BoolExpr>),
    /// Boolean literal (produced by constant folding).
    Literal(bool),
}

/// Left-hand side of a comparison.
#[derive(Debug)]
pub(crate) enum CmpLhs {
    /// Plain argument name.
    Arg(String),
    /// Masked argument: (arg & mask).
    Masked(String, Expr),
}

/// Comparison operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A value expression (integer literal, identifier, or bitwise-OR combination).
#[derive(Debug, Clone)]
pub(crate) enum Expr {
    /// Integer literal.
    Number(u64),
    /// Identifier (argument name or #define constant).
    Ident(String),
    /// Bitwise OR of sub-expressions: `O_RDWR | O_CREAT`.
    BitOr(Vec<Expr>),
}

/// Top-level `USE policy1, policy2 DEFAULT action` statement.
#[derive(Debug)]
pub(crate) struct UseStmt {
    pub(crate) policies: Vec<String>,
    pub(crate) default_action: Action,
}

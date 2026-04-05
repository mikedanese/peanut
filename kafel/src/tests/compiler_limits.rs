//! Compiler limit tests.
//!
//! Covers expression depth, BPF program size, and syscall argument count.

// ---------------------------------------------------------------------------
// Expression depth
// ---------------------------------------------------------------------------

#[test]
fn moderately_nested_and_chain() {
    // 50-deep AND chain should compile successfully
    let mut clauses = Vec::new();
    for _ in 0..50 {
        clauses.push("fd == 0");
    }
    let expr = clauses.join(" && ");
    let input =
        format!("POLICY p {{ ALLOW {{ write(fd, buf, count) {{ {expr} }} }} }} USE p DEFAULT KILL");
    let result = crate::compile(&input);
    assert!(
        result.is_ok(),
        "50-deep AND should compile: {:?}",
        result.err()
    );
}

#[test]
fn very_deep_and_chain_returns_error() {
    // 200-deep AND chains exceed the BPF u8 jump offset limit.
    // Should return a clean Error, not panic.
    let mut clauses = Vec::new();
    for _ in 0..200 {
        clauses.push("fd == 0");
    }
    let expr = clauses.join(" && ");
    let input =
        format!("POLICY p {{ ALLOW {{ write(fd, buf, count) {{ {expr} }} }} }} USE p DEFAULT KILL");
    let result = crate::compile(&input);
    assert!(
        matches!(result, Err(crate::Error::Codegen { .. })),
        "200-deep AND chain should return Codegen, got: {result:?}"
    );
}

#[test]
fn deeply_nested_or_chain() {
    let mut clauses = Vec::new();
    for i in 0..100 {
        clauses.push(format!("fd == {i}"));
    }
    let expr = clauses.join(" || ");
    let input =
        format!("POLICY p {{ ALLOW {{ write(fd, buf, count) {{ {expr} }} }} }} USE p DEFAULT KILL");
    let result = crate::compile(&input);
    // 100 OR clauses should compile successfully
    assert!(
        result.is_ok(),
        "100-way OR should compile: {:?}",
        result.err()
    );
}

#[test]
fn deeply_nested_parenthesized_expr() {
    // ((((fd == 0)))) with many nesting levels
    let mut expr = "fd == 0".to_string();
    for _ in 0..50 {
        expr = format!("({expr})");
    }
    let input =
        format!("POLICY p {{ ALLOW {{ write(fd, buf, count) {{ {expr} }} }} }} USE p DEFAULT KILL");
    let result = crate::compile(&input);
    let _ = result; // must not panic
}

// ---------------------------------------------------------------------------
// BPF program size
// ---------------------------------------------------------------------------

#[test]
fn many_syscalls_fits_in_program() {
    // A policy with many allowed syscalls should still produce a valid program
    let syscalls = [
        "read",
        "write",
        "open",
        "close",
        "stat",
        "fstat",
        "lstat",
        "poll",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "ioctl",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "access",
        "pipe",
        "select",
        "sched_yield",
        "mremap",
        "msync",
        "mincore",
        "madvise",
        "dup",
        "dup2",
        "pause",
        "nanosleep",
        "getpid",
        "socket",
        "connect",
        "accept",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "bind",
        "listen",
        "getsockname",
        "getpeername",
        "socketpair",
        "fork",
        "execve",
        "exit",
        "wait4",
        "kill",
        "uname",
        "fcntl",
    ];
    let list = syscalls.join(", ");
    let input = format!("POLICY p {{ ALLOW {{ {list} }} }} USE p DEFAULT KILL");
    let prog = crate::compile(&input).unwrap();
    assert!(
        prog.instructions().len() <= u16::MAX as usize,
        "program should fit in u16::MAX instructions"
    );
}

// ---------------------------------------------------------------------------
// Syscall arg count boundary
// ---------------------------------------------------------------------------

#[test]
fn exactly_six_args_allowed() {
    let result = crate::compile(
        "POLICY p { ALLOW { mmap(a, b, c, d, e, f) { a == 0 } } } USE p DEFAULT KILL",
    );
    assert!(
        result.is_ok(),
        "6 args should be allowed: {:?}",
        result.err()
    );
}

#[test]
fn seven_args_rejected() {
    let result =
        crate::compile("POLICY p { ALLOW { mmap(a, b, c, d, e, f, g) } } USE p DEFAULT KILL");
    assert!(result.is_err(), "7 args should be rejected");
}

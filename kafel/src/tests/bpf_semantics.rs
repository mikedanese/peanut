//! BPF semantic tests using the pure-Rust interpreter.
//!
//! These tests verify that compiled BPF programs behave correctly without
//! loading the kernel filter. Uses the in-process cBPF interpreter to
//! assert exact return values for specific syscall numbers and argument values.

use crate::interp::{SeccompData, run as run_bpf};

const ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const KILL: u32 = libc::SECCOMP_RET_KILL;
const KILL_PROCESS: u32 = libc::SECCOMP_RET_KILL_PROCESS;
const LOG: u32 = libc::SECCOMP_RET_LOG;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;

// ============================================================================
// Action Correctness Tests
// ============================================================================

#[test]
fn semantic_allow_action() {
    let prog = crate::compile("POLICY p { ALLOW { read } } USE p DEFAULT KILL").unwrap();
    let data = SeccompData {
        nr: 0, // read
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data), ALLOW);
}

#[test]
fn semantic_kill_action() {
    let prog = crate::compile("POLICY p { KILL { read } } USE p DEFAULT ALLOW").unwrap();
    let data = SeccompData {
        nr: 0, // read
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data), KILL);
}

#[test]
fn semantic_errno_action() {
    let prog = crate::compile("POLICY p { ERRNO(13) { read } } USE p DEFAULT ALLOW").unwrap();
    let data = SeccompData {
        nr: 0, // read
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    let result = run_bpf(prog.instructions(), &data);
    assert_eq!(result, libc::SECCOMP_RET_ERRNO | 13);
}

#[test]
fn semantic_trap_action() {
    let prog = crate::compile("POLICY p { TRAP(7) { read } } USE p DEFAULT ALLOW").unwrap();
    let data = SeccompData {
        nr: 0, // read
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    let result = run_bpf(prog.instructions(), &data);
    assert_eq!(result, libc::SECCOMP_RET_TRAP | 7);
}

#[test]
fn semantic_trace_action() {
    let prog = crate::compile("POLICY p { TRACE(42) { read } } USE p DEFAULT ALLOW").unwrap();
    let data = SeccompData {
        nr: 0, // read
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    let result = run_bpf(prog.instructions(), &data);
    assert_eq!(result, libc::SECCOMP_RET_TRACE | 42);
}

#[test]
fn semantic_log_action() {
    let prog = crate::compile("POLICY p { LOG { read } } USE p DEFAULT ALLOW").unwrap();
    let data = SeccompData {
        nr: 0, // read
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data), LOG);
}

// ============================================================================
// Arch Check
// ============================================================================

#[test]
fn semantic_arch_check_correct() {
    let prog = crate::compile("POLICY p { ALLOW { read } } USE p DEFAULT ALLOW").unwrap();

    // Correct arch should enter the policy
    let data = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data), ALLOW);
}

#[test]
fn semantic_arch_check_wrong() {
    let prog = crate::compile("POLICY p { ALLOW { read } } USE p DEFAULT ALLOW").unwrap();

    // Wrong arch should be killed immediately (before policy is checked)
    let data = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64 ^ 1, // flip a bit
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data), KILL_PROCESS);
}

// ============================================================================
// 64-bit Inequality Tests
// ============================================================================

#[test]
fn semantic_64bit_gt_high_word_dominant() {
    // a0 > 0x100000000 (hi=1, lo=0)
    // Test with value 0xFFFFFFFF (hi=0, lo=0xFFFFFFFF) — should fail (hi=0 < hi=1)
    // Test with value 0x100000001 (hi=1, lo=1) — should pass (hi=1, and lo matters next)
    let prog =
        crate::compile("POLICY p { ALLOW { read(a0) { a0 > 0x100000000 } } } USE p DEFAULT KILL")
            .unwrap();

    let data_fail = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0xFFFF_FFFF, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);

    let data_pass = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0001, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);
}

#[test]
fn semantic_64bit_gt_equal_hi_uses_lo() {
    // a0 > 0x100000005 (hi=1, lo=5)
    // Test 0x100000005: hi equal, lo equal → fail
    // Test 0x100000006: hi equal, lo > → pass
    let prog =
        crate::compile("POLICY p { ALLOW { read(a0) { a0 > 0x100000005 } } } USE p DEFAULT KILL")
            .unwrap();

    let data_fail = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0005, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);

    let data_pass = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0006, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);
}

#[test]
fn semantic_64bit_ge_boundary() {
    // a0 >= 0x100000000 (hi=1, lo=0)
    // Test 0xFFFFFFFF (hi=0): should fail
    // Test 0x100000000 (hi=1, lo=0): should pass (at boundary)
    let prog =
        crate::compile("POLICY p { ALLOW { read(a0) { a0 >= 0x100000000 } } } USE p DEFAULT KILL")
            .unwrap();

    let data_fail = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0xFFFF_FFFF, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);

    let data_pass = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0000, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);
}

#[test]
fn semantic_64bit_lt_high_word() {
    // a0 < 0x100000000 (hi=1, lo=0)
    // Test 0xFFFFFFFF (hi=0): should pass (hi < hi)
    // Test 0x100000000 (hi=1, lo=0): should fail (hi == hi, lo not <)
    let prog =
        crate::compile("POLICY p { ALLOW { read(a0) { a0 < 0x100000000 } } } USE p DEFAULT KILL")
            .unwrap();

    let data_pass = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0xFFFF_FFFF, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);

    let data_fail = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0000, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);
}

#[test]
fn semantic_64bit_le() {
    // a0 <= 0x100000005 (hi=1, lo=5)
    let prog =
        crate::compile("POLICY p { ALLOW { read(a0) { a0 <= 0x100000005 } } } USE p DEFAULT KILL")
            .unwrap();

    // hi=1, lo=6: > 0x100000005, should fail
    let data_fail = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0006, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);

    // hi=1, lo=5: == 0x100000005, should pass
    let data_pass = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0x1_0000_0005, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);
}

// ============================================================================
// Masked Compare Tests
// ============================================================================

#[test]
fn semantic_masked_eq() {
    // write(fd, buf, count) { (fd & 0x3) == 2 }
    let prog = crate::compile(
        "POLICY p { ALLOW { write(fd, buf, count) { (fd & 0x3) == 2 } } } USE p DEFAULT KILL",
    )
    .unwrap();

    // fd=2 (0b10): (2 & 3) = 2 → ALLOW
    let data_pass = SeccompData {
        nr: 1, // write
        arch: AUDIT_ARCH_X86_64,
        args: [2, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);

    // fd=6 (0b110): (6 & 3) = 2 → ALLOW
    let data_pass2 = SeccompData {
        nr: 1,
        arch: AUDIT_ARCH_X86_64,
        args: [6, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass2), ALLOW);

    // fd=3 (0b11): (3 & 3) = 3 → KILL
    let data_fail = SeccompData {
        nr: 1,
        arch: AUDIT_ARCH_X86_64,
        args: [3, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);
}

#[test]
fn semantic_masked_ne() {
    // write(fd, buf, count) { (fd & 0x3) != 0 }
    // This is emitted as JSET when (fd & 0x3) == 0 with swapped branches
    let prog = crate::compile(
        "POLICY p { ALLOW { write(fd, buf, count) { (fd & 0x3) != 0 } } } USE p DEFAULT KILL",
    )
    .unwrap();

    // fd=1: (1 & 3) != 0 → ALLOW
    let data_pass = SeccompData {
        nr: 1,
        arch: AUDIT_ARCH_X86_64,
        args: [1, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_pass), ALLOW);

    // fd=0: (0 & 3) == 0 → KILL
    let data_fail = SeccompData {
        nr: 1,
        arch: AUDIT_ARCH_X86_64,
        args: [0, 0, 0, 0, 0, 0],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_fail), KILL);
}

// ============================================================================
// Range and Default Action Tests
// ============================================================================

#[test]
fn semantic_coverage_property() {
    // Every syscall number 0..1023 should return exactly one action
    let prog = crate::compile("POLICY p { ALLOW { read, write } } USE p DEFAULT KILL").unwrap();

    for nr in 0..1024 {
        let data = SeccompData {
            nr: nr as u32,
            arch: AUDIT_ARCH_X86_64,
            args: [0; 6],
        };
        let result = run_bpf(prog.instructions(), &data);

        let expected = match nr {
            0 | 1 => ALLOW, // read, write
            _ => KILL,
        };

        assert_eq!(
            result, expected,
            "syscall {} returned {}, expected {}",
            nr, result, expected
        );
    }
}

#[test]
fn semantic_multiple_allowed_ranges() {
    // ALLOW read (0), write (1), open (2), close (3), mmap (9)
    // Expect gaps to be filled with KILL
    let prog =
        crate::compile("POLICY p { ALLOW { read, write, open, close, mmap } } USE p DEFAULT KILL")
            .unwrap();

    let cases = vec![
        (0, ALLOW), // read
        (1, ALLOW), // write
        (2, ALLOW), // open
        (3, ALLOW), // close
        (4, KILL),  // gap
        (5, KILL),  // gap
        (9, ALLOW), // mmap
        (10, KILL), // after mmap
    ];

    for (nr, expected) in cases {
        let data = SeccompData {
            nr: nr as u32,
            arch: AUDIT_ARCH_X86_64,
            args: [0; 6],
        };
        assert_eq!(
            run_bpf(prog.instructions(), &data),
            expected,
            "syscall {} expected {}",
            nr,
            expected
        );
    }
}

// ============================================================================
// Built-in Prelude Tests
// ============================================================================

#[test]
fn semantic_builtin_prelude_allow_default_policy() {
    let prog = crate::compile_with_options(
        "USE allow_default_policy DEFAULT KILL",
        &crate::CompileOptions::new().with_prelude(crate::BUILTIN_PRELUDE),
    )
    .unwrap();

    // read (0) should be in allow_default_policy
    let data_read = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_read), ALLOW);

    // ptrace (101 on x86_64) should be killed
    let data_ptrace = SeccompData {
        nr: 101,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_ptrace), KILL);
}

#[test]
fn semantic_builtin_prelude_allow_system_malloc() {
    let prog = crate::compile_with_options(
        "USE allow_system_malloc DEFAULT KILL",
        &crate::CompileOptions::new().with_prelude(crate::BUILTIN_PRELUDE),
    )
    .unwrap();

    // brk (12 on x86_64) should be allowed
    let data_brk = SeccompData {
        nr: 12,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_brk), ALLOW);

    // read (0) is not in allow_system_malloc
    let data_read = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_read), KILL);
}

#[test]
fn semantic_builtin_prelude_multiple() {
    // USE multiple built-in policies
    let prog = crate::compile_with_options(
        "USE allow_default_policy, allow_system_malloc DEFAULT KILL",
        &crate::CompileOptions::new().with_prelude(crate::BUILTIN_PRELUDE),
    )
    .unwrap();

    // read (0) is in allow_default_policy
    let data_read = SeccompData {
        nr: 0,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_read), ALLOW);

    // brk (12) is in allow_system_malloc
    let data_brk = SeccompData {
        nr: 12,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_brk), ALLOW);

    // ptrace (101) is in neither
    let data_ptrace = SeccompData {
        nr: 101,
        arch: AUDIT_ARCH_X86_64,
        args: [0; 6],
    };
    assert_eq!(run_bpf(prog.instructions(), &data_ptrace), KILL);
}

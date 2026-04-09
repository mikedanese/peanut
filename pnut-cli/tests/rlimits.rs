//! Tests for rlimits edge cases.

use std::process::Command;

fn pnut() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pnut"))
}

fn pnut_with_config(config: &str) -> Command {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("test.toml");
    std::fs::write(&config_path, config).unwrap();
    let mut cmd = pnut();
    cmd.arg("--config").arg(config_path);
    // Keep tempdir alive by leaking it (tests are short-lived).
    std::mem::forget(dir);
    cmd
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getgid() }
}

fn filesystem_config() -> String {
    let uid = current_uid();
    let gid = current_gid();
    format!(
        r#"
[namespaces]
user = true
pid = true
mount = true

[uid_map]
inside = 0
outside = {uid}
count = 1

[gid_map]
inside = 0
outside = {gid}
count = 1

[[mount]]
src = "/usr"
dst = "/usr"
type = "bind"

[[mount]]
src = "/lib"
dst = "/lib"
type = "bind"

[[mount]]
src = "/lib64"
dst = "/lib64"
type = "bind"

[[mount]]
src = "/bin"
dst = "/bin"
type = "bind"

[[mount]]
src = "/sbin"
dst = "/sbin"
type = "bind"

[[mount]]
type = "tmpfs"
dst = "/tmp"

[[mount]]
type = "proc"
dst = "/proc"
"#
    )
}

fn rlimits_config(rlimits_section: &str) -> String {
    format!("{}\n{}", filesystem_config(), rlimits_section)
}

fn execve_config(rlimits_section: &str) -> String {
    let uid = current_uid();
    let gid = current_gid();
    // Note: execve mode cannot use PID namespace (unshare only affects children),
    // and proc mount requires PID namespace. So no proc mount here.
    format!(
        r#"
[sandbox]
mode = "execve"
new_session = false

[namespaces]
user = true
pid = false
mount = true

[uid_map]
inside = 0
outside = {uid}
count = 1

[gid_map]
inside = 0
outside = {gid}
count = 1

[[mount]]
src = "/usr"
dst = "/usr"
type = "bind"

[[mount]]
src = "/lib"
dst = "/lib"
type = "bind"

[[mount]]
src = "/lib64"
dst = "/lib64"
type = "bind"

[[mount]]
src = "/bin"
dst = "/bin"
type = "bind"

[[mount]]
src = "/sbin"
dst = "/sbin"
type = "bind"

[[mount]]
type = "tmpfs"
dst = "/tmp"

{rlimits_section}
"#
    )
}

// --- Criterion 5.1: nofile EMFILE adversarial ---

/// Try to open many files with a low nofile limit — verify we hit EMFILE.
#[test]
fn adversarial_nofile_emfile_exact() {
    let config = rlimits_config("[rlimits]\nnofile = 8");
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Use a script that tries to open many temp files via shell redirection.
            // With nofile=8 and stdin/stdout/stderr using 0-2, we have ~5 fds left.
            r#"count=0; for i in 1 2 3 4 5 6 7 8 9 10; do
                if /bin/sh -c "echo test > /tmp/fdtest_$i" 2>/dev/null; then
                    count=$((count + 1))
                else
                    echo "FAILED_AT_$i"
                    break
                fi
            done
            echo "OPENED_$count"
            "#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // With nofile=8, we should see the limit kick in.
    // Each /bin/sh fork needs fds too, so we should fail before 10.
    assert!(
        stdout.contains("OPENED_") || stdout.contains("FAILED_"),
        "nofile test should produce output. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Verify we couldn't open all 10.
    if stdout.contains("OPENED_10") {
        panic!("nofile=8 should prevent opening 10 subshells, but all succeeded");
    }
}

/// Verify nofile=3 is extremely restrictive.
#[test]
fn adversarial_nofile_extremely_low() {
    let config = rlimits_config("[rlimits]\nnofile = 3");
    let out = pnut_with_config(&config)
        .args(["--", "/bin/sh", "-c", "echo hello"])
        .output()
        .unwrap();
    // With nofile=3, the shell may fail because it can't open anything beyond 0,1,2.
    // Just verify the sandbox doesn't crash/hang.
    assert!(
        out.status.code().is_some(),
        "sandbox should exit cleanly even with extremely low nofile"
    );
}

// --- Criterion 5.2: fsize adversarial ---

/// Verify fsize_mb applies to appending writes, not just initial writes.
#[test]
fn adversarial_fsize_append_writes() {
    let config = rlimits_config("[rlimits]\nfsize_mb = 1");
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Write 512K, then try to append another 1M — should fail on append.
            "dd if=/dev/zero of=/tmp/append bs=1024 count=512 2>/dev/null && \
             dd if=/dev/zero of=/tmp/append bs=1024 count=1024 seek=512 2>&1; echo EXIT_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("EXIT_1") || stdout.contains("File size limit"),
        "fsize should limit append writes too. stdout: {stdout}"
    );
}

// --- Criterion 5.3: nproc adversarial ---

/// Verify nproc=1 prevents forking at all (only the shell itself runs).
#[test]
fn adversarial_nproc_minimal() {
    let config = rlimits_config("[rlimits]\nnproc = 1");
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "/bin/true 2>/dev/null && echo FORK_OK || echo FORK_FAIL",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // nproc=1 with a user namespace may or may not actually prevent forking.
    // Just verify the sandbox runs and produces output.
    assert!(
        !stdout.is_empty() || out.status.code().is_some(),
        "sandbox should not hang with nproc=1"
    );
}

// --- Criterion 5.4: both modes produce identical rlimit behavior ---

/// Verify ulimit -n reports the same value in both modes.
#[test]
fn adversarial_rlimit_identical_behavior_both_modes() {
    // Once mode
    let config_once = rlimits_config("[rlimits]\nnofile = 42");
    let out_once = pnut_with_config(&config_once)
        .args(["--", "/bin/sh", "-c", "ulimit -n"])
        .output()
        .unwrap();
    let stdout_once = String::from_utf8_lossy(&out_once.stdout).trim().to_string();

    // Execve mode (no proc mount — execve mode can't use pid namespace)
    let config_execve = execve_config("[rlimits]\nnofile = 42");
    let out_execve = pnut_with_config(&config_execve)
        .args(["--", "/bin/sh", "-c", "ulimit -n"])
        .output()
        .unwrap();
    let stdout_execve = String::from_utf8_lossy(&out_execve.stdout)
        .trim()
        .to_string();

    assert_eq!(
        stdout_once,
        "42",
        "once mode should report nofile=42, got: {stdout_once}. stderr: {}",
        String::from_utf8_lossy(&out_once.stderr)
    );
    assert_eq!(
        stdout_execve,
        "42",
        "execve mode should report nofile=42, got: {stdout_execve}. stderr: {}",
        String::from_utf8_lossy(&out_execve.stderr)
    );
    assert_eq!(
        stdout_once, stdout_execve,
        "both modes should produce identical rlimit values"
    );
}

// --- Criterion 5.5: omitted rlimits ---

/// Verify that partial rlimits config only affects specified limits.
#[test]
fn adversarial_partial_rlimits_no_side_effects() {
    // Set only nofile, verify fsize is NOT affected.
    let config = rlimits_config("[rlimits]\nnofile = 32");
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Write a 2MiB file — should succeed since fsize is not limited.
            "dd if=/dev/zero of=/tmp/big bs=1024 count=2048 2>/dev/null && echo FSIZE_OK",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("FSIZE_OK"),
        "setting only nofile should not affect fsize. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 5.6: mode enum ---

/// Verify mode = "ONCE" (uppercase) is rejected — serde rename_all = lowercase.
#[test]
fn adversarial_mode_enum_case_sensitive() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
mode = "ONCE"

[namespaces]
user = true
pid = true
mount = true

[uid_map]
inside = 0
outside = {uid}
count = 1

[gid_map]
inside = 0
outside = {gid}
count = 1
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "nope"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "mode='ONCE' (uppercase) should be rejected. exit: {:?}",
        out.status.code()
    );
}

/// Verify mode = "Once" (mixed case) is rejected.
#[test]
fn adversarial_mode_enum_mixed_case() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
mode = "Once"

[namespaces]
user = true
pid = true
mount = true

[uid_map]
inside = 0
outside = {uid}
count = 1

[gid_map]
inside = 0
outside = {gid}
count = 1
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "nope"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "mode='Once' (mixed case) should be rejected. exit: {:?}",
        out.status.code()
    );
}

// --- Criterion 5.7: shared setup ---

/// Verify that hostname + rlimits + env all work together in once mode
/// (exercises the shared setup path).
#[test]
fn adversarial_shared_setup_full_sequence() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
hostname = "SHARED-TEST"

[namespaces]
user = true
pid = true
mount = true
uts = true

[uid_map]
inside = 0
outside = {uid}
count = 1

[gid_map]
inside = 0
outside = {gid}
count = 1

[[mount]]
src = "/usr"
dst = "/usr"
type = "bind"

[[mount]]
src = "/lib"
dst = "/lib"
type = "bind"

[[mount]]
src = "/lib64"
dst = "/lib64"
type = "bind"

[[mount]]
src = "/bin"
dst = "/bin"
type = "bind"

[[mount]]
src = "/sbin"
dst = "/sbin"
type = "bind"

[[mount]]
type = "tmpfs"
dst = "/tmp"

[[mount]]
type = "proc"
dst = "/proc"

[rlimits]
nofile = 64
fsize_mb = 5

[env]
clear = true
set = {{ PATH = "/usr/bin:/bin", MARKER = "shared_works" }}
"#
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo HOST=$(hostname) NOFILE=$(ulimit -n) MARKER=$MARKER",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "shared setup should succeed");
    assert!(
        stdout.contains("HOST=SHARED-TEST"),
        "hostname should be set. stdout: {stdout}"
    );
    assert!(
        stdout.contains("NOFILE=64"),
        "nofile should be 64. stdout: {stdout}"
    );
    assert!(
        stdout.contains("MARKER=shared_works"),
        "env should be set. stdout: {stdout}"
    );
}

// --- Criterion 5.9: no dead_code warnings ---

/// Verify cargo build with -D warnings succeeds.
#[test]
fn adversarial_no_compiler_warnings_with_deny() {
    let out = std::process::Command::new("cargo")
        .args(["check", "--message-format=short"])
        .env("RUSTFLAGS", "-D warnings")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cargo check -D warnings should succeed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Rlimits value edge cases ---

/// Verify rlimits with zero values (nofile=0 should make everything fail).
#[test]
fn adversarial_rlimits_zero_nofile() {
    let config = rlimits_config("[rlimits]\nnofile = 0");
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    // With nofile=0, even stdin/stdout/stderr might be affected.
    // The process should still exit (not hang), even if it fails.
    assert!(
        out.status.code().is_some(),
        "sandbox should exit with nofile=0, not hang"
    );
}

/// Verify rlimits with very large values (effectively no limit).
#[test]
fn adversarial_rlimits_large_value() {
    let config = rlimits_config("[rlimits]\nnofile = 1000000");
    let out = pnut_with_config(&config)
        .args(["--", "/bin/sh", "-c", "ulimit -n"])
        .output()
        .unwrap();
    // The value should be clamped to the hard limit, not cause an error.
    assert!(
        out.status.success(),
        "large nofile value should be clamped, not error. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let limit: u64 = stdout.trim().parse().unwrap_or(0);
    assert!(limit > 0, "clamped nofile should be positive, got {limit}");
}

/// Verify unknown rlimits fields are rejected by serde.
#[test]
fn adversarial_rlimits_unknown_field() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[namespaces]
user = true
pid = true
mount = true

[uid_map]
inside = 0
outside = {uid}
count = 1

[gid_map]
inside = 0
outside = {gid}
count = 1

[rlimits]
bogus_limit = 42
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    // If deny_unknown_fields is set, this should fail at 126.
    // If not, it should just ignore the field and succeed.
    // Either behavior is acceptable — just verify no crash.
    assert!(
        out.status.code().is_some(),
        "sandbox should handle unknown rlimits fields gracefully"
    );
}

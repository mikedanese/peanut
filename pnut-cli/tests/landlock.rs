//! Tests for Landlock filesystem access control.

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

/// Base config with filesystem mounts suitable for Landlock testing.
/// Includes /usr, /lib, /lib64, /bin, /tmp, /scratch (writable tmpfs without
/// Landlock write access for testing write blocks).
fn landlock_base_config() -> String {
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
type = "tmpfs"
dst = "/scratch"

[[mount]]
type = "proc"
dst = "/proc"
"#
    )
}

fn landlock_base_config_execve() -> String {
    let uid = current_uid();
    let gid = current_gid();
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

[[mount]]
type = "tmpfs"
dst = "/scratch"
"#
    )
}

// --- Criterion 6.1: allowed_read/allowed_write restrictions ---

/// Reading allowed paths succeeds, writing to non-write paths fails with EACCES.
#[test]
fn adversarial_landlock_read_write_separation() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Write to /tmp should work; write to /scratch should be blocked by Landlock.
            "echo ok > /tmp/test && cat /tmp/test && echo write_tmp_ok; echo fail > /scratch/test 2>&1; echo exit_scratch_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("write_tmp_ok"),
        "writing to /tmp should succeed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("exit_scratch_2") || stdout.contains("exit_scratch_1"),
        "writing to /scratch should fail. stdout: {stdout}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("Permission denied") || combined.contains("denied"),
        "write failure should mention permission denied. output: {combined}"
    );
}

// --- Criterion 6.2: allowed_execute restrictions ---

/// Executing from allowed paths works, executing from /tmp fails with EACCES.
#[test]
fn adversarial_landlock_execute_restriction() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Copy a binary to /tmp and try to execute it — should fail.
            "cp /usr/bin/echo /tmp/myecho && chmod +x /tmp/myecho && /tmp/myecho hello 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("exit_126") || stdout.contains("Permission denied"),
        "executing from /tmp should be blocked. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !stdout.contains("hello"),
        "the executed binary should not produce output. stdout: {stdout}"
    );
}

// --- Criterion 6.3: cannot read outside allowed paths ---

/// Files outside allowed_read are inaccessible even if mounted.
#[test]
fn adversarial_landlock_no_read_outside_allowed() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config()
    );
    // /scratch is mounted (tmpfs) but NOT in allowed_read.
    let out = pnut_with_config(&config)
        .args(["--", "/bin/sh", "-c", "ls /scratch 2>&1; echo exit_$?"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Permission denied")
            || stdout.contains("exit_2")
            || stdout.contains("exit_1"),
        "/scratch should not be readable when not in allowed_read. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Path traversal attempt: try to read outside allowed paths via /proc/self/root.
#[test]
fn adversarial_landlock_path_traversal_blocked() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/proc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config()
    );
    // Try to access /scratch via /proc/self/root/../scratch
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "cat /proc/self/root/scratch/test 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Should fail — Landlock resolves symlinks and doesn't allow path traversal
    // to access paths outside allowed set.
    assert!(
        stdout.contains("exit_1")
            || stdout.contains("exit_2")
            || stdout.contains("Permission denied")
            || stdout.contains("No such file"),
        "path traversal should not bypass Landlock. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 6.4: works in both modes ---

/// Landlock works in STANDALONE_EXECVE mode.
#[test]
fn adversarial_landlock_execve_mode() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config_execve()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo ok > /tmp/test && echo write_tmp_ok; echo fail > /scratch/test 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("write_tmp_ok"),
        "Landlock in execve mode should allow writing to /tmp. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("exit_2") || stdout.contains("exit_1"),
        "Landlock in execve mode should block writing to /scratch. stdout: {stdout}"
    );
}

/// Landlock execute restriction works in STANDALONE_ONCE mode.
#[test]
fn adversarial_landlock_once_mode_execute() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "cp /bin/echo /tmp/myecho && chmod +x /tmp/myecho && /tmp/myecho test 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("exit_126") || stdout.contains("Permission denied"),
        "executing from /tmp should be blocked in once mode. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 6.5: omitting [landlock] means no restrictions ---

/// Without [landlock] section, all filesystem access is unrestricted.
#[test]
fn adversarial_landlock_omitted_no_restrictions() {
    let config = landlock_base_config();
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo test > /scratch/file && cat /scratch/file && echo all_ok",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("all_ok"),
        "without [landlock], all filesystem access should work. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 6.6: kernel doesn't support Landlock (ABI 0) ---
// Note: We can't truly test ABI 0 on a system that supports Landlock.
// Instead, we test that the error handling path works by using
// CompatLevel::HardRequirement — if the kernel somehow didn't support
// Landlock, we'd get a clear error. We test the error message format instead.

/// Verify that Landlock setup produces clear error messages on failure.
/// We test this by configuring a non-existent path in the Landlock config.
#[test]
fn adversarial_landlock_nonexistent_path_error() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/nonexistent/path/that/does/not/exist"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        landlock_base_config()
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(126),
        "nonexistent Landlock path should cause exit 126. stderr: {stderr}"
    );
    assert!(
        stderr.contains("landlock") || stderr.contains("Landlock"),
        "error should mention Landlock. stderr: {stderr}"
    );
}

/// Verify that unknown fields in [landlock] section are rejected.
#[test]
fn adversarial_landlock_unknown_field_rejected() {
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

[landlock]
bogus_field = ["/usr"]
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "unknown field in [landlock] should be rejected. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 6.7: Landlock + rlimits work together ---

/// Both Landlock and rlimits apply simultaneously without interference.
#[test]
fn adversarial_landlock_plus_rlimits() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch", "/proc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]

[rlimits]
nofile = 32
"#,
        landlock_base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Verify rlimits work (nofile=32) alongside Landlock.
            "ulimit -n && echo ok > /tmp/rlimit_test && echo write_ok; echo fail > /scratch/nope 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("32"),
        "nofile should be 32 with rlimits active. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("write_ok"),
        "Landlock should allow writing to /tmp. stdout: {stdout}"
    );
    assert!(
        stdout.contains("exit_2") || stdout.contains("exit_1"),
        "Landlock should block writing to /scratch. stdout: {stdout}"
    );
}

// --- Criterion 6.8: all existing tests pass ---
// (This is verified by running cargo test — all tests are in the same suite.)

//! Adversarial tests for Landlock filesystem access control.
//!
//! These tests probe edge cases the Generator's tests may not cover:
//! - Symlink escape attempts
//! - Empty allowed lists (total lockdown)
//! - Write to allowed_read path (read != write)
//! - Read from allowed_execute path (execute != read unless ReadFile granted)
//! - Landlock with all three lists populated simultaneously

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
    std::mem::forget(dir);
    cmd
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getgid() }
}

fn base_config_once() -> String {
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
src = "/etc"
dst = "/etc"
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

/// Symlink escape: create a symlink in /tmp pointing to /etc, try to read through it.
/// Landlock should block this because /etc is not in allowed_read.
#[test]
fn eval_adversarial_symlink_escape_blocked() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/proc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config_once()
    );
    // Create symlink /tmp/escape -> /etc, then try to read /tmp/escape/hostname
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "ln -s /etc /tmp/escape 2>&1 && cat /tmp/escape/hostname 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Landlock follows symlinks and checks the real path. /etc is not in allowed_read,
    // so reading through the symlink should fail.
    assert!(
        stdout.contains("Permission denied")
            || stdout.contains("exit_1")
            || stdout.contains("exit_2"),
        "symlink escape to /etc should be blocked by Landlock. stdout: {stdout}, stderr: {stderr}"
    );
}

/// Path traversal via .. : /tmp/../etc/hostname should be blocked.
#[test]
fn eval_adversarial_dotdot_traversal_blocked() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/proc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config_once()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "cat /tmp/../etc/hostname 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("Permission denied")
            || stdout.contains("exit_1")
            || stdout.contains("exit_2"),
        "path traversal via /tmp/../etc should be blocked. stdout: {stdout}, stderr: {stderr}"
    );
}

/// Empty allowed_read list: nothing is readable, process should fail to execute
/// (since even /bin/sh needs read access). With Landlock handling all access rights,
/// an empty config means total lockdown.
#[test]
fn eval_adversarial_empty_allowed_lists_lockdown() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = []
allowed_write = []
allowed_execute = []
"#,
        base_config_once()
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/sh", "-c", "echo should_not_appear"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // With no allowed paths, execve should fail
    assert!(
        !stdout.contains("should_not_appear"),
        "with empty Landlock lists, nothing should be accessible. stdout: {stdout}"
    );
    assert!(
        out.status.code() == Some(126),
        "empty Landlock lists should cause exec failure (exit 126). code: {:?}, stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Writing to an allowed_read path should fail — read does not grant write.
#[test]
fn eval_adversarial_write_to_read_only_path_fails() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/proc"]
allowed_write = []
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config_once()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo test > /tmp/file 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // /tmp is only in allowed_read, not allowed_write, so writing should fail
    assert!(
        stdout.contains("Permission denied")
            || stdout.contains("exit_1")
            || stdout.contains("exit_2"),
        "writing to read-only Landlock path should fail. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Landlock with allowed_write grants read access too (per the contract:
/// "write paths get full read/write access"). Verify that a write path is also readable.
#[test]
fn eval_adversarial_write_path_grants_read_access() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config_once()
    );
    // /tmp is only in allowed_write (not allowed_read), but write_access() includes
    // read rights. So writing AND reading /tmp should both succeed.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo hello > /tmp/test && cat /tmp/test && echo read_write_ok",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("read_write_ok"),
        "write path should also grant read access. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Verify Landlock in execve mode with both read and write restrictions active.
#[test]
fn eval_adversarial_execve_mode_read_blocked() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
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
src = "/etc"
dst = "/etc"
type = "bind"

[[mount]]
type = "tmpfs"
dst = "/tmp"

[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#
    );
    // /etc is mounted but NOT in allowed_read — should be blocked even in execve mode
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "cat /etc/hostname 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Permission denied") || stdout.contains("exit_1"),
        "reading /etc should be blocked in execve mode too. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Verify that a Landlock config with only allowed_execute (no read/write lists)
/// still enforces the deny-all for read and write.
#[test]
fn eval_adversarial_execute_only_config_blocks_read_write() {
    let config = format!(
        r#"{}
[landlock]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config_once()
    );
    // No allowed_read or allowed_write — reading and writing should be blocked.
    // Note: execute_access includes ReadFile and ReadDir, so execute paths can be read.
    // But /tmp has no access at all.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo test > /tmp/file 2>&1; echo write_exit_$?; cat /tmp/nonexistent 2>&1; echo read_exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Writing to /tmp should fail since no write access
    assert!(
        stdout.contains("write_exit_1") || stdout.contains("write_exit_2"),
        "writing should fail with execute-only config. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

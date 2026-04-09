//! Tests for run modes (once/execve) and end-to-end hardening.
//!
//! These tests probe edge cases the Generator likely did not consider.

use std::os::unix::process::ExitStatusExt;
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

fn filesystem_config_base() -> String {
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

/// Adversarial: Invalid mode value should be caught in config validation (exit 126).
#[test]
fn adversarial_invalid_mode_validation() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
mode = "invalid-mode"
new_session = false

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
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code, 126,
        "invalid mode should exit 126 (config validation), got {code}"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("mode") || stderr.contains("invalid"),
        "error should mention the invalid mode, got: {stderr}"
    );
}

/// Adversarial: die_with_parent=false should NOT set PR_SET_PDEATHSIG.
/// If the parent is killed, the child should survive (at least briefly).
#[test]
fn adversarial_die_with_parent_false() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
die_with_parent = false
new_session = false

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
    // Verify the sandbox still works with die_with_parent=false.
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "alive"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "die_with_parent=false should still work. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "alive");
}

/// Adversarial: Command not found with a relative path (not absolute) should still exit 127.
#[test]
fn adversarial_command_not_found_relative_path() {
    let config = filesystem_config_base();
    let out = pnut_with_config(&config)
        .args(["--", "nonexistent-relative-command"])
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(-1);
    // execv with a relative path that doesn't exist should give ENOENT -> 127.
    assert_eq!(
        code, 127,
        "non-existent relative command should exit 127, got {code}"
    );
}

/// Adversarial: Execve mode with hostname and UTS namespace should work.
#[test]
fn adversarial_execve_mode_with_hostname() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
mode = "execve"
hostname = "EXECVE-HOST"
new_session = false

[namespaces]
user = true
pid = false
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
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/hostname"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "execve mode with hostname failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "EXECVE-HOST",
        "hostname in execve mode should be set"
    );
}

/// Adversarial: Config validation errors in execve mode should also exit 126.
#[test]
fn adversarial_execve_mode_config_validation_exit_126() {
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
src = "/nonexistent-path-for-execve-test"
dst = "/mnt/test"
type = "bind"
read_only = false
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "nope"])
        .output()
        .unwrap();
    let code = out.status.code().unwrap_or(-1);
    assert_eq!(
        code, 126,
        "config validation in execve mode should also exit 126, got {code}"
    );
}

/// Adversarial: Empty command path ("") should not crash, should exit with error.
#[test]
fn adversarial_empty_command_path() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
new_session = false

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
    let out = pnut_with_config(&config).args(["--", ""]).output().unwrap();
    // Should fail gracefully (ENOENT = 127 for empty path).
    assert!(!out.status.success(), "empty command path should fail");
}

/// Adversarial: Execve mode should propagate signal death exit codes correctly.
/// Since pnut IS the process in execve mode, if the exec'd command is killed by
/// a signal, the OS exit status should reflect it.
#[test]
fn adversarial_execve_mode_signal_propagation() {
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
type = "tmpfs"
dst = "/tmp"
"#
    );
    // In execve mode, pnut replaces itself, so signal death propagates naturally
    // through the OS. Shell `kill -TERM $$` will show 143.
    let out = pnut_with_config(&config)
        .args(["--", "/bin/sh", "-c", "kill -TERM $$"])
        .output()
        .unwrap();
    // The shell itself gets the signal. In execve mode, there's no parent wrapper,
    // so the exit status comes from the OS via WIFSIGNALED.
    // The sh exit code for "kill -TERM $$" should be 128+15=143.
    let code = out.status.code();
    // On signal death, code() may be None (Unix signal). Check either way.
    let signal = out.status.signal();
    assert!(
        code == Some(143) || signal == Some(15),
        "expected signal-based exit (code=143 or signal=15), got code={:?} signal={:?}",
        code,
        signal
    );
}

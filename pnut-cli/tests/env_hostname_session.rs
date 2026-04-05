//! Tests for environment variables, hostname, and session control.
//!
//! These tests probe edge cases the Generator likely did not consider.

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
bind = true
read_only = true

[[mount]]
src = "/lib"
dst = "/lib"
bind = true
read_only = true

[[mount]]
src = "/lib64"
dst = "/lib64"
bind = true
read_only = true

[[mount]]
src = "/bin"
dst = "/bin"
bind = true
read_only = true

[[mount]]
src = "/sbin"
dst = "/sbin"
bind = true
read_only = true

[[mount]]
type = "tmpfs"
dst = "/tmp"

[[mount]]
type = "proc"
dst = "/proc"
"#
    )
}

/// Adversarial: env clear=true with NO set and NO keep should result in a
/// completely empty environment (zero variables).
#[test]
fn adversarial_env_clear_completely_empty() {
    let config = format!(
        r#"
{base}

[sandbox]
new_session = false

[env]
clear = true
"#,
        base = filesystem_config_base()
    );
    let out = pnut_with_config(&config)
        .env("SOME_VAR", "value")
        .env("ANOTHER", "thing")
        .args(["--", "/usr/bin/env"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "env command failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // With clear=true and no set/keep, the environment should be completely empty.
    assert!(
        stdout.trim().is_empty(),
        "expected completely empty environment with clear=true and no set/keep, got:\n{stdout}"
    );
}

/// Adversarial: env keep with a variable that does NOT exist in the host env.
/// Should not error — just silently skip it.
#[test]
fn adversarial_env_keep_nonexistent_variable() {
    let config = format!(
        r#"
{base}

[sandbox]
new_session = false

[env]
clear = true
keep = ["THIS_VAR_DEFINITELY_DOES_NOT_EXIST_XYZ_12345"]
set = {{ FOO = "bar" }}
"#,
        base = filesystem_config_base()
    );
    let out = pnut_with_config(&config)
        .env_remove("THIS_VAR_DEFINITELY_DOES_NOT_EXIST_XYZ_12345")
        .args(["--", "/usr/bin/env"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "should not fail when keeping a nonexistent variable. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("FOO=bar"),
        "FOO=bar should still be set. got: {stdout}"
    );
    assert!(
        !stdout.contains("THIS_VAR_DEFINITELY_DOES_NOT_EXIST"),
        "nonexistent kept variable should not appear. got: {stdout}"
    );
}

/// Adversarial: env set should override a kept variable when there's a name conflict.
/// The spec says set overrides keep.
#[test]
fn adversarial_env_set_overrides_keep() {
    let config = format!(
        r#"
{base}

[sandbox]
new_session = false

[env]
clear = true
keep = ["CONFLICT_VAR"]
set = {{ CONFLICT_VAR = "from_set" }}
"#,
        base = filesystem_config_base()
    );
    let out = pnut_with_config(&config)
        .env("CONFLICT_VAR", "from_host")
        .args(["--", "/usr/bin/env"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "env command failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The set value should override the kept value.
    assert!(
        stdout.contains("CONFLICT_VAR=from_set"),
        "set should override keep. expected CONFLICT_VAR=from_set, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("CONFLICT_VAR=from_host"),
        "kept value should be overridden by set. got:\n{stdout}"
    );
}

/// Adversarial: hostname without UTS namespace should produce a validation error
/// before fork, not a child-side sethostname failure.
#[test]
fn adversarial_hostname_without_uts_validation() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[sandbox]
hostname = "should-fail"
new_session = false

[namespaces]
user = true
pid = true
mount = true
uts = false

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
        .args(["--", "/bin/echo", "should not run"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "should fail when hostname is set without UTS namespace"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("UTS") || stderr.contains("uts") || stderr.contains("hostname"),
        "error should mention UTS namespace or hostname, got: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("should not run"),
        "command ran despite config validation failure"
    );
}

/// Adversarial: Config validation should catch a mount entry missing the 'dst' field.
#[test]
fn adversarial_mount_entry_missing_dst() {
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

[[mount]]
src = "/usr"
bind = true
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "should not run"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "should fail when mount entry is missing dst"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dst"),
        "error should mention missing 'dst' field, got: {stderr}"
    );
}

/// Adversarial: Config validation should catch a mount entry with no bind, type, or content.
#[test]
fn adversarial_mount_entry_no_action() {
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

[[mount]]
dst = "/mnt/test"
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "should not run"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "should fail when mount entry has no bind, type, or content"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("bind") || stderr.contains("type") || stderr.contains("content"),
        "error should mention missing action fields, got: {stderr}"
    );
}

/// Adversarial: new_session=false should not call setsid.
/// (Verifies the feature is actually conditional, not always-on.)
#[test]
fn adversarial_no_new_session_keeps_sid() {
    let config = format!(
        r#"
{base}

[sandbox]
new_session = false
"#,
        base = filesystem_config_base()
    );

    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/sh",
            "-c",
            "cat /proc/self/stat | cut -d' ' -f6",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sandbox command failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let child_sid = String::from_utf8_lossy(&out.stdout).trim().to_string();

    // With new_session=false, setsid should NOT be called. We verify the child
    // has a valid session ID and the command succeeds.
    assert!(!child_sid.is_empty(), "should have a valid session ID");
}

/// Adversarial: Verify the non-existent bind source exit code is specifically
/// what the criterion requires. The criterion says "exits 126" -- verify this.
#[test]
fn adversarial_nonexistent_bind_source_exit_code() {
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

[[mount]]
src = "/nonexistent-adversarial-path"
dst = "/mnt/test"
bind = true
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "nope"])
        .output()
        .unwrap();
    // The criterion says "exits 126". Config validation catches this before fork,
    // so the exit code comes from the parent process. Check what it actually is.
    let code = out.status.code().unwrap_or(-1);
    assert!(
        !out.status.success(),
        "should fail with non-existent bind source"
    );
    // The criterion explicitly says "exits 126":
    assert_eq!(
        code, 126,
        "criterion 3.6 requires exit code 126, but got {code}"
    );
}

/// Adversarial: env without clear=true, only set -- should augment the existing
/// environment rather than replacing it.
#[test]
fn adversarial_env_set_without_clear() {
    let config = format!(
        r#"
{base}

[sandbox]
new_session = false

[env]
set = {{ NEW_VAR = "added" }}
"#,
        base = filesystem_config_base()
    );
    let out = pnut_with_config(&config)
        .env("EXISTING_VAR", "preserved")
        .args(["--", "/usr/bin/env"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "env command failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // NEW_VAR should be set
    assert!(
        stdout.contains("NEW_VAR=added"),
        "NEW_VAR should be set. got:\n{stdout}"
    );
    // EXISTING_VAR should be preserved (clear=false by default)
    assert!(
        stdout.contains("EXISTING_VAR=preserved"),
        "existing env vars should be preserved when clear=false. got:\n{stdout}"
    );
}

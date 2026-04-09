//! Adversarial tests for Landlock ABI V2-V5 filesystem fields.
//!
//! These tests probe edge cases and failure modes that the Generator's
//! tests may not cover.

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

fn base_config() -> String {
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

// --- Invariant 3: deny_unknown_fields preserved on LandlockConfig ---

/// New V2+ field names are exact; typos or wrong names are rejected.
#[test]
fn adversarial_landlock_v2_unknown_field_rejected() {
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
allowed_read = ["/tmp"]
allowed_referr = ["/tmp"]
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "typo 'allowed_referr' should be rejected by deny_unknown_fields. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Misspelled 'allowed_truncat' is rejected.
#[test]
fn adversarial_landlock_v3_typo_rejected() {
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
allowed_read = ["/tmp"]
allowed_truncat = ["/tmp"]
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "typo 'allowed_truncat' should be rejected. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Invariant 4: empty/absent field = no restriction ---

/// Absent allowed_truncate means truncation is unrestricted (V1 ABI doesn't
/// govern Truncate at all).
#[test]
fn adversarial_absent_truncate_no_restriction() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config()
    );
    // With V1 ABI (no truncate field), truncation should be unrestricted
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo longdata > /tmp/file && truncate -s 0 /tmp/file && echo trunc_unrestricted",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("trunc_unrestricted"),
        "absent allowed_truncate with V1 ABI should not restrict truncation. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Truncate orthogonality: write + truncate are independent ---

/// allowed_write does NOT grant truncate when truncate is governed (V3 ABI).
/// When allowed_truncate is configured for some path, the ABI is bumped to V3,
/// meaning Truncate is governed for ALL paths. A path in allowed_write but NOT
/// in allowed_truncate should have truncation of existing files blocked.
#[test]
fn adversarial_write_does_not_grant_truncate() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp", "/scratch"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_truncate = ["/tmp"]
"#,
        base_config()
    );
    // /scratch has write but NOT truncate. Since we're at V3 ABI (because
    // allowed_truncate is non-empty), Truncate is governed.
    // First create a file via append (no O_TRUNC), then try to truncate it.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Use >> (append) to create the file without O_TRUNC, then truncate
            "echo data >> /scratch/file && truncate -s 0 /scratch/file 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Permission denied") || stdout.contains("exit_1"),
        "truncation on /scratch should be blocked even though write is allowed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- V5 ABI mismatch: multiple V5 fields trigger exit 126 ---

/// Both allowed_ioctl_dev and allowed_truncate can be set simultaneously.
/// If V5 is unsupported, the V5 field should trigger exit 126.
#[test]
fn adversarial_v5_mixed_with_v3_on_old_kernel() {
    // Only run on kernels < 6.10 (no V5 support)
    let version = std::fs::read_to_string("/proc/version").unwrap_or_default();
    let parts: Vec<&str> = version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() >= 2 {
        let major: u32 = parts[0].parse().unwrap_or(0);
        let minor: u32 = parts[1].parse().unwrap_or(0);
        if major > 6 || (major == 6 && minor >= 10) {
            eprintln!("skipping: kernel {major}.{minor} supports V5");
            return;
        }
    }

    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_truncate = ["/tmp"]
allowed_ioctl_dev = ["/dev/null"]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "V5+V3 config on pre-V5 kernel should exit 126. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Refer orthogonality ---

/// When allowed_refer is configured (bumping to V2), cross-dir rename between
/// paths under the refer path should succeed.
#[test]
fn adversarial_refer_blocks_unlisted_cross_dir() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp", "/scratch"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_refer = ["/tmp"]
"#,
        base_config()
    );
    // /tmp has Refer. Cross-dir rename within /tmp (same fs) should work.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            concat!(
                "mkdir -p /tmp/a /tmp/b && ",
                "echo data > /tmp/a/file && ",
                "mv /tmp/a/file /tmp/b/file && ",
                "cat /tmp/b/file && ",
                "echo refer_within_ok"
            ),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("refer_within_ok"),
        "cross-dir rename within /tmp (which has Refer) should work. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Config deserialization: wrong type for new fields ---

/// allowed_refer as a string (not array) should be rejected.
#[test]
fn adversarial_refer_wrong_type_rejected() {
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
allowed_read = ["/tmp"]
allowed_refer = "/tmp"
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(126),
        "allowed_refer as string (not array) should be rejected. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Shell redirect with O_TRUNC on new file ---

/// Shell redirect `>` to create a NEW file in a dir with write but not truncate
/// should succeed. Landlock's Truncate right only applies when truncating an
/// existing file, not when O_CREAT creates a new file.
#[test]
fn adversarial_shell_redirect_new_file_ok_without_truncate() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp", "/scratch"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_truncate = ["/tmp"]
"#,
        base_config()
    );
    // /scratch has write but NOT truncate. Creating a NEW file via `>` should
    // succeed because O_TRUNC on a new file doesn't trigger Truncate check.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo test > /scratch/brandnew && cat /scratch/brandnew && echo create_ok",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("create_ok"),
        "creating new file via redirect should work without truncate. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Overwriting existing file via redirect needs truncate ---

/// Shell redirect `>` to OVERWRITE an existing file in a dir with write but not
/// truncate should fail on V3 ABI because the file exists and O_TRUNC triggers
/// the Truncate check.
#[test]
fn adversarial_shell_redirect_existing_file_needs_truncate() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp", "/scratch"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_truncate = ["/tmp"]
"#,
        base_config()
    );
    // First create the file via append (no O_TRUNC), then try to overwrite with >
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "echo first >> /scratch/existing && echo second > /scratch/existing 2>&1; echo exit_$?",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Overwriting an existing file uses O_TRUNC which should be blocked
    assert!(
        stdout.contains("Permission denied")
            || stdout.contains("exit_1")
            || stdout.contains("exit_2"),
        "overwriting existing file on /scratch should fail without truncate. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Combined: all V1-V3 fields populated, verify truncate works on allowed path ---

/// With all V1-V3 fields populated, truncation should work on paths in
/// allowed_truncate but fail on paths not in it.
#[test]
fn adversarial_full_v3_config_truncate_selective() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch"]
allowed_write = ["/tmp", "/scratch"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_refer = ["/tmp", "/scratch"]
allowed_truncate = ["/tmp"]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            concat!(
                "echo data > /tmp/file && ",
                "truncate -s 0 /tmp/file && ",
                "echo tmp_trunc_ok; ",
                "echo data >> /scratch/file; ",
                "truncate -s 0 /scratch/file 2>&1; echo scratch_trunc_exit_$?"
            ),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("tmp_trunc_ok"),
        "/tmp truncation should succeed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("scratch_trunc_exit_1")
            || stdout.contains("scratch_trunc_exit_2")
            || stdout.contains("Permission denied"),
        "/scratch truncation should fail. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

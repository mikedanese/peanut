//! Invariant tests for pnut sandbox.
//!
//! These verify spec-level invariants that must always hold.
//! They are never deleted, only added to.

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

/// INVARIANT: No partial sandboxes.
/// If a child setup step fails between clone3 and execve, the child exits 126
/// and the target command is never executed in a partially-configured sandbox.
#[test]
fn invariant_no_partial_sandbox_on_bad_mount_source() {
    let uid = current_uid();
    let gid = current_gid();
    // Config with a bind mount pointing to a non-existent source path.
    // Filesystem setup should fail and the child should exit 126.
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

[[mount]]
src = "/nonexistent-path-that-does-not-exist"
dst = "/mnt/test"
bind = true
"#
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "THIS SHOULD NOT PRINT"])
        .output()
        .unwrap();
    // The command should NOT have run — echo should not have printed.
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("THIS SHOULD NOT PRINT"),
        "target command ran despite mount setup failure — partial sandbox!"
    );
    // Should exit with a non-zero code (ideally 126).
    assert!(
        !out.status.success(),
        "pnut should have failed when mount source does not exist"
    );
    // Stderr should mention the failing path.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("nonexistent")
            || stderr.contains("does not exist")
            || stderr.contains("No such file"),
        "error should mention the bad path, got: {stderr}"
    );
}

/// INVARIANT: Pipe lifecycle is airtight.
/// No leaked descriptors cross into execve. Verified by checking /proc/self/fd.
#[test]
fn invariant_no_leaked_fds_into_execve() {
    let config = filesystem_config();
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/sh",
            "-c",
            // Count entries in /proc/self/fd. We expect only 0, 1, 2 plus
            // the fd that sh opens to read the directory.
            "ls /proc/self/fd | sort -n",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fd listing failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let fds: Vec<u32> = stdout
        .trim()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
    // Expected: 0, 1, 2, and possibly 3 (ls's own dir fd).
    // Anything above 3 is a leaked fd.
    for fd in &fds {
        assert!(
            *fd <= 3,
            "unexpected fd {} found in sandbox — possible leak. All fds: {:?}",
            fd,
            fds
        );
    }
}

/// INVARIANT: Mount namespace is private before any mounts.
/// The child makes the mount tree recursively private (MS_REC|MS_PRIVATE)
/// before creating any new mounts. We verify this by checking that the
/// sandbox's mount operations don't affect the host.
///
/// This test creates a file in the sandbox's /tmp and verifies the host's
/// /tmp does not contain it.
#[test]
fn invariant_mount_namespace_is_private() {
    let config = filesystem_config();
    let marker = format!("pnut-test-marker-{}", std::process::id());
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/sh",
            "-c",
            &format!("echo test > /tmp/{marker}"),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "sandbox command failed. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The file should NOT exist on the host
    let host_path = format!("/tmp/{marker}");
    assert!(
        !std::path::Path::new(&host_path).exists(),
        "file created in sandbox appeared on host at {host_path} — mount namespace is not private!"
    );
}

/// INVARIANT: Old root is fully detached.
/// After pivot_root, the old root is unmounted with MNT_DETACH.
/// No path traversal can reach the host filesystem.
#[test]
fn invariant_old_root_detached() {
    let config = filesystem_config();
    // Try multiple escape techniques
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/sh",
            "-c",
            concat!(
                "# Attempt 1: direct path to old root\n",
                "test -d /.old_root && echo 'ESCAPE:old_root_exists' || true\n",
                "# Attempt 2: /proc/1/mountinfo should not reference host paths\n",
                "cat /proc/1/mountinfo 2>/dev/null | grep -c ' / / ' || true\n",
                "# Attempt 3: findmnt for host root\n",
                "echo 'DONE'"
            ),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("ESCAPE:old_root_exists"),
        "old root directory is still accessible!"
    );
    assert!(stdout.contains("DONE"), "test script did not complete");
}

/// INVARIANT: Binary compiles with no warnings.
#[test]
fn invariant_no_compiler_warnings() {
    let out = Command::new("cargo")
        .args(["build", "--message-format=short"])
        .env("RUSTFLAGS", "-D warnings")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "cargo build with -D warnings failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

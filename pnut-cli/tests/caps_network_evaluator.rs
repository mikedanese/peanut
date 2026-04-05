//! Adversarial tests for capability dropping and network loopback.
//!
//! These tests probe edge cases the Generator's tests may not cover:
//! - Capability dropping in execve mode
//! - Attempting to bind to external addresses in net namespace
//! - Multiple capabilities in the keep list
//! - Case sensitivity of capability names
//! - Bounding set verification (can't regain caps via file caps)
//! - Loopback with capability dropping combined

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

fn filesystem_config_with_net() -> String {
    let uid = current_uid();
    let gid = current_gid();
    format!(
        r#"
[namespaces]
user = true
pid = true
mount = true
net = true

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

/// Filesystem config for execve mode -- pid=false and no proc mount
/// (proc mount requires PID namespace, which execve mode doesn't create).
fn filesystem_config_execve() -> String {
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
"#
    )
}

// ── Test: Capability dropping works in execve mode ──
// Verifies criterion 7.1 works in both run modes (spec invariant 6).

#[test]
fn eval_adversarial_caps_execve_mode() {
    // In execve mode we can't mount proc, so verify caps are dropped by
    // attempting a privileged operation that should fail with EPERM.
    let config = format!(
        r#"{}
[capabilities]
keep = []
"#,
        filesystem_config_execve()
    );

    // With all caps dropped, trying to sethostname should fail with EPERM.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import ctypes, sys
libc = ctypes.CDLL('libc.so.6', use_errno=True)
ret = libc.sethostname(b'test', 4)
if ret != 0:
    errno = ctypes.get_errno()
    if errno == 1:  # EPERM
        print('caps_dropped_ok')
        sys.exit(0)
    else:
        print(f'unexpected_errno:{errno}')
        sys.exit(1)
else:
    print('sethostname_succeeded_bad')
    sys.exit(1)
"#,
        ])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("caps_dropped_ok"),
        "capabilities should be dropped in execve mode.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}

// ── Test: Multiple capabilities in keep list ──

#[test]
fn eval_adversarial_caps_keep_multiple() {
    let config = format!(
        r#"{}
[capabilities]
keep = ["CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN"]
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "grep '^CapEff:' /proc/self/status | sed 's/.*\t//'",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let cap_eff = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let cap_val = u64::from_str_radix(&cap_eff, 16).expect("CapEff should be hex");
    // CAP_NET_BIND_SERVICE = bit 10 = 0x400
    // CAP_SYS_ADMIN = bit 21 = 0x200000
    let expected = 0x400 | 0x200000;
    assert_eq!(
        cap_val, expected,
        "expected CapEff = 0x{:x} (NET_BIND_SERVICE + SYS_ADMIN), got: 0x{:x}",
        expected, cap_val
    );
}

// ── Test: Case sensitivity — lowercase cap name behavior ──

#[test]
fn eval_adversarial_caps_case_sensitive() {
    let config = format!(
        r#"{}
[capabilities]
keep = ["cap_net_bind_service"]
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr);

    if code != 0 {
        assert_eq!(
            code, 126,
            "if lowercase cap name is rejected, should be exit 126, got: {}. stderr: {}",
            code, stderr
        );
    }
}

// ── Test: Bounding set is also cleared ──

#[test]
fn eval_adversarial_caps_bounding_set_cleared() {
    let config = format!(
        r#"{}
[capabilities]
keep = []
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "grep '^CapBnd:' /proc/self/status | sed 's/.*\t//'",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let cap_bnd = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        cap_bnd, "0000000000000000",
        "CapBnd should be all zeros with keep=[] for defense in depth, got: {}",
        cap_bnd
    );
}

// ── Test: Permitted set matches keep list ──

#[test]
fn eval_adversarial_caps_permitted_matches_keep() {
    let config = format!(
        r#"{}
[capabilities]
keep = ["CAP_NET_BIND_SERVICE"]
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "grep -E '^Cap(Eff|Prm):' /proc/self/status | sed 's/.*\t//'",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout_str = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = stdout_str.trim().split('\n').map(|s| s.trim()).collect();

    assert_eq!(
        lines.len(),
        2,
        "expected 2 lines (CapEff, CapPrm), got: {:?}",
        lines
    );

    assert_eq!(
        lines[0], lines[1],
        "CapEff and CapPrm should match. CapEff={}, CapPrm={}",
        lines[0], lines[1]
    );
}

// ── Test: Net namespace — bind to non-loopback should fail ──

#[test]
fn eval_adversarial_net_bind_external_fails() {
    let config = filesystem_config_with_net();

    let script = r#"
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('10.0.0.1', 12345))
    s.close()
    print('bind_succeeded')
    sys.exit(1)
except OSError:
    print('bind_blocked')
    sys.exit(0)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bind_blocked"),
        "binding to external IP should fail in net namespace.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}

// ── Test: Loopback + capability drop combined ──

#[test]
fn eval_adversarial_loopback_with_caps_dropped() {
    let uid = current_uid();
    let gid = current_gid();
    let config = format!(
        r#"
[namespaces]
user = true
pid = true
mount = true
net = true

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

[capabilities]
keep = []
"#
    );

    let script = r#"
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    print(f'loopback_ok:{port}')
    sys.exit(0)
except Exception as e:
    print(f'loopback_fail:{e}')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("loopback_ok"),
        "loopback should work even with all caps dropped.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}

// ── Test: deny_unknown_fields on CapabilitiesConfig ──

#[test]
fn eval_adversarial_caps_unknown_field_rejected() {
    let config = format!(
        r#"{}
[capabilities]
keep = []
drop = ["CAP_SYS_ADMIN"]
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(126),
        "unknown field 'drop' in [capabilities] should be rejected. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Test: Ambient capabilities also cleared ──

#[test]
fn eval_adversarial_caps_ambient_cleared() {
    let config = format!(
        r#"{}
[capabilities]
keep = []
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "grep '^CapAmb:' /proc/self/status | sed 's/.*\t//'",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let cap_amb = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        cap_amb, "0000000000000000",
        "CapAmb should be all zeros with keep=[], got: {}",
        cap_amb
    );
}

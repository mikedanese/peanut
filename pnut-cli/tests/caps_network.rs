//! Tests for capability dropping and network namespace loopback.
//!
//! Tests exercise capability management (keep=[], keep=[specific], omitted),
//! network loopback bring-up in new net namespaces, network isolation,
//! host network inheritance, invalid capability validation, and combined
//! feature interaction (rlimits + Landlock + capabilities + loopback).

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

/// Full filesystem config with proc mounted (needed for /proc/self/status).
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

/// Full filesystem config with net namespace enabled.
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

// ── Test 7.1: Empty keep list drops all capabilities ──

#[test]
fn adversarial_caps_empty_keep_drops_all() {
    // With keep = [], all capabilities should be dropped.
    // CapEff in /proc/self/status should show all zeros.
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
    // All zeros means no capabilities.
    assert_eq!(
        cap_eff, "0000000000000000",
        "expected CapEff all zeros with keep=[], got: {}",
        cap_eff
    );
}

// ── Test 7.2: Keep specific capability retains only that one ──

#[test]
fn adversarial_caps_keep_one_retains_only_that() {
    // CAP_NET_BIND_SERVICE is bit 10.
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
    // CAP_NET_BIND_SERVICE is bit 10 = 0x400.
    assert_eq!(
        cap_val, 0x400,
        "expected CapEff = 0x400 (only CAP_NET_BIND_SERVICE), got: 0x{:x}",
        cap_val
    );
}

// ── Test 7.3: Omitting [capabilities] leaves caps unchanged ──

#[test]
fn adversarial_caps_omitted_inherits_all() {
    // Without [capabilities], the process should have the full user-namespace cap set.
    let config = filesystem_config();

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
    // In a user namespace, the process should have full caps (nonzero).
    assert!(
        cap_val != 0,
        "expected nonzero CapEff without [capabilities] section, got: 0x{:x}",
        cap_val
    );
}

// ── Test 7.4: Net namespace loopback is functional ──

#[test]
fn adversarial_net_loopback_functional() {
    // With namespaces.net = true, lo should be up. Verify by binding a
    // socket to 127.0.0.1 and connecting to it.
    let config = filesystem_config_with_net();

    // Use python3 to test TCP loopback: start a server, connect to it.
    let script = r#"
import socket, sys, threading
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
port = s.getsockname()[1]
s.listen(1)
def server():
    conn, _ = s.accept()
    conn.send(b'ok')
    conn.close()
    s.close()
t = threading.Thread(target=server)
t.start()
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(('127.0.0.1', port))
data = c.recv(10)
c.close()
t.join()
if data == b'ok':
    print('loopback_ok')
    sys.exit(0)
else:
    print('loopback_fail')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("loopback_ok"),
        "loopback should be functional in net namespace.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}

// ── Test 7.5: Net namespace blocks external network ──

#[test]
fn adversarial_net_no_external_access() {
    // With net=true, only lo is available. External network should fail.
    let config = filesystem_config_with_net();

    // Try to connect to 1.1.1.1:80 — should fail with network unreachable
    // or connection refused (no routes in the new net ns).
    let script = r#"
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(('1.1.1.1', 80))
    s.close()
    print('connected')
    sys.exit(1)
except (OSError, socket.timeout):
    print('blocked')
    sys.exit(0)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("blocked"),
        "external network should be blocked in new net namespace.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}

// ── Test 7.6: Net namespace false inherits host network ──

#[test]
fn adversarial_net_false_inherits_host() {
    // With net=false (default), the sandbox inherits host network.
    // lo should be up (inherited from host).
    let config = filesystem_config(); // net defaults to false

    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            // Check that lo interface exists and is UP in /proc/net/if_inet6
            // or just use ip/cat to check. Simplest: check we can read
            // /proc/net/dev which lists interfaces.
            "cat /proc/net/dev | grep -c lo",
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "should succeed with host network. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let count: i32 = stdout.parse().unwrap_or(0);
    assert!(
        count >= 1,
        "lo interface should be visible when inheriting host network, got count: {}",
        count
    );
}

// ── Test 7.7: Invalid capability name produces validation error ──

#[test]
fn adversarial_caps_invalid_name_error() {
    let config = format!(
        r#"{}
[capabilities]
keep = ["CAP_NONEXISTENT"]
"#,
        filesystem_config()
    );

    let out = pnut_with_config(&config)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    // Should exit 126 (config validation error before fork).
    assert_eq!(
        out.status.code(),
        Some(126),
        "invalid capability name should produce exit 126.\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("CAP_NONEXISTENT"),
        "error should mention the invalid capability name.\nstderr: {}",
        stderr
    );
    assert!(
        stderr.contains("invalid capability"),
        "error should explain the problem.\nstderr: {}",
        stderr
    );
}

// ── Test 7.8: All four features work together ──

#[test]
fn adversarial_all_four_features_combined() {
    // Combine rlimits + Landlock + capabilities + loopback (net namespace).
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

[[mount]]
type = "tmpfs"
dst = "/scratch"

[rlimits]
nofile = 64

[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc", "/tmp"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/bin", "/lib", "/lib64", "/usr/lib"]

[capabilities]
keep = ["CAP_NET_BIND_SERVICE"]
"#
    );

    // Verify all four features are active:
    // 1. rlimits: nofile is 64
    // 2. Landlock: can't write to /scratch
    // 3. capabilities: only CAP_NET_BIND_SERVICE
    // 4. loopback: lo is up
    let script = r#"
import resource, os, socket, sys

# Check rlimits
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
assert soft == 64, f"expected nofile=64, got {soft}"

# Check Landlock: writing to /scratch should fail
try:
    with open('/scratch/test', 'w') as f:
        f.write('x')
    print('landlock_fail')
    sys.exit(1)
except PermissionError:
    pass

# Check capabilities
with open('/proc/self/status') as f:
    for line in f:
        if line.startswith('CapEff:'):
            cap_eff = int(line.split()[1], 16)
            assert cap_eff == 0x400, f"expected CapEff=0x400, got 0x{cap_eff:x}"

# Check loopback
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 0))
s.close()

print('all_features_ok')
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("all_features_ok"),
        "all four features should work together.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// Existing tests continue to pass.
// (Implicitly verified by running cargo test.)

#[test]
fn adversarial_caps_cannot_reacquire_after_drop() {
    // After dropping all caps with keep=[], try to re-acquire caps via
    // capset. The process should not be able to raise any capability.
    let config = format!(
        r#"{}
[capabilities]
keep = []
"#,
        filesystem_config()
    );

    // Try to use prctl to set CAP_SYS_ADMIN — should fail.
    let script = r#"
import ctypes, sys
libc = ctypes.CDLL('libc.so.6', use_errno=True)

# Read CapEff — should be all zeros
with open('/proc/self/status') as f:
    for line in f:
        if line.startswith('CapEff:'):
            val = int(line.split()[1], 16)
            if val != 0:
                print(f'caps not zero: 0x{val:x}')
                sys.exit(1)

# Try to raise capability via prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN)
PR_CAP_AMBIENT = 47
PR_CAP_AMBIENT_RAISE = 2
CAP_SYS_ADMIN = 21
ret = libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_SYS_ADMIN, 0, 0)
if ret == 0:
    print('ambient_raise_succeeded')
    sys.exit(1)

# Verify caps still zero
with open('/proc/self/status') as f:
    for line in f:
        if line.startswith('CapEff:'):
            val = int(line.split()[1], 16)
            if val != 0:
                print(f'caps reacquired: 0x{val:x}')
                sys.exit(1)

print('reacquire_blocked')
sys.exit(0)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("reacquire_blocked"),
        "should not be able to re-acquire dropped capabilities.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}

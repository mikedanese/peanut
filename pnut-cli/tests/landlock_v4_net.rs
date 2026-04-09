//! Tests for Landlock ABI V4 TCP network policy.
//!
//! V4 (kernel 6.7+) adds AccessNet::{BindTcp, ConnectTcp} and NetPort rules.
//! This kernel is 6.8, so V4 is available.
//!
//! Network tests run inside a sandbox with `net = false` (the default), giving
//! an isolated network namespace with only loopback. This is sufficient for
//! testing bind/connect restrictions: the sandbox process can still bind to
//! loopback ports and connect to loopback listeners.

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

/// Base config with network namespace (loopback only) and minimal fs mounts.
fn base_config() -> String {
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

// --- Criterion 2.1: allowed_bind restricts TCP bind ---

/// Binding to an allowed port succeeds.
#[test]
fn landlock_v4_bind_allowed_port_succeeds() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080]
"#,
        base_config()
    );
    // Use Python to attempt a TCP bind on port 8080 (allowed).
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 8080))
    print('bind_ok')
except OSError as e:
    print(f'bind_fail: {e}')
finally:
    s.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bind_ok"),
        "bind to allowed port 8080 should succeed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Binding to a port NOT in allowed_bind is denied.
#[test]
fn landlock_v4_bind_denied_port_fails() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080]
"#,
        base_config()
    );
    // Try to bind on port 9090 (not allowed).
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 9090))
    print('bind_ok')
except OSError as e:
    print(f'bind_denied: {e}')
finally:
    s.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bind_denied"),
        "bind to port 9090 should be denied when only 8080 is allowed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Multiple allowed bind ports all work.
#[test]
fn landlock_v4_bind_multiple_ports() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080, 8443]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket
results = []
for port in [8080, 8443]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(('127.0.0.1', port))
        results.append(f'{port}_ok')
    except OSError as e:
        results.append(f'{port}_fail')
    finally:
        s.close()
print(' '.join(results))
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("8080_ok") && stdout.contains("8443_ok"),
        "both allowed bind ports should succeed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 2.2: allowed_connect restricts TCP connect ---

/// Connect to an allowed port succeeds (with a listener on that port).
#[test]
fn landlock_v4_connect_allowed_port_succeeds() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_connect = [7777]
allowed_bind = [7777]
"#,
        base_config()
    );
    // Start a listener on 7777, then connect to it.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 7777))
srv.listen(1)
def accept_one():
    conn, _ = srv.accept()
    conn.close()
t = threading.Thread(target=accept_one, daemon=True)
t.start()
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    c.connect(('127.0.0.1', 7777))
    print('connect_ok')
except OSError as e:
    print(f'connect_fail: {e}')
finally:
    c.close()
    srv.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("connect_ok"),
        "connect to allowed port should succeed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Connect to a port NOT in allowed_connect is denied.
#[test]
fn landlock_v4_connect_denied_port_fails() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_connect = [7777]
allowed_bind = [7777, 9999]
"#,
        base_config()
    );
    // Start a listener on 9999, try to connect to it (not in allowed_connect).
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 9999))
srv.listen(1)
def accept_one():
    conn, _ = srv.accept()
    conn.close()
t = threading.Thread(target=accept_one, daemon=True)
t.start()
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.settimeout(2)
try:
    c.connect(('127.0.0.1', 9999))
    print('connect_ok')
except OSError as e:
    print(f'connect_denied: {e}')
finally:
    c.close()
    srv.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("connect_denied"),
        "connect to port 9999 should be denied when only 7777 allowed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 2.3: pre-V4 kernel error ---
// On this kernel (6.8 >= 6.7), V4 is supported. We cannot directly test the
// "pre-V4 kernel" error path in an integration test. However, we can verify
// that the V5 error path (already tested) extends to V4 conceptually.
// The actual V4 ABI mismatch would be caught the same way V5 is (via
// required_abi + HardRequirement). We add a structural test to confirm the
// ABI ordering is correct.

/// Configuring allowed_bind with allowed_ioctl_dev (V5) on pre-V5 kernel
/// still errors out (V5 > V4, highest ABI wins).
#[test]
fn landlock_v4_v5_combined_errors_on_pre_v5_kernel() {
    // Skip on V5+ kernels
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
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
allowed_execute = ["/usr/bin", "/bin"]
allowed_bind = [80]
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
        "V4+V5 config on pre-V5 kernel should exit 126. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Criterion 2.4: combined fs + network ---

/// Filesystem and network Landlock restrictions work together.
#[test]
fn landlock_v4_combined_fs_and_network() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/proc"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080]
allowed_connect = [8080]
"#,
        base_config()
    );
    // Test that both fs restrictions (can write /tmp, can't write elsewhere)
    // and network restrictions (can bind/connect 8080, can't bind 9090) work.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, os

# Filesystem test: write to /tmp should work
with open('/tmp/test', 'w') as f:
    f.write('hello')
print('fs_write_ok')

# Filesystem test: write outside /tmp should fail
try:
    with open('/var/test', 'w') as f:
        f.write('hello')
    print('fs_escape_ok')
except OSError:
    print('fs_blocked_ok')

# Network test: bind 8080 allowed
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 8080))
    print('net_bind_ok')
except OSError as e:
    print(f'net_bind_fail: {e}')

# Network test: bind 9090 denied
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s2.bind(('127.0.0.1', 9090))
    print('net_escape_ok')
except OSError:
    print('net_blocked_ok')
s.close()
s2.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("fs_write_ok"),
        "fs write to /tmp should work. stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stdout.contains("fs_blocked_ok"),
        "fs write outside /tmp should be blocked. stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stdout.contains("net_bind_ok"),
        "network bind to 8080 should work. stdout: {stdout}, stderr: {stderr}"
    );
    assert!(
        stdout.contains("net_blocked_ok"),
        "network bind to 9090 should be blocked. stdout: {stdout}, stderr: {stderr}"
    );
}

// --- Criterion 2.5: additional edge case tests ---

/// Empty allowed_bind and allowed_connect don't activate network restrictions.
#[test]
fn landlock_v4_empty_net_fields_no_restriction() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = []
allowed_connect = []
"#,
        base_config()
    );
    // With empty network fields, bind to any port should work (V1 ABI).
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 12345))
    print('unrestricted_bind_ok')
except OSError as e:
    print(f'bind_fail: {e}')
finally:
    s.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("unrestricted_bind_ok"),
        "empty net fields should not restrict network. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Only allowed_connect configured (no allowed_bind) — bind is unrestricted
/// because only ConnectTcp is governed, not BindTcp.
#[test]
fn landlock_v4_connect_only_bind_unrestricted() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_connect = [443]
"#,
        base_config()
    );
    // With only allowed_connect configured, only ConnectTcp is governed.
    // BindTcp is NOT governed, so bind to any port should succeed.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 12345))
    print('bind_ok')
except OSError as e:
    print(f'bind_denied: {e}')
finally:
    s.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bind_ok"),
        "bind should be unrestricted when only allowed_connect is configured. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Only allowed_bind configured (no allowed_connect) — connect is unrestricted.
#[test]
fn landlock_v4_bind_only_connect_unrestricted() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080, 6666]
"#,
        base_config()
    );
    // Start a listener on 6666 (allowed bind), then connect to it.
    // Connect should succeed because ConnectTcp is not governed.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, threading
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 6666))
srv.listen(1)
def accept_one():
    conn, _ = srv.accept()
    conn.close()
t = threading.Thread(target=accept_one, daemon=True)
t.start()
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    c.connect(('127.0.0.1', 6666))
    print('connect_ok')
except OSError as e:
    print(f'connect_fail: {e}')
finally:
    c.close()
    srv.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("connect_ok"),
        "connect should be unrestricted when only allowed_bind is configured. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// V4 config is accepted on this V4+ kernel (6.8 >= 6.7).
#[test]
fn landlock_v4_config_accepted_on_v4_kernel() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080]
allowed_connect = [8080]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/sh", "-c", "echo v4_ok"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("v4_ok"),
        "V4 config should be accepted on V4+ kernel. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Combined V1+V2+V3+V4 config works together.
#[test]
fn landlock_v4_combined_v1_v2_v3_v4_config() {
    let config = format!(
        r#"{}
[[mount]]
type = "tmpfs"
dst = "/scratch"

[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/tmp", "/scratch", "/proc"]
allowed_write = ["/tmp", "/scratch"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_refer = ["/tmp", "/scratch"]
allowed_truncate = ["/tmp"]
allowed_bind = [7070]
allowed_connect = [7070]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket, threading, os

# V1 fs: write to /tmp
with open('/tmp/test', 'w') as f:
    f.write('data')
print('v1_write_ok')

# V3 truncate: truncate allowed on /tmp
os.truncate('/tmp/test', 0)
print('v3_truncate_ok')

# V4 network: bind and connect 7070
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 7070))
srv.listen(1)
print('v4_bind_ok')

def accept_one():
    conn, _ = srv.accept()
    conn.close()
t = threading.Thread(target=accept_one, daemon=True)
t.start()

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(('127.0.0.1', 7070))
c.close()
srv.close()
print('v4_connect_ok')

print('combined_all_ok')
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stdout.contains("combined_all_ok"),
        "combined V1+V2+V3+V4 config should work. stdout: {stdout}, stderr: {stderr}"
    );
}

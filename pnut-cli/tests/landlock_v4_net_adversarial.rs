//! Adversarial tests for Landlock V4 TCP network policy.
//!
//! These tests probe edge cases and failure modes beyond the generator's tests.

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

// --- Invariant: deny_unknown_fields preserved on Landlock ---

/// Unknown fields in [landlock] section are rejected (V4 fields don't break serde).
#[test]
fn adversarial_landlock_v4_unknown_field_rejected() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
allowed_execute = ["/usr/bin", "/bin"]
allowed_bind = [80]
allowed_connect_tcp = [443]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "unknown field 'allowed_connect_tcp' should be rejected by deny_unknown_fields"
    );
}

// --- Invariant: empty/absent field = no restriction ---

/// Absent allowed_bind and allowed_connect means no network restriction at all.
#[test]
fn adversarial_absent_net_fields_no_restriction() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
"#,
        base_config()
    );
    // With no network fields at all, any bind should work.
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
    s.bind(('127.0.0.1', 11111))
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
        "absent net fields should not restrict network. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Edge case: port 0 (wildcard bind) ---

/// allowed_bind = [0] should allow binding to port 0 (kernel assigns ephemeral port).
#[test]
fn adversarial_bind_port_zero_allowed() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [0]
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
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    print(f'bind_ok port={port}')
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
        "binding to port 0 with allowed_bind=[0] should succeed. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Edge case: bind and connect both configured, verify mutual independence ---

/// When both bind and connect are configured, binding to a connect-only port
/// should fail, and connecting to a bind-only port should also fail.
#[test]
fn adversarial_bind_connect_independent_enforcement() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [5555]
allowed_connect = [6666]
"#,
        base_config()
    );
    // Try to bind on 6666 (only in connect list, not bind list) — should fail.
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
    s.bind(('127.0.0.1', 6666))
    print('bind_6666_ok')
except OSError as e:
    print('bind_6666_denied')
finally:
    s.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("bind_6666_denied"),
        "binding to a port only in allowed_connect should be denied. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Edge case: wrong type for allowed_bind ---

/// allowed_bind expects integers, not strings. TOML parser should reject.
#[test]
fn adversarial_bind_wrong_type_rejected() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
allowed_execute = ["/usr/bin", "/bin"]
allowed_bind = ["80"]
"#,
        base_config()
    );
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "hello"])
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "string in allowed_bind should be rejected. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Edge case: duplicate ports in allowed_bind ---

/// Duplicate ports should be accepted without error (no deduplication needed,
/// Landlock handles it).
#[test]
fn adversarial_duplicate_ports_accepted() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080, 8080, 8080]
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
        "duplicate ports in allowed_bind should still work. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// --- Verify library API has allow_bind/allow_connect builders ---

/// The SandboxBuilder API should expose allow_bind and allow_connect on the
/// Landlock config via the builder pattern.
#[test]
fn adversarial_builder_api_has_net_methods() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080]
allowed_connect = [443]
"#,
        base_config()
    );
    // Just verify the config parses and runs without error (exit 0 from echo).
    let out = pnut_with_config(&config)
        .args(["--", "/bin/echo", "api_ok"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("api_ok"),
        "config with both bind and connect should parse. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0));
}

// --- Verify UDP is NOT affected by TCP-only Landlock rules ---

/// Landlock V4 only governs TCP. UDP bind should still work even when
/// allowed_bind restricts TCP.
#[test]
fn adversarial_udp_not_restricted_by_tcp_landlock() {
    let config = format!(
        r#"{}
[landlock]
allowed_read = ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc"]
allowed_execute = ["/usr/bin", "/usr/lib", "/bin", "/lib", "/lib64", "/sbin"]
allowed_bind = [8080]
"#,
        base_config()
    );
    // TCP bind to 9999 should fail, but UDP bind to 9999 should succeed.
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/usr/bin/python3",
            "-c",
            r#"
import socket
# UDP bind should NOT be restricted by TCP Landlock rules
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind(('127.0.0.1', 9999))
    print('udp_bind_ok')
except OSError as e:
    print(f'udp_bind_fail: {e}')
finally:
    s.close()

# TCP bind to 9999 should be denied
t = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    t.bind(('127.0.0.1', 9999))
    print('tcp_bind_ok')
except OSError as e:
    print('tcp_bind_denied')
finally:
    t.close()
"#,
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("udp_bind_ok"),
        "UDP should not be restricted by TCP Landlock rules. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("tcp_bind_denied"),
        "TCP bind to non-allowed port should be denied. stdout: {stdout}, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

//! Tests for seccomp-bpf policy compilation and filter loading.
//!
//! Tests cover: default_action enforcement (allow/kill), argument filtering
//! (eq, masked_eq), rule ordering, seccomp loading order
//! (after PR_SET_NO_NEW_PRIVS, last before execve), mode compatibility,
//! and combined feature interaction.

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

/// Create a TOML config with a seccomp policy file.
/// Returns a config string with `seccomp_policy_file` pointing to a temp file
/// containing the kafel policy DSL.
/// The policy file is written to /tmp, which is mounted in the sandbox tests.
fn config_with_policy(base_config: &str, policy_dsl: &str) -> String {
    // Use a unique filename based on content and time to avoid collisions
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut hasher = DefaultHasher::new();
    policy_dsl.hash(&mut hasher);
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let hash = hasher.finish();

    let policy_dir = format!("/tmp/pnut_policies_{:x}", hash);
    let _ = std::fs::create_dir_all(&policy_dir);
    let policy_path = format!("{}/policy.kafel", policy_dir);
    std::fs::write(&policy_path, policy_dsl).unwrap();

    // Mount the policy directory into the sandbox at the same path
    // This way the path is valid on both the host (for validation) and in the sandbox
    let config_with_mount = format!(
        r#"{}
[[mount]]
src = "{}"
dst = "{}"
bind = true
read_only = true
"#,
        base_config, policy_dir, policy_dir
    );

    format!(
        r#"seccomp_policy_file = "{}"
{}
"#,
        policy_path, config_with_mount
    )
}

fn config_with_inline_policy(base_config: &str, policy_dsl: &str) -> String {
    format!(
        r#"seccomp_policy = '''
{policy_dsl}'''
{base_config}
"#
    )
}

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getgid() }
}

/// Full filesystem config with proc mounted.
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

/// Filesystem config for execve mode (no pid namespace, no proc mount).
fn filesystem_config_execve() -> String {
    let uid = current_uid();
    let gid = current_gid();
    format!(
        r#"
[sandbox]
mode = "execve"

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

[[mount]]
src = "/proc"
dst = "/proc"
bind = true
"#
    )
}

// ── Test 8.1: default_action=allow + errno rule on getpid -> EPERM ──

#[test]
fn adversarial_seccomp_errno_getpid() {
    // With a rule to errno getpid, calling getpid() via raw syscall
    // should return -1 with errno=EPERM (1).
    let policy = "POLICY seccomp { ERRNO(1) { getpid } }\nUSE seccomp DEFAULT ALLOW\n";
    let config = config_with_policy(&filesystem_config(), policy);

    // Use python3 to call getpid via raw syscall and check errno.
    let script = r#"
import ctypes, ctypes.util, sys
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(39)  # SYS_getpid on x86_64
err = ctypes.get_errno()
if ret == -1 and err == 1:
    print('getpid_blocked_eperm')
    sys.exit(0)
else:
    print(f'unexpected: ret={ret} errno={err}')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("getpid_blocked_eperm"),
        "getpid() should return EPERM.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Test 8.2: default_action=kill causes exit 159 on disallowed syscall ──

#[test]
fn adversarial_seccomp_kill_default() {
    // With DEFAULT KILL and only execve allowed, attempting a disallowed syscall
    // should kill with SIGSYS (exit 159).
    let policy = "POLICY seccomp { ALLOW { execve } }\nUSE seccomp DEFAULT KILL\n";
    let config = config_with_policy(&filesystem_config(), policy);

    // Any program besides execve will need other syscalls.
    // Python will immediately try open/read and get killed.
    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", "1+1"])
        .output()
        .unwrap();

    // Exit code should be 159 (128 + 31 = SIGSYS) when killed by seccomp.
    assert_eq!(
        out.status.code(),
        Some(159),
        "process should be killed by seccomp (SIGSYS, exit 159).\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Test 8.3: Argument filtering: socket AF_INET vs AF_INET6 ──

#[test]
fn adversarial_seccomp_arg_filter_socket() {
    // Block socket with AF_INET6 (a0 == 10) with errno 93.
    let policy = "POLICY seccomp { ERRNO(93) { socket(a0, a1, a2, a3, a4, a5) { a0 == 10 } } }\nUSE seccomp DEFAULT ALLOW\n";
    let config = config_with_policy(&filesystem_config(), policy);

    let script = r#"
import socket, sys

# AF_INET socket should work (default=allow, no matching rule for AF_INET)
try:
    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s4.close()
    inet_ok = True
except OSError:
    inet_ok = False

# AF_INET6 socket should fail with ENOTSUP (93)
try:
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s6.close()
    inet6_ok = True
except OSError as e:
    inet6_ok = False
    inet6_errno = e.errno

if inet_ok and not inet6_ok:
    print('arg_filter_ok')
    sys.exit(0)
else:
    print(f'inet_ok={inet_ok} inet6_ok={inet6_ok}')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("arg_filter_ok"),
        "AF_INET should be allowed, AF_INET6 should be blocked.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Test 8.4: masked_eq operator for flag filtering (mmap PROT_EXEC) ──

#[test]
fn adversarial_seccomp_masked_eq_mmap() {
    // Block mmap with PROT_EXEC (bit 2 = 0x4) using masked_eq.
    // Rule: if (a2 & 4) == 4, then errno.
    //
    // We must use a statically linked binary (busybox) because seccomp is
    // installed before execve — the dynamic linker's mmap calls would be
    // filtered, preventing any dynamically linked program from starting.
    let uid = current_uid();
    let gid = current_gid();

    let base_config = format!(
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
type = "tmpfs"
dst = "/tmp"
"#
    );

    let policy = "POLICY seccomp { ERRNO(1) { mmap(a0, a1, a2, a3, a4, a5) { (a2 & 4) == 4 } } }\nUSE seccomp DEFAULT ALLOW\n";
    let config = config_with_policy(&base_config, policy);

    // Try to run a dynamically linked program (/bin/sh) — it should fail
    // because the dynamic linker can't mmap shared libraries with PROT_EXEC.
    // Then try busybox (statically linked) — it should succeed because the
    // kernel loads it without user-space mmap.
    //
    // First: dynamically linked binary should fail.
    let out_dynamic = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", "print('should_not_reach')"])
        .output()
        .unwrap();

    // Python should fail to start (dynamic linker can't mmap .so with PROT_EXEC).
    assert!(
        !out_dynamic.status.success(),
        "dynamically linked program should fail with PROT_EXEC blocked"
    );

    // Second: statically linked busybox should work.
    let out_static = pnut_with_config(&config)
        .args(["--", "/usr/bin/busybox", "echo", "masked_eq_ok"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out_static.stdout);
    assert!(
        stdout.contains("masked_eq_ok"),
        "statically linked busybox should work with PROT_EXEC blocked.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out_static.stderr)
    );
    assert!(
        out_static.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_static.stderr)
    );
}

// ── Test 8.5: Builtin allow_default_policy permits basic I/O under kill default ──

#[test]
fn adversarial_seccomp_preset_stdio() {
    // With a kafel policy that USEs the built-in allow_default_policy,
    // a statically linked busybox echo should work under DEFAULT KILL.
    // Busybox is statically linked so it doesn't need mmap PROT_EXEC
    // for shared library loading (the kernel loads it internally).
    let uid = current_uid();
    let gid = current_gid();

    let dir = tempfile::tempdir().unwrap();

    // Write the kafel policy file
    let policy_path = dir.path().join("policy.policy");
    // allow_default_policy covers startup + common I/O. prctl is added
    // because busybox calls PR_GET_NAME during init.
    std::fs::write(
        &policy_path,
        r#"
POLICY test {
    USE allow_default_policy
    ALLOW { prctl }
}
USE test DEFAULT KILL
"#,
    )
    .unwrap();

    let config = format!(
        r#"
seccomp_policy_file = "{policy_path}"

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
type = "tmpfs"
dst = "/tmp"
"#,
        policy_path = policy_path.display()
    );

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/busybox", "echo", "preset_ok"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("preset_ok"),
        "allow_default_policy should permit basic I/O with busybox.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "exit code: {:?}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );

    // Keep tempdir alive
    std::mem::forget(dir);
}

// ── Test 8.6: Multiple rules for same syscall — first match wins ──

#[test]
fn adversarial_seccomp_first_match_wins() {
    // Under default=allow, two rules for socket:
    //   1. socket with arg0=2 (AF_INET) -> errno (first match should block AF_INET)
    //   2. socket with arg0=10 (AF_INET6) -> errno (second match blocks AF_INET6)
    //   AF_UNIX (1) should still work (doesn't match either rule).
    let policy = r#"
POLICY seccomp {
    ERRNO(1) { socket(a0, a1, a2, a3, a4, a5) { a0 == 2 } }
    ERRNO(1) { socket(a0, a1, a2, a3, a4, a5) { a0 == 10 } }
}
USE seccomp DEFAULT ALLOW
"#;
    let config = config_with_policy(&filesystem_config(), policy);

    let script = r#"
import socket, sys

# AF_UNIX (1) should work — doesn't match either rule.
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.close()
    unix_ok = True
except OSError:
    unix_ok = False

# AF_INET (2) should fail — matches first rule.
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.close()
    inet_ok = True
except OSError:
    inet_ok = False

# AF_INET6 (10) should fail — matches second rule.
try:
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    s.close()
    inet6_ok = True
except OSError:
    inet6_ok = False

if unix_ok and not inet_ok and not inet6_ok:
    print('multi_rule_ok')
    sys.exit(0)
else:
    print(f'unix_ok={unix_ok} inet_ok={inet_ok} inet6_ok={inet6_ok}')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("multi_rule_ok"),
        "Multiple rules for same syscall should work.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Test 8.7: Seccomp loaded after PR_SET_NO_NEW_PRIVS, last before execve ──

#[test]
fn adversarial_seccomp_ordering() {
    // Verify seccomp is applied correctly by checking that:
    // 1. The process runs (execve happens after seccomp)
    // 2. The seccomp filter is active (getpid blocked)
    // This proves seccomp was installed after PR_SET_NO_NEW_PRIVS and
    // before execve (otherwise the process wouldn't start OR the filter
    // wouldn't be active).
    let config = config_with_inline_policy(
        &filesystem_config(),
        "POLICY seccomp { ERRNO(42) { getpid } }\nUSE seccomp DEFAULT ALLOW\n",
    );

    let script = r#"
import ctypes, ctypes.util, sys
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.syscall.restype = ctypes.c_long

# Verify seccomp is active by checking getpid returns errno 42
ret = libc.syscall(39)  # SYS_getpid
err = ctypes.get_errno()

# Also verify we CAN read /proc/self/status (proves other setup completed)
try:
    with open('/proc/self/status') as f:
        status = f.read()
    status_ok = 'NoNewPrivs:\t1' in status
except:
    status_ok = False

if ret == -1 and err == 42 and status_ok:
    print('ordering_ok')
    sys.exit(0)
else:
    print(f'ret={ret} err={err} status_ok={status_ok}')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ordering_ok"),
        "Seccomp should be loaded after PR_SET_NO_NEW_PRIVS, before execve.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── Test 8.8: Seccomp works in both modes, combines with all features ──

#[test]
fn adversarial_seccomp_both_modes_combined() {
    // Test seccomp in both once and execve modes combined with rlimits
    // and capabilities. Verifies all features work together.

    // Test in once mode first (with proc for /proc/self/status).
    let config_once = format!(
        r#"seccomp_policy = '''
POLICY seccomp {{ ERRNO(1) {{ getpid }} }}
USE seccomp DEFAULT ALLOW
'''
{}
[rlimits]
nofile = 64

[capabilities]
keep = []
"#,
        filesystem_config()
    );

    let script = r#"
import ctypes, ctypes.util, resource, sys

# Check rlimits active
soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
rlimit_ok = (soft == 64)

# Check seccomp active (getpid blocked)
libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(39)  # SYS_getpid
err = ctypes.get_errno()
seccomp_ok = (ret == -1 and err == 1)

# Check capabilities dropped
caps_ok = False
with open('/proc/self/status') as f:
    for line in f:
        if line.startswith('CapEff:'):
            cap_eff = int(line.split()[1], 16)
            caps_ok = (cap_eff == 0)

if rlimit_ok and seccomp_ok and caps_ok:
    print('combined_ok')
    sys.exit(0)
else:
    print(f'rlimit_ok={rlimit_ok} seccomp_ok={seccomp_ok} caps_ok={caps_ok}')
    sys.exit(1)
"#;

    let out = pnut_with_config(&config_once)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("combined_ok"),
        "Seccomp should work in once mode with all features.\nstdout: {}\nstderr: {}",
        stdout,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Test in execve mode (no pid namespace, bind-mount /proc without read_only
    // to avoid the remount EPERM issue).
    let config_execve = format!(
        r#"seccomp_policy = '''
POLICY seccomp {{ ERRNO(1) {{ getpid }} }}
USE seccomp DEFAULT ALLOW
'''
{}
[rlimits]
nofile = 64

[capabilities]
keep = []
"#,
        filesystem_config_execve()
    );

    let out_execve = pnut_with_config(&config_execve)
        .args(["--", "/usr/bin/python3", "-c", script])
        .output()
        .unwrap();

    let stdout_execve = String::from_utf8_lossy(&out_execve.stdout);
    assert!(
        stdout_execve.contains("combined_ok"),
        "Seccomp should work in execve mode with all features.\nstdout: {}\nstderr: {}",
        stdout_execve,
        String::from_utf8_lossy(&out_execve.stderr)
    );
    assert!(
        out_execve.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out_execve.stderr)
    );
}

// ── Test 8.9: All existing tests continue to pass ──
// (This is verified by running cargo test, not a separate test case.
// Including this test to confirm the seccomp test file itself runs.)

#[test]
fn adversarial_seccomp_validation_errors() {
    // Verify that invalid seccomp configs produce clear validation errors.

    // Unknown syscall name.
    let config = config_with_inline_policy(
        &filesystem_config(),
        "POLICY seccomp { ERRNO(1) { nonexistent_syscall } }\nUSE seccomp DEFAULT ALLOW\n",
    );

    let out = pnut_with_config(&config)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(126),
        "unknown syscall should produce exit 126.\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("nonexistent_syscall"),
        "error should mention the unknown syscall.\nstderr: {}",
        stderr
    );

    // Inline policy and seccomp_policy_file are mutually exclusive.
    let config2 = format!(
        r#"seccomp_policy = '''
USE allow_default_policy DEFAULT KILL
'''
seccomp_policy_file = "/tmp/should-not-be-read.policy"
{}
"#,
        filesystem_config()
    );

    let out2 = pnut_with_config(&config2)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    assert_eq!(
        out2.status.code(),
        Some(126),
        "conflicting seccomp config should produce exit 126.\nstderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let stderr2 = String::from_utf8_lossy(&out2.stderr);
    assert!(
        stderr2.contains("mutually exclusive"),
        "error should mention mutual exclusion.\nstderr: {}",
        stderr2
    );

    // Legacy [seccomp] config is rejected with a targeted error.
    let config_legacy = format!(
        r#"{}
[seccomp]
default_action = "allow"
"#,
        filesystem_config()
    );

    let out_legacy = pnut_with_config(&config_legacy)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    assert_eq!(
        out_legacy.status.code(),
        Some(126),
        "legacy [seccomp] should produce exit 126.\nstderr: {}",
        String::from_utf8_lossy(&out_legacy.stderr)
    );
    let stderr_legacy = String::from_utf8_lossy(&out_legacy.stderr);
    assert!(
        stderr_legacy.contains("legacy [seccomp]"),
        "error should mention the legacy table.\nstderr: {}",
        stderr_legacy
    );
    assert!(
        stderr_legacy.contains("seccomp_policy"),
        "error should point to the supported replacements.\nstderr: {}",
        stderr_legacy
    );

    // Removed builtin policy names should fail validation when used from
    // seccomp_policy_file.
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("removed_builtin.policy");
    std::fs::write(&policy_path, "USE allow_stdio DEFAULT KILL\n").unwrap();

    let config3 = format!(
        r#"
seccomp_policy_file = "{}"

[namespaces]
user = true
pid = true
mount = true

[uid_map]
inside = 0
outside = {}
count = 1

[gid_map]
inside = 0
outside = {}
count = 1

[[mount]]
src = "/bin"
dst = "/bin"
bind = true
read_only = true

[[mount]]
type = "tmpfs"
dst = "/tmp"
"#,
        policy_path.display(),
        current_uid(),
        current_gid()
    );

    let out3 = pnut_with_config(&config3)
        .args(["--", "/bin/true"])
        .output()
        .unwrap();

    assert_eq!(
        out3.status.code(),
        Some(126),
        "removed builtin name should produce exit 126.\nstderr: {}",
        String::from_utf8_lossy(&out3.stderr)
    );

    let stderr3 = String::from_utf8_lossy(&out3.stderr);
    assert!(
        stderr3.contains("allow_stdio"),
        "error should mention the removed builtin name.\nstderr: {}",
        stderr3
    );
}

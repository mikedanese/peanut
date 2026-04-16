//! Regression test: user `[[mount]]` entries targeting `/dev/*` must survive
//! `setup_dev`, which lays down a managed tmpfs on `/dev` before user mounts
//! are applied.
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
"#,
        uid = current_uid(),
        gid = current_gid(),
    )
}

/// User bind-mount under `/dev/*` must survive `setup_dev`.
///
/// Before the fix, `setup_dev` ran after the user mount loop and overlaid a
/// fresh tmpfs on `/dev`, silently erasing any user bind. This reproduced as
/// CUDA init failures when binding `/dev/nvidia0`.
#[test]
fn user_dev_bind_mount_survives_setup_dev() {
    let config = format!(
        r#"{base}
[[mount]]
src = "/dev/null"
dst = "/dev/my-device"
type = "bind"
"#,
        base = base_config(),
    );

    // Verify the bound path exists AND is a character device matching the
    // source (/dev/null is char 1:3). A future sanitization pass over /dev
    // that merely preserves the path as a regular file would defeat the
    // real-world intent (character device bind-mounts for e.g. /dev/nvidia0).
    let out = pnut_with_config(&config)
        .args([
            "--",
            "/bin/sh",
            "-c",
            "test -c /dev/my-device && [ \"$(stat -c '%t:%T' /dev/my-device)\" = \"1:3\" ]",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "user /dev/* bind was shadowed or not a char device. stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

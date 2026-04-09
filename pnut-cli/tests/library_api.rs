use pnut::{RunMode, SandboxBuilder};

fn current_uid() -> u32 {
    unsafe { libc::getuid() }
}

fn current_gid() -> u32 {
    unsafe { libc::getgid() }
}

fn base_builder() -> SandboxBuilder {
    let mut builder = SandboxBuilder::new();
    builder.uid_map(0, current_uid(), 1);
    builder.gid_map(0, current_gid(), 1);
    builder
}

#[test]
fn public_sandbox_builder_runs_command() {
    let mut builder = base_builder();
    builder.command("/bin/true");

    assert_eq!(builder.build().unwrap().run().unwrap(), 0);
}

#[test]
fn public_sandbox_builder_propagates_exit_code() {
    let mut builder = base_builder();
    builder.mode(RunMode::Once);
    builder.command("/bin/sh").args(["-c", "exit 7"]);

    assert_eq!(builder.build().unwrap().run().unwrap(), 7);
}

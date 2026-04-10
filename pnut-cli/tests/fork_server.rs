//! Multi-threaded fork-server safety tests.
//!
//! These tests prove that a single `Sandbox` can be shared by reference across
//! multiple OS threads and that each thread can independently call
//! `Sandbox::run()` without deadlocks, data races, or surprising failures.
//!
//! The pnut-child refactor (no_std, no heap) was motivated by making the
//! library safe to use from multi-threaded programs — post-fork code can't
//! deadlock on locks inherited from dead sibling threads. These tests
//! validate that premise end-to-end.

use std::thread;

use pnut::{Sandbox, SandboxBuilder, SeccompSource};

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

const THREADS: usize = 8;
const ITERS_PER_THREAD: usize = 4;

/// Spawn `THREADS` workers each invoking `sandbox.run()` `ITERS_PER_THREAD`
/// times, then flatten and assert every result is `Ok(0)`.
fn hammer(sandbox: &Sandbox) {
    let results: Vec<Vec<Result<i32, pnut::Error>>> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            handles.push(scope.spawn(|| {
                let mut local = Vec::with_capacity(ITERS_PER_THREAD);
                for _ in 0..ITERS_PER_THREAD {
                    local.push(sandbox.run());
                }
                local
            }));
        }
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let flat: Vec<Result<i32, pnut::Error>> = results.into_iter().flatten().collect();
    assert_eq!(
        flat.len(),
        THREADS * ITERS_PER_THREAD,
        "expected {} total runs",
        THREADS * ITERS_PER_THREAD
    );

    for (idx, r) in flat.iter().enumerate() {
        match r {
            Ok(code) => assert_eq!(*code, 0, "run #{idx} returned non-zero exit: {code}"),
            Err(e) => panic!("run #{idx} returned Err: {e:?}"),
        }
    }
}

#[test]
fn parallel_run_plain() {
    let mut builder = base_builder();
    builder.command("/bin/true");
    let sandbox = builder.build().unwrap();
    hammer(&sandbox);
}

#[test]
fn parallel_run_with_seccomp() {
    // Permissive seccomp policy: the point is to prove the compiled
    // kafel::BpfProgram inside the Sandbox can be read concurrently and
    // installed into each child. `/bin/true` just needs to execve and exit,
    // so `allow_default_policy` with a DEFAULT ALLOW fallback is plenty.
    let policy = "USE allow_default_policy DEFAULT ALLOW\n";

    let mut builder = base_builder();
    builder.command("/bin/true");
    builder.seccomp(SeccompSource::Inline(policy.to_string()));
    let sandbox = builder.build().unwrap();
    hammer(&sandbox);
}

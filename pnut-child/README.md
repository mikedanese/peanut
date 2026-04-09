# pnut-child

`pnut-child` is the child-runtime crate for `pnut`: the `#![no_std]` executor
that runs after `clone3()` and before `execve()`.

## Why this crate exists

After `clone3`/`fork`, the child process inherits a copy of the parent's
address space — including any locked mutexes held by threads that no longer
exist. Calling `malloc`, `std::env`, or any function that takes a lock will
deadlock. This is fine when the parent is single-threaded (like the `pnut`
CLI), but breaks for library users embedding `pnut` in multi-threaded
programs (tokio, rayon, etc.).

`pnut-child` enforces the correct execution model:

- `#![no_std]`, no `alloc` — zero heap allocation after fork
- raw syscalls only — no libc functions that aren't async-signal-safe
- data-driven — consumes a pre-built `ChildSpec`, doesn't reach back into
  parent data structures

## Architecture

```
pnut (parent/planner)              pnut-child (child/executor)
─────────────────────              ─────────────────────────
parse config                       
validate                           
compile seccomp → BPF              
build CStrings, buffers            
                                   
    Sandbox::prepare(&arena) → ChildSpec<'a>
                                   
         clone3()                  
           │                       
           └──child──→ run(&mut spec) -> !
                         1. PR_SET_PDEATHSIG
                         2. verify parent alive
                         3. wait on sync pipe
                         4. PR_SET_DUMPABLE
                         5. mount + pivot_root
                         6. hostname
                         7. loopback
                         8. rlimits
                         9. landlock
                        10. env assembly
                        11. capabilities
                        12. setsid
                        13. fd actions + close
                        14. TSC restriction
                        15. PR_SET_NO_NEW_PRIVS
                        16. PR_SET_MDWE
                        17. seccomp
                        18. chdir
                        19. execve
```

## Public API

The public interface is intentionally narrow:

- `run(&mut ChildSpec<'_>) -> !` — the executor entry point
- `ChildSpec<'a>` and subsystem spec types — the data contract
- `ChildFailure` and `Stage` — the fatal failure protocol

Everything else (fd helpers, mount syscall wrappers, env assembly, Landlock
execution) is internal implementation detail.

## Failure reporting

On setup failure, `pnut-child` writes a fixed-size 16-byte `ChildFailure`
record to `status_fd`:

```
[version: u16 | stage: u16 | errno: i32 | detail: i32 | exit_code: i32]
```

The parent decodes this into a structured `Error::ChildSetup` with the
failing stage, errno, and a human-readable message. On successful `execve`,
the `CLOEXEC` flag closes the write end automatically — the parent reads
0 bytes (no failure).

When `status_fd` is `None` (execve mode), `pnut-child` writes stage-specific
error messages directly to stderr.

## Crate properties

- `#![no_std]` with only `libc` as a dependency
- no heap allocation anywhere
- all operations are async-signal-safe
- safe for use after fork in multi-threaded processes

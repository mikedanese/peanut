# pnut Architecture

A lightweight, config-driven Linux sandbox tool. Uses raw syscalls, TOML configuration, and supports Landlock filesystem access control. Runs entirely unprivileged via user namespaces.

## Crate Structure

```
pnut/           Library crate — planner/preparer. Validates config, compiles
                seccomp, builds CString storage, and translates high-level
                config types into pnut-child spec types.

pnut-child/     #![no_std] child runtime — executor. Runs after clone3, uses
                only raw syscalls, zero heap allocation. Consumes a borrowed
                ChildSpec and applies all sandbox restrictions before execve.

pnut-cli/       CLI binary — TOML config loading, argument parsing, invokes
                pnut library.

kafel/          Standalone seccomp-bpf policy compiler (Kafel DSL to BPF).
```

## Run Modes

- **Once** (default): Parent creates the sandbox via `clone3`, child calls `pnut_child::run()`, parent supervises with pidfd + signalfd poll loop, forwards signals, propagates exit status.

- **Execve**: Calling process `unshare`s namespaces, writes its own ID maps, calls `pnut_child::run()` in-process (no fork). The process replaces itself with the target command. Useful when invoked as a wrapper by a process manager.

## Key Isolation Techniques

- **Linux namespaces** — `clone3` creates user, PID, mount, network, IPC, UTS, cgroup, and time namespaces in a single syscall. CLONE_PIDFD provides race-free process management.

- **Seccomp-bpf** — Kafel-inspired policy DSL compiled directly to BPF bytecode. Supports named arguments, `#define` constants, boolean expression trees, policy composition via `USE`, `#include` for reusable policies, and built-in stdlib policies.

- **Filesystem isolation** — New mount API (`fsopen`/`fsconfig`/`fsmount`/`move_mount`/`open_tree`/`mount_setattr`) for fd-based mount construction. Eliminates TOCTOU races. Entire mount tree built fd-relative to the root tmpfs. `pivot_root(".", ".")` via fchdir for the final root switch.

- **Landlock** — LSM-based filesystem and network access control (ABI V1-V5). Applied in the child after mount setup.

- **Network isolation** — Optional network namespace with automatic loopback bring-up.

- **Resource limits** — rlimit enforcement (memory, open files, processes, CPU time, file sizes).

- **Capabilities** — All dropped by default; explicit keep-list translated to raw capset bitmasks.

## Module Layout

### pnut (library)

```
pnut/src/
  lib.rs              Re-exports
  config.rs           All config types: SandboxBuilder, NamespaceConfig,
                      CapsConfig, EnvConfig, FdConfig, RlimitConfig,
                      LandlockConfig, IdMap, Command, ProcessOptions,
                      RunMode, SeccompSource
  mount.rs            MountEntry enum (Bind/Tmpfs/Proc/Mqueue/File), Table
  error.rs            Error, BuildError, Stage (Clone/IdMap/Child)
  seccomp.rs          Seccomp policy compilation (Kafel → BPF)
  sandbox.rs          Sandbox, TryFrom<SandboxBuilder>, run()
  sandbox/parent.rs   Once mode: clone3, ID maps, pidfd supervision,
                      signal forwarding, ChildFailure decoding
  sandbox/standalone.rs  Execve mode: unshare + in-process exec
  sandbox/prepare.rs  Prepare trait + arena-based config → spec translation
```

### pnut-child (executor)

```
pnut-child/src/
  lib.rs              #![no_std], public exports
  spec.rs             ChildSpec, ExecSpec, MountPlan, EnvSpec, etc.
  runtime.rs          run() — 19-stage execution sequence
  report.rs           ChildFailure, Stage, Reporter
  mount/mod.rs        Mount tree construction (new mount API)
  mount/syscall.rs    Raw mount syscall wrappers
  mount/dev.rs        /dev setup
  env.rs              No-alloc environment assembly
  fd.rs               Fd mapping and close policy
  caps.rs             Capability dropping (raw capset)
  landlock.rs         Landlock ruleset construction
  seccomp.rs          Seccomp filter installation
  rlimit.rs           Resource limit application
  net.rs              Loopback bring-up
  process.rs          prctl, execve, sethostname wrappers
  io.rs               Raw read/write helpers
  error.rs            Minimal Errno type
```

## Planner/Executor Split

pnut is the planner — it owns config validation, type translation, and
everything that requires heap allocation. pnut-child is the executor — it
runs after fork using only raw syscalls.

The data flows one way:

```
SandboxBuilder   (user-facing, String-based)
    │ TryFrom
    ▼
Sandbox          (validated, seccomp compiled)
    │ prepare(&arena)
    ▼
ChildSpec<'a>    (borrows from arena, passed to pnut_child::run)
```

Each config type implements the `Prepare` trait, which translates it into
its corresponding pnut-child spec type, allocating all CStrings and slices
into a `bumpalo::Bump` arena. The arena is created before `clone3` and
COW'd into the child. Since pnut-child is `#![no_std]`, it never touches
libc locks — safe even when forking from a multi-threaded process.

## Sandbox Setup Sequence

### Parent (once mode)

```
 1. Validate config, compile seccomp → BPF
 2. Build PreparedChild + ChildView (all allocation happens here)
 3. Create sync pipe + status pipe (both CLOEXEC)
 4. Block SIGCHLD + forwarded signals
 5. clone3(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | ... | CLONE_PIDFD)
 6. Write /proc/<child>/setgroups → "deny"
 7. Write /proc/<child>/uid_map
 8. Write /proc/<child>/gid_map
 9. Write byte to sync pipe (unblocks child)
10. Poll on pidfd + signalfd:
    - Signal received → forward to child via pidfd_send_signal
    - pidfd readable → child exited, collect status via waitpid
11. Read status pipe → decode ChildFailure (if any)
12. Return exit code or Error::ChildSetup
```

### Child (pnut_child::run)

```
 1. PR_SET_PDEATHSIG(SIGKILL)           — die if parent dies
 2. Verify parent still alive            — race check
 3. Read sync pipe                       — wait for ID maps
 4. PR_SET_DUMPABLE                      — prevent ptrace
 5. Mount setup:
    a. mount_setattr("/", AT_RECURSIVE, MS_PRIVATE)
    b. fsopen("tmpfs") → fsmount → move_mount (root)
    c. Process mount entries (bind/tmpfs/proc/mqueue/file) fd-relative
    d. Setup /dev (tmpfs + device bind mounts + devpts + symlinks)
    e. fchdir(root_fd) + pivot_root(".", ".") + umount2(".", MNT_DETACH)
 6. sethostname                          — requires UTS namespace
 7. Bring up loopback                    — requires NET namespace
 8. setrlimit for each resource
 9. Landlock: create_ruleset → add_rule (path/net) → restrict_self
10. Assemble envp from scratch buffers   — no-alloc
11. capset: drop all except keep-list
12. setsid                               — disconnect from terminal
13. Apply fd actions (dup2) + close_other_fds (close_range)
14. PR_SET_TSC (x86 only)
15. PR_SET_NO_NEW_PRIVS                  — required for seccomp
16. PR_SET_MDWE                          — W^X enforcement
17. seccomp(SECCOMP_SET_MODE_FILTER)     — MUST BE LAST
18. chdir(cwd)
19. execve(path, argv, envp)
20. On failure: write ChildFailure to status_fd, _exit(126/127)
```

## Error Propagation

- **Parent-side errors** (clone3 fails, ID map write fails): returned as `Error::Setup { stage: Stage::Clone/IdMap }`.
- **Child-side errors**: child writes a 16-byte `ChildFailure` to the status pipe. Parent decodes it into `Error::ChildSetup { stage, errno, detail, message }`. Library users get programmatic access to the failing stage.
- **Successful exec**: status pipe write end closes via CLOEXEC, parent reads 0 bytes.
- **Exit codes**: 127 = command not found (ENOENT), 126 = setup/permission failure, 128+N = signal death.

## Unprivileged by Design

pnut runs entirely without root, setuid, or special capabilities. The only kernel requirement is `kernel.unprivileged_userns_clone = 1`.

| Feature | Mechanism |
|---------|-----------|
| User namespace | `clone3(CLONE_NEWUSER)` |
| PID namespace | `clone3(CLONE_NEWPID)` inside user namespace |
| Mount namespace | `clone3(CLONE_NEWNS)` inside user namespace |
| Bind mounts | `open_tree(OPEN_TREE_CLONE)` + `move_mount` |
| tmpfs/proc/mqueue | `fsopen` → `fsconfig` → `fsmount` → `move_mount` |
| Read-only mounts | `mount_setattr(MOUNT_ATTR_RDONLY)` — atomic, no remount |
| pivot_root | `fchdir(root_fd)` + `pivot_root(".", ".")` |
| /dev setup | Bind-mount device nodes from host, devpts newinstance |
| File injection | Write to tmpfs, `open_tree(OPEN_TREE_CLONE)` + `move_mount` |
| Loopback bring-up | `ioctl(SIOCSIFFLAGS)` in owned network namespace |
| UID/GID mapping | Parent writes `/proc/<child>/{uid_map,gid_map}` |
| Hostname | `sethostname()` in owned UTS namespace |
| Seccomp-bpf | `prctl(PR_SET_NO_NEW_PRIVS)` then `seccomp()` |
| Landlock | `landlock_create_ruleset()` / `landlock_restrict_self()` |
| Capability dropping | `capset` with precomputed bitmasks |
| rlimits | `setrlimit()` — can lower soft, raise up to hard |
| Environment | No-alloc assembly from scratch buffers in child |
| Process supervision | pidfd + signalfd poll loop, `pidfd_send_signal` |

## Config Format

TOML. Mount entries are a tagged enum:

```toml
[[mount]]
type = "bind"
src = "/usr"
dst = "/usr"
read_only = true

[[mount]]
type = "tmpfs"
dst = "/tmp"
size = 10485760

[[mount]]
type = "proc"
dst = "/proc"

[[mount]]
type = "file"
dst = "/etc/hostname"
content = "sandbox\n"
read_only = true
```

## Dependencies

### pnut (library)
| Crate | Purpose |
|-------|---------|
| pnut-child | Child runtime executor |
| kafel | Seccomp policy compilation |
| nix | Signal handling, pipe, poll, pid types |
| libc | clone3 syscall, seccomp constants |
| landlock | Landlock access mask constants (AccessFs, AccessNet) |
| caps | Capability enum type |
| thiserror | Error derive |

### pnut-child (executor)
| Crate | Purpose |
|-------|---------|
| libc | Raw syscall wrappers |

### pnut-cli (binary)
| Crate | Purpose |
|-------|---------|
| clap | CLI argument parsing |
| serde/toml | TOML config deserialization |
| anyhow | CLI error handling |

## Kernel Requirements

- Linux >= 5.2 (clone3, new mount API, CLONE_PIDFD)
- Unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone = 1`)

## Seccomp Policy

Kafel-inspired DSL compiled directly to BPF bytecode. Range optimization merges adjacent syscalls with the same action into contiguous ranges checked with a balanced binary tree (O(log n) comparisons instead of O(n)).

```
POLICY app {
  ALLOW { read, write, close, mmap, munmap, exit_group }
  KILL  { ptrace, process_vm_readv }
}
USE app DEFAULT KILL
```

Built-in stdlib policies (`allow_default_policy`, `allow_static_startup`, etc.) are compiled into the binary via `include_str!`.

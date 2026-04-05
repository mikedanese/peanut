# pnut Architecture

A lightweight, config-driven Linux sandbox tool. Uses raw syscalls (no bwrap/nsjail dependency), TOML configuration, and supports Landlock filesystem access control. Runs entirely unprivileged via user namespaces.

## Run Modes

- **STANDALONE_ONCE**: Executes a target program a single time and then exits. The parent process creates the sandbox, runs the child, waits for it to finish, and propagates the exit status. This is the default mode. The child calls `prctl(PR_SET_PDEATHSIG, SIGKILL)` so that if the parent dies unexpectedly, the kernel automatically kills all sandbox processes — preventing orphaned sandboxes from lingering.

- **STANDALONE_EXECVE**: Executes a program directly without a supervising process. The calling process itself sets up the sandbox (namespaces, mounts, Landlock, seccomp) and then replaces itself with the target program via execve. No parent remains to wait or clean up. This is useful when pnut is invoked as a wrapper in a process tree where the caller manages the lifecycle (e.g., a systemd unit or container runtime).

## Key Isolation Techniques

- **Linux namespaces** isolate system resources such as process IDs, network interfaces, and file system views. pnut uses `clone3` to create user, PID, mount, network, IPC, UTS, and cgroup namespaces in a single syscall.

- **Seccomp-bpf policies** filter system calls, allowing only explicitly permitted actions by sandboxed processes. pnut compiles a Kafel-inspired policy DSL directly to BPF bytecode — no intermediate library. Policies support named arguments, `#define` constants, boolean expression trees, policy composition via `USE`, and `#include` for reusable policy files (including built-in policies compiled into the binary). Uses `prctl(PR_SET_NO_NEW_PRIVS, 1)` to enable unprivileged seccomp filter loading.

- **Filesystem isolation** controls access to the host filesystem, preventing unauthorized modifications. pnut constructs a new root filesystem from explicit mount entries, uses `pivot_root` to confine the process, and applies Landlock LSM rules for fine-grained path-based access control (read, write, execute).

- **Network isolation** optionally creates a new network namespace, confining the sandbox to loopback-only connectivity. When the network namespace is not unshared (`namespaces.net = false`), the sandbox inherits the host's network stack and retains full connectivity — useful for sandboxes that need outbound access (e.g., `curl`, package managers) while still being isolated in other dimensions.

- **Resource limits** restrict per-process resource consumption. pnut lowers rlimits (soft limits, up to the hard limit ceiling) to constrain memory, open files, child processes, and file sizes.

- **Linux capabilities management** restricts privileges available to processes within the sandbox, minimizing potential attack vectors. pnut drops all capabilities by default, keeping only those explicitly listed in the config.

## Unprivileged by Design

pnut runs entirely without root, without setuid, without any special capabilities. The only kernel requirement is `kernel.unprivileged_userns_clone = 1` (the default on most modern distros).

| Feature | Mechanism |
|---------|-----------|
| User namespace | `clone3(CLONE_NEWUSER)` |
| PID namespace | `clone3(CLONE_NEWPID)` inside user namespace |
| Mount namespace | `clone3(CLONE_NEWNS)` inside user namespace |
| UTS namespace | `clone3(CLONE_NEWUTS)` inside user namespace |
| IPC namespace | `clone3(CLONE_NEWIPC)` inside user namespace |
| Network namespace | `clone3(CLONE_NEWNET)` inside user namespace |
| Cgroup namespace | `clone3(CLONE_NEWCGROUP)` inside user namespace |
| Bind mounts (ro/rw) | `mount(MS_BIND)` in owned mount namespace |
| tmpfs mounts | `mount("tmpfs")` in owned mount namespace |
| proc mount | `mount("proc")` in owned mount namespace |
| Overlayfs | `mount("overlay")` in user namespace (kernel >= 5.11) |
| pivot_root | Works in owned mount namespace |
| /dev setup | Bind-mount individual device nodes from host |
| File content injection | Write to tmpfs, bind-mount into place |
| Symlinks | `symlink()` in new root |
| Loopback bring-up | `ioctl(SIOCSIFFLAGS)` in owned network namespace |
| UID/GID mapping | Parent writes `/proc/<child>/{uid_map,gid_map}` |
| Hostname | `sethostname()` in owned UTS namespace |
| Seccomp-bpf | `prctl(PR_SET_NO_NEW_PRIVS)` then `seccomp()` |
| Landlock | `landlock_create_ruleset()` / `landlock_restrict_self()` |
| Capability dropping | `prctl(PR_SET_KEEPCAPS)` / capset in user namespace |
| rlimits (lowering) | `setrlimit()` — can lower soft, raise soft up to hard |
| Environment control | `clearenv()` / `setenv()` / `unsetenv()` |
| PR_SET_PDEATHSIG | `prctl()` — always available |
| New session (setsid) | `setsid()` — always available |
| mqueue mount | `mount("mqueue")` in owned mount namespace |

### Deferred (Requires Privileges)

The following features are out of scope for v0.1. They require real root or specific capabilities and will be considered in a future privileged mode:

- **Cgroup v2 resource limits** — creating cgroup directories and writing controller files (memory.max, pids.max, cpu.max) requires ownership of the cgroup subtree
- **Raising rlimits above hard limit** — requires `CAP_SYS_RESOURCE`
- **devtmpfs mount** — requires `CAP_SYS_ADMIN` in init user namespace (pnut uses device bind-mounts instead)
- **disable_userns** — writing `user.max_user_namespaces` sysctl requires `CAP_SYS_ADMIN`
- **Network beyond loopback** — veth pairs, iptables/nftables, bridge setup require `CAP_NET_ADMIN`
- **Time namespace** — `CLONE_NEWTIME` requires real capabilities

## Usage

```
pnut --config sandbox.toml -- ls /
```

## Module Layout

```
src/
  main.rs        -- CLI (clap), config loading, invoke sandbox::run()
  config.rs      -- Serde structs for TOML config, defaults, validation
  sandbox.rs     -- Orchestrator: clone3, pipe sync, parent/child flow, waitpid
  namespace.rs   -- clone3 wrapper, clone flag construction
  idmap.rs       -- Write /proc/PID/{uid_map,gid_map,setgroups}
  mount.rs       -- Bind mounts, tmpfs, proc, dev, overlayfs, pivot_root
  landlock.rs    -- Landlock ruleset construction and enforcement
  seccomp/       -- Seccomp policy compiler (parser, resolver, codegen, built-in policies)
  rlimit.rs      -- setrlimit calls
  caps.rs        -- Capability bounding set drop/keep
  net.rs         -- Loopback bring-up via ioctl
  env.rs         -- Environment clear/set/keep
```

Single binary. Flat module structure. Each module is one file, one concern.

## Config Format

TOML. Full example:

```toml
[sandbox]
hostname = "POPCORN"
cwd = "/"
mode = "once"                   # "once" (default) or "execve"
new_session = true              # setsid() — prevents terminal injection (CVE-2017-5226)
die_with_parent = true          # SIGKILL child if parent dies

[namespaces]
user = true                     # always needed for unprivileged sandboxing
pid = true
mount = true
uts = true
ipc = true
net = false                     # false = inherit host network (like unshare -U -p --fork)
cgroup = false

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
type = "tmpfs"
dst = "/tmp"
size = 10485760                 # 10 MiB
perms = "0700"

[[mount]]
type = "proc"
dst = "/proc"

[[mount]]
type = "mqueue"
dst = "/dev/mqueue"

[[mount]]
dst = "/etc/resolv.conf"
content = "nameserver 8.8.8.8\nnameserver 1.1.1.1\n"

[[mount]]
dst = "/etc/hostname"
content = "POPCORN\n"
read_only = true

[landlock]
allowed_read = ["/usr", "/lib"]
allowed_write = ["/tmp"]
allowed_execute = ["/usr/bin"]

# Seccomp policy: inline DSL string or path to .policy file (mutually exclusive)
seccomp_policy = """
#include "stdio.policy"
#include "malloc.policy"

POLICY app {
  KILL { ptrace, syslog, process_vm_readv, process_vm_writev }
}

USE stdio, malloc, app DEFAULT KILL
"""
# seccomp_policy_file = "/etc/pnut/myapp.policy"

[rlimits]
nofile = 256
nproc = 512
fsize_mb = 1
stack_mb = 8

[uid_map]
inside = 0
outside = 1000
count = 1

[gid_map]
inside = 0
outside = 1000
count = 1

[capabilities]
keep = ["CAP_NET_BIND_SERVICE"]

[env]
clear = true
set = { PATH = "/usr/bin:/bin", HOME = "/" }
keep = ["TERM"]

[run]
path = "/bin/sh"
args = ["-i"]
argv0 = "sh"                   # optional: override argv[0]
```

## Sandbox Setup Sequence

The ordering is constrained by Linux kernel rules about which operations require which privileges and namespaces.

### Parent Process

```
 1. Parse config, validate
 2. Create two pipe pairs:
    - sync_pipe  (parent writes, child reads)
    - ready_pipe (child writes, parent reads)
 3. clone3(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | ...)
 4. Write /proc/<child>/setgroups -> "deny"
 5. Write /proc/<child>/uid_map
 6. Write /proc/<child>/gid_map
 7. Write byte to sync_pipe   (unblocks child)
 8. Read from ready_pipe      (blocks until child is ready)
 9. If json_status_fd: write {"child-pid": <pid>} to status fd
10. waitpid -> propagate exit status
11. If json_status_fd: write {"exit-code": <code>} to status fd
```

### Child Process (after sync_pipe unblocks)

```
 1. prctl(PR_SET_PDEATHSIG, SIGKILL)         -- die if parent dies
 2. mount("", "/", "", MS_REC|MS_PRIVATE)     -- make mount tree private
 3. Mount tmpfs as new root
 4. Process mount table: bind mounts, tmpfs, proc, dev nodes, content files
 5. Create /dev with minimal devices (null, zero, urandom, random, tty)
 6. Create symlinks: /dev/fd -> /proc/self/fd, /dev/stdin, /dev/stdout, /dev/stderr
 7. pivot_root(new_root, put_old)
 8. umount2(put_old, MNT_DETACH)
 9. chdir(cwd)
10. sethostname                               -- requires UTS namespace
11. If net namespace: bring up loopback        -- requires NET namespace
12. Set rlimits
13. Apply Landlock restrictions
14. Set environment variables (clearenv, setenv, keep)
15. Drop capabilities
16. If new_session: setsid()                  -- disconnect from terminal
17. prctl(PR_SET_NO_NEW_PRIVS, 1)            -- required for unprivileged seccomp
18. Load seccomp filter                       -- MUST BE LAST before execve
19. Write byte to ready_pipe                  -- signal parent
20. execve(command)
```

### Why This Order

- **clone3 with all flags at once**: Single syscall. CLONE_NEWUSER grants capabilities in the new user namespace so mount/pivot_root work without real root.
- **PR_SET_PDEATHSIG first in child**: Must be set before any blocking operations to avoid a race where the parent dies before the child sets it.
- **UID/GID maps written by parent**: The child cannot reliably write its own maps. Parent writes setgroups deny, then uid_map, then gid_map. Standard pattern that avoids races.
- **Mounts first in child**: Everything else happens inside the new filesystem view.
- **Content files during mount phase**: Files with inline content (like `/etc/resolv.conf`) are written to tmpfs and bind-mounted into place, same as nsjail's `src_content`.
- **pivot_root before anything sensitive**: Child only sees the intended filesystem.
- **Landlock after mounts**: Landlock restricts future filesystem access; must apply after all mounts are established.
- **setsid before seccomp**: setsid() is a syscall that seccomp might block.
- **PR_SET_NO_NEW_PRIVS before seccomp**: Required by kernel for unprivileged seccomp filter loading.
- **Seccomp absolutely last**: Once installed, it constrains the execve syscall itself. Any setup syscalls needed after seccomp would fail.

### Error Propagation

- **Child fails during setup**: Writes error to stderr, exits with code 126 ("command cannot run"). Parent detects via waitpid.
- **Parent fails** (e.g., writing UID maps): Closes sync_pipe without writing. Child gets EOF, exits. Parent returns the error.
- **Exit status**: Parent exits with child's exit code. If child killed by signal: 128 + signal_number (shell convention).

## clone3 Wrapper

`nix` does not expose `clone3`, so we use a thin unsafe wrapper:

```rust
#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
}

unsafe fn clone3(flags: u64) -> Result<Pid> {
    let mut args = CloneArgs {
        flags,
        exit_signal: libc::SIGCHLD as u64,
        ..std::mem::zeroed()
    };
    let ret = libc::syscall(
        libc::SYS_clone3,
        &mut args as *mut CloneArgs,
        std::mem::size_of::<CloneArgs>(),
    );
    match ret {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Pid::from_raw(0)),   // child
        pid => Ok(Pid::from_raw(pid as i32)),  // parent
    }
}
```

This gives us all namespace flags in one syscall and makes the child PID 1 in the new PID namespace. Using fork+unshare(CLONE_NEWPID) would NOT make the caller PID 1 -- only its children would be.

## /dev Setup

Bind-mount specific devices from the host rather than mounting devtmpfs (which requires real CAP_SYS_ADMIN).

### Implementation Sequence

1. **Mount a fresh tmpfs at `/dev`**: Ensures the sandbox doesn't see the host's full device list.
2. **Create placeholder files and directories**: Empty files for character devices, directories for `pts` and `shm`, to serve as bind mount targets inside the tmpfs.
3. **Bind mount each device**: `mount(source, target, NULL, MS_BIND, NULL)` for each device node.
4. **Remount read-only (optional)**: For devices that shouldn't be writable, remount with `MS_BIND | MS_REMOUNT | MS_RDONLY`.

### Standard Device Set

```
/dev/null     -> bind from host /dev/null
/dev/zero     -> bind from host /dev/zero
/dev/full     -> bind from host /dev/full
/dev/random   -> bind from host /dev/random
/dev/urandom  -> bind from host /dev/urandom
/dev/tty      -> bind from host /dev/tty (if the app needs a controlling terminal)
/dev/fd       -> symlink to /proc/self/fd
/dev/stdin    -> symlink to /proc/self/fd/0
/dev/stdout   -> symlink to /proc/self/fd/1
/dev/stderr   -> symlink to /proc/self/fd/2
```

### /dev/pts

Don't bind mount the host's `/dev/pts/` nodes individually. Instead, mount a new instance of devpts with the `newinstance` option:

```
mount -t devpts devpts /sandbox/dev/pts -o newinstance,ptmxmode=0666,mode=620
```

devpts is one of the few filesystems that is user-namespace aware and provides true isolation for terminal sessions.

### Mount Propagation

Bind mounts require a mount namespace (`CLONE_NEWNS`), which pnut already creates. The sandbox's mount namespace must be set to `MS_PRIVATE` (or `MS_SLAVE`) so that `/dev` mounts don't leak back to the host or other namespaces. pnut does this early in the child setup: `mount("", "/", "", MS_REC|MS_PRIVATE, NULL)`.

## File Content Injection

Mount entries with a `content` field inject inline data into the sandbox filesystem. The content is written to a temporary file on a tmpfs, then bind-mounted (optionally read-only) at the destination path. This is useful for synthetic files like `/etc/resolv.conf`, `/etc/hostname`, or `/etc/passwd` that need sandbox-specific content without a host-side file.

## Terminal Security

By default, pnut calls `setsid()` in the child to create a new terminal session, disconnecting from the controlling terminal. Without this, the sandboxed process can inject keystrokes into the parent terminal via the `TIOCSTI` ioctl (CVE-2017-5226). This can be disabled in config if the sandbox needs terminal access (e.g., interactive shells), in which case a seccomp rule blocking TIOCSTI is recommended.

## Status Reporting

For programmatic consumers, pnut supports writing JSON status to a file descriptor (`--json-status-fd`). The parent writes:
1. `{"child-pid": <pid>}` after the child is set up and ready
2. `{"exit-code": <code>}` after the child exits

This enables orchestrators to track sandbox lifecycle without parsing stderr.

## Seccomp Policy Design

pnut compiles a Kafel-inspired policy DSL directly to BPF bytecode. The compiler is self-contained: policy text in, `sock_fprog` out. No dependency on seccompiler, libseccomp, or any external BPF generation library.

### Compilation Pipeline

```
Policy text → Parse (pest) → AST → Resolve → Range Optimize → BPF Codegen
```

1. **Parse**: pest grammar tokenizes and builds the AST. Handles `#include` directives during parsing (with search paths and depth limiting).
2. **Resolve**: `#define` constants are substituted, syscall names are mapped to numbers (architecture-specific table), declared argument names are mapped to arg0–arg5 indices, `USE` references are flattened (with cycle detection).
3. **Range optimize**: Syscalls with the same unconditional action are sorted by number and merged into contiguous ranges. This is the key optimization from Kafel's `range_rules.c` — instead of one `BPF_JEQ` per syscall (O(n) like sandboxed-api), ranges are checked with `BPF_JGE` in a binary decision tree (O(log n) comparisons).
4. **BPF codegen**: Emit raw `sock_filter` instructions. Architecture check first (`seccomp_data.arch == AUDIT_ARCH_X86_64`, KILL_PROCESS on mismatch). Then the syscall decision tree over ranges. Conditional rules (argument filtering) generate expression evaluation code with 64-bit high/low word splitting for arguments wider than 32 bits. Jump offsets are resolved in a fixup pass; distances > 255 use intermediate trampolines (BPF conditional jumps have 8-bit offsets).

### Policy Language

Kafel-inspired DSL with C-like syntax:

```
#include "dynamic.policy"

#define STDOUT 1
#define STDERR 2

POLICY stdio {
  ALLOW {
    read,
    write(fd, buf, count) { fd == STDOUT || fd == STDERR },
    close, dup, dup2, lseek, fstat
  }
}

POLICY basic {
  ALLOW { brk, mmap, munmap, mprotect, exit_group }
  KILL { ptrace, process_vm_readv, process_vm_writev }
}

USE stdio, basic DEFAULT KILL
```

**Key constructs:**
- `POLICY name { ... }` — named, composable policy blocks
- `USE p1, p2 DEFAULT action` — top-level composition with default action
- `#define NAME value` — compile-time constants
- `#include "file.policy"` — file inclusion with search paths and max depth (10)
- `syscall(arg1, arg2) { expr }` — argument filtering with named parameters
- Boolean expressions: `&&`, `||`, `!`, comparisons (`==`, `!=`, `<`, `<=`, `>`, `>=`), masked comparison `(arg & mask) == val`
- Actions: `ALLOW`, `KILL`, `KILL_PROCESS`, `LOG`, `ERRNO(n)`, `TRAP(n)`, `TRACE(n)`

### Built-in Policies

The kafel crate now bakes a single seccomp stdlib file into the binary via
`include_str!()`: `kafel/src/prelude.policy`. It is exposed as
`kafel::BUILTIN_PRELUDE`, and pnut passes that prelude automatically when it
validates or compiles `seccomp_policy_file` policies.

The stdlib mirrors the seccomp-expressible subset of Sandboxed API's
`PolicyBuilder` helpers. Instead of four coarse convenience groups, it exposes a
broader family of composable `allow_*` policies such as:

- `allow_default_policy` — seccomp-only mirror of `Sandbox2Config::DefaultPolicyBuilder()`
- `allow_static_startup` / `allow_dynamic_startup` — glibc/runtime startup helpers
- `allow_system_malloc`, `allow_scudo_malloc`, `allow_tcmalloc` — allocator-specific memory helpers
- `allow_safe_fcntl`, `allow_tcgets`, `allow_getrlimit` — argument-filtered syscall helpers

**Usage** (in a kafel policy or pnut's `seccomp_policy_file`):

```
USE allow_default_policy DEFAULT KILL
```

User-defined policy files can reference these built-ins directly and layer extra
rules on top:

```
POLICY custom {
    USE allow_default_policy
    ALLOW { custom_syscall }
}
USE custom DEFAULT KILL
```

### Range Optimization

The key insight from Kafel: most policies allow or deny large groups of syscalls. Checking each syscall individually wastes BPF instructions. Instead:

1. Sort all unconditional rules by syscall number
2. Merge adjacent syscalls with the same action into ranges (e.g., syscalls 0–15 → ALLOW)
3. Build a balanced binary decision tree over the ranges using `BPF_JGE` (jump-if-greater-or-equal)
4. Conditional rules (with argument filters) are kept separate and checked individually after the range tree

For a policy allowing 50 consecutive syscalls, this produces ~6 comparisons (log2(50)) instead of 50. The BPF program is smaller and the kernel evaluates it faster.

### Actions

- `ALLOW` — SECCOMP_RET_ALLOW
- `KILL` — SECCOMP_RET_KILL_THREAD
- `KILL_PROCESS` — SECCOMP_RET_KILL_PROCESS
- `ERRNO(n)` — SECCOMP_RET_ERRNO with specified errno value
- `LOG` — SECCOMP_RET_LOG (log and allow)
- `TRAP(n)` — SECCOMP_RET_TRAP (send SIGSYS with data)
- `TRACE(n)` — SECCOMP_RET_TRACE (ptrace notification)

## Structured Exit Reporting

For the JSON status fd (`--json-status-fd`), pnut reports structured exit information beyond simple exit codes:

```json
{"child-pid": 12345}
{"exit-code": 0, "reason": "exited"}
```

When the sandbox terminates abnormally:
```json
{"exit-code": 159, "reason": "signaled", "signal": "SIGSYS"}
{"exit-code": 126, "reason": "setup-error", "detail": "mount failed: /nonexistent: No such file or directory"}
```

This enables orchestrators to distinguish between: normal exit, signal death, seccomp violation (SIGSYS from seccomp TRAP/KILL), setup failure, and command-not-found. Inspired by Sandboxed API's fine-grained `Result::StatusEnum`.

## Network Namespace

Two modes of network access:

1. **Inherit host network** (`namespaces.net = false`, the default): The sandbox shares the host's network namespace. Full connectivity — DNS, outbound TCP/UDP, everything works. Equivalent to `unshare -U -p --fork -- curl google.com`. No setup required.

2. **Loopback only** (`namespaces.net = true`): A new network namespace is created. Only the loopback interface exists. pnut brings it up automatically:
   ```rust
   let sock = socket(AF_INET, SOCK_DGRAM, 0);
   // ioctl(sock, SIOCGIFFLAGS, &ifr)  -- get current flags
   // ifr.ifr_flags |= IFF_UP
   // ioctl(sock, SIOCSIFFLAGS, &ifr)  -- set flags
   ```
   No external network access. Useful for pure computation sandboxes.

## Dependencies

```toml
[dependencies]
anyhow = "1"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
nix = { version = "0.31", features = ["mount", "sched", "signal", "user", "process", "hostname", "resource", "net"] }
landlock = "0.4"
caps = "0.5"
libc = "0.2"
pest = "2.8"
pest_derive = "2.8"
```

| Crate | Rationale |
|-------|-----------|
| nix | Safe wrappers for mount, pivot_root, prctl, setrlimit, unshare, sethostname, etc. Avoids raw libc FFI for most syscalls. |
| landlock | Kernel Landlock ABI abstraction. Handles ABI version negotiation. |
| pest / pest_derive | Parser generator for the seccomp policy DSL. Generates a PEG parser from the grammar file. |
| caps | Linux capability manipulation. |
| libc | Needed for SYS_clone3, seccomp(), and ioctl constants not in nix. Also provides syscall number constants for the seccomp compiler's syscall table. |
| anyhow | Error propagation with context. Appropriate for a CLI tool. |

## Kernel Requirements

- Linux >= 5.11 (clone3, Landlock ABI v1, overlayfs in user namespace)
- Unprivileged user namespaces enabled (`kernel.unprivileged_userns_clone = 1`)

## Implementation Phases

### Phase 1: Sandbox Core (complete)
- CLI parsing (clap), TOML config loading, config validation
- clone3 wrapper, pipe sync, UID/GID map writing
- Mount namespace: bind mounts, tmpfs, proc, /dev, content injection, pivot_root
- UTS (hostname), environment control, setsid, argv0 override
- STANDALONE_ONCE and STANDALONE_EXECVE modes
- die_with_parent, exit code propagation (126/127/128+signal)

### Phase 2: Security Hardening
- Landlock filesystem access control (read/write/execute restrictions)
- Seccomp-bpf: kafel-style policy compiler with direct BPF codegen, built-in policies, range optimization
- Rlimits (lowering only, unprivileged)
- Capability dropping
- Network namespace loopback bring-up
- Structured exit reporting via JSON status fd
- Refactor sandbox.rs duplication (evaluator concern from Phase 1)

## Future Work

Features to explore after Phase 2, informed by Sandboxed API, nsjail, and bwrap:

- **Seccomp SECCOMP_RET_USER_NOTIF** — userspace syscall interception (kernel 5.0+). Allows a supervisor to intercept and respond to syscalls without ptrace. Lower overhead, useful for policy-as-code scenarios. Sandboxed API uses this as an alternative to ptrace monitoring.
- **Network proxy / allowed hosts** — fine-grained per-connection network filtering, as in Sandboxed API's `AllowedHosts` + `NetworkProxyServer`. Goes beyond the binary net-namespace-on/off model.
- **Fork server** — persistent child process that handles fork requests, avoiding repeated namespace/mount initialization overhead. Useful for repeated sandbox invocations (batch processing, server mode). Used by Sandboxed API for efficiency.
- **Notification hooks** — emit structured events (syscall violations, lifecycle changes) to the status fd, allowing external monitoring without modifying core code. Inspired by Sandboxed API's `Notify` base class.
- **Overlayfs mounts** — writable overlay on top of read-only bind mounts.
- **mqueue mounts** — POSIX message queue support.
- **Cgroup v2 resource limits** (privileged) — memory, PID, CPU limits via cgroup hierarchy.
- **disable_userns** (privileged) — prevent nested user namespace creation.
- **Time namespace** (privileged) — `CLONE_NEWTIME` for clock isolation.
- **Shared memory buffer** — `memfd_create` for efficient large data exchange between host and sandboxee.
- **Additional built-in policies** — expand the set of compiled-in policy files as real-world usage patterns emerge (e.g., `gpu.policy`, `audio.policy`, `x11.policy`).

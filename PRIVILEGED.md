# Privileged Mode

> **Note:** This document is a brainstorm of what a privileged mode could
> enable. None of this is implemented. pnut focuses primarily on unprivileged
> sandboxing right now.

pnut currently runs entirely unprivileged — all isolation bootstraps from
`CLONE_NEWUSER`. A future **privileged mode** would assume the supervisor
process starts with elevated capabilities (root, or a targeted capability set)
and drops them before exec. This unlocks several containment features that
have no unprivileged equivalent.

## Activation

Privileged mode would be opt-in via config:

```toml
[sandbox]
privileged = true
```

When enabled, pnut skips `CLONE_NEWUSER` (or makes it optional) and instead
uses real UID/GID transitions and capability bounding to confine the child.
The supervisor retains capabilities only long enough to set up the sandbox,
then drops everything before exec.

## Capabilities unlocked

### Cgroup v2 resource limits

The single biggest gap in unprivileged mode. With `CAP_SYS_ADMIN` (or
delegated cgroup ownership), the supervisor can create a cgroup subtree and
apply hard limits before moving the child into it.

```toml
[cgroup]
memory_max = "512M"
memory_swap_max = "0"
pids_max = 64
cpu_quota_us = 100000    # 100ms per 100ms period
cpu_period_us = 100000
io_max = "259:0 rbps=10485760"  # 10 MB/s read on device 259:0
```

Controllers:
- **memory** — `memory.max`, `memory.swap.max`, `memory.high`
- **pids** — `pids.max`
- **cpu** — `cpu.max` (quota/period), `cpu.weight`
- **io** — `io.max` (rbps, wbps, riops, wiops per device)

The supervisor should write limits, move the child PID into the cgroup, then
release its own membership. On child exit the cgroup is removed.

**Cgroup v2 delegation:** With cgroup v2, the host can delegate a subtree to
an unprivileged process by chowning the subtree directory (e.g., via systemd
`Delegate=yes` on a user slice). The process can then write its own resource
limits within that subtree without root. This is a middle ground — the
delegation itself requires privileged setup, but the sandbox process stays
unprivileged. See [containerd#10924](https://github.com/containerd/containerd/issues/10924)
for prior art on writable cgroup mounts in unprivileged containers.

### Raise rlimits above hard limit

Unprivileged mode can only lower soft limits to at most the current hard
limit. With `CAP_SYS_RESOURCE`, the supervisor can raise hard limits before
dropping privileges, allowing configs like:

```toml
[rlimits]
nofile = 1048576  # above default 1024 hard limit
```

### Network: veth pairs, bridges, MACVLAN

Unprivileged network isolation is limited to loopback-only or inheriting the
host. With `CAP_NET_ADMIN`, the supervisor can set up real network plumbing
before dropping into the sandbox:

```toml
[network]
mode = "veth"               # or "macvlan"

[network.veth]
bridge = "pnut-br0"         # host-side bridge (created if absent)
sandbox_addr = "10.0.0.2/24"
gateway = "10.0.0.1"

[network.macvlan]
parent = "eth0"
mode = "private"            # private | vepa | bridge | passthru
sandbox_addr = "192.168.1.100/24"
gateway = "192.168.1.1"
```

For veth:
1. Create veth pair.
2. Move one end into the child's network namespace.
3. Attach the host end to a bridge.
4. Configure addresses and routes inside the namespace.

This enables sandboxes with filtered but real network connectivity (combined
with nftables rules on the host bridge for egress filtering).

### nftables / iptables egress policy

With network plumbing in place, the supervisor can install per-sandbox
firewall rules:

```toml
[[network.allow]]
proto = "tcp"
dst = "0.0.0.0/0"
dport = 443

[[network.allow]]
proto = "udp"
dst = "8.8.8.8"
dport = 53
```

### devtmpfs

Unprivileged mode bind-mounts individual `/dev` nodes from the host. With
`CAP_SYS_ADMIN` the supervisor can mount a real `devtmpfs` and then
selectively remove nodes, or use `mknod` to create only the needed devices:

```toml
[dev]
mode = "minimal"   # null, zero, full, random, urandom, tty
# or
mode = "devtmpfs"  # full devtmpfs, then restrict via Landlock/seccomp
```

### Device cgroup (or Landlock + devtmpfs)

Control which device major:minor numbers the child can open. Prevents access
to raw disks, GPUs, etc. even if the device nodes exist in the namespace.

### Real UID/GID transitions

Without user namespaces, the supervisor can `setuid`/`setgid` to a real
unprivileged user after setup. This is the traditional privilege-separation
model (like OpenSSH). Avoids the quirks and kernel attack surface of user
namespaces entirely.

```toml
[sandbox]
privileged = true
run_as_uid = 65534    # nobody
run_as_gid = 65534
```

### Disable nested user namespaces

Write `0` to `user.max_user_namespaces` inside the child's user namespace to
prevent the sandboxed process from creating its own namespaces (a common
sandbox escape vector). Requires `CAP_SYS_ADMIN`.

```toml
[sandbox]
deny_nested_userns = true
```

### chroot (without pivot_root)

Some deployment contexts (minimal containers, initramfs) may not support
`pivot_root`. With `CAP_SYS_CHROOT`, `chroot` is available as a fallback.
`pivot_root` remains preferred.

### Mount real filesystems

With `CAP_SYS_ADMIN`, the supervisor can mount real filesystem images
(ext4, squashfs, erofs) as the sandbox root, rather than relying on bind
mounts from the host. Useful for running sandboxes against OS images or
container layers.

```toml
[[mount]]
src = "/images/rootfs.squashfs"
dst = "/"
type = "squashfs"
read_only = true
```

## Architecture

The privileged mode should share the same `SandboxBuilder` / `Sandbox` /
`run_child_setup` pipeline. The key differences are:

1. **Pre-clone setup phase** — operations requiring host-level privileges
   (cgroup creation, veth setup, nftables rules) happen in the parent
   *before* `clone3`.
2. **Capability-aware clone** — `CLONE_NEWUSER` becomes optional. When
   omitted, the child inherits real UIDs and the supervisor writes cgroup
   memberships, uid/gid transitions, and capability bounds directly.
3. **Post-setup privilege drop** — after all setup, the child drops to the
   target UID/GID and clears the bounding set. This is the point of no
   return.
4. **Cleanup** — the parent tears down host-side resources (veth, cgroup
   subtree, nftables rules) after the child exits. This already fits the
   `Once` mode supervisor loop.

The existing unprivileged path remains the default and is unaffected.

## Non-goals

- **Full container runtime** — pnut is not a replacement for runc/crun.
  Privileged mode adds targeted capabilities, not OCI compatibility.
- **Image management** — pulling, layering, or storing images is out of
  scope. The user provides paths; pnut mounts them.
- **Orchestration** — no daemon, no API server, no pod concept.

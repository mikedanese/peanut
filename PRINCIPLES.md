# pnut Design Principles

These principles guide architectural decisions in pnut. They are not
implementation details — those live in [ARCHITECTURE.md](ARCHITECTURE.md).
When a design choice is ambiguous, refer here.

## 1. The process is the protection domain

Unix already isolates processes from each other: separate address spaces,
separate file descriptor tables, separate credentials. pnut builds on this
directly. Fork, drop privileges, exec. No kernel modules, no custom LSMs,
no long-running daemon. The mechanisms are the ones that have been tested
by decades of adversarial pressure on production systems.

This principle comes from Provos, Friedl, and Honeyman's work on privilege
separation in OpenSSH (USENIX Security 2003), which demonstrated that
splitting a service into a privileged monitor and an unprivileged slave —
using only fork, UID separation, and chroot — contained every known
OpenSSH vulnerability at the time of publication, with zero measurable
performance cost and a 2% change to the existing codebase.

## 2. Unprivileged by construction

pnut never requires root, setuid binaries, or ambient capabilities. Every
operation uses `CLONE_NEWUSER` to enter a user namespace where the caller
has full capabilities *only within that namespace*. If the kernel doesn't
allow an unprivileged user to perform an operation, pnut doesn't perform it.

This is a hard constraint, not a preference. It means pnut can be installed
and run by any user without coordination with a system administrator.

A privileged mode is being explored (see [PRIVILEGED.md](PRIVILEGED.md)) as
an optional extension for features with no unprivileged equivalent, but the
default remains fully unprivileged.

## 3. Orthogonal layers, not feature sprawl

Namespaces, mount isolation, seccomp-bpf, and Landlock are independent
confinement mechanisms. pnut composes them — it does not unify them behind
a single policy abstraction. Each layer is configured separately, fails
independently, and can be understood on its own.

The temptation is always to build one policy engine that "does everything."
That path leads to a system where no single layer can be reasoned about
in isolation, bugs in the policy engine compromise all layers simultaneously,
and the abstraction eventually leaks because the underlying mechanisms have
genuinely different semantics.

## 4. Declarative over interactive

A TOML config file describes the complete sandbox before exec. There is no
runtime negotiation, no monitor granting capabilities on request, no policy
that evolves during execution. The sandbox is fully determined by its
configuration.

This is simpler than Provos's monitor FSM model because pnut has no
authentication phase — there is no state transition from "unknown user" to
"authenticated user" that requires runtime privilege changes. If a future
use case requires post-exec capability granting (fd passing, pty creation),
the monitor pattern is the right tool, but we don't add it speculatively.

## 5. Immutable after setup

`no_new_privs` is set before exec. Seccomp filters and Landlock rulesets
are loaded and locked before the target runs. There is no mechanism to
widen the sandbox from inside. The target process cannot influence its own
confinement.

This property is what makes the sandbox trustworthy to the caller: the
target's behavior cannot weaken the policy, regardless of what code it runs.

## 6. Fail closed

If any setup step fails — mount, pivot_root, seccomp load, id mapping —
pnut exits 126 without executing the target command. A partially configured
sandbox is never inhabited. The caller can distinguish "sandbox setup
failed" (126) from "command not found" (127) from "command failed" (1+).

## 7. Minimal trusted code

The trusted code is the setup path: everything between clone/unshare and
exec. After exec, pnut is either gone (execve mode) or inert (clone3 mode,
just waiting on waitpid). The target binary runs in its own process — pnut
is not interposed on its syscalls, does not proxy its I/O, and does not
interpret its behavior.

This means bugs in the target cannot corrupt pnut, and bugs in pnut's
non-setup code cannot weaken the sandbox.

---

## Influences

- **OpenSSH privilege separation** (Provos, Friedl, Honeyman, 2003) —
  the monitor/slave pattern, process-as-protection-domain, and the
  demonstration that privilege separation composes with (not replaces)
  application confinement.
- **bubblewrap** — unprivileged sandboxing via user namespaces, the
  proof that setuid is unnecessary for container-like isolation.
  pnut's name is a nod to bubblewrap (packing peanuts, packing material).
- **Landlock** — unprivileged filesystem access control that composes
  with namespaces rather than replacing them.
- **seccomp-bpf** — syscall filtering that is immutable after load,
  enforced by the kernel, and requires no privilege to install
  (with `no_new_privs`).
- **nsjail** — production-grade namespace jail with a protobuf config
  schema, demonstrating the value of declarative sandbox configuration
  over ad-hoc flag accumulation.
- **Sandboxed API** (Google) — per-library sandboxing with a
  policy-builder API, showing how to compose seccomp filters from
  reusable building blocks.

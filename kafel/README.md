# kafel

A Rust implementation of Google's [Kafel](https://github.com/google/kafel)
seccomp policy language. Parses a Kafel-inspired DSL, resolves names and
constants, and compiles to BPF bytecode ready for
`seccomp(SECCOMP_SET_MODE_FILTER)`.

This crate is part of [pnut](https://github.com/mikedanese/pcorn), but can
be used standalone by any project that needs seccomp-bpf policy compilation.

## Usage

```rust
let program = kafel::compile(
    "POLICY p { ALLOW { read, write, close } } USE p DEFAULT KILL"
).unwrap();

// Install the filter (constrains the process permanently).
kafel::install_filter(&program).unwrap();
```

## Typed Policy API

For programmatic policy construction, use `parse_policy` to get a mutable
`Policy`, modify it, then generate BPF:

```rust
use kafel::{parse_policy, resolve_syscall, PolicyEntry, Action, CompileOptions};

let opts = CompileOptions::new().with_prelude(kafel::BUILTIN_PRELUDE);
let mut policy = parse_policy(
    "POLICY p { ALLOW { read, write } } USE p DEFAULT KILL",
    &opts,
).unwrap();

// Add a rule programmatically.
let nr = resolve_syscall("close").unwrap();
policy.add_entry(PolicyEntry {
    syscall_number: nr,
    action: Action::Allow,
    filter: None,
});

let program = policy.codegen().unwrap();
```

## Built-in Prelude

The crate ships a seccomp stdlib (`BUILTIN_PRELUDE`) with composable policies
mirroring Sandboxed API's `PolicyBuilder` helpers:

- `allow_default_policy` — broad baseline (I/O, memory, signals, startup)
- `allow_static_startup` / `allow_dynamic_startup` — glibc/runtime init
- `allow_system_malloc`, `allow_scudo_malloc`, `allow_tcmalloc` — allocator-specific
- `allow_safe_fcntl`, `allow_tcgets`, `allow_getrlimit` — filtered syscall helpers

## Upstream

The policy language is based on Google's
[kafel](https://github.com/google/kafel) (C), which is used by
[nsjail](https://github.com/google/nsjail) and
[Sandboxed API](https://github.com/google/sandboxed-api).
This crate is a clean-room Rust reimplementation — it does not link to or
vendor the C library.

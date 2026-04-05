pnut(1)

# NAME

pnut - lightweight, unprivileged Linux sandbox

# SYNOPSIS

*pnut* *--config* _path_ [*--*] [_command_ [_args..._]]

# DESCRIPTION

*pnut* confines processes using Linux kernel isolation
primitives. It requires no root privileges, no setuid binaries, and no special
capabilities. All isolation is bootstrapped from CLONE_NEWUSER, so any
unprivileged user can create a sandbox.

The sandbox is configured entirely through a TOML file (see *pnut.toml*(5)).
The only runtime arguments are the config path and an optional command to
execute inside the sandbox.

*pnut* supports two execution modes:

*once*
	(default) Fork a child via *clone3*(2) with the requested namespaces. The
	parent supervises the child and propagates its exit status.

*execve*
	The calling process *unshare*(2)s into the new namespaces and then
	*execve*(2)s the command directly. No supervising parent is created.

# OPTIONS

*-c*, *--config* _path_
	Path to the TOML sandbox configuration file. Required.

*-h*, *--help*
	Print help and exit.

*-V*, *--version*
	Print version and exit.

_command_ [_args..._]
	Command and arguments to run inside the sandbox, specified after a *--*
	separator. If provided, this overrides the *[run]* section in the
	configuration file. Either a command on the command line or a *[run]*
	section in the config is required.

# CONFIGURATION

All sandbox behavior is controlled by the TOML configuration file. See
*pnut.toml*(5) for the full schema reference.

The configuration covers:

- Namespace selection (user, PID, mount, UTS, IPC, network, cgroup, time)
- Filesystem setup (bind mounts, tmpfs, proc, inline file content, pivot_root)
- UID/GID mapping
- Environment variable policy
- Resource limits (rlimits)
- Seccomp-bpf syscall filtering (Kafel DSL)
- Landlock LSM filesystem access control
- Linux capability management
- File descriptor policy

# EXIT STATUS

*0*
	The sandboxed command exited successfully.

_N_
	The sandboxed command exited with status _N_. The exit code is propagated
	from the child process.

*1*
	A runtime error occurred (e.g., failed to read config, I/O error).

*126*
	Configuration validation failed (e.g., invalid mount entry, bad capability
	name, seccomp policy compilation error). This matches the shell convention
	for "command cannot execute."

# ENVIRONMENT

By default, the sandboxed process inherits the parent's environment. Use the
*[env]* section in the config file to clear, set, or selectively keep
variables. See *pnut.toml*(5).

# REQUIREMENTS

- Linux >= 5.11
- Unprivileged user namespaces enabled (*kernel.unprivileged_userns_clone = 1*)

# EXAMPLES

Run a command in a minimal namespace sandbox:

```
pnut --config minimal.toml -- /bin/echo hello
```

Run an interactive shell with filesystem isolation:

```
pnut --config shell.toml -- /bin/sh
```

Use the config file's embedded command:

```
# If the config contains a [run] section:
pnut --config server.toml
```

# SEE ALSO

*pnut.toml*(5), *bwrap*(1), *unshare*(1), *clone3*(2), *namespaces*(7),
*user_namespaces*(7), *pivot_root*(2), *seccomp*(2), *landlock*(7),
*capabilities*(7)

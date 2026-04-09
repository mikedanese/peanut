//! Arena-based preparation: translates pnut config types into pnut-child
//! spec types. All allocations go into a `bumpalo::Bump` arena with a
//! single lifetime.

use std::ffi::CStr;

use bumpalo::Bump;

use landlock::{ABI, Access, AccessFs, AccessNet, make_bitflags};

use pnut_child::{
    BindMount, CapsSpec, ChildSpec, EnvBinding, EnvSpec, EnvStorage, ExecSpec, FdAction, FdSpec,
    FileMount, HidePid as ChildHidePid, LandlockNetRule, LandlockPathRule, LandlockRulesetAttr,
    LandlockSpec, MountEntry, MountPlan, MqueueMount, ProcMount, ProcSubset as ChildProcSubset,
    ProcessSpec, RlimitEntry, RlimitSpec, SeccompSpec, TmpfsMount,
};

use crate::config::{
    Capabilities, Command, Environment, FileDescriptors, Landlock, ProcessOptions, ResourceLimits,
};
use crate::error::BuildError;
use crate::mount;

const MIB: u64 = 1024 * 1024;

// ---------------------------------------------------------------------------
// Arena helpers
// ---------------------------------------------------------------------------

/// Allocate a null-terminated C string in the arena.
fn alloc_cstr<'a>(arena: &'a Bump, s: &str, context: &str) -> Result<&'a CStr, BuildError> {
    if s.as_bytes().contains(&0) {
        return Err(BuildError::InvalidConfig(format!(
            "{context}: interior null byte in \"{s}\""
        )));
    }
    let buf = arena.alloc_slice_fill_copy(s.len() + 1, 0u8);
    buf[..s.len()].copy_from_slice(s.as_bytes());
    Ok(unsafe { CStr::from_bytes_with_nul_unchecked(buf) })
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Translate a pnut config type into a pnut-child spec type, allocating
/// all intermediate data into the provided arena.
pub(crate) trait Prepare {
    type Spec<'a>;
    fn prepare<'a>(&self, arena: &'a Bump) -> Result<Self::Spec<'a>, BuildError>;
}

// ---------------------------------------------------------------------------
// Sandbox → ChildSpec (composes all Prepare impls)
// ---------------------------------------------------------------------------

use super::Sandbox;

impl Sandbox {
    pub(super) fn prepare<'a>(&'a self, arena: &'a Bump) -> Result<ChildSpec<'a>, BuildError> {
        let exec = self.command.prepare(arena)?;
        let process = self.process.prepare(arena)?;
        let cwd = self.command.cwd.as_str();
        let cwd = Some(alloc_cstr(arena, cwd, "working directory")?);

        let hostname = match &self.namespaces.hostname {
            Some(h) if self.namespaces.uts => Some(alloc_cstr(arena, h, "hostname")?),
            _ => None,
        };

        let env = self.env.as_ref().map(|c| c.prepare(arena)).transpose()?;
        let rlimits = self
            .rlimits
            .as_ref()
            .map(|c| c.prepare(arena))
            .transpose()?;

        let mounts = if self.mounts.is_empty() {
            None
        } else {
            Some(self.mounts.prepare(arena)?)
        };

        let landlock = self
            .landlock
            .as_ref()
            .map(|c| c.prepare(arena))
            .transpose()?;
        let caps = self
            .capabilities
            .as_ref()
            .map(|c| c.prepare(arena))
            .transpose()?;
        let fds = self
            .fd
            .as_ref()
            .map(|c| c.prepare(arena))
            .transpose()?
            .unwrap_or_default();

        let seccomp = self.seccomp_program.as_ref().map(prepare_seccomp);

        Ok(ChildSpec {
            sync_fd: None,
            status_fd: None,
            process,
            mounts,
            hostname,
            bring_up_loopback: self.namespaces.net,
            env,
            rlimits,
            landlock,
            caps,
            fds,
            seccomp,
            cwd,
            exec,
        })
    }
}

// ---------------------------------------------------------------------------
// Implementations
// ---------------------------------------------------------------------------

impl Prepare for Command {
    type Spec<'a> = ExecSpec<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<ExecSpec<'a>, BuildError> {
        let path = alloc_cstr(arena, &self.args[0], "command path")?;

        let mut argv_cstrs: Vec<&CStr> = Vec::with_capacity(self.args.len());
        if let Some(ref argv0) = self.argv0 {
            argv_cstrs.push(alloc_cstr(arena, argv0, "argv0 override")?);
        } else {
            argv_cstrs.push(alloc_cstr(arena, &self.args[0], "argv[0]")?);
        }
        for (i, arg) in self.args.iter().enumerate().skip(1) {
            argv_cstrs.push(alloc_cstr(arena, arg, &format!("argv[{i}]"))?);
        }

        let argv = arena.alloc_slice_fill_copy(argv_cstrs.len() + 1, std::ptr::null());
        for (i, cs) in argv_cstrs.iter().enumerate() {
            argv[i] = cs.as_ptr();
        }

        Ok(ExecSpec { path, argv })
    }
}

impl Prepare for ProcessOptions {
    type Spec<'a> = ProcessSpec;

    fn prepare(&self, _arena: &Bump) -> Result<ProcessSpec, BuildError> {
        Ok(ProcessSpec {
            pdeathsig: if self.die_with_parent {
                Some(libc::SIGKILL)
            } else {
                None
            },
            verify_parent_alive: self.die_with_parent,
            dumpable: self.dumpable,
            new_session: self.new_session,
            disable_tsc: self.disable_tsc,
            no_new_privs: self.no_new_privs,
            mdwe_flags: if self.mdwe {
                Some(libc::PR_MDWE_REFUSE_EXEC_GAIN as libc::c_ulong)
            } else {
                None
            },
        })
    }
}

impl Prepare for Environment {
    type Spec<'a> = EnvSpec<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<EnvSpec<'a>, BuildError> {
        let keep: Vec<&CStr> = self
            .keep
            .iter()
            .map(|k| alloc_cstr(arena, k, "env keep key"))
            .collect::<Result<_, _>>()?;
        let keep = arena.alloc_slice_fill_iter(keep);

        let set: Vec<EnvBinding<'a>> = self
            .set
            .iter()
            .map(|(k, v)| {
                Ok(EnvBinding {
                    key: alloc_cstr(arena, k, "env set key")?,
                    value: alloc_cstr(arena, v, "env set value")?,
                })
            })
            .collect::<Result<_, BuildError>>()?;
        let set = arena.alloc_slice_fill_iter(set);

        let envp_capacity = if self.clear {
            keep.len() + set.len() + 1
        } else {
            std::env::vars_os().count() + set.len() + 1
        };
        let envp = arena.alloc_slice_fill_copy(envp_capacity, std::ptr::null());

        let bytes_capacity: usize = set
            .iter()
            .map(|b| b.key.to_bytes().len() + 1 + b.value.to_bytes().len() + 1)
            .sum();
        let bytes = arena.alloc_slice_fill_copy(bytes_capacity, 0u8);

        Ok(EnvSpec {
            clear: self.clear,
            keep,
            set,
            storage: EnvStorage { envp, bytes },
        })
    }
}

impl Prepare for ResourceLimits {
    type Spec<'a> = RlimitSpec<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<RlimitSpec<'a>, BuildError> {
        let mut entries = Vec::new();
        if let Some(v) = self.nofile {
            entries.push(make_rlimit(libc::RLIMIT_NOFILE as i32, v));
        }
        if let Some(v) = self.nproc {
            entries.push(make_rlimit(libc::RLIMIT_NPROC as i32, v));
        }
        if let Some(v) = self.fsize_mb {
            entries.push(make_rlimit(
                libc::RLIMIT_FSIZE as i32,
                v.saturating_mul(MIB),
            ));
        }
        if let Some(v) = self.stack_mb {
            entries.push(make_rlimit(
                libc::RLIMIT_STACK as i32,
                v.saturating_mul(MIB),
            ));
        }
        if let Some(v) = self.as_mb {
            entries.push(make_rlimit(libc::RLIMIT_AS as i32, v.saturating_mul(MIB)));
        }
        if let Some(v) = self.core_mb {
            entries.push(make_rlimit(libc::RLIMIT_CORE as i32, v.saturating_mul(MIB)));
        }
        if let Some(v) = self.cpu_seconds {
            entries.push(make_rlimit(libc::RLIMIT_CPU as i32, v));
        }
        Ok(RlimitSpec {
            limits: arena.alloc_slice_fill_iter(entries),
        })
    }
}

fn make_rlimit(resource: libc::c_int, value: u64) -> RlimitEntry {
    RlimitEntry {
        resource,
        limit: libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        },
    }
}

impl Prepare for mount::Table {
    type Spec<'a> = MountPlan<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<MountPlan<'a>, BuildError> {
        let entries: Vec<MountEntry<'a>> = self
            .iter()
            .map(|e| e.prepare(arena))
            .collect::<Result<_, _>>()?;
        Ok(MountPlan {
            entries: arena.alloc_slice_fill_iter(entries),
        })
    }
}

impl Prepare for mount::MountEntry {
    type Spec<'a> = MountEntry<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<MountEntry<'a>, BuildError> {
        match self {
            mount::MountEntry::Bind {
                src,
                dst,
                read_only,
            } => {
                let metadata = std::fs::metadata(src).map_err(|e| {
                    BuildError::InvalidConfig(format!("cannot stat bind source {src}: {e}"))
                })?;
                Ok(MountEntry::Bind(BindMount {
                    src: alloc_cstr(arena, src, "mount src")?,
                    dst_rel: alloc_cstr(arena, dst.trim_start_matches('/'), "mount dst")?,
                    src_is_dir: metadata.is_dir(),
                    read_only: *read_only,
                }))
            }
            mount::MountEntry::Tmpfs {
                dst,
                size,
                mode,
                read_only,
            } => Ok(MountEntry::Tmpfs(TmpfsMount {
                dst_rel: alloc_cstr(arena, dst.trim_start_matches('/'), "mount dst")?,
                size_bytes: *size,
                mode: *mode,
                read_only: *read_only,
            })),
            mount::MountEntry::Proc {
                dst,
                subset,
                hidepid,
            } => Ok(MountEntry::Proc(ProcMount {
                dst_rel: alloc_cstr(arena, dst.trim_start_matches('/'), "mount dst")?,
                subset: subset.map(|s| match s {
                    mount::ProcSubset::Pid => ChildProcSubset::Pid,
                }),
                hidepid: hidepid.map(|h| match h {
                    mount::HidePid::Visible => ChildHidePid::Visible,
                    mount::HidePid::Hidden => ChildHidePid::Hidden,
                    mount::HidePid::Invisible => ChildHidePid::Invisible,
                }),
            })),
            mount::MountEntry::Mqueue { dst } => Ok(MountEntry::Mqueue(MqueueMount {
                dst_rel: alloc_cstr(arena, dst.trim_start_matches('/'), "mount dst")?,
            })),
            mount::MountEntry::File {
                dst,
                content,
                read_only,
            } => Ok(MountEntry::File(FileMount {
                dst_rel: alloc_cstr(arena, dst.trim_start_matches('/'), "mount dst")?,
                content: arena.alloc_slice_copy(content.as_bytes()),
                read_only: *read_only,
            })),
        }
    }
}

impl Prepare for Landlock {
    type Spec<'a> = LandlockSpec<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<LandlockSpec<'a>, BuildError> {
        let categories: &[(&[String], u64)] = &[
            (
                &self.allowed_read,
                make_bitflags!(AccessFs::{ReadFile | ReadDir}).bits(),
            ),
            (
                &self.allowed_write,
                (AccessFs::from_all(ABI::V1) & !AccessFs::Execute).bits(),
            ),
            (
                &self.allowed_execute,
                make_bitflags!(AccessFs::{Execute | ReadFile | ReadDir}).bits(),
            ),
            (
                &self.allowed_refer,
                make_bitflags!(AccessFs::{Refer}).bits(),
            ),
            (
                &self.allowed_truncate,
                make_bitflags!(AccessFs::{Truncate}).bits(),
            ),
            (
                &self.allowed_ioctl_dev,
                make_bitflags!(AccessFs::{IoctlDev}).bits(),
            ),
        ];

        let mut path_rules = Vec::new();
        for &(paths, access) in categories {
            for path in paths {
                path_rules.push(LandlockPathRule {
                    path: alloc_cstr(arena, path, "landlock path")?,
                    allowed_access: access,
                });
            }
        }
        let path_rules = arena.alloc_slice_fill_iter(path_rules);

        let net_bind = landlock::BitFlags::from(AccessNet::BindTcp).bits();
        let net_connect = landlock::BitFlags::from(AccessNet::ConnectTcp).bits();
        let mut net_rules = Vec::new();
        for &port in &self.allowed_bind {
            net_rules.push(LandlockNetRule {
                port,
                allowed_access: net_bind,
            });
        }
        for &port in &self.allowed_connect {
            net_rules.push(LandlockNetRule {
                port,
                allowed_access: net_connect,
            });
        }
        let net_rules = arena.alloc_slice_fill_iter(net_rules);

        let min_abi = compute_landlock_abi(self);
        let handled_access_fs = compute_handled_access_fs(min_abi);
        let mut handled_access_net: u64 = 0;
        if !self.allowed_bind.is_empty() {
            handled_access_net |= net_bind;
        }
        if !self.allowed_connect.is_empty() {
            handled_access_net |= net_connect;
        }

        Ok(LandlockSpec {
            min_abi,
            ruleset: LandlockRulesetAttr {
                handled_access_fs,
                handled_access_net,
            },
            path_rules,
            net_rules,
        })
    }
}

fn compute_landlock_abi(config: &Landlock) -> u32 {
    if !config.allowed_ioctl_dev.is_empty() {
        5
    } else if !config.allowed_bind.is_empty() || !config.allowed_connect.is_empty() {
        4
    } else if !config.allowed_truncate.is_empty() {
        3
    } else if !config.allowed_refer.is_empty() {
        2
    } else {
        1
    }
}

fn compute_handled_access_fs(abi: u32) -> u64 {
    let mut mask = AccessFs::from_all(ABI::V1).bits();
    if abi >= 2 {
        mask |= make_bitflags!(AccessFs::{Refer}).bits();
    }
    if abi >= 3 {
        mask |= make_bitflags!(AccessFs::{Truncate}).bits();
    }
    if abi >= 5 {
        mask |= make_bitflags!(AccessFs::{IoctlDev}).bits();
    }
    mask
}

impl Prepare for Capabilities {
    type Spec<'a> = CapsSpec<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<CapsSpec<'a>, BuildError> {
        let mut effective = [0u32; 2];
        let mut permitted = [0u32; 2];
        let mut inheritable = [0u32; 2];

        for cap in &self.keep {
            let nr = cap.index() as u32;
            let idx = if nr > 31 { 1 } else { 0 };
            let bit = 1u32 << (nr % 32);
            effective[idx] |= bit;
            permitted[idx] |= bit;
            inheritable[idx] |= bit;
        }

        let keep_set: std::collections::HashSet<u8> = self.keep.iter().map(|c| c.index()).collect();
        let bounding_drop: Vec<u32> = caps::all()
            .into_iter()
            .filter(|c| !keep_set.contains(&c.index()))
            .map(|c| c.index() as u32)
            .collect();
        let bounding_drop = arena.alloc_slice_fill_iter(bounding_drop);

        Ok(CapsSpec {
            effective,
            permitted,
            inheritable,
            bounding_drop,
            clear_ambient: true,
        })
    }
}

impl Prepare for FileDescriptors {
    type Spec<'a> = FdSpec<'a>;

    fn prepare<'a>(&self, arena: &'a Bump) -> Result<FdSpec<'a>, BuildError> {
        let actions: Vec<FdAction> = self
            .mappings
            .iter()
            .map(|m| FdAction::Dup2 {
                src: m.src,
                dst: m.dst,
            })
            .collect();
        let actions = arena.alloc_slice_fill_iter(actions);

        let mut keep_set = std::collections::BTreeSet::new();
        keep_set.insert(0);
        keep_set.insert(1);
        keep_set.insert(2);
        for m in &self.mappings {
            keep_set.insert(m.dst);
        }
        let keep: Vec<libc::c_int> = keep_set.into_iter().collect();
        let keep = arena.alloc_slice_fill_iter(keep);

        Ok(FdSpec {
            actions,
            keep,
            close_fds: self.close_fds,
        })
    }
}

fn prepare_seccomp(program: &kafel::BpfProgram) -> SeccompSpec {
    let insns = program.instructions();
    SeccompSpec {
        program: libc::sock_fprog {
            len: insns.len() as u16,
            filter: insns.as_ptr() as *mut libc::sock_filter,
        },
        flags: libc::SECCOMP_FILTER_FLAG_TSYNC as u32,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxBuilder;

    fn base_builder() -> SandboxBuilder {
        let mut sb = SandboxBuilder::new();
        sb.uid_map(0, 1000, 1).gid_map(0, 1000, 1);
        sb
    }

    #[test]
    fn exec_spec_basic_command() {
        let mut sb = base_builder();
        sb.command("/bin/echo").arg("hello");
        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let spec = sandbox.prepare(&arena).unwrap();

        assert_eq!(spec.exec.path.to_str().unwrap(), "/bin/echo");
        assert_eq!(spec.exec.argv.len(), 3); // echo, hello, NULL
        assert!(spec.exec.argv[2].is_null());
    }

    #[test]
    fn interior_null_byte_in_command() {
        let mut sb = base_builder();
        sb.command("/bin/\0echo");
        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let err = sandbox.prepare(&arena).unwrap_err();
        assert!(matches!(err, BuildError::InvalidConfig(msg) if msg.contains("null byte")));
    }

    #[test]
    fn process_spec_all_enabled() {
        let mut opts = ProcessOptions::default();
        opts.die_with_parent = true;
        opts.mdwe = true;
        opts.no_new_privs = true;
        opts.new_session = true;
        let arena = Bump::new();
        let spec = opts.prepare(&arena).unwrap();
        assert_eq!(spec.pdeathsig, Some(libc::SIGKILL));
        assert!(spec.verify_parent_alive);
        assert!(spec.no_new_privs);
        assert!(spec.new_session);
    }

    #[test]
    fn env_spec_with_clear_keep_set() {
        let mut sb = base_builder();
        sb.command("/bin/true");
        sb.env().clear(true).keep("PATH").set("FOO", "bar");
        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let spec = sandbox.prepare(&arena).unwrap();

        let env = spec.env.as_ref().unwrap();
        assert!(env.clear);
        assert_eq!(env.keep.len(), 1);
        assert_eq!(env.keep[0].to_str().unwrap(), "PATH");
        assert_eq!(env.set.len(), 1);
        assert_eq!(env.set[0].key.to_str().unwrap(), "FOO");
        assert_eq!(env.set[0].value.to_str().unwrap(), "bar");
    }

    #[test]
    fn mount_bind_tmpfs_proc_file() {
        let mut sb = base_builder();
        sb.command("/bin/true");
        sb.mounts().bind_read_only("/usr", "/usr");
        sb.mounts()
            .tmpfs_with_options("/tmp", Some(64 * MIB), Some(0o1777));
        sb.mounts().push(mount::MountEntry::Proc {
            dst: "/proc".into(),
            subset: Some(mount::ProcSubset::Pid),
            hidepid: Some(mount::HidePid::Invisible),
        });
        sb.mounts().inject_file("/etc/hostname", "test");

        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let spec = sandbox.prepare(&arena).unwrap();

        let plan = spec.mounts.unwrap();
        assert_eq!(plan.entries.len(), 4);

        match &plan.entries[0] {
            MountEntry::Bind(b) => {
                assert_eq!(b.src.to_str().unwrap(), "/usr");
                assert_eq!(b.dst_rel.to_str().unwrap(), "usr");
                assert!(b.read_only);
            }
            other => panic!("expected Bind, got: {other:?}"),
        }
        match &plan.entries[1] {
            MountEntry::Tmpfs(t) => {
                assert_eq!(t.dst_rel.to_str().unwrap(), "tmp");
                assert_eq!(t.size_bytes, Some(64 * MIB));
                assert_eq!(t.mode, Some(0o1777));
            }
            other => panic!("expected Tmpfs, got: {other:?}"),
        }
        match &plan.entries[2] {
            MountEntry::Proc(p) => {
                assert_eq!(p.subset, Some(ChildProcSubset::Pid));
                assert_eq!(p.hidepid, Some(ChildHidePid::Invisible));
            }
            other => panic!("expected Proc, got: {other:?}"),
        }
        match &plan.entries[3] {
            MountEntry::File(f) => {
                assert_eq!(f.content, b"test");
            }
            other => panic!("expected File, got: {other:?}"),
        }
    }

    #[test]
    fn landlock_read_execute() {
        let mut sb = base_builder();
        sb.command("/bin/true");
        sb.landlock().allow_read("/usr").allow_execute("/usr/bin");
        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let spec = sandbox.prepare(&arena).unwrap();

        let ll = spec.landlock.unwrap();
        assert_eq!(ll.min_abi, 1);
        assert_eq!(ll.path_rules.len(), 2);
    }

    #[test]
    fn caps_single_capability() {
        use caps::Capability;
        let mut sb = base_builder();
        sb.command("/bin/true");
        sb.capabilities().keep(Capability::CAP_NET_BIND_SERVICE);
        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let spec = sandbox.prepare(&arena).unwrap();

        let caps = spec.caps.unwrap();
        let nr = Capability::CAP_NET_BIND_SERVICE.index() as u32;
        assert_eq!(caps.effective[0], 1u32 << nr);
        assert!(!caps.bounding_drop.contains(&nr));
    }

    #[test]
    fn fd_mapping() {
        let mut sb = base_builder();
        sb.command("/bin/true");
        sb.fd().map(5, 0);
        let sandbox = sb.build().unwrap();
        let arena = Bump::new();
        let spec = sandbox.prepare(&arena).unwrap();

        assert_eq!(spec.fds.actions.len(), 1);
        assert!(spec.fds.keep.contains(&0));
        assert!(spec.fds.close_fds);
    }
}

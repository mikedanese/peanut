//! Typed child-runtime inputs.

use core::ffi::{CStr, c_char};

use crate::fd::FdAction;

/// One complete child-runtime invocation.
#[derive(Debug)]
pub struct ChildSpec<'a> {
    pub sync_fd: Option<libc::c_int>,
    pub status_fd: Option<libc::c_int>,
    pub process: ProcessSpec,
    pub mounts: Option<MountPlan<'a>>,
    pub hostname: Option<&'a CStr>,
    pub bring_up_loopback: bool,
    pub env: Option<EnvSpec<'a>>,
    pub rlimits: Option<RlimitSpec<'a>>,
    pub landlock: Option<LandlockSpec<'a>>,
    pub caps: Option<CapsSpec<'a>>,
    pub fds: FdSpec<'a>,
    pub seccomp: Option<SeccompSpec>,
    pub cwd: Option<&'a CStr>,
    pub exec: ExecSpec<'a>,
}

/// Process toggles applied during child setup.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessSpec {
    pub pdeathsig: Option<libc::c_int>,
    pub verify_parent_alive: bool,
    pub dumpable: bool,
    pub new_session: bool,
    pub disable_tsc: bool,
    pub no_new_privs: bool,
    pub mdwe_flags: Option<libc::c_ulong>,
}

/// Prepared filesystem mount plan for child-side execution.
#[derive(Clone, Copy, Debug)]
pub struct MountPlan<'a> {
    pub entries: &'a [MountEntry<'a>],
}

/// One filesystem mount operation.
#[derive(Clone, Copy, Debug)]
pub enum MountEntry<'a> {
    Bind(BindMount<'a>),
    Tmpfs(TmpfsMount<'a>),
    Proc(ProcMount<'a>),
    Mqueue(MqueueMount<'a>),
    File(FileMount<'a>),
}

/// One bind-mount operation.
#[derive(Clone, Copy, Debug)]
pub struct BindMount<'a> {
    pub src: &'a CStr,
    pub dst_rel: &'a CStr,
    pub src_is_dir: bool,
    pub read_only: bool,
}

/// One tmpfs mount operation.
#[derive(Clone, Copy, Debug)]
pub struct TmpfsMount<'a> {
    pub dst_rel: &'a CStr,
    pub read_only: bool,
    pub size_bytes: Option<u64>,
    pub mode: Option<u32>,
}

/// Proc mount `subset=` option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcSubset {
    Pid,
}

/// Proc mount `hidepid=` option.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HidePid {
    Visible,
    Hidden,
    Invisible,
}

/// One procfs mount operation.
#[derive(Clone, Copy, Debug)]
pub struct ProcMount<'a> {
    pub dst_rel: &'a CStr,
    pub subset: Option<ProcSubset>,
    pub hidepid: Option<HidePid>,
}

/// One mqueue mount operation.
#[derive(Clone, Copy, Debug)]
pub struct MqueueMount<'a> {
    pub dst_rel: &'a CStr,
}

/// One file-content injection operation.
#[derive(Clone, Copy, Debug)]
pub struct FileMount<'a> {
    pub dst_rel: &'a CStr,
    pub content: &'a [u8],
    pub read_only: bool,
}

/// Borrowed view of a fully prepared exec request.
#[derive(Clone, Copy, Debug)]
pub struct ExecSpec<'a> {
    pub path: &'a CStr,
    pub argv: &'a [*const c_char],
}

/// Environment policy applied in the child into caller-provided scratch space.
#[derive(Debug)]
pub struct EnvSpec<'a> {
    pub clear: bool,
    pub keep: &'a [&'a CStr],
    pub set: &'a [EnvBinding<'a>],
    pub storage: EnvStorage<'a>,
}

/// One environment variable assignment.
#[derive(Clone, Copy, Debug)]
pub struct EnvBinding<'a> {
    pub key: &'a CStr,
    pub value: &'a CStr,
}

/// Scratch buffers for building the final `envp`.
#[derive(Debug)]
pub struct EnvStorage<'a> {
    pub envp: &'a mut [*const c_char],
    pub bytes: &'a mut [u8],
}

/// Prepared file-descriptor policy.
#[derive(Clone, Copy, Debug)]
pub struct FdSpec<'a> {
    pub actions: &'a [FdAction],
    pub keep: &'a [libc::c_int],
    pub close_fds: bool,
}

impl Default for FdSpec<'_> {
    fn default() -> Self {
        Self {
            actions: &[],
            keep: &[],
            close_fds: true,
        }
    }
}

/// Precomputed resource limits.
#[derive(Clone, Copy, Debug)]
pub struct RlimitSpec<'a> {
    pub limits: &'a [RlimitEntry],
}

/// One `setrlimit` call.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RlimitEntry {
    pub resource: libc::c_int,
    pub limit: libc::rlimit,
}

/// Prepared Landlock ruleset.
#[derive(Clone, Copy, Debug)]
pub struct LandlockSpec<'a> {
    pub min_abi: u32,
    pub ruleset: LandlockRulesetAttr,
    pub path_rules: &'a [LandlockPathRule<'a>],
    pub net_rules: &'a [LandlockNetRule],
}

/// Ruleset attributes passed to `landlock_create_ruleset`.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,
}

/// One `LANDLOCK_RULE_PATH_BENEATH` rule.
#[derive(Clone, Copy, Debug)]
pub struct LandlockPathRule<'a> {
    pub path: &'a CStr,
    pub allowed_access: u64,
}

/// One `LANDLOCK_RULE_NET_PORT` rule.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct LandlockNetRule {
    pub port: u16,
    pub allowed_access: u64,
}

/// Prepared Linux capability state.
#[derive(Clone, Copy, Debug)]
pub struct CapsSpec<'a> {
    pub effective: [u32; 2],
    pub permitted: [u32; 2],
    pub inheritable: [u32; 2],
    pub bounding_drop: &'a [u32],
    pub clear_ambient: bool,
}

/// Prepared seccomp filter installation request.
#[derive(Clone, Copy, Debug)]
pub struct SeccompSpec {
    pub program: libc::sock_fprog,
    pub flags: u32,
}

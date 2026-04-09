//! Raw Landlock ruleset application.

use crate::error::{Errno, Result};
use crate::fd::OwnedFd;
use crate::spec::{LandlockNetRule, LandlockPathRule, LandlockRulesetAttr, LandlockSpec};

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const LANDLOCK_RULE_NET_PORT: libc::c_int = 2;

#[repr(C)]
struct RawPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct RawNetPortAttr {
    allowed_access: u64,
    port: u64,
}

pub fn apply(spec: &LandlockSpec<'_>) -> Result<()> {
    if spec.min_abi != 0 {
        let abi = abi_version()?;
        if abi < spec.min_abi as libc::c_long {
            return Err(Errno::new(libc::ENOSYS));
        }
    }

    let ruleset = OwnedFd::new(create_ruleset(spec.ruleset)?);
    apply_rules(ruleset.as_raw(), spec)?;
    restrict_self(ruleset.as_raw())
}

fn abi_version() -> Result<libc::c_long> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            core::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret >= 0 {
        Ok(ret)
    } else {
        Err(Errno::last())
    }
}

fn create_ruleset(attr: LandlockRulesetAttr) -> Result<libc::c_int> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            core::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ret >= 0 {
        Ok(ret as libc::c_int)
    } else {
        Err(Errno::last())
    }
}

fn apply_rules(ruleset_fd: libc::c_int, spec: &LandlockSpec<'_>) -> Result<()> {
    for rule in spec.path_rules {
        add_path_rule(ruleset_fd, rule)?;
    }
    for rule in spec.net_rules {
        add_net_rule(ruleset_fd, *rule)?;
    }
    Ok(())
}

fn add_path_rule(ruleset_fd: libc::c_int, rule: &LandlockPathRule<'_>) -> Result<()> {
    let path_fd = unsafe { libc::open(rule.path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if path_fd < 0 {
        return Err(Errno::last());
    }
    let path_fd = OwnedFd::new(path_fd);

    let attr = RawPathBeneathAttr {
        allowed_access: rule.allowed_access,
        parent_fd: path_fd.as_raw(),
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const RawPathBeneathAttr,
            0u32,
        )
    };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

fn add_net_rule(ruleset_fd: libc::c_int, rule: LandlockNetRule) -> Result<()> {
    let attr = RawNetPortAttr {
        allowed_access: rule.allowed_access,
        port: rule.port as u64,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_NET_PORT,
            &attr as *const RawNetPortAttr,
            0u32,
        )
    };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

fn restrict_self(ruleset_fd: libc::c_int) -> Result<()> {
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0u32) };
    if ret == 0 { Ok(()) } else { Err(Errno::last()) }
}

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

//! Minimal helpers for code that runs in the child after `clone3()` and
//! before `execve()`.
//!
//! This crate is intentionally small and has no dependency on `pnut`. The
//! child path should consume precomputed data from the parent and restrict
//! itself to raw syscalls and simple borrowed views.

mod caps;
mod env;
mod error;
mod fd;
mod io;
mod landlock;
mod mount;
mod net;
mod process;
mod report;
mod rlimit;
mod runtime;
mod seccomp;
mod spec;

pub use fd::FdAction;
pub use report::{ChildFailure, Stage};
pub use runtime::run;
pub use spec::{
    BindMount, CapsSpec, ChildSpec, EnvBinding, EnvSpec, EnvStorage, ExecSpec, FdSpec, FileMount,
    HidePid, LandlockNetRule, LandlockPathRule, LandlockRulesetAttr, LandlockSpec, MountEntry,
    MountPlan, MqueueMount, ProcMount, ProcSubset, ProcessSpec, RlimitEntry, RlimitSpec,
    SeccompSpec, TmpfsMount,
};

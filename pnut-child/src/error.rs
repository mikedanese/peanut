//! Minimal errno-based error reporting for child-runtime code.

/// Linux errno captured by value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Errno(pub i32);

pub(crate) type Result<T> = core::result::Result<T, Errno>;

impl Errno {
    pub(crate) const fn new(code: i32) -> Self {
        Self(code)
    }

    /// Read the current thread's errno value.
    pub(crate) fn last() -> Self {
        #[cfg(target_os = "linux")]
        unsafe {
            Self(*libc::__errno_location())
        }
    }
}

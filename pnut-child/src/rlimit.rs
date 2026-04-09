//! Raw `setrlimit` execution.

use crate::error::{Errno, Result};
use crate::spec::RlimitSpec;

pub fn apply(spec: &RlimitSpec<'_>) -> Result<()> {
    for entry in spec.limits {
        let ret = unsafe { libc::setrlimit(entry.resource as _, &entry.limit) };
        if ret != 0 {
            return Err(Errno::last());
        }
    }
    Ok(())
}

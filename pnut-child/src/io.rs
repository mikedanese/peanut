//! Raw read/write helpers for child-runtime control pipes and error pipes.

use crate::error::{Errno, Result};

/// Read exactly `buf.len()` bytes or return the first hard error.
pub fn read_exact(fd: libc::c_int, buf: &mut [u8]) -> Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let ret = unsafe {
            libc::read(
                fd,
                buf[filled..].as_mut_ptr().cast::<libc::c_void>(),
                buf.len() - filled,
            )
        };
        if ret > 0 {
            filled += ret as usize;
            continue;
        }
        if ret == 0 {
            return Err(Errno(libc::EPIPE));
        }
        let err = Errno::last();
        if err.0 == libc::EINTR {
            continue;
        }
        return Err(err);
    }
    Ok(())
}

/// Read one byte.
pub fn read_byte(fd: libc::c_int) -> Result<u8> {
    let mut buf = [0u8; 1];
    read_exact(fd, &mut buf)?;
    Ok(buf[0])
}

/// Write all bytes from `buf`.
pub fn write_all(fd: libc::c_int, buf: &[u8]) -> Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let ret = unsafe {
            libc::write(
                fd,
                buf[written..].as_ptr().cast::<libc::c_void>(),
                buf.len() - written,
            )
        };
        if ret >= 0 {
            written += ret as usize;
            continue;
        }
        let err = Errno::last();
        if err.0 == libc::EINTR {
            continue;
        }
        return Err(err);
    }
    Ok(())
}

/// Best-effort write to stderr for fixed error messages.
pub fn write_stderr(buf: &[u8]) -> Result<()> {
    write_all(libc::STDERR_FILENO, buf)
}

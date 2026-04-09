//! Child-side environment preparation without heap allocation.

use core::ffi::{CStr, c_char};

use crate::error::{Errno, Result};
use crate::process::current_environ;
use crate::spec::{EnvBinding, EnvSpec};

/// Build the final `envp` in caller-provided scratch storage.
///
/// The returned pointer is suitable for `execve`.
pub fn prepare(spec: &mut EnvSpec<'_>) -> Result<*const *const c_char> {
    let mut envp_len = 0usize;
    let mut bytes_len = 0usize;
    let clear = spec.clear;
    let keep = spec.keep;
    let set = spec.set;
    let storage = &mut spec.storage;
    let envp_out = &mut storage.envp;
    let bytes_out = &mut storage.bytes;

    let mut cursor = current_environ();
    unsafe {
        while !cursor.is_null() && !(*cursor).is_null() {
            let entry = *cursor;
            if should_include(entry, clear, keep, set) {
                push_env_ptr(envp_out, &mut envp_len, entry)?;
            }
            cursor = cursor.add(1);
        }
    }

    for &binding in set {
        let ptr = encode_binding(&binding, bytes_out, &mut bytes_len)?;
        push_env_ptr(envp_out, &mut envp_len, ptr)?;
    }

    if envp_len >= envp_out.len() {
        return Err(Errno::new(libc::ENOSPC));
    }
    envp_out[envp_len] = core::ptr::null();
    Ok(envp_out.as_ptr())
}

fn should_include(
    entry: *const c_char,
    clear: bool,
    keep: &[&CStr],
    set: &[EnvBinding<'_>],
) -> bool {
    if matches_any_key(entry, set.iter().map(|binding| binding.key)) {
        return false;
    }

    if clear {
        matches_any_key(entry, keep.iter().copied())
    } else {
        true
    }
}

fn matches_any_key<'a>(entry: *const c_char, keys: impl Iterator<Item = &'a CStr>) -> bool {
    for key in keys {
        if entry_key_eq(entry, key) {
            return true;
        }
    }
    false
}

fn entry_key_eq(entry: *const c_char, key: &CStr) -> bool {
    let key_bytes = key.to_bytes();
    if key_bytes.contains(&b'=') {
        return false;
    }

    unsafe {
        for (idx, &expected) in key_bytes.iter().enumerate() {
            let byte = *entry.add(idx) as u8;
            if byte != expected {
                return false;
            }
        }
        // The entry must have '=' immediately after the key.
        *entry.add(key_bytes.len()) as u8 == b'='
    }
}

fn push_env_ptr(
    envp_out: &mut [*const c_char],
    len: &mut usize,
    entry: *const c_char,
) -> Result<()> {
    if *len >= envp_out.len().saturating_sub(1) {
        return Err(Errno::new(libc::ENOSPC));
    }
    envp_out[*len] = entry;
    *len += 1;
    Ok(())
}

fn encode_binding<'a>(
    binding: &EnvBinding<'a>,
    bytes: &mut [u8],
    bytes_len: &mut usize,
) -> Result<*const c_char> {
    let key = binding.key.to_bytes();
    let value = binding.value.to_bytes();

    if key.contains(&b'=') {
        return Err(Errno::new(libc::EINVAL));
    }

    let needed = key.len() + 1 + value.len() + 1;
    if *bytes_len + needed > bytes.len() {
        return Err(Errno::new(libc::ENOSPC));
    }

    let start = *bytes_len;
    bytes[start..start + key.len()].copy_from_slice(key);
    bytes[start + key.len()] = b'=';
    let value_start = start + key.len() + 1;
    bytes[value_start..value_start + value.len()].copy_from_slice(value);
    bytes[value_start + value.len()] = 0;
    *bytes_len += needed;

    Ok(bytes[start..].as_ptr().cast::<c_char>())
}

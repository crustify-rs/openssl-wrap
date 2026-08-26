//! Wrappers assigned from `crypto/rand/randfile.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_long};

use libcrypto_sys as ffi;

/// Wraps: RAND_file_name
/// Writes the default seed-file path into `output` and borrows it back as a C string.
#[must_use]
pub fn RAND_file_name(output: &mut [u8]) -> Option<&CStr> {
    // SAFETY: `output` supplies its exact writable extent. OpenSSL returns null
    // or the start of the same buffer after writing a terminating NUL byte.
    let path = unsafe { ffi::RAND_file_name(output.as_mut_ptr().cast(), output.len()) };
    if path.is_null() {
        None
    } else {
        // SAFETY: a non-null result is the start of `output`, and the C
        // contract guarantees a NUL-terminated pathname on success.
        Some(unsafe { CStr::from_ptr(path) })
    }
}

/// Wraps: RAND_load_file
/// Loads at most `maximum` bytes, or the complete file when it is `None`.
pub fn RAND_load_file(file: &CStr, maximum: Option<usize>) -> i32 {
    let maximum = match maximum {
        Some(maximum) => {
            let Ok(maximum) = c_long::try_from(maximum) else {
                return -1;
            };
            maximum
        }
        None => -1,
    };
    // SAFETY: `file` is a live NUL-terminated pathname for this synchronous
    // operation; OpenSSL neither mutates nor retains it.
    unsafe { ffi::RAND_load_file(file.as_ptr(), maximum) }
}

/// Wraps: RAND_write_file
pub fn RAND_write_file(file: &CStr) -> i32 {
    // SAFETY: `file` is a live NUL-terminated pathname for this synchronous
    // operation; OpenSSL neither mutates nor retains it.
    unsafe { ffi::RAND_write_file(file.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn default_name_rejects_a_too_small_buffer() {
        let mut output = [0; 1];
        assert!(RAND_file_name(&mut output).is_none());
    }

    #[test]
    fn seed_file_round_trip_uses_nul_terminated_paths_and_a_load_limit() {
        let path = std::env::temp_dir().join(format!(
            "crustify-rand-seed-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let path = CString::new(path.as_os_str().as_encoded_bytes()).expect("path without NUL");
        assert!(RAND_write_file(&path) > 0);
        assert_eq!(RAND_load_file(&path, Some(8)), 8);
        std::fs::remove_file(path.to_string_lossy().as_ref()).expect("remove seed fixture");
    }
}

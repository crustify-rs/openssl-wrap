//! Wrappers assigned from `crypto/bio/bss_fd.c`.

use libcrypto_sys as ffi;

/// Wraps: BIO_fd_non_fatal_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_fd_non_fatal_error(error: i32) -> bool {
    // SAFETY: the classifier takes only a by-value error code.
    unsafe { ffi::BIO_fd_non_fatal_error(error) != 0 }
}

/// Wraps: BIO_fd_should_retry
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_fd_should_retry(result: i32) -> bool {
    // SAFETY: the classifier takes only a by-value operation result.
    unsafe { ffi::BIO_fd_should_retry(result) != 0 }
}

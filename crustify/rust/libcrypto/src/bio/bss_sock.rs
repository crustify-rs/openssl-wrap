//! Wrappers assigned from `crypto/bio/bss_sock.c`.

use libcrypto_sys as ffi;

/// Wraps: BIO_sock_non_fatal_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_non_fatal_error(error: i32) -> bool {
    // SAFETY: the classifier takes only a by-value socket error.
    unsafe { ffi::BIO_sock_non_fatal_error(error) != 0 }
}

/// Wraps: BIO_sock_should_retry
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_should_retry(result: i32) -> bool {
    // SAFETY: the classifier takes only a by-value operation result.
    unsafe { ffi::BIO_sock_should_retry(result) != 0 }
}

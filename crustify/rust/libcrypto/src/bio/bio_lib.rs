//! Wrappers assigned from `crypto/bio/bio_lib.c`.

use libcrypto_sys as ffi;

/// Wraps: BIO_err_is_non_fatal
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_err_is_non_fatal(error_code: u32) -> bool {
    // SAFETY: the classifier takes only a by-value packed error code.
    unsafe { ffi::BIO_err_is_non_fatal(error_code) != 0 }
}

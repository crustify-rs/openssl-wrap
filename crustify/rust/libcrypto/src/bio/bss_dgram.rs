//! Wrappers assigned from `crypto/bio/bss_dgram.c`.

use libcrypto_sys as ffi;

/// Wraps: BIO_dgram_non_fatal_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_dgram_non_fatal_error(error: i32) -> bool {
    // SAFETY: the classifier takes only a by-value error code.
    unsafe { ffi::BIO_dgram_non_fatal_error(error) != 0 }
}

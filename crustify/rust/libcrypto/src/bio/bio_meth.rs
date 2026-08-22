//! Wrappers assigned from `crypto/bio/bio_meth.c`.

use libcrypto_sys as ffi;

/// Wraps: BIO_get_new_index
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_new_index() -> i32 {
    // SAFETY: the allocator has no caller-side memory obligations.
    unsafe { ffi::BIO_get_new_index() }
}

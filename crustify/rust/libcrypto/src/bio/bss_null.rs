//! Wrappers assigned from `crypto/bio/bss_null.c`.

use libcrypto_sys as ffi;

use super::internal_bio::{BioMethodRef, static_bio_method};

/// Wraps: BIO_s_null
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_null() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // a process-lifetime static method table or null.
    static_bio_method(unsafe { ffi::BIO_s_null() })
}

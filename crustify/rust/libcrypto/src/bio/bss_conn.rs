//! Wrappers assigned from `crypto/bio/bss_conn.c`.

use core::ffi::CStr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::internal_bio::{BioMethodRef, static_bio_method};

use super::bio_bio_local::Bio;

/// Wraps: BIO_new_connect
/// Creates an owned connecting BIO from a copied host/service string.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_connect(host_service: &CStr) -> Option<CBox<Bio>> {
    // SAFETY: the input is NUL-terminated and remains live while OpenSSL
    // copies it; a non-null result transfers one fresh BIO reference.
    unsafe { CBox::from_raw(ffi::BIO_new_connect(host_service.as_ptr())) }
}

/// Wraps: BIO_s_connect
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_connect() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // a process-lifetime static method table or null.
    static_bio_method(unsafe { ffi::BIO_s_connect() })
}

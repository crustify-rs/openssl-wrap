//! Wrappers assigned from `crypto/bio/bss_conn.c`.

use core::ffi::CStr;

use ffibox::CBox;
use libcrypto_sys as ffi;

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

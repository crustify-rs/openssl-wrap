//! Wrappers assigned from `crypto/objects/obj_lib.c`.

use crate::asn1::asn1::{Asn1ObjectDuplicate, Asn1ObjectRef};

use libcrypto_sys as ffi;

/// Wraps: OBJ_cmp
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_cmp(left: Asn1ObjectRef<'_>, right: Asn1ObjectRef<'_>) -> core::cmp::Ordering {
    // SAFETY: both shared handles are live for the synchronous byte comparison.
    unsafe { ffi::OBJ_cmp(left.as_ptr(), right.as_ptr()) }.cmp(&0)
}

/// Wraps: OBJ_dup
/// Preserves OpenSSL's dynamic-owned versus static-borrowed result distinction.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_dup<'a>(object: Asn1ObjectRef<'a>) -> Option<Asn1ObjectDuplicate<'a>> {
    object.try_dup()
}

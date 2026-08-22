//! Wrappers assigned from `crypto/objects/obj_xref.c`.

use libcrypto_sys as ffi;

/// Wraps: OBJ_find_sigid_algs
/// Returns the digest and public-key NIDs for a signature NID.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_find_sigid_algs(signature_nid: i32) -> Option<(i32, i32)> {
    let mut digest_nid = 0;
    let mut public_key_nid = 0;
    // SAFETY: both output pointers refer to live initialized scalar slots.
    let found =
        unsafe { ffi::OBJ_find_sigid_algs(signature_nid, &mut digest_nid, &mut public_key_nid) };
    (found == 1).then_some((digest_nid, public_key_nid))
}

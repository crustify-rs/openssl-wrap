//! Wrappers assigned from `crypto/objects/obj_xref.c`.

use libcrypto_sys as ffi;

/// Wraps: OBJ_find_sigid_algs
/// Returns the digest and public-key NIDs for a signature NID.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_find_sigid_algs(signature_nid: i32) -> Option<(i32, i32)> {
    if signature_nid <= 0 {
        return None;
    }
    let mut digest_nid = 0;
    let mut public_key_nid = 0;
    // SAFETY: both output pointers refer to live initialized scalar slots.
    let found =
        unsafe { ffi::OBJ_find_sigid_algs(signature_nid, &mut digest_nid, &mut public_key_nid) };
    (found == 1).then_some((digest_nid, public_key_nid))
}

/// Wraps: OBJ_add_sigid
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_add_sigid(signature_nid: i32, digest_nid: i32, public_key_nid: i32) -> bool {
    if signature_nid <= 0 || digest_nid <= 0 || public_key_nid <= 0 {
        return false;
    }
    // SAFETY: all arguments are by-value registry identifiers.
    unsafe { ffi::OBJ_add_sigid(signature_nid, digest_nid, public_key_nid) == 1 }
}

/// Wraps: OBJ_find_sigid_by_algs
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_find_sigid_by_algs(digest_nid: i32, public_key_nid: i32) -> Option<i32> {
    if digest_nid <= 0 || public_key_nid <= 0 {
        return None;
    }
    let mut signature_nid = 0;
    // SAFETY: the output pointer is a live initialized scalar slot.
    let found =
        unsafe { ffi::OBJ_find_sigid_by_algs(&mut signature_nid, digest_nid, public_key_nid) };
    (found == 1).then_some(signature_nid)
}

/// Wraps: OBJ_sigid_free
///
/// # Safety
/// No C or Rust code may concurrently query or modify the process-global
/// signature registry, and no such operation may race with this teardown.
#[allow(non_snake_case)]
pub unsafe fn OBJ_sigid_free() {
    // SAFETY: the caller excludes all concurrent registry operations.
    unsafe { ffi::OBJ_sigid_free() }
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;
    use crate::objects::obj_dat::OBJ_txt2nid;

    #[test]
    fn signature_lookup_round_trips_builtin_algorithm_ids() {
        let signature = OBJ_txt2nid(c"sha256WithRSAEncryption");
        let digest = OBJ_txt2nid(c"SHA256");
        let public_key = OBJ_txt2nid(c"rsaEncryption");
        assert_eq!(OBJ_find_sigid_by_algs(digest, public_key), Some(signature));
        assert_eq!(OBJ_find_sigid_algs(signature), Some((digest, public_key)));
    }

    #[test]
    fn an_unregistered_signature_nid_has_no_algorithms() {
        assert_eq!(OBJ_find_sigid_algs(0), None);
    }

    #[test]
    fn non_positive_nids_are_rejected_before_the_c_comparators() {
        for invalid in [i32::MIN, -1, 0] {
            assert_eq!(OBJ_find_sigid_algs(invalid), None);
            assert_eq!(OBJ_find_sigid_by_algs(invalid, 1), None);
            assert_eq!(OBJ_find_sigid_by_algs(1, invalid), None);
            assert!(!OBJ_add_sigid(invalid, 1, 1));
            assert!(!OBJ_add_sigid(1, invalid, 1));
            assert!(!OBJ_add_sigid(1, 1, invalid));
        }
    }
}

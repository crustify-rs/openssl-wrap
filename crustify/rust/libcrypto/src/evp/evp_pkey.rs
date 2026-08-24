//! Wrappers assigned from `crypto/evp/evp_pkey.c`.

use libcrypto_sys as ffi;

use crate::evp::evp::EvpPkeyRef;

/// Wraps: EVP_PKEY_get_attr_by_NID
/// Returns the next matching attribute index after `last_position`.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_attr_by_NID(pkey: EvpPkeyRef<'_>, nid: i32, last_position: i32) -> i32 {
    // SAFETY: the shared key keeps its attribute stack live for the lookup.
    unsafe { ffi::EVP_PKEY_get_attr_by_NID(pkey.as_ptr(), nid, last_position) }
}

/// Wraps: EVP_PKEY_get_attr_count
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_attr_count(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key keeps its attribute stack live for the count.
    unsafe { ffi::EVP_PKEY_get_attr_count(pkey.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::p_lib::EVP_PKEY_new;

    #[test]
    fn fresh_key_has_no_attributes() {
        let key = EVP_PKEY_new().expect("EVP_PKEY_new");
        assert_eq!(EVP_PKEY_get_attr_count(key.as_ref()), -1);
        assert_eq!(EVP_PKEY_get_attr_by_NID(key.as_ref(), 1, -1), -1);
    }
}

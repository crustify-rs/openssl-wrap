//! Wrappers assigned from `crypto/evp/evp_pkey_type.c`.

use libcrypto_sys as ffi;

/// Wraps: EVP_PKEY_type
/// Returns the base key type for an OpenSSL key-type identifier.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_type(key_type: i32) -> i32 {
    // SAFETY: the operation accepts every integer identifier by value, reads
    // only OpenSSL's registered method table, and returns a scalar identifier.
    unsafe { ffi::EVP_PKEY_type(key_type) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_type_maps_to_undefined() {
        assert_eq!(EVP_PKEY_type(i32::MAX), ffi::NID_undef as i32);
    }

    #[test]
    fn legacy_rsa_alias_maps_to_the_rsa_base_type() {
        assert_eq!(
            EVP_PKEY_type(ffi::EVP_PKEY_RSA2 as i32),
            ffi::EVP_PKEY_RSA as i32
        );
    }
}

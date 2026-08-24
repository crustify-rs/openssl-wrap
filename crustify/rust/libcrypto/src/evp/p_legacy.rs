//! Wrappers assigned from `crypto/evp/p_legacy.c`.

use crate::evp::evp::EvpPkeyMut;
use crate::keys::ec_local::EcKeyRef;
use libcrypto_sys as ffi;

/// Wraps: EVP_PKEY_set1_EC_KEY
///
/// Stores an independently reference-counted share of `key` in `pkey`. The
/// caller retains its own key reference, and replacement releases any previous
/// key material held by `pkey`.
#[allow(non_snake_case)]
pub fn EVP_PKEY_set1_EC_KEY(pkey: &mut EvpPkeyMut<'_>, key: EcKeyRef<'_>) -> bool {
    // SAFETY: both handles identify live objects. The exclusive PKEY handle
    // permits replacement, while OpenSSL raises `key`'s atomic reference count
    // before storing it and leaves the caller's shared borrow untouched.
    unsafe { ffi::EVP_PKEY_set1_EC_KEY(pkey.as_mut_ptr(), key.as_ptr().cast_mut()) == 1 }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::evp::evp::EvpPkey;
    use crate::keys::ec_local::EcKey;

    #[test]
    fn setting_an_ec_key_keeps_the_callers_reference() {
        // SAFETY: both constructors return fresh fully initialized objects or
        // null, and each non-null result transfers its public free obligation.
        let mut pkey =
            unsafe { CBox::<EvpPkey>::from_raw(ffi::EVP_PKEY_new()) }.expect("EVP_PKEY_new");
        // SAFETY: as above, for the legacy EC key constructor.
        let key = unsafe { CBox::<EcKey>::from_raw(ffi::EC_KEY_new()) }.expect("EC_KEY_new");

        assert!(EVP_PKEY_set1_EC_KEY(&mut pkey.as_mut(), key.as_ref()));
        assert!(!key.as_ref().as_ptr().is_null());
    }
}

//! Wrappers assigned from `crypto/evp/p_legacy.c`.

#![allow(non_snake_case)]

use libcrypto_sys as ffi;

#[cfg(feature = "deprecated-3-0")]
use crate::evp::evp::EvpPkeyRef;
use crate::keys::ec_local::EcKeyRef;
#[cfg(feature = "deprecated-3-0")]
use crate::keys::ec_local::SharedEcKey;

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0_EC_KEY
/// Borrows the legacy EC key retained by an EVP key container.
#[must_use]
pub fn EVP_PKEY_get0_EC_KEY<'a>(pkey: EvpPkeyRef<'a>) -> Option<EcKeyRef<'a>> {
    // SAFETY: the key container is live and retains any returned EC key.
    let raw = unsafe { ffi::EVP_PKEY_get0_EC_KEY(pkey.as_ptr()) };
    // SAFETY: null is absence; a non-null result remains borrowed from `pkey`.
    unsafe { EcKeyRef::from_ptr(raw.cast_mut()) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get1_EC_KEY
/// Raises and owns one shared-only EC key reference.
#[must_use]
pub fn EVP_PKEY_get1_EC_KEY<'a>(pkey: EvpPkeyRef<'a>) -> Option<SharedEcKey<'a>> {
    // SAFETY: the live EVP key permits OpenSSL to locate and up-reference its
    // legacy EC key without transferring the EVP key itself.
    let raw = unsafe { ffi::EVP_PKEY_get1_EC_KEY(pkey.as_ptr().cast_mut()) };
    // SAFETY: a non-null result transfers one matching `EC_KEY_free`
    // obligation; tying it to `pkey` conservatively preserves dependencies.
    unsafe { SharedEcKey::from_raw(raw) }
}

/// Wraps: EVP_PKEY_set1_EC_KEY
/// Stores a separately reference-counted share of `key` in `pkey`.
pub fn EVP_PKEY_set1_EC_KEY(pkey: &mut crate::evp::evp::EvpPkeyMut<'_>, key: EcKeyRef<'_>) -> bool {
    // SAFETY: both handles identify live objects. OpenSSL raises `key`'s
    // reference count before storing it in the exclusively borrowed PKEY.
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

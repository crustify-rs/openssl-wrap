//! Wrappers assigned from `crypto/x509/v3_akeya.c`.

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::x509::x509v3::AuthorityKeyId;

/// Wraps: AUTHORITY_KEYID_free
/// Consumes an optional complete authority-key-identifier allocation.
#[allow(non_snake_case)]
pub fn AUTHORITY_KEYID_free(value: Option<CBox<AuthorityKeyId>>) {
    drop(value);
}

/// Wraps: AUTHORITY_KEYID_new
/// Allocates an empty authority-key-identifier sequence.
#[must_use]
#[allow(non_snake_case)]
pub fn AUTHORITY_KEYID_new() -> Option<CBox<AuthorityKeyId>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 sequence whose
    // matching destructor is registered on `AuthorityKeyId`.
    unsafe { CBox::from_raw(ffi::AUTHORITY_KEYID_new()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_returns_an_owned_empty_sequence() {
        let value = AUTHORITY_KEYID_new().expect("AUTHORITY_KEYID_new");
        assert!(value.as_ref().key_id().is_none());
        assert!(value.as_ref().issuer().is_none());
        assert!(value.as_ref().serial().is_none());
        AUTHORITY_KEYID_free(Some(value));
        AUTHORITY_KEYID_free(None);
    }
}

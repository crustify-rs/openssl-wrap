//! Wrappers assigned from `crypto/x509/v3_bcons.c`.

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::x509::x509v3::BasicConstraints;

/// Wraps: BASIC_CONSTRAINTS_free
/// Consumes an optional complete basic-constraints allocation.
#[allow(non_snake_case)]
pub fn BASIC_CONSTRAINTS_free(value: Option<CBox<BasicConstraints>>) {
    drop(value);
}

/// Wraps: BASIC_CONSTRAINTS_new
/// Allocates an empty basic-constraints sequence.
#[must_use]
#[allow(non_snake_case)]
pub fn BASIC_CONSTRAINTS_new() -> Option<CBox<BasicConstraints>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 sequence whose
    // matching destructor is registered on `BasicConstraints`.
    unsafe { CBox::from_raw(ffi::BASIC_CONSTRAINTS_new()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_returns_an_owned_empty_sequence() {
        let value = BASIC_CONSTRAINTS_new().expect("BASIC_CONSTRAINTS_new");
        assert!(!value.as_ref().is_ca());
        assert!(value.as_ref().path_len().is_none());
        BASIC_CONSTRAINTS_free(Some(value));
        BASIC_CONSTRAINTS_free(None);
    }
}

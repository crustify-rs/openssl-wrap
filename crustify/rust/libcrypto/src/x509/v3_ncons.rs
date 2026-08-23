//! Wrappers assigned from `crypto/x509/v3_ncons.c`.

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::x509::x509v3::{GeneralSubtree, NameConstraints};

/// Wraps: NAME_CONSTRAINTS_free
/// Consumes an optional complete name-constraints allocation.
#[allow(non_snake_case)]
pub fn NAME_CONSTRAINTS_free(value: Option<CBox<NameConstraints>>) {
    drop(value);
}

/// Wraps: NAME_CONSTRAINTS_new
/// Allocates an empty name-constraints sequence.
#[must_use]
#[allow(non_snake_case)]
pub fn NAME_CONSTRAINTS_new() -> Option<CBox<NameConstraints>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 sequence whose
    // matching destructor is registered on `NameConstraints`.
    unsafe { CBox::from_raw(ffi::NAME_CONSTRAINTS_new()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_returns_an_owned_empty_sequence() {
        let value = NAME_CONSTRAINTS_new().expect("NAME_CONSTRAINTS_new");
        assert!(value.as_ref().permitted_subtrees().is_none());
        assert!(value.as_ref().excluded_subtrees().is_none());
        NAME_CONSTRAINTS_free(Some(value));
        NAME_CONSTRAINTS_free(None);
    }
}

/// Wraps: GENERAL_SUBTREE_free
/// Consumes an optional complete general-subtree allocation.
#[allow(non_snake_case)]
pub fn GENERAL_SUBTREE_free(value: Option<CBox<GeneralSubtree>>) {
    drop(value);
}

/// Wraps: GENERAL_SUBTREE_new
/// Allocates a fully initialized general-subtree sequence.
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_SUBTREE_new() -> Option<CBox<GeneralSubtree>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 sequence whose
    // matching destructor is registered on `GeneralSubtree`.
    unsafe { CBox::from_raw(ffi::GENERAL_SUBTREE_new()) }
}

#[cfg(test)]
mod general_subtree_tests {
    use super::*;

    #[test]
    fn constructor_and_nullable_destructor_preserve_ownership() {
        let value = GENERAL_SUBTREE_new().expect("GENERAL_SUBTREE_new");
        assert!(value.as_ref().base().is_some());
        assert!(value.as_ref().minimum().is_none());
        assert!(value.as_ref().maximum().is_none());
        GENERAL_SUBTREE_free(Some(value));
        GENERAL_SUBTREE_free(None);
    }
}

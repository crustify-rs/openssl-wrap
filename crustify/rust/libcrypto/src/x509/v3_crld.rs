//! Wrappers assigned from `crypto/x509/v3_crld.c`.

use core::ptr::NonNull;

use ffibox::{CBox, CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::x509::x509_internal::DistPointStack;
use crate::x509::x509v3::DistPointName;

/// Full ASN.1 teardown policy for CRL distribution points.
#[derive(Clone, Copy, Debug, Default)]
pub struct CrlDistPointsFree;

// SAFETY: the generated destructor releases every owned DIST_POINT and the
// generated stack exactly once.
unsafe impl CDropper<DistPointStack> for CrlDistPointsFree {
    unsafe fn c_drop(&self, object: NonNull<DistPointStack>) {
        // SAFETY: the dropper contract supplies the sole complete stack owner.
        unsafe { ffi::CRL_DIST_POINTS_free(object.as_ptr().cast()) }
    }
}

/// A CRL-distribution-points sequence that owns all its elements.
pub type CrlDistPoints = CBoxWith<DistPointStack, CrlDistPointsFree>;

/// Wraps: CRL_DIST_POINTS_free
#[allow(non_snake_case)]
pub fn CRL_DIST_POINTS_free(value: CrlDistPoints) {
    drop(value);
}

/// Wraps: CRL_DIST_POINTS_new
#[must_use]
#[allow(non_snake_case)]
pub fn CRL_DIST_POINTS_new() -> Option<CrlDistPoints> {
    // SAFETY: a non-null result is a fresh complete generated stack with one
    // matching full-destructor obligation.
    unsafe { CBoxWith::from_raw(ffi::CRL_DIST_POINTS_new().cast(), CrlDistPointsFree) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = CRL_DIST_POINTS_new().expect("CRL_DIST_POINTS_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        CRL_DIST_POINTS_free(value);
    }
}

/// Wraps: DIST_POINT_NAME_free
/// Consumes an optional complete distribution-point-name allocation.
#[allow(non_snake_case)]
pub fn DIST_POINT_NAME_free(value: Option<CBox<DistPointName>>) {
    drop(value);
}

/// Wraps: DIST_POINT_NAME_new
/// Allocates an empty, unset distribution-point-name choice.
#[must_use]
#[allow(non_snake_case)]
pub fn DIST_POINT_NAME_new() -> Option<CBox<DistPointName>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 choice whose
    // matching destructor is registered on `DistPointName`.
    unsafe { CBox::from_raw(ffi::DIST_POINT_NAME_new()) }
}

#[cfg(test)]
mod dist_point_name_tests {
    use super::*;
    use crate::x509::x509v3::{DistPointNameChoice, DistPointNameKind};

    #[test]
    fn constructor_returns_an_owned_unset_choice() {
        let value = DIST_POINT_NAME_new().expect("DIST_POINT_NAME_new");
        assert_eq!(value.as_ref().kind(), DistPointNameKind::Unset);
        assert!(matches!(value.as_ref().name(), DistPointNameChoice::Unset));
        assert!(value.as_ref().dp_name().is_none());
        DIST_POINT_NAME_free(Some(value));
        DIST_POINT_NAME_free(None);
    }
}

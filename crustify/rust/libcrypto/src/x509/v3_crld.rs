//! Wrappers assigned from `crypto/x509/v3_crld.c`.

use core::ptr::NonNull;

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::x509::x509_internal::DistPointStack;

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

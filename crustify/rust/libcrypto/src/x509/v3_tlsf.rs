//! Wrappers assigned from `crypto/x509/v3_tlsf.c`.

use core::ptr::NonNull;

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1IntegerStack;

/// Full ASN.1 teardown policy for a TLS-feature sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct TlsFeatureFree;

// SAFETY: the generated destructor releases every owned ASN1_INTEGER and the
// generated stack exactly once.
unsafe impl CDropper<Asn1IntegerStack> for TlsFeatureFree {
    unsafe fn c_drop(&self, object: NonNull<Asn1IntegerStack>) {
        // SAFETY: the dropper contract supplies the sole complete stack owner.
        unsafe { ffi::TLS_FEATURE_free(object.as_ptr().cast()) }
    }
}

/// A TLS-feature sequence that owns all its ASN.1 integers.
pub type TlsFeature = CBoxWith<Asn1IntegerStack, TlsFeatureFree>;

/// Wraps: TLS_FEATURE_free
#[allow(non_snake_case)]
pub fn TLS_FEATURE_free(value: TlsFeature) {
    drop(value);
}

/// Wraps: TLS_FEATURE_new
#[must_use]
#[allow(non_snake_case)]
pub fn TLS_FEATURE_new() -> Option<TlsFeature> {
    // SAFETY: a non-null result is a fresh complete generated stack with one
    // matching full-destructor obligation.
    unsafe { CBoxWith::from_raw(ffi::TLS_FEATURE_new().cast(), TlsFeatureFree) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = TLS_FEATURE_new().expect("TLS_FEATURE_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        TLS_FEATURE_free(value);
    }
}

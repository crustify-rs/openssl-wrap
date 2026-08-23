//! Wrappers assigned from `crypto/x509/v3_extku.c`.

use core::ptr::NonNull;

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1ObjectStack;

/// Full ASN.1 teardown policy for an extended-key-usage sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtendedKeyUsageFree;

// SAFETY: the generated destructor releases every owned ASN1_OBJECT and the
// generated stack exactly once.
unsafe impl CDropper<Asn1ObjectStack> for ExtendedKeyUsageFree {
    unsafe fn c_drop(&self, object: NonNull<Asn1ObjectStack>) {
        // SAFETY: the dropper contract supplies the sole complete stack owner.
        unsafe { ffi::EXTENDED_KEY_USAGE_free(object.as_ptr().cast()) }
    }
}

/// An extended-key-usage sequence that owns all object identifiers.
pub type ExtendedKeyUsage = CBoxWith<Asn1ObjectStack, ExtendedKeyUsageFree>;

/// Wraps: EXTENDED_KEY_USAGE_free
#[allow(non_snake_case)]
pub fn EXTENDED_KEY_USAGE_free(value: ExtendedKeyUsage) {
    drop(value);
}

/// Wraps: EXTENDED_KEY_USAGE_new
#[must_use]
#[allow(non_snake_case)]
pub fn EXTENDED_KEY_USAGE_new() -> Option<ExtendedKeyUsage> {
    // SAFETY: a non-null result is a fresh complete generated stack with one
    // matching full-destructor obligation.
    unsafe { CBoxWith::from_raw(ffi::EXTENDED_KEY_USAGE_new().cast(), ExtendedKeyUsageFree) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = EXTENDED_KEY_USAGE_new().expect("EXTENDED_KEY_USAGE_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        EXTENDED_KEY_USAGE_free(value);
    }
}

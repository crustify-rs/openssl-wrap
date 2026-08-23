//! Wrappers assigned from `crypto/x509/v3_genn.c`.

use core::ptr::NonNull;

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::x509::x509_internal::GeneralNameStack;

/// Full ASN.1 teardown policy for a general-names sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct GeneralNamesFree;

// SAFETY: the generated destructor releases every owned GENERAL_NAME and the
// generated stack exactly once.
unsafe impl CDropper<GeneralNameStack> for GeneralNamesFree {
    unsafe fn c_drop(&self, object: NonNull<GeneralNameStack>) {
        // SAFETY: the dropper contract supplies the sole complete stack owner.
        unsafe { ffi::GENERAL_NAMES_free(object.as_ptr().cast()) }
    }
}

/// A general-names sequence that owns all its elements.
pub type GeneralNames = CBoxWith<GeneralNameStack, GeneralNamesFree>;

/// Wraps: GENERAL_NAMES_free
#[allow(non_snake_case)]
pub fn GENERAL_NAMES_free(value: GeneralNames) {
    drop(value);
}

/// Wraps: GENERAL_NAMES_new
#[must_use]
#[allow(non_snake_case)]
pub fn GENERAL_NAMES_new() -> Option<GeneralNames> {
    // SAFETY: a non-null result is a fresh complete generated stack with one
    // matching full-destructor obligation.
    unsafe { CBoxWith::from_raw(ffi::GENERAL_NAMES_new().cast(), GeneralNamesFree) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = GENERAL_NAMES_new().expect("GENERAL_NAMES_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        GENERAL_NAMES_free(value);
    }
}

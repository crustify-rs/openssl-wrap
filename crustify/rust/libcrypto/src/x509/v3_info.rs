//! Wrappers assigned from `crypto/x509/v3_info.c`.

use core::ptr::NonNull;

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::x509::x509v3::AccessDescriptionStack;

/// Selects the ASN.1 full destructor for an authority-information-access
/// sequence, including every access-description element.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorityInfoAccessFree;

// SAFETY: the generated destructor accepts a fully initialized stack, releases
// every owned access-description element, and finally releases the stack.
unsafe impl CDropper<AccessDescriptionStack> for AuthorityInfoAccessFree {
    unsafe fn c_drop(&self, object: NonNull<AccessDescriptionStack>) {
        // SAFETY: the dropper contract supplies sole ownership of a complete
        // value and the generated stack erases to `OPENSSL_STACK`.
        unsafe { ffi::AUTHORITY_INFO_ACCESS_free(object.as_ptr().cast()) }
    }
}

/// An authority-information-access sequence that owns all its elements.
pub type AuthorityInfoAccess = CBoxWith<AccessDescriptionStack, AuthorityInfoAccessFree>;

/// Wraps: AUTHORITY_INFO_ACCESS_free
/// Consumes a complete authority-information-access sequence.
#[allow(non_snake_case)]
pub fn AUTHORITY_INFO_ACCESS_free(value: AuthorityInfoAccess) {
    drop(value);
}

/// Wraps: AUTHORITY_INFO_ACCESS_new
/// Allocates an empty authority-information-access sequence.
#[must_use]
#[allow(non_snake_case)]
pub fn AUTHORITY_INFO_ACCESS_new() -> Option<AuthorityInfoAccess> {
    // SAFETY: a non-null result is a fresh complete generated stack carrying
    // exactly one matching full-destructor obligation.
    unsafe {
        CBoxWith::from_raw(
            ffi::AUTHORITY_INFO_ACCESS_new().cast(),
            AuthorityInfoAccessFree,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = AUTHORITY_INFO_ACCESS_new().expect("AUTHORITY_INFO_ACCESS_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        AUTHORITY_INFO_ACCESS_free(value);
    }
}

//! Wrappers assigned from `crypto/x509/v3_info.c`.

use core::ptr::NonNull;

use ffibox::{CBox, CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::x509::x509v3::{AccessDescription, AccessDescriptionStack};

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

/// Wraps: ACCESS_DESCRIPTION_free
/// Consumes an optional complete access-description allocation.
#[allow(non_snake_case)]
pub fn ACCESS_DESCRIPTION_free(value: Option<CBox<AccessDescription>>) {
    drop(value);
}

/// Wraps: ACCESS_DESCRIPTION_new
/// Allocates a fully initialized access-description sequence.
#[must_use]
#[allow(non_snake_case)]
pub fn ACCESS_DESCRIPTION_new() -> Option<CBox<AccessDescription>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 sequence whose
    // matching destructor is registered on `AccessDescription`.
    unsafe { CBox::from_raw(ffi::ACCESS_DESCRIPTION_new()) }
}

#[cfg(test)]
mod access_description_tests {
    use super::*;

    #[test]
    fn constructor_and_nullable_destructor_preserve_ownership() {
        let value = ACCESS_DESCRIPTION_new().expect("ACCESS_DESCRIPTION_new");
        assert!(value.as_ref().method().is_some());
        assert!(value.as_ref().location().is_some());
        ACCESS_DESCRIPTION_free(Some(value));
        ACCESS_DESCRIPTION_free(None);
    }
}

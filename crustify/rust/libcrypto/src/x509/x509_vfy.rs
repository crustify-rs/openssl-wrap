//! Wrappers assigned from `include/openssl/x509_vfy.h`.

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Opaque element marker for the `POLICYQUALINFO` records stored in this
/// stack.
///
/// The concrete record has separate authored type-route work. Until that
/// wrapper is available, this unconstructible marker retains the generated
/// stack's element type without exposing or dereferencing its layout.
#[repr(C)]
pub struct PolicyQualInfo {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_POLICYQUALINFO
///
/// Typed view of OpenSSL's `STACK_OF(POLICYQUALINFO)`. `DEFINE_STACK_OF`
/// forward-declares the generated tag and casts every operation to
/// `OPENSSL_STACK *`, so this alias preserves the qualifier element type over
/// the generic container.
///
/// A plain stack owns its pointer array, not the qualifier records. Element
/// ownership can instead be selected explicitly with [`Stack::into_pop_free`].
pub type PolicyQualInfoStack = Stack<PolicyQualInfo>;

/// Shared borrowed handle to a `STACK_OF(POLICYQUALINFO)`.
pub type PolicyQualInfoStackRef<'a> = StackRef<'a, PolicyQualInfo>;

/// Exclusive borrowed handle to a `STACK_OF(POLICYQUALINFO)`.
pub type PolicyQualInfoStackMut<'a> = StackMut<'a, PolicyQualInfo>;

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::stack::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num};

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn policy_qualifier_stack_produces_typed_borrows() {
        assert_owned_cloneable_cell::<PolicyQualInfoStack>();
        assert_eq!(
            size_of::<CBox<PolicyQualInfoStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<PolicyQualInfoStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<PolicyQualInfoStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack: CBox<PolicyQualInfoStack> =
            OPENSSL_sk_new_null().expect("POLICYQUALINFO stack");
        let raw = stack.as_ptr();
        let shared: PolicyQualInfoStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let exclusive: PolicyQualInfoStackMut<'_> = stack.as_mut();
        assert_eq!(OPENSSL_sk_num(Some(exclusive.as_ref())), Some(0));
    }
}

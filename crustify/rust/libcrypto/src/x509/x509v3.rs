//! Wrappers assigned from `include/openssl/x509v3.h`.

use core::ptr::NonNull;

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Opaque element marker for the `GENERAL_SUBTREE` records stored in this
/// stack.
///
/// `GENERAL_SUBTREE` has its own authored item and is outside this worklist.
/// Until that layout wrapper is available, this unconstructible marker keeps
/// the generated stack typed without exposing or dereferencing the record.
/// Replace it with the element wrapper when `GENERAL_SUBTREE_st` is filled.
#[repr(C)]
pub struct GeneralSubtree {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_GENERAL_SUBTREE
///
/// Typed view of OpenSSL's `STACK_OF(GENERAL_SUBTREE)`. The generated C tag is
/// only a forward declaration and every operation erases it to the common
/// `OPENSSL_STACK *`, so this is the generic container with its subtree
/// element type retained.
///
/// The plain owner releases only the stack and its pointer array. Element
/// ownership must be selected explicitly through the generic stack's
/// pop-free policy.
pub type GeneralSubtreeStack = Stack<GeneralSubtree>;

/// Shared borrowed handle to a `STACK_OF(GENERAL_SUBTREE)`.
pub type GeneralSubtreeStackRef<'a> = StackRef<'a, GeneralSubtree>;

/// Exclusive borrowed handle to a `STACK_OF(GENERAL_SUBTREE)`.
pub type GeneralSubtreeStackMut<'a> = StackMut<'a, GeneralSubtree>;

/// Opaque element marker for the `ACCESS_DESCRIPTION` records stored in this
/// stack.
///
/// The element record has its own public definition and lifecycle, but that
/// higher-layer type is not part of this worklist. Until its wrapper is
/// available, this unconstructible marker retains the generated stack's
/// element type without exposing or dereferencing an element layout.
#[repr(C)]
pub struct AccessDescription {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_ACCESS_DESCRIPTION
///
/// Typed view of OpenSSL's `STACK_OF(ACCESS_DESCRIPTION)`. The generated C tag
/// is a forward declaration and every stack operation erases it to the common
/// `OPENSSL_STACK *` representation, so this is the generic container with its
/// element type retained.
///
/// A plain [`ffibox::CBox<AccessDescriptionStack>`] owns only the stack and its
/// pointer array. [`AuthorityInfoAccess`] additionally owns every stored
/// access description and uses the ASN.1 full destructor.
pub type AccessDescriptionStack = Stack<AccessDescription>;

/// Shared borrowed handle to a `STACK_OF(ACCESS_DESCRIPTION)`.
pub type AccessDescriptionStackRef<'a> = StackRef<'a, AccessDescription>;

/// Exclusive borrowed handle to a `STACK_OF(ACCESS_DESCRIPTION)`.
pub type AccessDescriptionStackMut<'a> = StackMut<'a, AccessDescription>;

/// Selects the ASN.1 full destructor for an authority-information-access
/// sequence, including every `ACCESS_DESCRIPTION` element.
#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorityInfoAccessFree;

// SAFETY: `AUTHORITY_INFO_ACCESS_free` accepts a fully initialized generated
// stack, releases every owned access-description element, and finally releases
// the common stack allocation.
unsafe impl CDropper<AccessDescriptionStack> for AuthorityInfoAccessFree {
    unsafe fn c_drop(&self, object: NonNull<AccessDescriptionStack>) {
        // SAFETY: the `CDropper` contract supplies sole ownership of a complete
        // authority-info-access value. Its generated stack tag and
        // `OPENSSL_STACK` have the same pointer representation.
        unsafe { ffi::AUTHORITY_INFO_ACCESS_free(object.as_ptr().cast()) }
    }
}

/// Owning authority-information-access sequence whose elements are released
/// together with its generated stack.
pub type AuthorityInfoAccess = CBoxWith<AccessDescriptionStack, AuthorityInfoAccessFree>;

impl AccessDescriptionStack {
    /// Allocates a complete empty authority-information-access sequence.
    #[must_use]
    pub fn new_authority_info_access() -> Option<AuthorityInfoAccess> {
        // SAFETY: a non-null ASN.1 constructor result is a fresh, fully
        // initialized generated stack carrying one
        // `AUTHORITY_INFO_ACCESS_free` obligation.
        unsafe {
            CBoxWith::from_raw(
                ffi::AUTHORITY_INFO_ACCESS_new().cast(),
                AuthorityInfoAccessFree,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, StackElement,
    };

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn generated_subtree_stack_uses_the_typed_erased_container() {
        assert_owned_cloneable_cell::<GeneralSubtreeStack>();
        assert_eq!(
            size_of::<CBox<GeneralSubtreeStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<GeneralSubtreeStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<GeneralSubtreeStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<GeneralSubtree>().expect("subtree stack");
        let raw = stack.as_ptr();
        assert_eq!(stack.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(stack.as_mut().as_mut_ptr(), raw);
    }

    #[test]
    fn subtree_stack_preserves_borrowed_element_addresses() {
        let subtree_storage = Box::new(0x5a_u8);
        // SAFETY: the stable box address outlives both stacks. With no
        // comparator installed, the container only moves this opaque address
        // between slots and never dereferences it.
        let element = unsafe {
            StackElement::from_raw(
                ptr::from_ref(&*subtree_storage)
                    .cast_mut()
                    .cast::<GeneralSubtree>(),
            )
        }
        .expect("non-null subtree address");

        let mut stack = OPENSSL_sk_new_null::<GeneralSubtree>().expect("subtree stack");
        assert_eq!(
            // SAFETY: the stable stand-in allocation remains live through
            // every stack use and no callback can inspect the marker.
            unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) },
            Some(1)
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );

        // Cloning duplicates the pointer array and deliberately shares the
        // borrowed element address.
        let duplicate = stack.try_clone().expect("duplicate subtree stack");
        assert_eq!(
            OPENSSL_sk_value(Some(duplicate.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );
        drop(duplicate);
        drop(stack);
        assert_eq!(*subtree_storage, 0x5a);
    }

    #[test]
    fn generated_access_stack_keeps_its_typed_erased_surface() {
        assert_owned_cloneable_cell::<AccessDescriptionStack>();
        assert_eq!(
            size_of::<CBox<AccessDescriptionStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<AccessDescriptionStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<AccessDescriptionStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<AccessDescription>().expect("access stack");
        let raw = stack.as_ptr();
        assert_eq!(stack.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(stack.as_mut().as_mut_ptr(), raw);
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(0));
    }

    #[test]
    fn authority_owner_preserves_the_full_drop_policy() {
        let mut access =
            AccessDescriptionStack::new_authority_info_access().expect("AUTHORITY_INFO_ACCESS_new");
        let raw = access.as_ptr();
        assert_eq!(access.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(access.as_mut().as_mut_ptr(), raw);
        assert_eq!(OPENSSL_sk_num(Some(access.as_ref())), Some(0));
        assert_eq!(
            size_of::<AuthorityInfoAccess>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }
}

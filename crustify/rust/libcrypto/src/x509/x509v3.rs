//! Wrappers assigned from `include/openssl/x509v3.h`.

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
}

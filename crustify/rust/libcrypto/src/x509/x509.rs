//! Wrappers assigned from `include/openssl/x509.h`.

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Opaque element marker for the `X509_EXTENSION` records stored in this
/// stack.
///
/// The element type has its own authored home and is not part of this
/// worklist. Until that wrapper is available, this unconstructible marker
/// retains the generated stack's element type without exposing or
/// dereferencing an extension layout. The stack itself owns only its pointer
/// array; element ownership must be selected explicitly with the generic
/// stack's pop-free policy.
#[repr(C)]
pub struct X509Extension {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_X509_EXTENSION
///
/// Typed view of OpenSSL's `STACK_OF(X509_EXTENSION)`. The generated C tag is
/// only a forward declaration and every operation erases it to
/// `OPENSSL_STACK *`, so this is the generic container with its extension
/// element type retained.
pub type X509ExtensionStack = Stack<X509Extension>;

/// Shared borrowed handle to a `STACK_OF(X509_EXTENSION)`.
pub type X509ExtensionStackRef<'a> = StackRef<'a, X509Extension>;

/// Exclusive borrowed handle to a `STACK_OF(X509_EXTENSION)`.
pub type X509ExtensionStackMut<'a> = StackMut<'a, X509Extension>;

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
    fn extension_stack_keeps_its_typed_erased_surface() {
        assert_owned_cloneable_cell::<X509ExtensionStack>();
        assert_eq!(
            size_of::<CBox<X509ExtensionStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<X509ExtensionStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<X509ExtensionStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<X509Extension>().expect("extension stack");
        let raw = stack.as_ptr();
        let shared: X509ExtensionStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: X509ExtensionStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
    }

    #[test]
    fn extension_stack_preserves_borrowed_element_addresses() {
        let extension_storage = Box::new(0x5a_u8);
        // SAFETY: the stable box address outlives the stack, which only moves
        // the opaque address between slots and never dereferences the marker.
        let element = unsafe {
            StackElement::from_raw(
                ptr::from_ref(&*extension_storage)
                    .cast_mut()
                    .cast::<X509Extension>(),
            )
        }
        .expect("non-null extension address");

        let mut stack = OPENSSL_sk_new_null::<X509Extension>().expect("extension stack");
        // SAFETY: `extension_storage` remains live through the final stack use,
        // and this stack has no comparator that could inspect the marker.
        assert_eq!(
            // SAFETY: the stable storage is valid for the retained borrow.
            unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) },
            Some(1)
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );

        // Plain stack destruction releases only the pointer array.
        drop(stack);
        assert_eq!(*extension_storage, 0x5a);
    }
}

//! Wrappers assigned from `crypto/objects/obj_xref.h`.

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Stand-in for the `nid_triple` records this stack points at.
///
/// `nid_triple` is defined in the generated private header `obj_xref.h` and
/// has no wrapper in this campaign, so the stack names its element type
/// without publishing a layout for it. The marker is zero-sized and has no
/// public constructor: only the address of a C `nid_triple` is ever given
/// this type, at an FFI seam, and the stack never dereferences it. Replace it
/// with the element wrapper once `nid_triple` is homed.
#[repr(C)]
pub struct NidTriple {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_nid_triple
///
/// Typed view of OpenSSL's `STACK_OF(nid_triple)`. `DEFINE_STACK_OF` only
/// forward-declares the tag and casts every operation to `OPENSSL_STACK *`,
/// so the instance is the generic container with its element type retained.
pub type NidTripleStack = Stack<NidTriple>;

/// Shared borrowed handle to a `STACK_OF(nid_triple)`.
pub type NidTripleStackRef<'a> = StackRef<'a, NidTriple>;

/// Exclusive borrowed handle to a `STACK_OF(nid_triple)`.
pub type NidTripleStackMut<'a> = StackMut<'a, NidTriple>;

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::CBox;
    use libcrypto_sys as ffi;

    use super::*;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop, OPENSSL_sk_push, OPENSSL_sk_value,
        StackElement,
    };

    #[test]
    fn concrete_stack_produces_typed_borrows() {
        // `OPENSSL_sk_dup(NULL)` constructs an empty stack in this OpenSSL
        // implementation.
        // SAFETY: the returned allocation is complete and ownership transfers
        // to `CBox`, whose generic stack destructor calls `OPENSSL_sk_free`.
        let mut stack =
            unsafe { CBox::<NidTripleStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
                .expect("allocate nid_triple stack");
        let raw = stack.as_ptr();

        let shared: NidTripleStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: NidTripleStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());

        // Both the owner and the handles are one pointer wide: the generated
        // tag adds nothing to `OPENSSL_STACK`'s representation.
        assert_eq!(
            size_of::<CBox<NidTripleStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<NidTripleStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<NidTripleStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn typed_stack_stores_element_addresses_and_never_owns_them() {
        // The marker types an address, so stand-in storage is enough to prove
        // that the pointer slots survive the container round trip untouched.
        let first = Box::new(0xA5_u8);
        let second = Box::new(0x5A_u8);
        // SAFETY: each address is stable for the whole test and the stack only
        // moves the pointer between slots; nothing dereferences the marker.
        let first_element = unsafe {
            StackElement::from_raw(ptr::from_ref(&*first).cast_mut().cast::<NidTriple>())
        }
        .expect("non-null element address");
        // SAFETY: as above, for the second stand-in record.
        let second_element = unsafe {
            StackElement::from_raw(ptr::from_ref(&*second).cast_mut().cast::<NidTriple>())
        }
        .expect("non-null element address");

        let mut stack = OPENSSL_sk_new_null::<NidTriple>().expect("allocate nid_triple stack");
        {
            let mut exclusive = stack.as_mut();
            // SAFETY: both boxes outlive the stack and the container has no
            // comparator that could dereference them.
            unsafe {
                assert_eq!(
                    OPENSSL_sk_push(Some(&mut exclusive), Some(first_element)),
                    Some(1)
                );
                assert_eq!(
                    OPENSSL_sk_push(Some(&mut exclusive), Some(second_element)),
                    Some(2)
                );
            }
        }
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(2));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0).map(StackElement::as_non_null),
            Some(first_element.as_non_null())
        );

        // `OPENSSL_sk_dup` shares the element pointers with the original.
        let duplicate = stack.try_clone().expect("duplicate nid_triple stack");
        assert_ne!(duplicate.as_ptr(), stack.as_ptr());
        assert_eq!(
            OPENSSL_sk_value(Some(duplicate.as_ref()), 1).map(StackElement::as_non_null),
            Some(second_element.as_non_null())
        );

        assert_eq!(
            OPENSSL_sk_pop(Some(&mut stack.as_mut())).map(StackElement::as_non_null),
            Some(second_element.as_non_null())
        );

        // Dropping both containers runs `OPENSSL_sk_free`, which releases the
        // pointer arrays only; the elements are still ours to read and free.
        drop(duplicate);
        drop(stack);
        assert_eq!(*first, 0xA5);
        assert_eq!(*second, 0x5A);
    }
}

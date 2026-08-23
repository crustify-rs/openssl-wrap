//! Wrappers assigned from `include/openssl/safestack.h`.

use core::ffi::c_char;

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Wraps: stack_st_OPENSSL_STRING
///
/// Typed view of OpenSSL's special `STACK_OF(OPENSSL_STRING)`. The generated
/// macros define its real element type as `char`, because every stored pointer
/// addresses the first byte of a NUL-terminated character array, and erase the
/// generated stack tag to the common `OPENSSL_STACK *` implementation.
///
/// A plain owner releases only the stack and its pointer array; it borrows the
/// strings. A stack that owns its strings instead uses the generic stack's
/// pop-free policy with the allocator-matched string destructor.
pub type OpenSslStringStack = Stack<c_char>;

/// Shared borrowed handle to a `STACK_OF(OPENSSL_STRING)`.
pub type OpenSslStringStackRef<'a> = StackRef<'a, c_char>;

/// Exclusive borrowed handle to a `STACK_OF(OPENSSL_STRING)`.
pub type OpenSslStringStackMut<'a> = StackMut<'a, c_char>;

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use std::ffi::{CStr, CString};

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, StackElement,
    };

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn special_string_stack_keeps_the_erased_c_layout() {
        assert_owned_cloneable_cell::<OpenSslStringStack>();
        assert_eq!(
            size_of::<CBox<OpenSslStringStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<OpenSslStringStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<OpenSslStringStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        let mut stack = OPENSSL_sk_new_null::<c_char>().expect("string stack");
        let raw = stack.as_ptr();
        assert_eq!(stack.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(stack.as_mut().as_mut_ptr(), raw);
    }

    #[test]
    fn plain_string_stack_borrows_nul_terminated_elements() {
        let string = CString::new("borrowed string").expect("no interior NUL");
        // SAFETY: the CString has a stable non-null address and outlives both
        // stacks. With no comparator installed, no stack callback reads or
        // writes its character array.
        let element = unsafe { StackElement::from_raw(string.as_ptr().cast_mut()) }
            .expect("CString pointer is non-null");

        let mut stack = OPENSSL_sk_new_null::<c_char>().expect("string stack");
        assert_eq!(
            // SAFETY: the stable CString remains live and immutable through
            // every stack use; the stack only retains and moves its address.
            unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) },
            Some(1)
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        let stored = OPENSSL_sk_value(Some(stack.as_ref()), 0).expect("stored string");
        assert_eq!(stored.as_non_null(), element.as_non_null());
        assert_eq!(
            // SAFETY: the token is the unchanged live CString pointer and
            // therefore has a readable NUL terminator.
            unsafe { CStr::from_ptr(stored.as_non_null().as_ptr()) },
            string.as_c_str()
        );

        // A plain duplicate shares the borrowed strings while owning a new
        // pointer array.
        let duplicate = stack.try_clone().expect("duplicate string stack");
        assert_eq!(
            OPENSSL_sk_value(Some(duplicate.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );
        drop(duplicate);
        drop(stack);
        assert_eq!(string.as_c_str().to_bytes(), b"borrowed string");
    }
}

//! Wrappers assigned from `crypto/objects/obj_xref.h`.

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Type-level identity for the `nid_triple` pointers stored in this stack.
///
/// The stack wrapper keeps its elements opaque, so no Rust value of this type
/// is ever constructed or referenced.
pub enum NidTripleStackElement {}

/// Wraps: stack_st_nid_triple
/// A typed view of OpenSSL's erased `STACK_OF(nid_triple)` representation.
pub type NidTripleStack = Stack<NidTripleStackElement>;

/// Shared borrowed handle to a `STACK_OF(nid_triple)`.
pub type NidTripleStackRef<'a> = StackRef<'a, NidTripleStackElement>;

/// Exclusive borrowed handle to a `STACK_OF(nid_triple)`.
pub type NidTripleStackMut<'a> = StackMut<'a, NidTripleStackElement>;

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::CBox;
    use libcrypto_sys as ffi;

    use super::*;

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
    }
}

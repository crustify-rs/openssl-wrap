//! Wrappers assigned from `include/openssl/crypto.h`.

use core::ffi::c_void;

use crate::stack::stack::{Stack, StackMut, StackRef};

/// Wraps: stack_st_void
/// Type-erased instance of OpenSSL's generic stack representation.
pub type VoidStack = Stack<c_void>;

/// Shared borrowed handle to a type-erased OpenSSL stack.
pub type VoidStackRef<'a> = StackRef<'a, c_void>;

/// Exclusive borrowed handle to a type-erased OpenSSL stack.
pub type VoidStackMut<'a> = StackMut<'a, c_void>;

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn void_stack_uses_the_generic_stack_representation() {
        assert_owned_cloneable_cell::<VoidStack>();
        assert_eq!(
            core::mem::size_of::<VoidStack>(),
            core::mem::size_of::<ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::align_of::<VoidStack>(),
            core::mem::align_of::<ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<CBox<VoidStack>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<VoidStackRef<'static>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<VoidStackMut<'static>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn void_stack_owner_produces_void_stack_handles() {
        // `OPENSSL_sk_dup(NULL)` returns a new empty container. Ownership is
        // transferred to `CBox`, whose generic stack strategy frees it.
        // SAFETY: the returned pointer is null or a fully initialized,
        // uniquely owned `OPENSSL_STACK` allocation.
        let mut stack = unsafe { CBox::<VoidStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
            .expect("allocate empty OpenSSL stack");
        let raw = stack.as_ptr();

        let shared: VoidStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: VoidStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
    }
}

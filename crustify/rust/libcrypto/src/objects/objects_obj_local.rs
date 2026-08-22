//! Wrappers assigned from `crypto/objects/obj_local.h`.

use crate::bio::openssl_lhash::{LHash, LHashMut, LHashRef};
use crate::objects::openssl_objects::ObjName;
use crate::stack::stack::{Stack, StackMut, StackRef};

/// Type-level identity for the `NAME_FUNCS` pointers stored in this stack.
///
/// The stack wrapper keeps its elements opaque, so no Rust value of this type
/// is ever constructed or referenced.
pub enum NameFuncsStackElement {}

/// Wraps: stack_st_NAME_FUNCS
/// A typed view of OpenSSL's erased `STACK_OF(NAME_FUNCS)` representation.
pub type NameFuncsStack = Stack<NameFuncsStackElement>;

/// Shared borrowed handle to a `STACK_OF(NAME_FUNCS)`.
pub type NameFuncsStackRef<'a> = StackRef<'a, NameFuncsStackElement>;

/// Exclusive borrowed handle to a `STACK_OF(NAME_FUNCS)`.
pub type NameFuncsStackMut<'a> = StackMut<'a, NameFuncsStackElement>;

/// Wraps: lhash_st_OBJ_NAME
///
/// Typed view of OpenSSL's `LHASH_OF(OBJ_NAME)`. The generated C type erases
/// to the common `OPENSSL_LHASH` representation; this alias retains the
/// element type without exposing the macro's dummy layout.
pub type ObjNameLHash = LHash<ObjName>;

/// Shared borrowed handle to an `LHASH_OF(OBJ_NAME)`.
pub type ObjNameLHashRef<'a> = LHashRef<'a, ObjName>;

/// Exclusive borrowed handle to an `LHASH_OF(OBJ_NAME)`.
pub type ObjNameLHashMut<'a> = LHashMut<'a, ObjName>;

#[cfg(test)]
mod tests {
    use core::{mem::size_of, ptr};

    use ffibox::{CBox, CCell, CDropped};
    use libcrypto_sys as ffi;

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn concrete_stack_produces_typed_borrows() {
        // `OPENSSL_sk_dup(NULL)` constructs an empty stack in this OpenSSL
        // implementation.
        // SAFETY: the returned allocation is complete and ownership transfers
        // to `CBox`, whose generic stack destructor calls `OPENSSL_sk_free`.
        let mut stack =
            unsafe { CBox::<NameFuncsStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
                .expect("allocate NAME_FUNCS stack");
        let raw = stack.as_ptr();

        let shared: NameFuncsStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: NameFuncsStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
    }

    #[test]
    fn obj_name_lhash_keeps_its_typed_erased_surface() {
        assert_owned_cell::<ObjNameLHash>();
        assert_eq!(size_of::<ObjNameLHash>(), size_of::<ffi::OPENSSL_LHASH>());
        assert_eq!(
            size_of::<CBox<ObjNameLHash>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<ObjNameLHashRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<ObjNameLHashMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
    }
}

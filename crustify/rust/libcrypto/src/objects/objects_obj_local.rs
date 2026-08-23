//! Wrappers assigned from `crypto/objects/obj_local.h`.

use crate::bio::openssl_lhash::{LHash, LHashMut, LHashRef};
use crate::objects::openssl_objects::ObjName;
use crate::stack::stack::{Stack, StackMut, StackRef};

/// Stand-in for the `NAME_FUNCS` records this stack points at.
///
/// `name_funcs_st` is defined in this private header and has no wrapper in
/// the campaign, so the stack names its element type without publishing a
/// layout for it. The marker is zero-sized and has no public constructor:
/// only the address of a C `NAME_FUNCS` is ever given this type, at an FFI
/// seam, and the stack never dereferences it. Replace it with the element
/// wrapper once `name_funcs_st` is homed.
#[repr(C)]
pub struct NameFuncs {
    _opaque: [u8; 0],
}

/// Wraps: stack_st_NAME_FUNCS
///
/// Typed view of OpenSSL's `STACK_OF(NAME_FUNCS)`. `DEFINE_STACK_OF` only
/// forward-declares the tag and casts every operation to `OPENSSL_STACK *`,
/// so the instance is the generic container with its element type retained.
pub type NameFuncsStack = Stack<NameFuncs>;

/// Shared borrowed handle to a `STACK_OF(NAME_FUNCS)`.
pub type NameFuncsStackRef<'a> = StackRef<'a, NameFuncs>;

/// Exclusive borrowed handle to a `STACK_OF(NAME_FUNCS)`.
pub type NameFuncsStackMut<'a> = StackMut<'a, NameFuncs>;

/// Wraps: lhash_st_OBJ_NAME
///
/// Typed view of OpenSSL's `LHASH_OF(OBJ_NAME)`. `DEFINE_LHASH_OF_EX` gives
/// the generated tag a dummy union body and casts every operation to
/// `OPENSSL_LHASH *`, so the instance is the generic table with its element
/// type retained and none of that dummy layout exposed. The table owns its
/// nodes; the `OBJ_NAME` records stay with whoever inserted them.
pub type ObjNameLHash = LHash<ObjName>;

/// Shared borrowed handle to an `LHASH_OF(OBJ_NAME)`.
pub type ObjNameLHashRef<'a> = LHashRef<'a, ObjName>;

/// Exclusive borrowed handle to an `LHASH_OF(OBJ_NAME)`.
pub type ObjNameLHashMut<'a> = LHashMut<'a, ObjName>;

#[cfg(test)]
mod tests {
    use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
    use core::ptr;

    use ffibox::{CBox, CCell, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, StackElement,
    };

    fn assert_owned_cell<T: CCell + CDropped>() {}

    /// Hashes an `OBJ_NAME` record by its type, as `OBJ_NAME_add` needs the
    /// table to distinguish classes.
    unsafe extern "C" fn hash_obj_name(data: *const c_void) -> c_ulong {
        // SAFETY: this table only ever receives the records inserted below.
        let entry = unsafe { data.cast::<ffi::OBJ_NAME>().read() };
        entry.type_ as c_ulong
    }

    unsafe extern "C" fn compare_obj_name(left: *const c_void, right: *const c_void) -> c_int {
        // SAFETY: as `hash_obj_name`; both operands are inserted records.
        let (left, right) = unsafe {
            (
                left.cast::<ffi::OBJ_NAME>().read(),
                right.cast::<ffi::OBJ_NAME>().read(),
            )
        };
        left.type_ - right.type_
    }

    fn record(kind: c_int, name: &'static CStr, data: &'static CStr) -> ffi::OBJ_NAME {
        ffi::OBJ_NAME {
            type_: kind,
            alias: 0,
            name: name.as_ptr().cast::<c_char>(),
            data: data.as_ptr().cast::<c_char>(),
        }
    }

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
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());

        // Both the owner and the handles are one pointer wide: the generated
        // tag adds nothing to `OPENSSL_STACK`'s representation.
        assert_eq!(
            size_of::<CBox<NameFuncsStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<NameFuncsStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<NameFuncsStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn typed_stack_stores_element_addresses_and_never_owns_them() {
        // The marker types an address, so stand-in storage is enough to prove
        // that the pointer slots survive the container round trip untouched.
        let entry = Box::new(0x3C_u8);
        // SAFETY: the box outlives the stack and the container only moves its
        // address between pointer slots; nothing dereferences the marker.
        let element = unsafe {
            StackElement::from_raw(ptr::from_ref(&*entry).cast_mut().cast::<NameFuncs>())
        }
        .expect("non-null element address");

        let mut stack = OPENSSL_sk_new_null::<NameFuncs>().expect("allocate NAME_FUNCS stack");
        {
            let mut exclusive = stack.as_mut();
            // SAFETY: the box outlives the stack and no comparator is set.
            unsafe {
                assert_eq!(
                    OPENSSL_sk_push(Some(&mut exclusive), Some(element)),
                    Some(1)
                );
            }
        }
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0).map(StackElement::as_non_null),
            Some(element.as_non_null())
        );

        // `OPENSSL_sk_free` releases the pointer array only.
        drop(stack);
        assert_eq!(*entry, 0x3C);
    }

    #[test]
    fn obj_name_lhash_keeps_its_typed_erased_surface() {
        assert_owned_cell::<ObjNameLHash>();
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

    #[test]
    fn obj_name_lhash_round_trips_records_through_the_erased_table() {
        // `lh_OBJ_NAME_new` is `OPENSSL_LH_new` plus the per-type thunks,
        // which only re-type the arguments the untyped path already passes.
        // SAFETY: a non-null result is a fresh table whose sole release
        // primitive is the `OPENSSL_LH_free` bound by `LHash`'s `CDropped`.
        let mut table = unsafe {
            CBox::<ObjNameLHash>::from_raw(ffi::OPENSSL_LH_new(
                Some(hash_obj_name),
                Some(compare_obj_name),
            ))
        }
        .expect("allocate LHASH_OF(OBJ_NAME)");

        let mut first = record(1, c"first", c"first-data");
        let mut second = record(2, c"second", c"second-data");
        {
            let mut exclusive: ObjNameLHashMut<'_> = table.as_mut();
            let raw = exclusive.as_mut_ptr();
            // SAFETY: `raw` is the live table and both records outlive it. A
            // null result means the key was not already present.
            unsafe {
                assert!(
                    ffi::OPENSSL_LH_insert(raw, ptr::addr_of_mut!(first).cast::<c_void>())
                        .is_null()
                );
                assert!(
                    ffi::OPENSSL_LH_insert(raw, ptr::addr_of_mut!(second).cast::<c_void>())
                        .is_null()
                );
            }
        }

        let shared: ObjNameLHashRef<'_> = table.as_ref();
        // SAFETY: the shared handle borrows the live table for this read.
        assert_eq!(unsafe { ffi::OPENSSL_LH_num_items(shared.as_ptr()) }, 2);

        // `OPENSSL_LH_free` releases the table's own nodes and nothing else,
        // so the inserted records stay valid afterwards.
        drop(table);
        assert_eq!(first.type_, 1);
        assert_eq!(second.type_, 2);
    }
}

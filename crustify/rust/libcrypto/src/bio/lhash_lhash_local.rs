//! Wrappers assigned from `crypto/lhash/lhash_local.h`.

/// Wraps: lhash_st
///
/// OpenSSL erases every generated `LHASH_OF(T)` to this common private
/// layout. The generic wrapper retains `T` only as a zero-sized marker, while
/// its borrowed handles and owner continue to address an `OPENSSL_LHASH`.
///
/// The layout's fields stay private because the public API exposes the table
/// as an opaque handle, and `libcrypto-sys` binds `lhash_st` from that
/// forward declaration alone. `LHash<T>` is therefore a handle-only wrapper:
/// it is reached through a pointer C allocated, and it is never embedded by
/// value in a `#[repr(C)]` mirror nor stack-allocated, which is why it exposes
/// no `zeroed` constructor and no field accessor.
///
/// Reviewed against `crypto/lhash/lhash.c`: `OPENSSL_LH_free` is the type's
/// only release primitive — it frees every node, the bucket array `b` and the
/// table itself, and deliberately leaves the `void *` payloads to their
/// owners, so [`ffibox::CDropped`] is the whole lifecycle contract. The
/// remaining fields are unreachable by construction: `b` is an owned bucket
/// array that `expand`/`contract` reallocate, `comp` and `hash` are borrowed
/// callbacks `OPENSSL_LH_new` defaults to non-null, and the four thunks stay
/// nullable until `OPENSSL_LH_set_thunks` installs them.
pub use super::openssl_lhash::{LHash, LHashMut, LHashRef};

#[cfg(test)]
mod tests {
    use core::ffi::{c_int, c_ulong, c_void};
    use core::mem::{align_of, size_of};
    use core::ptr::addr_of;

    use ffibox::{CBox, CCell, CDropped};
    use libcrypto_sys as ffi;

    use super::*;

    /// A stand-in element: the table stores the pointer, never the value.
    struct Entry {
        key: c_ulong,
    }

    unsafe extern "C" fn hash_entry(data: *const c_void) -> c_ulong {
        // SAFETY: the table is only ever given pointers to live `Entry`
        // values, and `OPENSSL_LH_*` hands each of them back unchanged.
        unsafe { addr_of!((*data.cast::<Entry>()).key).read() }
    }

    unsafe extern "C" fn compare_entries(left: *const c_void, right: *const c_void) -> c_int {
        // SAFETY: as `hash_entry`; both arguments address live `Entry` values.
        let left = unsafe { addr_of!((*left.cast::<Entry>()).key).read() };
        // SAFETY: as above.
        let right = unsafe { addr_of!((*right.cast::<Entry>()).key).read() };
        c_int::from(left != right)
    }

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn common_layout_reuses_the_typed_lhash_surface() {
        assert_owned_cell::<LHash<c_void>>();
        assert_eq!(size_of::<LHash<c_void>>(), size_of::<ffi::OPENSSL_LHASH>());
        assert_eq!(
            align_of::<LHash<c_void>>(),
            align_of::<ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<CBox<LHash<c_void>>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<LHashRef<'static, c_void>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<LHashMut<'static, c_void>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
    }

    #[test]
    fn owned_table_releases_its_nodes_and_leaves_the_elements_alone() {
        // SAFETY: both callbacks match the C signatures `OPENSSL_LH_new`
        // expects and only read the `Entry` values this test inserts.
        let created = unsafe { ffi::OPENSSL_LH_new(Some(hash_entry), Some(compare_entries)) };
        // SAFETY: `OPENSSL_LH_new` returns a fresh table this test uniquely
        // owns, released once by `OPENSSL_LH_free` when the `CBox` drops.
        let mut table: CBox<LHash<Entry>> =
            unsafe { CBox::from_raw(created) }.expect("OPENSSL_LH_new failed");

        // The elements stay Rust-owned; the table only records their pointers.
        // 64 distinct keys drive `expand` past its first reallocation of the
        // bucket array (it grows at 30 items), so the release path frees a
        // grown `b` rather than the one `OPENSSL_LH_new` allocated.
        let elements: Vec<*mut Entry> = (0..64)
            .map(|key| Box::into_raw(Box::new(Entry { key })))
            .collect();

        for &element in &elements {
            // SAFETY: the exclusive handle addresses the live table, and
            // `element` outlives every use the table makes of it below.
            let previous =
                unsafe { ffi::OPENSSL_LH_insert(table.as_mut().as_mut_ptr(), element.cast()) };
            assert!(
                previous.is_null(),
                "keys are distinct, so nothing is replaced"
            );
        }

        // The shared handle reads through a `*const` the exclusive one also
        // reaches by reborrowing.
        // SAFETY: the shared handle addresses the live table.
        let counted = unsafe { ffi::OPENSSL_LH_num_items(table.as_ref().as_ptr()) };
        assert_eq!(counted, elements.len() as c_ulong);
        // SAFETY: as above, through `LHashMut::as_ref`.
        let reborrowed = unsafe { ffi::OPENSSL_LH_num_items(table.as_mut().as_ref().as_ptr()) };
        assert_eq!(reborrowed, counted);

        // `OPENSSL_LH_free`: every node, the bucket array and the table.
        drop(table);

        // Still ours to reclaim. Had the table owned the payloads, this would
        // be a double free.
        for element in elements {
            // SAFETY: each pointer came from one `Box::into_raw` and was never
            // released by the table.
            drop(unsafe { Box::from_raw(element) });
        }
    }

    #[test]
    fn borrowed_handles_round_trip_the_erased_table_pointer() {
        // SAFETY: as in the owning test.
        let created = unsafe { ffi::OPENSSL_LH_new(Some(hash_entry), Some(compare_entries)) };
        // SAFETY: as in the owning test.
        let mut table: CBox<LHash<Entry>> =
            unsafe { CBox::from_raw(created) }.expect("OPENSSL_LH_new failed");

        let erased = table.as_mut().as_mut_ptr();
        // SAFETY: `erased` addresses the live table `table` owns for longer
        // than the handle borrowed here, and its element type is `Entry`.
        let borrowed = unsafe { LHashRef::<Entry>::from_ptr(erased) }.expect("non-null table");
        assert_eq!(borrowed.as_ptr().cast_mut(), erased);

        // SAFETY: as above, and `borrowed` is dead by the time this exclusive
        // handle is used.
        let mut exclusive = unsafe { LHashMut::<Entry>::from_ptr(erased) }.expect("non-null table");
        assert_eq!(exclusive.as_mut_ptr(), erased);
        // SAFETY: the reborrowed shared handle addresses the same live table.
        let empty = unsafe { ffi::OPENSSL_LH_num_items(exclusive.as_ref().as_ptr()) };
        assert_eq!(empty, 0);

        // SAFETY: a null pointer yields no handle rather than a dangling one.
        assert!(unsafe { LHashRef::<Entry>::from_ptr(core::ptr::null_mut()) }.is_none());
        // SAFETY: as above.
        assert!(unsafe { LHashMut::<Entry>::from_ptr(core::ptr::null_mut()) }.is_none());
    }
}

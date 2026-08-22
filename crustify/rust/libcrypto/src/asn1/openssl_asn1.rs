//! Wrappers assigned from `include/openssl/asn1.h`.

use core::ptr;

use ffibox::define_ctype;

use libcrypto_sys as ffi;

use crate::stack::stack::{Stack, StackMut, StackRef};

define_ctype!(
    /// Wraps: asn1_string_table_st
    Asn1StringTable,
    Asn1StringTableRef,
    Asn1StringTableMut,
    ffi::asn1_string_table_st
);

define_ctype!(
    /// Wraps: ASN1_VALUE_st
    ///
    /// OpenSSL deliberately leaves this tag undefined and uses its pointers as
    /// type-erased ASN.1 value handles. The borrowed handles therefore carry only
    /// pointer provenance and a Rust lifetime; they never expose a layout.
    Asn1Value,
    Asn1ValueRef,
    Asn1ValueMut,
    ffi::ASN1_VALUE_st
);

impl Asn1StringTableRef<'_> {
    /// Wraps: asn1_string_table_st.flags
    #[must_use]
    pub fn flags(&self) -> core::ffi::c_ulong {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).flags).read() }
    }

    /// Wraps: asn1_string_table_st.nid
    #[must_use]
    pub fn nid(&self) -> core::ffi::c_int {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).nid).read() }
    }

    /// Wraps: asn1_string_table_st.mask
    #[must_use]
    pub fn mask(&self) -> core::ffi::c_ulong {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).mask).read() }
    }

    /// Wraps: asn1_string_table_st.minsize
    #[must_use]
    pub fn min_size(&self) -> core::ffi::c_long {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).minsize).read() }
    }

    /// Wraps: asn1_string_table_st.maxsize
    #[must_use]
    pub fn max_size(&self) -> core::ffi::c_long {
        // SAFETY: this raw projection reads an initialized scalar field from
        // the live object represented by the shared handle.
        unsafe { ptr::addr_of!((*self.as_ptr()).maxsize).read() }
    }
}

impl Asn1StringTableMut<'_> {
    /// Set the table flags.
    pub fn set_flags(&mut self, flags: core::ffi::c_ulong) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).flags).write(flags) }
    }

    /// Set the numeric object identifier.
    pub fn set_nid(&mut self, nid: core::ffi::c_int) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).nid).write(nid) }
    }

    /// Set the permitted ASN.1 string type mask.
    pub fn set_mask(&mut self, mask: core::ffi::c_ulong) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).mask).write(mask) }
    }

    /// Set the minimum string size.
    pub fn set_min_size(&mut self, min_size: core::ffi::c_long) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).minsize).write(min_size) }
    }

    /// Set the maximum string size.
    pub fn set_max_size(&mut self, max_size: core::ffi::c_long) {
        // SAFETY: this raw projection writes the scalar field through the
        // exclusive handle without forming a reference to the C object.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).maxsize).write(max_size) }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;

    #[test]
    fn scalar_fields_round_trip_through_handles() {
        let mut value = Asn1StringTable::zeroed();
        let raw = ptr::addr_of_mut!(value).cast::<ffi::asn1_string_table_st>();
        // SAFETY: `raw` points to a live layout-compatible value and remains
        // exclusively borrowed for the lifetime of the returned handle.
        let mut view =
            unsafe { Asn1StringTableMut::from_ptr(raw) }.expect("stack ASN.1 string table");

        view.set_nid(7);
        view.set_min_size(8);
        view.set_max_size(64);
        view.set_mask(0x1234);
        view.set_flags(0x2);

        let shared = view.as_ref();
        assert_eq!(shared.nid(), 7);
        assert_eq!(shared.min_size(), 8);
        assert_eq!(shared.max_size(), 64);
        assert_eq!(shared.mask(), 0x1234);
        assert_eq!(shared.flags(), 0x2);
    }

    #[test]
    fn erased_value_borrows_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<Asn1ValueRef<'static>>(),
            core::mem::size_of::<*mut ffi::ASN1_VALUE_st>()
        );
        assert_eq!(
            core::mem::size_of::<Asn1ValueMut<'static>>(),
            core::mem::size_of::<*mut ffi::ASN1_VALUE_st>()
        );

        let mut storage = 0_u8;
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::ASN1_VALUE_st>();
        // SAFETY: the opaque ASN1_VALUE pointer denotes the live byte of
        // type-erased storage for the duration of this handle.
        let shared = unsafe { Asn1ValueRef::from_ptr(raw) }.expect("non-null value");
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let _ = shared;

        // SAFETY: the same live erased storage is now borrowed exclusively.
        let mut exclusive = unsafe { Asn1ValueMut::from_ptr(raw) }.expect("non-null value");
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());
    }
}

/// Wraps: stack_st_ASN1_STRING_TABLE
///
/// Typed view of OpenSSL's `STACK_OF(ASN1_STRING_TABLE)`. The generated C
/// type erases to the common `OPENSSL_STACK` representation while this alias
/// retains the element type.
pub type Asn1StringTableStack = Stack<Asn1StringTable>;

/// Shared borrowed handle to a `STACK_OF(ASN1_STRING_TABLE)`.
pub type Asn1StringTableStackRef<'a> = StackRef<'a, Asn1StringTable>;

/// Exclusive borrowed handle to a `STACK_OF(ASN1_STRING_TABLE)`.
pub type Asn1StringTableStackMut<'a> = StackMut<'a, Asn1StringTable>;

#[cfg(test)]
mod stack_tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::{CBox, CCell, CCloned, CDropped};

    use super::*;

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn string_table_stack_keeps_its_typed_erased_surface() {
        assert_owned_cloneable_cell::<Asn1StringTableStack>();
        assert_eq!(
            size_of::<Asn1StringTableStack>(),
            size_of::<ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<CBox<Asn1StringTableStack>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1StringTableStackRef<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            size_of::<Asn1StringTableStackMut<'static>>(),
            size_of::<*mut ffi::OPENSSL_STACK>()
        );

        // `OPENSSL_sk_dup(NULL)` creates a complete empty stack.
        // SAFETY: ownership of the returned allocation transfers to `CBox`,
        // whose generic stack destructor calls the matching `OPENSSL_sk_free`.
        let mut stack =
            unsafe { CBox::<Asn1StringTableStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
                .expect("allocate ASN1_STRING_TABLE stack");
        let raw = stack.as_ptr();

        let shared: Asn1StringTableStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: Asn1StringTableStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());

        let duplicate = stack.try_clone().expect("duplicate typed stack");
        assert_ne!(duplicate.as_ptr(), raw);
    }
}

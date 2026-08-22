//! Wrappers assigned from `include/openssl/asn1.h`.

use core::ptr;

use ffibox::define_ctype;

use libcrypto_sys as ffi;

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

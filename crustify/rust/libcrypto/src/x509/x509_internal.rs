//! Wrappers assigned from `include/crypto/x509.h`.

use ffibox::{define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: X509_name_st
    ///
    /// Pointer-compatible target for OpenSSL's distinguished-name object.
    /// Although the complete C layout lives in the private `crypto/x509.h`,
    /// the public API exposes `X509_NAME` only as an opaque handle. Its entry
    /// stack and cached encodings therefore remain behind OpenSSL's call
    /// surface rather than becoming Rust field accessors.
    ///
    /// An owning [`ffibox::CBox<X509Name>`] contains one complete name and
    /// releases its owned entries and encodings. Cloning performs the public
    /// ASN.1 deep duplication and creates an independent allocation.
    X509Name,
    X509NameRef,
    X509NameMut,
    ffi::X509_name_st
);

// `X509_NAME_free` is the public full destructor. It pop-frees the owned name
// entries, frees both encoding caches and then releases the name allocation.
impl_dropped!(X509Name, ffi::X509_name_st, ffi::X509_NAME_free);

// X509_NAME has no reference count. Its public duplication routine encodes
// and decodes the value into a fresh object, so each clone owes a full free.
impl_cloned!(X509Name, ffi::X509_name_st, dup = ffi::X509_NAME_dup);

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn opaque_name_owner_borrows_and_deep_clones() {
        // SAFETY: OpenSSL returns null or a fresh, fully initialized empty
        // name with one `X509_NAME_free` ownership obligation.
        let raw = unsafe { ffi::X509_NAME_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner
        // whose registered destructor is `X509_NAME_free`.
        let mut name = unsafe { CBox::<X509Name>::from_raw(raw) }.expect("X509_NAME_new");

        assert_eq!(name.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(name.as_mut().as_mut_ptr(), raw);

        let duplicate = name.try_clone().expect("X509_NAME_dup");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn opaque_name_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<X509NameRef<'static>>(),
            core::mem::size_of::<*const ffi::X509_name_st>()
        );
        assert_eq!(
            core::mem::size_of::<X509NameMut<'static>>(),
            core::mem::size_of::<*mut ffi::X509_name_st>()
        );
        assert_eq!(
            core::mem::size_of::<CBox<X509Name>>(),
            core::mem::size_of::<*mut ffi::X509_name_st>()
        );
    }
}

define_ctype!(
    /// Wraps: x509_st
    ///
    /// OpenSSL publishes `X509` as an opaque, reference-counted certificate.
    /// Its allocation and fields remain C-owned; this layout wrapper supplies
    /// the pointer-compatible target used by owning and borrowed handles.
    ///
    /// An owning [`ffibox::CBox<X509>`] carries one reference count. Cloning
    /// the owner calls `X509_up_ref`, so both owners identify the same
    /// certificate and each eventually pays one `X509_free`. Use
    /// [`X509Ref::try_dup`] for an independent deep copy.
    X509,
    X509Ref,
    X509Mut,
    ffi::x509_st
);

// `X509_free` is the public down-reference operation. On the final reference
// it disposes the ASN.1 fields, cached extension data, ex-data, lock, property
// query, and allocation.
impl_dropped!(X509, ffi::x509_st, ffi::X509_free);

// An owner clone represents another reference to the same certificate.
// `X509_up_ref` atomically increments the count and reports failure without
// creating an additional ownership debt.
impl_cloned!(X509, ffi::x509_st, up_ref = ffi::X509_up_ref);

impl<'a> X509Ref<'a> {
    /// Create an independently owned deep copy of this certificate.
    #[must_use]
    pub fn try_dup(self) -> Option<crate::x509::x_x509::BorrowedX509<'a>> {
        crate::x509::x_x509::X509_dup(Some(self))
    }
}

#[cfg(test)]
mod x509_tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn opaque_owner_borrows_and_clones_by_reference() {
        // SAFETY: OpenSSL returns null or a fresh fully initialized,
        // reference-count-one X509 allocation.
        let raw = unsafe { ffi::X509_new() };
        // SAFETY: ownership of the fresh result transfers once to an owner
        // whose registered down-reference operation is `X509_free`.
        let mut certificate = unsafe { CBox::<X509>::from_raw(raw) }.expect("X509_new");

        assert_eq!(certificate.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(certificate.as_mut().as_mut_ptr(), raw);

        let shared = certificate.try_clone().expect("X509_up_ref");
        assert_eq!(shared.as_ptr(), raw);
        drop(shared);
    }

    #[test]
    fn opaque_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<X509Ref<'static>>(),
            core::mem::size_of::<*const ffi::x509_st>()
        );
        assert_eq!(
            core::mem::size_of::<X509Mut<'static>>(),
            core::mem::size_of::<*mut ffi::x509_st>()
        );
        assert_eq!(
            core::mem::size_of::<CBox<X509>>(),
            core::mem::size_of::<*mut ffi::x509_st>()
        );
    }
}

define_ctype!(
    /// Wraps: X509_name_entry_st
    ///
    /// Opaque layout-compatible target for one distinguished-name entry.
    /// OpenSSL keeps the concrete record private, while the public API
    /// allocates, deep-duplicates and frees complete entries. Each entry owns
    /// its mandatory ASN.1 object and string children.
    X509NameEntry,
    X509NameEntryRef,
    X509NameEntryMut,
    ffi::X509_name_entry_st
);

// `X509_NAME_ENTRY_free` tears down both mandatory ASN.1 children before it
// releases the entry allocation.
impl_dropped!(
    X509NameEntry,
    ffi::X509_name_entry_st,
    ffi::X509_NAME_ENTRY_free
);

// Entries are not reference counted. The ASN.1 duplication routine creates an
// independent record and deep-copies both children.
impl_cloned!(
    X509NameEntry,
    ffi::X509_name_entry_st,
    dup = ffi::X509_NAME_ENTRY_dup
);

impl X509NameEntry {
    /// Allocates one fully initialized, empty distinguished-name entry.
    #[must_use]
    pub fn new() -> Option<ffibox::CBox<Self>> {
        crate::x509::x_name::X509_NAME_ENTRY_new()
    }
}

#[cfg(test)]
mod x509_name_entry_tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CCloned, CDropped};

    use super::*;

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn opaque_entry_owner_borrows_and_handles_duplication_failure() {
        assert_owned_cloneable_cell::<X509NameEntry>();

        let mut entry = X509NameEntry::new().expect("X509_NAME_ENTRY_new");
        let raw = entry.as_ptr();
        assert_eq!(entry.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(entry.as_mut().as_mut_ptr(), raw);

        // A newly allocated entry has empty mandatory children and therefore
        // is not yet ASN.1 encodable. Its deep duplication reports failure
        // rather than manufacturing a partial owner.
        assert!(entry.try_clone().is_none());
    }

    #[test]
    fn opaque_entry_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<X509NameEntryRef<'static>>(),
            size_of::<*const ffi::X509_name_entry_st>()
        );
        assert_eq!(
            size_of::<X509NameEntryMut<'static>>(),
            size_of::<*mut ffi::X509_name_entry_st>()
        );
        assert_eq!(
            size_of::<CBox<X509NameEntry>>(),
            size_of::<*mut ffi::X509_name_entry_st>()
        );
    }
}

//! Wrappers assigned from `crypto/x509/x509_local.h`.

use ffibox::{CBox, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: X509_extension_st
    ///
    /// Pointer-compatible target for an X.509 extension. OpenSSL publishes
    /// this record as an opaque handle even though its private layout contains
    /// an owned object identifier, a critical flag, and an embedded octet
    /// string. Those fields therefore remain behind the public
    /// `X509_EXTENSION_get_*` and `X509_EXTENSION_set_*` call surface.
    ///
    /// An owning [`CBox<X509Extension>`] releases all three fields and the
    /// record allocation. Cloning performs the ASN.1 deep duplication and
    /// produces an independent extension.
    X509Extension,
    X509ExtensionRef,
    X509ExtensionMut,
    ffi::X509_extension_st
);

// `X509_EXTENSION_free` is the public full destructor generated from the
// extension's ASN.1 sequence template. It disposes the object identifier and
// embedded octet-string storage before releasing the record.
impl_dropped!(
    X509Extension,
    ffi::X509_extension_st,
    ffi::X509_EXTENSION_free
);

// Extensions are not reference counted. ASN.1 duplication creates an
// independent record and deep-copies its object identifier and octet string.
impl_cloned!(
    X509Extension,
    ffi::X509_extension_st,
    dup = ffi::X509_EXTENSION_dup
);

impl X509Extension {
    /// Allocates one fully initialized empty extension.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        crate::x509::x_exten::X509_EXTENSION_new()
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use ffibox::{CCell, CCloned, CDropped};

    use super::*;

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn opaque_extension_owner_produces_typed_borrows() {
        assert_owned_cloneable_cell::<X509Extension>();

        let mut extension = X509Extension::new().expect("X509_EXTENSION_new");
        let raw = extension.as_ptr();
        assert_eq!(extension.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(extension.as_mut().as_mut_ptr(), raw);
    }

    #[test]
    fn opaque_extension_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<X509ExtensionRef<'static>>(),
            size_of::<*const ffi::X509_extension_st>()
        );
        assert_eq!(
            size_of::<X509ExtensionMut<'static>>(),
            size_of::<*mut ffi::X509_extension_st>()
        );
        assert_eq!(
            size_of::<CBox<X509Extension>>(),
            size_of::<*mut ffi::X509_extension_st>()
        );
    }
}

define_ctype!(
    /// Wraps: x509_attributes_st
    ///
    /// Pointer-compatible target for an X.509 attribute. OpenSSL publishes
    /// this record as an opaque handle; its private object identifier and set
    /// of ASN.1 values therefore remain behind the `X509_ATTRIBUTE_*` API.
    ///
    /// An owning [`CBox<X509Attribute>`] releases the identifier, every value,
    /// the value stack, and the record allocation. Cloning performs an ASN.1
    /// deep duplication and produces an independent attribute.
    X509Attribute,
    X509AttributeRef,
    X509AttributeMut,
    ffi::x509_attributes_st
);

// `X509_ATTRIBUTE_free` is the public full destructor generated from the
// attribute's ASN.1 sequence template. It recursively disposes both owned
// pointer fields before releasing the record.
impl_dropped!(
    X509Attribute,
    ffi::x509_attributes_st,
    ffi::X509_ATTRIBUTE_free
);

// Attributes are not reference counted. ASN.1 duplication creates a separate
// record with deep copies of the object identifier and every value.
impl_cloned!(
    X509Attribute,
    ffi::x509_attributes_st,
    dup = ffi::X509_ATTRIBUTE_dup
);

impl X509Attribute {
    /// Allocates one fully initialized empty attribute.
    #[must_use]
    pub fn new() -> Option<CBox<Self>> {
        // SAFETY: a non-null result is a fresh, fully initialized attribute
        // carrying one matching `X509_ATTRIBUTE_free` obligation.
        unsafe { CBox::from_raw(ffi::X509_ATTRIBUTE_new()) }
    }
}

#[cfg(test)]
mod attribute_tests {
    use core::mem::size_of;

    use ffibox::{CCell, CCloned, CDropped};

    use super::*;

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn opaque_attribute_owner_produces_typed_borrows() {
        assert_owned_cloneable_cell::<X509Attribute>();

        let mut attribute = X509Attribute::new().expect("X509_ATTRIBUTE_new");
        let raw = attribute.as_ptr();
        assert_eq!(attribute.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(attribute.as_mut().as_mut_ptr(), raw);
    }

    #[test]
    fn opaque_attribute_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<X509AttributeRef<'static>>(),
            size_of::<*const ffi::x509_attributes_st>()
        );
        assert_eq!(
            size_of::<X509AttributeMut<'static>>(),
            size_of::<*mut ffi::x509_attributes_st>()
        );
        assert_eq!(
            size_of::<CBox<X509Attribute>>(),
            size_of::<*mut ffi::x509_attributes_st>()
        );
    }
}

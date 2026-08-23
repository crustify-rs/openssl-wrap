//! Wrappers assigned from `crypto/x509/x509_v3.c`.

use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1ObjectRef, Asn1StringRef};
use crate::x509::x509_local::X509ExtensionRef;

/// Wraps: X509_EXTENSION_get_critical
/// Reports whether the extension's critical flag is set.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_EXTENSION_get_critical(extension: X509ExtensionRef<'_>) -> bool {
    // SAFETY: the shared extension is live and the getter only reads its flag.
    unsafe { ffi::X509_EXTENSION_get_critical(extension.as_ptr()) == 1 }
}

/// Wraps: X509_EXTENSION_get_object
/// Borrows the extension's object identifier.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_EXTENSION_get_object<'a>(extension: X509ExtensionRef<'a>) -> Option<Asn1ObjectRef<'a>> {
    // SAFETY: the getter returns null or the object owned by `extension`; the
    // shared handle keeps that object live for the returned lifetime.
    unsafe {
        Asn1ObjectRef::from_ptr(ffi::X509_EXTENSION_get_object(extension.as_ptr()).cast_mut())
    }
}

/// Wraps: X509_EXTENSION_get_data
/// Borrows the extension's embedded octet string.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_EXTENSION_get_data<'a>(
    extension: Option<X509ExtensionRef<'a>>,
) -> Option<Asn1StringRef<'a>> {
    let extension = extension.map_or(core::ptr::null(), |extension| extension.as_ptr());
    // SAFETY: a non-null extension is live for `'a`; the getter returns null
    // or its embedded octet string, which remains live with that extension.
    unsafe { Asn1StringRef::from_ptr(ffi::X509_EXTENSION_get_data(extension).cast_mut()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::x_exten::X509_EXTENSION_new;

    #[test]
    fn new_extension_exposes_its_default_fields() {
        let extension = X509_EXTENSION_new().expect("extension");
        assert!(!X509_EXTENSION_get_critical(extension.as_ref()));
        assert!(X509_EXTENSION_get_object(extension.as_ref()).is_some());
        assert!(X509_EXTENSION_get_data(Some(extension.as_ref())).is_some());
        assert!(X509_EXTENSION_get_data(None).is_none());
    }
}

//! Wrappers assigned from `include/crypto/asn1.h`.

use ffibox::{CBox, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: asn1_object_st
    ///
    /// The public OpenSSL API keeps `ASN1_OBJECT` opaque. Owned handles use
    /// `ffibox::CBox<Asn1Object>` and borrowed access remains lifetime-bound
    /// through `Asn1ObjectRef` and `Asn1ObjectMut`.
    Asn1Object,
    Asn1ObjectRef,
    Asn1ObjectMut,
    ffi::asn1_object_st
);

impl_dropped!(Asn1Object, ffi::asn1_object_st, ffi::ASN1_OBJECT_free);

/// The two ownership outcomes of `OBJ_dup`.
///
/// Dynamic objects produce an independently owned copy. For a non-dynamic
/// object OpenSSL returns the source pointer, so that result remains borrowed
/// for the source handle's lifetime.
pub enum Asn1ObjectDuplicate<'a> {
    /// A fresh object released by `ASN1_OBJECT_free`.
    Owned(CBox<Asn1Object>),
    /// The original non-dynamic object, still borrowed from the source.
    Borrowed(Asn1ObjectRef<'a>),
}

impl Asn1ObjectDuplicate<'_> {
    /// Borrow either duplicate outcome.
    #[must_use]
    pub fn as_ref(&self) -> Asn1ObjectRef<'_> {
        match self {
            Self::Owned(object) => object.as_ref(),
            Self::Borrowed(object) => *object,
        }
    }
}

impl<'a> Asn1ObjectRef<'a> {
    /// Duplicate this object, preserving OpenSSL's owned-versus-borrowed result.
    #[must_use]
    pub fn try_dup(&self) -> Option<Asn1ObjectDuplicate<'a>> {
        // SAFETY: this handle carries a live shared borrow. `OBJ_dup` leaves
        // its source unchanged and returns null, a fresh allocation, or the
        // same pointer when the source is non-dynamic.
        let duplicate = unsafe { ffi::OBJ_dup(self.as_ptr()) };
        if duplicate.cast_const() == self.as_ptr() {
            // SAFETY: pointer equality is the non-dynamic branch of `OBJ_dup`;
            // the returned borrow remains bounded by this handle's `'a`.
            let object = unsafe { Asn1ObjectRef::from_ptr(duplicate) }?;
            Some(Asn1ObjectDuplicate::Borrowed(object))
        } else {
            // SAFETY: a distinct non-null `OBJ_dup` result is a fresh object
            // carrying one `ASN1_OBJECT_free` obligation.
            let object = unsafe { CBox::from_raw(duplicate) }?;
            Some(Asn1ObjectDuplicate::Owned(object))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_object_duplicates_and_borrows() {
        // SAFETY: the input is a live NUL-terminated numeric OID; OpenSSL
        // returns either null or a fully initialized owned object.
        let raw = unsafe { ffi::OBJ_txt2obj(c"1.3.6.1.4.1.55555.999999".as_ptr(), 1) };
        // SAFETY: `OBJ_txt2obj` transfers its fresh result to the caller and
        // `Asn1Object` registers the matching `ASN1_OBJECT_free` destructor.
        let mut object =
            unsafe { CBox::<Asn1Object>::from_raw(raw) }.expect("numeric object identifier");

        assert_eq!(object.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(object.as_mut().as_mut_ptr(), raw);

        let duplicate = object.as_ref().try_dup().expect("OBJ_dup");
        let Asn1ObjectDuplicate::Owned(duplicate) = duplicate else {
            panic!("unregistered numeric OID unexpectedly resolved to a static object");
        };
        assert_ne!(duplicate.as_ptr(), raw);
        assert_eq!(duplicate.as_ref().as_ptr(), duplicate.as_ptr().cast_const());
    }

    #[test]
    fn duplicate_keeps_builtin_objects_borrowed() {
        // SAFETY: the input is a live NUL-terminated numeric OID. OpenSSL
        // returns the registered built-in object for this well-known value.
        let raw = unsafe { ffi::OBJ_txt2obj(c"1.2.840.113549.1.1.1".as_ptr(), 1) };
        // SAFETY: the returned pointer remains live until the matching free
        // below (which is a no-op for this built-in object).
        let object = unsafe { Asn1ObjectRef::from_ptr(raw) }.expect("RSA object identifier");
        let duplicate = object.try_dup().expect("OBJ_dup of built-in object");
        let is_borrowed = matches!(duplicate, Asn1ObjectDuplicate::Borrowed(_));
        drop(duplicate);
        // SAFETY: this releases the one result returned by `OBJ_txt2obj`; for
        // the expected built-in object OpenSSL intentionally does nothing.
        unsafe { ffi::ASN1_OBJECT_free(raw) };

        assert!(is_borrowed);
    }
}

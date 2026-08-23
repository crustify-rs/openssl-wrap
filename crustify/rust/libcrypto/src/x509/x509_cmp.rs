//! Wrappers assigned from `crypto/x509/x509_cmp.c`.

use core::cmp::Ordering;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1StringMut, Asn1StringRef};
use crate::evp::evp::{EvpPkey, EvpPkeyRef};
use crate::x509::x509_internal::{X509Mut, X509NameRef, X509Ref};

/// Wraps: X509_cmp
/// Compares complete certificate identities, allowing OpenSSL to refresh its
/// internally synchronized fingerprint caches.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_cmp(a: X509Ref<'_>, b: X509Ref<'_>) -> Ordering {
    // SAFETY: both shared certificate handles are live. OpenSSL's nominally
    // const comparison performs only its documented synchronized cache work.
    unsafe { ffi::X509_cmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

/// Wraps: X509_get0_pubkey
/// Borrows the certificate's decoded public key.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_pubkey<'a>(certificate: X509Ref<'a>) -> Option<EvpPkeyRef<'a>> {
    // SAFETY: the returned pointer is null or cached storage retained by the
    // certificate; the borrowed handle carries the certificate's lifetime.
    unsafe { EvpPkeyRef::from_ptr(ffi::X509_get0_pubkey(certificate.as_ptr())) }
}

/// Wraps: X509_get_issuer_name
/// Borrows the certificate issuer name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_issuer_name<'a>(certificate: X509Ref<'a>) -> X509NameRef<'a> {
    // SAFETY: every complete X509 owns a live issuer name. The result remains
    // bounded by the certificate borrow and transfers no ownership.
    unsafe { X509NameRef::from_ptr(ffi::X509_get_issuer_name(certificate.as_ptr()).cast_mut()) }
        .expect("a complete X509 has an issuer name")
}

/// Wraps: X509_get_pubkey
/// Returns a newly owned reference to the certificate's decoded public key.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_pubkey(certificate: X509Ref<'_>) -> Option<CBox<EvpPkey>> {
    // SAFETY: the certificate is live and a non-null result carries one new
    // EVP_PKEY reference obtained by `X509_PUBKEY_get`.
    unsafe { CBox::from_raw(ffi::X509_get_pubkey(certificate.as_ptr())) }
}

/// Wraps: X509_get_subject_name
/// Borrows the certificate subject name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_subject_name<'a>(certificate: X509Ref<'a>) -> X509NameRef<'a> {
    // SAFETY: every complete X509 owns a live subject name, retained for the
    // certificate borrow.
    unsafe { X509NameRef::from_ptr(ffi::X509_get_subject_name(certificate.as_ptr()).cast_mut()) }
        .expect("a complete X509 has a subject name")
}

/// Wraps: X509_issuer_and_serial_cmp
/// Orders optional certificates by serial number and then issuer name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_issuer_and_serial_cmp(a: Option<X509Ref<'_>>, b: Option<X509Ref<'_>>) -> Ordering {
    let a = a.map_or(ptr::null(), |certificate| certificate.as_ptr());
    let b = b.map_or(ptr::null(), |certificate| certificate.as_ptr());
    // SAFETY: the C comparator explicitly accepts null for either argument;
    // each non-null pointer comes from a live shared handle.
    unsafe { ffi::X509_issuer_and_serial_cmp(a, b) }.cmp(&0)
}

/// Wraps: X509_issuer_name_cmp
#[must_use]
#[allow(non_snake_case)]
pub fn X509_issuer_name_cmp(a: X509Ref<'_>, b: X509Ref<'_>) -> Ordering {
    // SAFETY: both live certificates own initialized issuer names.
    unsafe { ffi::X509_issuer_name_cmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

/// Wraps: X509_subject_name_cmp
#[must_use]
#[allow(non_snake_case)]
pub fn X509_subject_name_cmp(a: X509Ref<'_>, b: X509Ref<'_>) -> Ordering {
    // SAFETY: both live certificates own initialized subject names.
    unsafe { ffi::X509_subject_name_cmp(a.as_ptr(), b.as_ptr()) }.cmp(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::x_x509::{X509_free, X509_new};

    #[test]
    fn fresh_certificates_expose_lifetime_bound_names_and_compare() {
        let first = X509_new().expect("first certificate");
        let second = X509_new().expect("second certificate");

        assert_ne!(X509_get_issuer_name(first.as_ref()).as_ptr(), ptr::null());
        assert_ne!(X509_get_subject_name(first.as_ref()).as_ptr(), ptr::null());
        assert_eq!(
            X509_issuer_name_cmp(first.as_ref(), second.as_ref()),
            Ordering::Equal
        );
        assert_eq!(
            X509_subject_name_cmp(first.as_ref(), second.as_ref()),
            Ordering::Equal
        );
        assert_eq!(
            X509_issuer_and_serial_cmp(Some(first.as_ref()), None),
            Ordering::Greater
        );
        assert_eq!(X509_issuer_and_serial_cmp(None, None), Ordering::Equal);
        assert!(X509_get0_pubkey(first.as_ref()).is_none());
        assert!(X509_get_pubkey(first.as_ref()).is_none());

        X509_free(second);
        X509_free(first);
    }
}

/// Wraps: X509_get0_serialNumber
/// Borrows the certificate's embedded serial number without write access.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_serialNumber<'a>(certificate: X509Ref<'a>) -> Asn1StringRef<'a> {
    // SAFETY: a complete X509 contains an initialized embedded serial number
    // retained for the certificate borrow.
    unsafe { Asn1StringRef::from_ptr(ffi::X509_get0_serialNumber(certificate.as_ptr()).cast_mut()) }
        .expect("a complete X509 has a serial number")
}

/// Wraps: X509_get_serialNumber
/// Exclusively borrows the certificate's embedded mutable serial number.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_serialNumber<'a>(certificate: &'a mut X509Mut<'_>) -> Asn1StringMut<'a> {
    // SAFETY: the exclusive certificate reborrow permits exclusive access to
    // its embedded serial number for precisely the returned handle lifetime.
    unsafe { Asn1StringMut::from_ptr(ffi::X509_get_serialNumber(certificate.as_mut_ptr())) }
        .expect("a complete X509 has a serial number")
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;
    use crate::x509::x_x509::{X509_free, X509_new};

    #[test]
    fn serial_number_supports_shared_and_exclusive_reborrows() {
        let mut certificate = X509_new().expect("certificate");
        let shared = X509_get0_serialNumber(certificate.as_ref());
        assert!(!shared.as_ptr().is_null());
        let mut certificate_mut = certificate.as_mut();
        let mut exclusive = X509_get_serialNumber(&mut certificate_mut);
        assert!(!exclusive.as_mut_ptr().is_null());
        X509_free(certificate);
    }
}

//! Wrappers assigned from `crypto/x509/x509_cmp.c`.

use core::cmp::Ordering;
use core::ptr;

use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1StringMut, Asn1StringRef};
use crate::evp::evp::{EvpPkeyRef, SharedEvpPkey};
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
///
/// The certificate keeps its own reference to that cached key and
/// [`X509_get0_pubkey`] hands out a borrow of it, so the extra count is a
/// share: it yields a [`SharedEvpPkey`], which grants no exclusive handle.
/// [`EvpPkeyRef::try_dup`] is the route to an independent owner.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_pubkey(certificate: X509Ref<'_>) -> Option<SharedEvpPkey> {
    // SAFETY: the certificate is live and a non-null result carries one new
    // EVP_PKEY reference obtained by `X509_PUBKEY_get`; the key record itself
    // borrows nothing, so the share needs no lifetime bound.
    unsafe { SharedEvpPkey::from_raw(ffi::X509_get_pubkey(certificate.as_ptr())) }
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
///
/// The issuer comparison delegates to `X509_NAME_cmp`, so `None` reports the
/// same canonical-encoding failure that [`X509_NAME_cmp`] represents.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_issuer_and_serial_cmp(
    a: Option<X509Ref<'_>>,
    b: Option<X509Ref<'_>>,
) -> Option<Ordering> {
    let a = a.map_or(ptr::null(), |certificate| certificate.as_ptr());
    let b = b.map_or(ptr::null(), |certificate| certificate.as_ptr());
    // SAFETY: the C comparator explicitly accepts null for either argument;
    // each non-null pointer comes from a live shared handle.
    name_comparison(unsafe { ffi::X509_issuer_and_serial_cmp(a, b) })
}

/// Wraps: X509_issuer_name_cmp
/// Orders two certificates by issuer name.
///
/// `None` reports the canonical-encoding failure `X509_NAME_cmp` signals with
/// its distinct `-2` result rather than folding it into an ordering.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_issuer_name_cmp(a: X509Ref<'_>, b: X509Ref<'_>) -> Option<Ordering> {
    // SAFETY: both live certificates own initialized issuer names. OpenSSL may
    // refresh their canonical encodings but retains both name allocations.
    name_comparison(unsafe { ffi::X509_issuer_name_cmp(a.as_ptr(), b.as_ptr()) })
}

/// Wraps: X509_subject_name_cmp
/// Orders two certificates by subject name.
///
/// `None` reports the canonical-encoding failure `X509_NAME_cmp` signals with
/// its distinct `-2` result rather than folding it into an ordering.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_subject_name_cmp(a: X509Ref<'_>, b: X509Ref<'_>) -> Option<Ordering> {
    // SAFETY: both live certificates own initialized subject names. OpenSSL may
    // refresh their canonical encodings but retains both name allocations.
    name_comparison(unsafe { ffi::X509_subject_name_cmp(a.as_ptr(), b.as_ptr()) })
}

/// Maps a distinguished-name comparison result, whose `-2` encodes an encoding
/// failure rather than an ordering.
fn name_comparison(comparison: i32) -> Option<Ordering> {
    (comparison != -2).then(|| comparison.cmp(&0))
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
            Some(Ordering::Equal)
        );
        assert_eq!(
            X509_subject_name_cmp(first.as_ref(), second.as_ref()),
            Some(Ordering::Equal)
        );
        assert_eq!(
            X509_issuer_and_serial_cmp(Some(first.as_ref()), None),
            Some(Ordering::Greater)
        );
        assert_eq!(
            X509_issuer_and_serial_cmp(None, None),
            Some(Ordering::Equal)
        );
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
    use crate::x509::x_name::{X509_NAME_free, X509_NAME_new};
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

    #[test]
    fn name_comparison_preserves_null_ordering_and_reports_success() {
        let first = X509_NAME_new().expect("first name");
        let second = X509_NAME_new().expect("second name");
        assert_eq!(
            X509_NAME_cmp(Some(first.as_ref()), Some(second.as_ref())),
            Some(Ordering::Equal)
        );
        assert_eq!(X509_NAME_cmp(None, None), Some(Ordering::Equal));
        assert_eq!(
            X509_NAME_cmp(None, Some(second.as_ref())),
            Some(Ordering::Less)
        );
        assert_eq!(
            X509_NAME_cmp(Some(first.as_ref()), None),
            Some(Ordering::Greater)
        );
        X509_NAME_free(first);
        X509_NAME_free(second);
    }
}

/// Wraps: X509_NAME_cmp
/// Orders optional distinguished names after refreshing their canonical forms.
///
/// `None` reports an encoding failure; null names themselves participate in
/// the ordinary ordering and are represented by the optional arguments.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_cmp(a: Option<X509NameRef<'_>>, b: Option<X509NameRef<'_>>) -> Option<Ordering> {
    let a = a.map_or(ptr::null(), |name| name.as_ptr());
    let b = b.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: each input is null or a live shared name. OpenSSL may refresh
    // internal encoding caches but retains both allocations and their fields.
    name_comparison(unsafe { ffi::X509_NAME_cmp(a, b) })
}

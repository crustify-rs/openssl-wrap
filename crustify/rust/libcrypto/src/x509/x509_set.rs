//! Wrappers assigned from `crypto/x509/x509_set.c`.

use core::ffi::c_long;

use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1StringRef;
use crate::stack::stack::StackRef;
use crate::x509::x_pubkey::X509PubkeyRef;
use crate::x509::x_x509::BorrowedX509;
use crate::x509::x509::{X509AlgorRef, X509Extension, X509ExtensionStackRef};
use crate::x509::x509_internal::X509Ref;

/// Wraps: X509_get0_extensions
/// Borrows the certificate's extension stack, when present.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_extensions<'a>(certificate: X509Ref<'a>) -> Option<X509ExtensionStackRef<'a>> {
    // SAFETY: the getter returns null or the certificate's live generated
    // `STACK_OF(X509_EXTENSION)`, erased here to its common stack layout.
    unsafe {
        StackRef::<X509Extension>::from_ptr(
            ffi::X509_get0_extensions(certificate.as_ptr())
                .cast_mut()
                .cast(),
        )
    }
}

/// Wraps: X509_get_X509_PUBKEY
/// Borrows the certificate's SubjectPublicKeyInfo container.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_X509_PUBKEY<'a>(certificate: X509Ref<'a>) -> Option<X509PubkeyRef<'a>> {
    // SAFETY: the getter returns null or a container owned by the certificate;
    // the resulting handle is bounded by the certificate borrow.
    unsafe { X509PubkeyRef::from_ptr(ffi::X509_get_X509_PUBKEY(certificate.as_ptr()).cast_mut()) }
}

/// Validated signature metadata cached by an X509 certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct X509SignatureInfo {
    /// Numeric identifier of the digest algorithm.
    pub digest_nid: i32,
    /// Numeric identifier of the public-key algorithm.
    pub public_key_nid: i32,
    /// Estimated security strength in bits.
    pub security_bits: i32,
    /// OpenSSL `X509_SIG_INFO_*` flags.
    pub flags: u32,
}

/// Wraps: X509_get_signature_info
/// Returns signature metadata only when OpenSSL marks the cached result valid.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_signature_info(certificate: X509Ref<'_>) -> Option<X509SignatureInfo> {
    let mut digest_nid = 0;
    let mut public_key_nid = 0;
    let mut security_bits = 0;
    let mut flags = 0;
    // SAFETY: the shared certificate is live and all four outputs are valid,
    // disjoint scalar slots. Cache refresh is internally synchronized.
    let valid = unsafe {
        ffi::X509_get_signature_info(
            certificate.as_ptr(),
            &mut digest_nid,
            &mut public_key_nid,
            &mut security_bits,
            &mut flags,
        )
    };
    (valid == 1).then_some(X509SignatureInfo {
        digest_nid,
        public_key_nid,
        security_bits,
        flags,
    })
}

/// Wraps: X509_get_signature_type
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_signature_type(certificate: X509Ref<'_>) -> i32 {
    // SAFETY: the live certificate contains an initialized signature algorithm.
    unsafe { ffi::X509_get_signature_type(certificate.as_ptr()) }
}

/// Wraps: X509_up_ref
/// Acquires a new owned reference to the same certificate.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_up_ref<'a>(certificate: X509Ref<'a>) -> Option<BorrowedX509<'a>> {
    let raw = certificate.as_ptr().cast_mut();
    // SAFETY: the certificate is live. A successful call creates exactly one
    // additional reference-count debt on this same pointer.
    if unsafe { ffi::X509_up_ref(raw) } != 1 {
        return None;
    }
    // SAFETY: the successful increment above transfers the new reference to
    // this owner without consuming the source borrow.
    unsafe { BorrowedX509::from_raw(raw) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::x_x509::{X509_free, X509_new};

    #[test]
    fn certificate_children_and_reference_clone_remain_typed() {
        let certificate = X509_new().expect("certificate");
        assert!(X509_get_X509_PUBKEY(certificate.as_ref()).is_some());
        assert!(X509_get0_extensions(certificate.as_ref()).is_none());
        let _ = X509_get_signature_type(certificate.as_ref());

        let shared = X509_up_ref(certificate.as_ref()).expect("up-ref");
        assert_eq!(shared.as_ref().as_ptr(), certificate.as_ptr().cast_const());
        drop(shared);
        X509_free(certificate);
    }
}

/// Wraps: X509_get0_notAfter
/// Borrows the certificate's embedded not-after time.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_notAfter<'a>(certificate: X509Ref<'a>) -> Asn1StringRef<'a> {
    // SAFETY: a complete X509 contains a live not-after string retained for
    // the certificate lifetime.
    unsafe { Asn1StringRef::from_ptr(ffi::X509_get0_notAfter(certificate.as_ptr()).cast_mut()) }
        .expect("a complete X509 has a not-after time")
}

/// Wraps: X509_get0_notBefore
/// Borrows the certificate's embedded not-before time.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_notBefore<'a>(certificate: X509Ref<'a>) -> Asn1StringRef<'a> {
    // SAFETY: a complete X509 contains a live not-before string retained for
    // the certificate lifetime.
    unsafe { Asn1StringRef::from_ptr(ffi::X509_get0_notBefore(certificate.as_ptr()).cast_mut()) }
        .expect("a complete X509 has a not-before time")
}

/// Wraps: X509_get0_tbs_sigalg
/// Borrows the certificate's embedded to-be-signed signature algorithm.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_tbs_sigalg<'a>(certificate: X509Ref<'a>) -> X509AlgorRef<'a> {
    // SAFETY: the getter addresses an embedded, initialized field retained for
    // the live certificate handle's lifetime.
    unsafe { X509AlgorRef::from_ptr(ffi::X509_get0_tbs_sigalg(certificate.as_ptr()).cast_mut()) }
        .expect("a complete X509 has a TBS signature algorithm")
}

/// Wraps: X509_get_version
/// Returns the certificate's zero-based X509 version number.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_version(certificate: X509Ref<'_>) -> c_long {
    // SAFETY: the shared certificate contains an initialized version value.
    unsafe { ffi::X509_get_version(certificate.as_ptr()) }
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;
    use crate::x509::x_x509::{X509_free, X509_new};

    #[test]
    fn version_times_and_tbs_algorithm_are_lifetime_bound() {
        let certificate = X509_new().expect("certificate");
        assert_eq!(X509_get_version(certificate.as_ref()), 0);
        let _ = X509_get0_notBefore(certificate.as_ref());
        let _ = X509_get0_notAfter(certificate.as_ref());
        let _ = X509_get0_tbs_sigalg(certificate.as_ref());
        X509_free(certificate);
    }
}

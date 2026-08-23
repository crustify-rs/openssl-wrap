//! Wrappers assigned from `crypto/x509/x_x509.c`.

use core::ffi::{CStr, c_long, c_void};
use core::marker::PhantomData;
use core::ptr;

use ffibox::{CBox, CType};
use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1StringRef;
use crate::bio::context::OsslLibCtxRef;
use crate::x509::x_pubkey::encode_der;
use crate::x509::x509::X509AlgorRef;
use crate::x509::x509_internal::{X509, X509Mut, X509Ref};

/// An owned X509 certificate whose library context is borrowed for `'a`.
#[must_use = "dropping the owner releases its certificate reference"]
pub struct BorrowedX509<'a> {
    inner: CBox<X509>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedX509<'_> {
    pub(crate) unsafe fn from_raw(raw: *mut ffi::X509) -> Option<Self> {
        // SAFETY: the caller transfers one freshly constructed X509 reference.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the certificate without write access.
    #[must_use]
    pub fn as_ref(&self) -> X509Ref<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the certificate.
    #[must_use]
    pub fn as_mut(&mut self) -> X509Mut<'_> {
        self.inner.as_mut()
    }
}

/// Wraps: X509_dup
/// Deep-copies an optional certificate into an independent allocation.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_dup<'a>(certificate: Option<X509Ref<'a>>) -> Option<BorrowedX509<'a>> {
    let certificate = certificate.map_or(ptr::null(), |certificate| certificate.as_ptr());
    // SAFETY: the argument is null or a live shared certificate. A non-null
    // result is a fresh fully initialized X509 with its own reference count.
    unsafe { BorrowedX509::from_raw(ffi::X509_dup(certificate)) }
}

/// Wraps: X509_free
/// Consumes one owned certificate reference.
#[allow(non_snake_case)]
pub fn X509_free(certificate: CBox<X509>) {
    drop(certificate);
}

/// Wraps: X509_get_signature_nid
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_signature_nid(certificate: X509Ref<'_>) -> i32 {
    // SAFETY: the live certificate contains an initialized signature algorithm.
    unsafe { ffi::X509_get_signature_nid(certificate.as_ptr()) }
}

/// Wraps: X509_new
/// Allocates a certificate using the default library context.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_new() -> Option<CBox<X509>> {
    // SAFETY: OpenSSL returns null or a fresh, fully initialized X509 carrying
    // one reference-count ownership obligation.
    unsafe { CBox::from_raw(ffi::X509_new()) }
}

/// Wraps: X509_new_ex
/// Allocates a certificate retaining the optional library-context borrow.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_new_ex<'a>(
    context: Option<OsslLibCtxRef<'a>>,
    property_query: Option<&CStr>,
) -> Option<BorrowedX509<'a>> {
    let context = context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), |query| query.as_ptr());
    // SAFETY: non-null inputs are live for the call. OpenSSL copies the query;
    // `BorrowedX509` keeps the retained context borrow alive in the type.
    unsafe { BorrowedX509::from_raw(ffi::X509_new_ex(context, property_query)) }
}

/// Wraps: d2i_X509
/// Decodes one DER certificate and advances `input` past it.
#[must_use]
#[allow(non_snake_case)]
pub fn d2i_X509(input: &mut &[u8]) -> Option<CBox<X509>> {
    let source = *input;
    let length = c_long::try_from(source.len()).ok()?;
    let start = source.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` addresses exactly `length` readable source bytes and a
    // null destination requests a fresh certificate allocation.
    let raw = unsafe { ffi::d2i_X509(ptr::null_mut(), &mut cursor, length) };
    // SAFETY: a non-null result transfers one owned X509 reference.
    let decoded = unsafe { CBox::from_raw(raw) }?;
    let consumed = cursor.addr().wrapping_sub(start.addr());
    if consumed > source.len() {
        return None;
    }
    *input = &source[consumed..];
    Some(decoded)
}

/// Wraps: i2d_X509
/// Encodes a complete certificate into a newly owned DER byte vector.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_X509(certificate: X509Ref<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the shared certificate remains live and `encode_der`
        // supplies either null or the exact extent returned by the length pass.
        unsafe { ffi::i2d_X509(certificate.as_ptr(), output) }
    })
}

/// Wraps: i2d_re_X509_tbs
/// Marks and re-encodes the mutable certificate's to-be-signed portion.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_re_X509_tbs(certificate: &mut X509Mut<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the exclusive handle permits the cache-modification flag and
        // encoding cache to be updated; the output follows `encode_der`'s
        // two-pass exact-buffer contract.
        unsafe { ffi::i2d_re_X509_tbs(certificate.as_mut_ptr(), output) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_certificate_encoding_reports_failure() {
        let mut certificate = X509_new().expect("certificate");
        assert!(i2d_X509(certificate.as_ref()).is_none());
        assert!(i2d_re_X509_tbs(&mut certificate.as_mut()).is_none());
        let _ = X509_get_signature_nid(certificate.as_ref());

        X509_free(certificate);
    }

    #[test]
    fn failed_decode_does_not_advance_and_context_is_lifetime_bound() {
        let invalid = [0_u8, 1, 2];
        let mut input = invalid.as_slice();
        assert!(d2i_X509(&mut input).is_none());
        assert_eq!(input, invalid);
        assert!(X509_dup(None).is_none());

        // SAFETY: the constructor returns null or a fresh context owner.
        let context =
            unsafe { CBox::<crate::bio::context::OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
                .expect("context");
        let certificate = X509_new_ex(Some(context.as_ref()), None).expect("certificate");
        drop(certificate);
        drop(context);
    }
}

/// Borrowed outer-signature fields of an X509 certificate.
#[derive(Clone, Copy)]
pub struct X509Signature<'a> {
    /// Encoded signature bit string.
    pub value: Asn1StringRef<'a>,
    /// AlgorithmIdentifier paired with the signature.
    pub algorithm: X509AlgorRef<'a>,
}

/// Wraps: X509_get0_signature
/// Borrows the certificate's outer signature value and algorithm.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_signature<'a>(certificate: X509Ref<'a>) -> X509Signature<'a> {
    let mut signature = ptr::null();
    let mut algorithm = ptr::null();
    // SAFETY: both outputs are valid disjoint scalar slots and the shared
    // certificate retains the two embedded results for its handle lifetime.
    unsafe { ffi::X509_get0_signature(&mut signature, &mut algorithm, certificate.as_ptr()) };
    // SAFETY: every complete certificate has an initialized embedded
    // signature bit string retained by the source certificate.
    let value = unsafe { Asn1StringRef::from_ptr(signature.cast_mut()) }
        .expect("a complete X509 has a signature bit string");
    // SAFETY: likewise for its outer signature AlgorithmIdentifier.
    let algorithm = unsafe { X509AlgorRef::from_ptr(algorithm.cast_mut()) }
        .expect("a complete X509 has a signature algorithm");
    X509Signature { value, algorithm }
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;

    #[test]
    fn outer_signature_borrows_both_embedded_fields() {
        let certificate = X509_new().expect("certificate");
        let signature = X509_get0_signature(certificate.as_ref());
        assert!(!signature.value.as_ptr().is_null());
        assert!(!signature.algorithm.as_ptr().is_null());
        X509_free(certificate);
    }
}

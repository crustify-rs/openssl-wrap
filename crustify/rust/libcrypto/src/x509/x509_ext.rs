//! Wrappers assigned from `crypto/x509/x509_ext.c`.

use core::ptr;

use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1ObjectRef;
use crate::x509::v3_lib::{X509V3DecodeError, X509V3Decoded, X509V3ExtensionKind, decode_result};
use crate::x509::x509_internal::X509Ref;
use crate::x509::x509_local::X509ExtensionRef;
use crate::x509::x509name::InvalidNid;

fn last_position(position: Option<usize>) -> Option<i32> {
    position.map_or(Some(-1), |value| i32::try_from(value).ok())
}

fn found_position(position: i32) -> Option<usize> {
    usize::try_from(position).ok()
}

/// Wraps: X509_get_ext
/// Borrows the extension at `index` from a certificate.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_ext<'a>(certificate: X509Ref<'a>, index: usize) -> Option<X509ExtensionRef<'a>> {
    let index = i32::try_from(index).ok()?;
    // SAFETY: the shared certificate is live and a non-null result is an
    // extension retained by it for the certificate borrow's lifetime.
    unsafe { X509ExtensionRef::from_ptr(ffi::X509_get_ext(certificate.as_ptr(), index).cast_mut()) }
}

/// Wraps: X509_get_ext_by_NID
/// Finds the next extension carrying `nid` after `last`.
///
/// OpenSSL resolves `nid` to an object identifier first and reports an
/// unregistered number with a `-2` distinct from its `-1` not-found result, so
/// the two outcomes stay distinct here as well.
#[allow(non_snake_case)]
pub fn X509_get_ext_by_NID(
    certificate: X509Ref<'_>,
    nid: i32,
    last: Option<usize>,
) -> Result<Option<usize>, InvalidNid> {
    let Some(last) = last_position(last) else {
        return Ok(None);
    };
    // SAFETY: the shared certificate is live and the integer arguments carry
    // no pointer obligations.
    match unsafe { ffi::X509_get_ext_by_NID(certificate.as_ptr(), nid, last) } {
        -2 => Err(InvalidNid),
        position => Ok(found_position(position)),
    }
}

/// Wraps: X509_get_ext_by_OBJ
/// Finds the next extension with the supplied object identifier.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_ext_by_OBJ(
    certificate: X509Ref<'_>,
    object: Asn1ObjectRef<'_>,
    last: Option<usize>,
) -> Option<usize> {
    let last = last_position(last)?;
    // SAFETY: both shared handles are live for the synchronous comparison.
    found_position(unsafe { ffi::X509_get_ext_by_OBJ(certificate.as_ptr(), object.as_ptr(), last) })
}

/// Wraps: X509_get_ext_by_critical
/// Finds the next extension with the requested criticality.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_ext_by_critical(
    certificate: X509Ref<'_>,
    critical: bool,
    last: Option<usize>,
) -> Option<usize> {
    let last = last_position(last)?;
    // SAFETY: the shared certificate is live and the scalar arguments are
    // validated by their Rust representations.
    found_position(unsafe {
        ffi::X509_get_ext_by_critical(certificate.as_ptr(), i32::from(critical), last)
    })
}

/// Wraps: X509_get_ext_count
/// Returns the certificate's extension count.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get_ext_count(certificate: X509Ref<'_>) -> usize {
    // SAFETY: the shared certificate is live; a non-null X509 reports a
    // non-negative stack count.
    usize::try_from(unsafe { ffi::X509_get_ext_count(certificate.as_ptr()) })
        .expect("a live X509 has a non-negative extension count")
}

/// Wraps: X509_get_ext_d2i
/// Finds and decodes one uniquely occurring certificate extension.
#[allow(non_snake_case)]
pub fn X509_get_ext_d2i(
    certificate: X509Ref<'_>,
    kind: X509V3ExtensionKind,
) -> Result<X509V3Decoded, X509V3DecodeError> {
    let mut critical = -1;
    // SAFETY: the shared certificate is live, `critical` is a valid output,
    // and null `idx` requests duplicate rejection.
    let raw = unsafe {
        ffi::X509_get_ext_d2i(
            certificate.as_ptr(),
            kind.nid(),
            &mut critical,
            ptr::null_mut(),
        )
    };
    // SAFETY: the lookup above is keyed on `kind.nid()`, so a non-null result
    // is a freshly decoded, solely owned extension of exactly that syntax.
    unsafe { decode_result(kind, critical, raw) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::a_object::ASN1_OBJECT_create;
    use crate::x509::x_x509::X509_new;

    #[test]
    fn empty_certificate_has_no_extensions() {
        let certificate = X509_new().expect("certificate");
        assert_eq!(X509_get_ext_count(certificate.as_ref()), 0);
        assert!(X509_get_ext(certificate.as_ref(), 0).is_none());
        assert_eq!(X509_get_ext_by_NID(certificate.as_ref(), 0, None), Ok(None));
        assert_eq!(
            X509_get_ext_by_NID(certificate.as_ref(), i32::MAX, None),
            Err(InvalidNid)
        );
        let object = ASN1_OBJECT_create(0, &[0x2a], None, None).expect("OID");
        assert!(X509_get_ext_by_OBJ(certificate.as_ref(), object.as_ref(), None).is_none());
        assert!(X509_get_ext_by_critical(certificate.as_ref(), false, None).is_none());
        assert!(matches!(
            X509_get_ext_d2i(certificate.as_ref(), X509V3ExtensionKind::GeneralNames),
            Err(X509V3DecodeError::NotFound)
        ));
    }
}

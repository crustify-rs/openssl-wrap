//! Wrappers assigned from `crypto/asn1/x_algor.c`.

use core::cmp::Ordering;
use core::ffi::c_long;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1ObjectRef;
use crate::asn1::openssl_asn1::Asn1TypeRef;
use crate::x509::x_pubkey::encode_der;
use crate::x509::x509::{X509Algor, X509AlgorRef};

/// Wraps: X509_ALGOR_cmp
/// Orders two complete ASN.1 AlgorithmIdentifiers.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_ALGOR_cmp(a: X509AlgorRef<'_>, b: X509AlgorRef<'_>) -> Option<Ordering> {
    // The C implementation unconditionally dereferences both algorithm-object
    // fields, while the safe mutable field surface permits detaching an object
    // to construct an intentionally incomplete identifier.
    a.algorithm()?;
    b.algorithm()?;
    // SAFETY: both shared handles identify live AlgorithmIdentifiers for the
    // duration of OpenSSL's read-only comparison, and both required object
    // fields were checked non-null above.
    Some(unsafe { ffi::X509_ALGOR_cmp(a.as_ptr(), b.as_ptr()) }.cmp(&0))
}

/// Wraps: X509_ALGOR_dup
/// Deep-copies an optional AlgorithmIdentifier.
///
/// The copy is made by re-encoding and re-decoding the source, so `None` also
/// reports a source the SEQUENCE template cannot encode — a detached
/// `algorithm`, or one holding an OID with no content octets such as the
/// built-in object [`X509_ALGOR_new`] installs.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_ALGOR_dup(algorithm: Option<X509AlgorRef<'_>>) -> Option<CBox<X509Algor>> {
    let algorithm = algorithm.map_or(ptr::null(), |algorithm| algorithm.as_ptr());
    // SAFETY: the input is null or a live shared identifier. A non-null result
    // is an independent allocation with one `X509_ALGOR_free` obligation.
    unsafe { CBox::from_raw(ffi::X509_ALGOR_dup(algorithm)) }
}

/// Wraps: X509_ALGOR_free
/// Consumes one complete AlgorithmIdentifier allocation.
#[allow(non_snake_case)]
pub fn X509_ALGOR_free(algorithm: CBox<X509Algor>) {
    drop(algorithm);
}

/// Borrowed components returned by [`X509_ALGOR_get0`].
#[derive(Clone, Copy)]
pub struct X509AlgorComponents<'a> {
    /// The identifier's algorithm object, when installed.
    pub algorithm: Option<Asn1ObjectRef<'a>>,
    /// The optional tagged ASN.1 parameter.
    pub parameter: Option<Asn1TypeRef<'a>>,
}

/// Wraps: X509_ALGOR_get0
/// Borrows the identifier's algorithm object and tagged parameter.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_ALGOR_get0<'a>(algorithm: X509AlgorRef<'a>) -> X509AlgorComponents<'a> {
    let mut object = ptr::null();
    // SAFETY: the identifier is live and `object` is a valid scalar output
    // slot. The returned object remains owned by `algorithm`.
    unsafe {
        ffi::X509_ALGOR_get0(
            &mut object,
            ptr::null_mut(),
            ptr::null_mut(),
            algorithm.as_ptr(),
        )
    };
    // SAFETY: a non-null getter result is owned by the live identifier and is
    // therefore valid for the handle lifetime carried by `algorithm`.
    let object = unsafe { Asn1ObjectRef::from_ptr(object.cast_mut()) };
    X509AlgorComponents {
        algorithm: object,
        parameter: algorithm.parameter(),
    }
}

/// Wraps: X509_ALGOR_new
/// Allocates a fully initialized AlgorithmIdentifier.
///
/// The template installs the built-in `NID_undef` object in `algorithm` and
/// leaves `parameter` null; see [`X509Algor::new`] for what that state does and
/// does not allow.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_ALGOR_new() -> Option<CBox<X509Algor>> {
    // SAFETY: a non-null result is a fresh complete allocation whose matching
    // destructor is registered on `X509Algor`.
    unsafe { CBox::from_raw(ffi::X509_ALGOR_new()) }
}

/// Wraps: d2i_X509_ALGOR
/// Decodes one DER AlgorithmIdentifier and advances `input` past it.
#[must_use]
#[allow(non_snake_case)]
pub fn d2i_X509_ALGOR(input: &mut &[u8]) -> Option<CBox<X509Algor>> {
    let source = *input;
    let length = c_long::try_from(source.len()).ok()?;
    let start = source.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` addresses exactly `length` readable bytes; a null
    // destination requests a fresh complete allocation.
    let raw = unsafe { ffi::d2i_X509_ALGOR(ptr::null_mut(), &mut cursor, length) };
    // SAFETY: a non-null result transfers one `X509_ALGOR_free` obligation.
    let decoded = unsafe { CBox::from_raw(raw) }?;
    let consumed = cursor.addr().wrapping_sub(start.addr());
    if consumed > source.len() {
        return None;
    }
    *input = &source[consumed..];
    Some(decoded)
}

/// Wraps: i2d_X509_ALGOR
/// Encodes a complete AlgorithmIdentifier into a Rust-owned DER vector.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_X509_ALGOR(algorithm: X509AlgorRef<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the shared identifier remains live; `encode_der` supplies
        // null for the length pass and then an exactly sized output buffer.
        unsafe { ffi::i2d_X509_ALGOR(algorithm.as_ptr(), output) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::a_object::ASN1_OBJECT_create;

    #[test]
    fn lifecycle_components_comparison_and_der_are_typed() {
        let mut algorithm = X509_ALGOR_new().expect("algorithm");
        let oid = [0x2a_u8, 0x03, 0x04];
        let object = ASN1_OBJECT_create(0, &oid, None, None).expect("OID");
        algorithm.as_mut().set_algorithm(Some(object));

        let components = X509_ALGOR_get0(algorithm.as_ref());
        assert!(components.algorithm.is_some());
        assert!(components.parameter.is_none());

        let encoded = i2d_X509_ALGOR(algorithm.as_ref()).expect("DER");
        let mut input = encoded.as_slice();
        let decoded = d2i_X509_ALGOR(&mut input).expect("decode");
        assert!(input.is_empty());
        assert_eq!(
            X509_ALGOR_cmp(algorithm.as_ref(), decoded.as_ref()),
            Some(Ordering::Equal)
        );

        let duplicate = X509_ALGOR_dup(Some(algorithm.as_ref())).expect("duplicate");
        assert_ne!(duplicate.as_ptr(), algorithm.as_ptr());
        assert!(X509_ALGOR_dup(None).is_none());
        X509_ALGOR_free(duplicate);
        X509_ALGOR_free(decoded);
        X509_ALGOR_free(algorithm);
    }

    #[test]
    fn incomplete_identifiers_are_not_passed_to_the_c_comparator() {
        let mut first = X509_ALGOR_new().expect("first");
        let second = X509_ALGOR_new().expect("second");
        drop(first.as_mut().take_algorithm());
        assert_eq!(X509_ALGOR_cmp(first.as_ref(), second.as_ref()), None);
    }
}

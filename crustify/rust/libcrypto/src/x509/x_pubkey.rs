//! Wrappers assigned from `crypto/x509/x_pubkey.c`.

use core::ffi::{CStr, c_long, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CSlice, CType, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1ObjectRef, Asn1StringRef};
use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::{EvpPkey, EvpPkeyRef};
use crate::x509::x509::X509AlgorRef;
use crate::x509::x509_internal::X509Ref;

define_ctype!(
    /// Wraps: X509_pubkey_st
    ///
    /// Pointer-compatible handle target for OpenSSL's public-key container.
    /// The public API exposes `X509_PUBKEY` only as an opaque forward
    /// declaration, so its fields remain behind OpenSSL's call surface.
    ///
    /// An owning [`ffibox::CBox<X509Pubkey>`] represents one complete object
    /// returned by an `X509_PUBKEY` constructor or decoder. The borrowed
    /// handles retain the lifetime and mutability of their source without
    /// forming a Rust reference over storage that OpenSSL may mutate.
    ///
    /// A container stores the `OSSL_LIB_CTX` it was built with as a plain
    /// borrowed pointer and hands it to the decoder on every
    /// [`X509_PUBKEY_get`] and [`X509_PUBKEY_get0`]. A plain
    /// [`ffibox::CBox<X509Pubkey>`] therefore holds only a container whose
    /// context outlives it — the default context, or none at all. Every
    /// operation that produces or preserves a borrowed context yields
    /// [`BorrowedX509Pubkey`] instead, which carries that borrow in its type;
    /// adopting a raw pointer with `CBox::from_raw` takes on the same
    /// obligation. `Clone` on the plain owner relies on it, since
    /// `X509_PUBKEY_dup` copies the source's context pointer into the copy.
    X509Pubkey,
    X509PubkeyRef,
    X509PubkeyMut,
    ffi::X509_pubkey_st
);

// `X509_PUBKEY_free` is the public full destructor. It releases the owned
// algorithm and bit string, the optional cached `EVP_PKEY` reference and
// property-query copy, then the pubkey allocation itself. `libctx` is only
// borrowed and is deliberately not released.
impl_dropped!(X509Pubkey, ffi::X509_pubkey_st, ffi::X509_PUBKEY_free);

// This type has no reference count. `X509_PUBKEY_dup` creates an independent
// allocation, deep-copying the algorithm, bit string, property query and any
// cached `EVP_PKEY`, so each successful clone owes its own full destructor.
impl_cloned!(X509Pubkey, ffi::X509_pubkey_st, dup = ffi::X509_PUBKEY_dup);

#[cfg(test)]
mod tests {
    use ffibox::{CBox, CVec};

    use super::*;
    use crate::asn1::asn1::Asn1Object;
    use crate::mem::CryptoFree;

    #[test]
    fn opaque_owner_borrows_and_deep_clones() {
        // SAFETY: OpenSSL returns null or a fresh, fully initialized
        // `X509_PUBKEY` allocation owned by the caller.
        let raw = unsafe { ffi::X509_PUBKEY_new() };
        // SAFETY: ownership of the freshly allocated result transfers once to a
        // `CBox` whose registered destructor is `X509_PUBKEY_free`.
        let mut pubkey =
            unsafe { CBox::<X509Pubkey>::from_raw(raw) }.expect("X509_PUBKEY_new result");

        // Use a private object identifier and allocator-matched key bytes to
        // turn the blank container into one its public deep-copy routine can
        // duplicate. This avoids process-global OID registration state.
        let oid = [0x2a_u8, 0x03, 0x04];
        // SAFETY: `oid` supplies its declared readable byte count; the null
        // names are accepted, and a non-null result is freshly owned.
        let algorithm = unsafe {
            ffi::ASN1_OBJECT_create(
                0,
                oid.as_ptr().cast_mut(),
                i32::try_from(oid.len()).expect("small OID"),
                core::ptr::null(),
                core::ptr::null(),
            )
        };
        // SAFETY: a non-null result is a fresh dynamic object with one
        // `ASN1_OBJECT_free` debt, held until the set0 transfer below.
        let algorithm =
            unsafe { CBox::<Asn1Object>::from_raw(algorithm) }.expect("ASN1_OBJECT_create result");
        let key_bytes = [0x30_u8, 0x00];
        // SAFETY: `key_bytes` supplies its declared readable bytes; OpenSSL
        // returns null or a fresh allocator-matched copy.
        let encoded = unsafe {
            ffi::CRYPTO_memdup(
                key_bytes.as_ptr().cast(),
                key_bytes.len(),
                core::ptr::null(),
                0,
            )
        };
        // SAFETY: the non-null allocation contains exactly `key_bytes.len()`
        // initialized bytes and is released by ordinary `CRYPTO_free` unless
        // transferred below.
        let encoded =
            unsafe { CVec::<u8, CryptoFree>::from_raw_parts(encoded.cast(), key_bytes.len()) }
                .expect("CRYPTO_memdup result");
        let algorithm = algorithm.into_raw();
        let (encoded, encoded_len) = encoded.into_raw_parts();
        // SAFETY: the exclusive handle names the complete destination.
        // `algorithm` and `encoded` are fresh matching allocations, and this
        // successful set0 call transfers both into the pubkey.
        assert_eq!(
            // SAFETY: the arguments satisfy the ownership and extent contract
            // established immediately above.
            unsafe {
                ffi::X509_PUBKEY_set0_param(
                    pubkey.as_mut().as_mut_ptr(),
                    algorithm,
                    ffi::V_ASN1_NULL as i32,
                    core::ptr::null_mut(),
                    encoded,
                    i32::try_from(encoded_len).expect("small key"),
                )
            },
            1
        );

        assert_eq!(pubkey.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(pubkey.as_mut().as_mut_ptr(), raw);
        assert!(i2d_X509_PUBKEY(pubkey.as_ref()).is_some());
        assert!(X509_PUBKEY_get0(pubkey.as_ref()).is_none());
        assert!(X509_PUBKEY_get(pubkey.as_ref()).is_none());
        let parameters = X509_PUBKEY_get0_param(pubkey.as_ref()).expect("parameters");
        assert!(parameters.algorithm.is_some());
        assert!(parameters.algorithm_identifier.is_some());
        let encoded = parameters.encoded_key.expect("encoded key");
        assert_eq!(encoded.len(), key_bytes.len());
        assert_eq!(encoded.elems().collect::<Vec<_>>(), key_bytes);

        let duplicate = pubkey.try_clone().expect("X509_PUBKEY_dup");
        assert_ne!(duplicate.as_ptr(), raw);
        let duplicate = X509_PUBKEY_dup(pubkey.as_ref()).expect("safe X509_PUBKEY_dup");
        assert_ne!(duplicate.as_ref().as_ptr(), raw.cast_const());
    }

    #[test]
    fn opaque_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            core::mem::size_of::<X509PubkeyRef<'static>>(),
            core::mem::size_of::<*const ffi::X509_pubkey_st>()
        );
        assert_eq!(
            core::mem::size_of::<X509PubkeyMut<'static>>(),
            core::mem::size_of::<*mut ffi::X509_pubkey_st>()
        );
        assert_eq!(
            core::mem::size_of::<CBox<X509Pubkey>>(),
            core::mem::size_of::<*mut ffi::X509_pubkey_st>()
        );
    }
}

/// An owned `X509_PUBKEY` whose library context is borrowed for `'a`.
#[must_use = "dropping the owner releases the public-key container"]
pub struct BorrowedX509Pubkey<'a> {
    inner: CBox<X509Pubkey>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedX509Pubkey<'_> {
    unsafe fn from_raw(raw: *mut ffi::X509_PUBKEY) -> Option<Self> {
        // SAFETY: the caller transfers one freshly constructed container.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the public-key container without write access.
    #[must_use]
    pub fn as_ref(&self) -> X509PubkeyRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the public-key container.
    #[must_use]
    pub fn as_mut(&mut self) -> X509PubkeyMut<'_> {
        self.inner.as_mut()
    }
}

/// Wraps: X509_PUBKEY_free
/// Consumes one complete public-key container.
#[allow(non_snake_case)]
pub fn X509_PUBKEY_free(public_key: CBox<X509Pubkey>) {
    drop(public_key);
}

/// Wraps: X509_PUBKEY_get
/// Returns a newly owned reference to the decoded key cached by the container.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_PUBKEY_get(public_key: X509PubkeyRef<'_>) -> Option<CBox<EvpPkey>> {
    // SAFETY: the shared container is live. On success OpenSSL increments the
    // cached key's reference count before returning it.
    unsafe { CBox::from_raw(ffi::X509_PUBKEY_get(public_key.as_ptr())) }
}

/// Wraps: X509_PUBKEY_get0
/// Borrows the decoded key cached by the container.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_PUBKEY_get0<'a>(public_key: X509PubkeyRef<'a>) -> Option<EvpPkeyRef<'a>> {
    // SAFETY: OpenSSL returns null or the container's cached key. The returned
    // handle cannot outlive the container borrow and transfers no reference.
    unsafe { EvpPkeyRef::from_ptr(ffi::X509_PUBKEY_get0(public_key.as_ptr())) }
}

/// Wraps: X509_PUBKEY_new_ex
/// Constructs a container that retains the optional library-context borrow.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_PUBKEY_new_ex<'a>(
    context: Option<OsslLibCtxRef<'a>>,
    property_query: Option<&CStr>,
) -> Option<BorrowedX509Pubkey<'a>> {
    let context = context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), |query| query.as_ptr());
    // SAFETY: both optional inputs are live for the call. OpenSSL copies the
    // query and the returned owner carries the context borrow for its lifetime.
    unsafe { BorrowedX509Pubkey::from_raw(ffi::X509_PUBKEY_new_ex(context, property_query)) }
}

/// Wraps: d2i_X509_PUBKEY
/// Decodes one DER SubjectPublicKeyInfo and advances `input` past it.
#[must_use]
#[allow(non_snake_case)]
pub fn d2i_X509_PUBKEY(input: &mut &[u8]) -> Option<CBox<X509Pubkey>> {
    let source = *input;
    let length = c_long::try_from(source.len()).ok()?;
    let start = source.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` starts at `source`, whose readable extent is exactly
    // `length`; a null destination requests a fresh complete allocation.
    let raw = unsafe { ffi::d2i_X509_PUBKEY(ptr::null_mut(), &mut cursor, length) };
    // SAFETY: a non-null result transfers one `X509_PUBKEY_free` obligation.
    let decoded = unsafe { CBox::from_raw(raw) }?;
    let consumed = cursor.addr().wrapping_sub(start.addr());
    if consumed > source.len() {
        return None;
    }
    *input = &source[consumed..];
    Some(decoded)
}

/// Wraps: i2d_X509_PUBKEY
/// Encodes the public-key container into a newly owned DER byte vector.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_X509_PUBKEY(public_key: X509PubkeyRef<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the shared handle remains live. `encode_der` first supplies
        // null and then a buffer sized from OpenSSL's own length query.
        unsafe { ffi::i2d_X509_PUBKEY(public_key.as_ptr(), output) }
    })
}

pub(crate) fn encode_der(mut encode: impl FnMut(*mut *mut u8) -> i32) -> Option<Vec<u8>> {
    let length = usize::try_from(encode(ptr::null_mut())).ok()?;
    if length == 0 {
        return None;
    }
    let mut output = vec![0_u8; length];
    let start = output.as_mut_ptr();
    let mut cursor = start;
    let written = usize::try_from(encode(&mut cursor)).ok()?;
    (written == length && cursor == start.wrapping_add(length)).then_some(output)
}

#[cfg(test)]
mod wrapper_tests {
    use super::*;

    #[test]
    fn failed_der_decode_does_not_advance() {
        let invalid = [0_u8, 1, 2];
        let mut input = invalid.as_slice();
        assert!(d2i_X509_PUBKEY(&mut input).is_none());
        assert_eq!(input, invalid);
    }

    #[test]
    fn contextual_constructor_retains_its_context_lifetime() {
        // SAFETY: the constructor returns null or one fresh context owner.
        let context =
            unsafe { CBox::<crate::bio::context::OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
                .expect("context");
        let public_key = X509_PUBKEY_new_ex(Some(context.as_ref()), Some(c"provider=default"))
            .expect("contextual public key");
        assert!(X509_PUBKEY_get0(public_key.as_ref()).is_none());

        // A duplicate inherits the source's borrowed context pointer, so its
        // result type carries the same borrow. The blank container has no
        // encodable algorithm identifier, so OpenSSL declines this copy.
        let duplicate: Option<BorrowedX509Pubkey<'_>> = X509_PUBKEY_dup(public_key.as_ref());
        assert!(duplicate.is_none());

        drop(public_key);
        drop(context);
    }
}

/// Wraps: X509_PUBKEY_dup
/// Deep-copies a complete public-key container, retaining its context borrow.
///
/// The C routine copies the source's `libctx` pointer into the duplicate and
/// the decoder later dereferences it, so the copy is bounded by the same
/// borrow as its source rather than becoming an unconstrained owner.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_PUBKEY_dup<'a>(public_key: X509PubkeyRef<'a>) -> Option<BorrowedX509Pubkey<'a>> {
    // SAFETY: the required source is live and shared. A non-null result is an
    // independent allocation with one `X509_PUBKEY_free` obligation, and the
    // library context it borrows outlives the source handle's `'a`.
    unsafe { BorrowedX509Pubkey::from_raw(ffi::X509_PUBKEY_dup(public_key.as_ptr())) }
}

/// Wraps: X509_PUBKEY_eq
/// Tests semantic key equality, preserving OpenSSL's negative error codes.
#[allow(non_snake_case)]
pub fn X509_PUBKEY_eq(
    a: Option<X509PubkeyRef<'_>>,
    b: Option<X509PubkeyRef<'_>>,
) -> Result<bool, i32> {
    let (Some(a), Some(b)) = (a, b) else {
        return Ok(a.is_none() && b.is_none());
    };
    if a.as_ptr() == b.as_ptr() {
        return Ok(true);
    }
    // The C equality routine passes the inner algorithm object to `OBJ_cmp`
    // without checking it, so reject a malformed or incomplete C-created
    // container before entering that path.
    if X509_PUBKEY_get0_param(a)
        .and_then(|parameters| parameters.algorithm)
        .is_none()
        || X509_PUBKEY_get0_param(b)
            .and_then(|parameters| parameters.algorithm)
            .is_none()
    {
        return Err(-2);
    }
    // SAFETY: both pointers come from live shared handles, and the required
    // algorithm object fields were checked non-null above.
    match unsafe { ffi::X509_PUBKEY_eq(a.as_ptr(), b.as_ptr()) } {
        1 => Ok(true),
        0 => Ok(false),
        error => Err(error),
    }
}

/// Borrowed SubjectPublicKeyInfo components.
#[derive(Clone, Copy)]
pub struct X509PubkeyParameters<'a> {
    /// Algorithm object installed in the AlgorithmIdentifier.
    pub algorithm: Option<Asn1ObjectRef<'a>>,
    /// Encoded subject-public-key bytes, when a non-null byte run is present.
    pub encoded_key: Option<CSlice<'a, u8>>,
    /// Complete AlgorithmIdentifier retained by the public-key container.
    pub algorithm_identifier: Option<X509AlgorRef<'a>>,
}

/// Wraps: X509_PUBKEY_get0_param
/// Borrows the algorithm and encoded key from a public-key container.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_PUBKEY_get0_param<'a>(
    public_key: X509PubkeyRef<'a>,
) -> Option<X509PubkeyParameters<'a>> {
    let mut algorithm = ptr::null_mut();
    let mut encoded = ptr::null();
    let mut encoded_len = 0;
    let mut identifier = ptr::null_mut();
    // SAFETY: all outputs are valid disjoint scalar slots and the shared
    // container remains live, retaining each returned child and byte run.
    let result = unsafe {
        ffi::X509_PUBKEY_get0_param(
            &mut algorithm,
            &mut encoded,
            &mut encoded_len,
            &mut identifier,
            public_key.as_ptr(),
        )
    };
    if result != 1 {
        return None;
    }
    let encoded_len = usize::try_from(encoded_len).ok()?;
    let encoded_key = NonNull::new(encoded.cast_mut()).map(|encoded| {
        // SAFETY: OpenSSL reports `encoded_len` initialized bytes retained by
        // `public_key`; `CSlice` copies bytes out without forming a reference.
        unsafe { CSlice::from_raw_parts(encoded, encoded_len) }
    });
    // SAFETY: non-null child pointers are owned by the live public-key
    // container, and each handle is bounded by that container borrow.
    let algorithm = unsafe { Asn1ObjectRef::from_ptr(algorithm) };
    // SAFETY: as above, for the complete AlgorithmIdentifier child.
    let algorithm_identifier = unsafe { X509AlgorRef::from_ptr(identifier) };
    Some(X509PubkeyParameters {
        algorithm,
        encoded_key,
        algorithm_identifier,
    })
}

/// Wraps: X509_get0_pubkey_bitstr
/// Borrows a certificate's encoded public-key bit string.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get0_pubkey_bitstr<'a>(certificate: Option<X509Ref<'a>>) -> Option<Asn1StringRef<'a>> {
    let certificate = certificate.map_or(ptr::null(), |value| value.as_ptr());
    // SAFETY: the pointer is null or a live shared certificate. A non-null
    // result is retained by the certificate for the source handle lifetime.
    unsafe { Asn1StringRef::from_ptr(ffi::X509_get0_pubkey_bitstr(certificate).cast_mut()) }
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;

    #[test]
    fn null_equality_and_optional_certificate_are_preserved() {
        use crate::x509::x_x509::{X509_free, X509_new};

        assert_eq!(X509_PUBKEY_eq(None, None), Ok(true));
        assert!(X509_get0_pubkey_bitstr(None).is_none());

        let certificate = X509_new().expect("certificate");
        assert!(X509_get0_pubkey_bitstr(Some(certificate.as_ref())).is_some());
        X509_free(certificate);

        // SAFETY: OpenSSL returns null or a fresh complete public-key owner.
        let raw = unsafe { ffi::X509_PUBKEY_new() };
        // SAFETY: the fresh allocation transfers once to its matching owner.
        let public_key = unsafe { CBox::<X509Pubkey>::from_raw(raw) }.expect("public key");
        assert_eq!(X509_PUBKEY_eq(Some(public_key.as_ref()), None), Ok(false));
        // SAFETY: OpenSSL returns null or a fresh complete public-key owner.
        let other_raw = unsafe { ffi::X509_PUBKEY_new() };
        // SAFETY: the fresh allocation transfers once to its matching owner.
        let other = unsafe { CBox::<X509Pubkey>::from_raw(other_raw) }.expect("other public key");
        assert_eq!(
            X509_PUBKEY_eq(Some(public_key.as_ref()), Some(other.as_ref())),
            Err(-2)
        );
        let parameters = X509_PUBKEY_get0_param(public_key.as_ref()).expect("parameters");
        assert!(parameters.algorithm_identifier.is_some());
    }
}

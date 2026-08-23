//! Wrappers assigned from `crypto/x509/x_pubkey.c`.

use core::ffi::{CStr, c_long, c_void};
use core::marker::PhantomData;
use core::ptr;

use ffibox::{CBox, CType, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::{EvpPkey, EvpPkeyRef};

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

        let duplicate = pubkey.try_clone().expect("X509_PUBKEY_dup");
        assert_ne!(duplicate.as_ptr(), raw);
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
        drop(public_key);
        drop(context);
    }
}

//! Wrappers assigned from `crypto/x509/x_pubkey.c`.

use ffibox::{define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

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

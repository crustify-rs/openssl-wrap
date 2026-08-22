//! Zeroizing ownership strategy for public security-parameter buffers.

use ffibox::CLenDropped;

use crate::mem::CryptoClearFree;

/// Replaces: ossl_public_param_free
/// Length-aware strategy that always takes the helper's zeroizing branch.
///
/// OpenSSL's C helper cleanses only when pedantic zeroization is configured.
/// Rust owners use the stronger cleanup unconditionally, preserving allocator
/// compatibility while ensuring public security-parameter bytes are erased.
#[derive(Debug, Clone, Copy, Default)]
pub struct PublicParamFree;

// SAFETY: this delegates to the allocator-matched, length-aware OpenSSL
// cleansing strategy under the same buffer contract.
unsafe impl CLenDropped for PublicParamFree {
    unsafe fn c_drop_len(ptr: *mut u8, byte_len: usize) {
        // SAFETY: the caller upholds the identical `CLenDropped` contract for
        // this OpenSSL allocation and exact byte length.
        unsafe { CryptoClearFree::c_drop_len(ptr, byte_len) }
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::CVec;
    use libcrypto_sys as ffi;

    use super::*;

    #[test]
    fn public_parameter_owner_releases_openssl_storage() {
        let source = [9_u8, 10, 11];
        // SAFETY: `source` supplies its reported number of readable bytes.
        let raw = unsafe {
            ffi::CRYPTO_memdup(source.as_ptr().cast(), source.len(), ptr::null(), 0).cast()
        };
        // SAFETY: `raw` is a fresh ordinary OpenSSL allocation of source.len()
        // initialized bytes, transferred to the compatible strategy.
        let owned = unsafe { CVec::<u8, PublicParamFree>::from_raw_parts(raw, source.len()) }
            .expect("CRYPTO_memdup allocation");
        assert_eq!(owned.as_slice(), source);
    }
}

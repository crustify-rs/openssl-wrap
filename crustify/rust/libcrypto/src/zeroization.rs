//! Zeroizing ownership strategy for public security-parameter buffers.

use ffibox::CLenDropped;

use crate::mem::CryptoClearFree;

/// Replaces: ossl_public_param_free
/// Length-aware strategy that always takes the helper's zeroizing branch.
///
/// The C helper is `static ossl_inline` in `include/internal/zeroization.h`,
/// so it exposes no symbol to call: this is a native translation of the branch
/// it selects rather than a wrapper over it. C picks that branch at build time
/// — `OPENSSL_clear_free(ptr, size)` when `OPENSSL_PEDANTIC_ZEROIZATION` is
/// defined and plain `OPENSSL_free(ptr)` otherwise — and Rust owners take the
/// cleansing one unconditionally.
///
/// Choosing it independently of how the C library was configured is sound
/// because both branches release through `CRYPTO_free`. The buffer is an
/// ordinary OpenSSL allocation either way, so one C allocated can be dropped
/// here and one dropped by C is released exactly as it always was; only how
/// much of it is erased first differs, and this direction erases more.
///
/// The byte length an owner reports is what reaches `OPENSSL_cleanse`, so it
/// must be the buffer's live extent. That is the shape OpenSSL's own callers
/// already have: `params->seed` is an `OPENSSL_memdup` of exactly
/// `params->seedlen` bytes (`crypto/ffc/ffc_params.c`).
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

    #[test]
    fn absent_public_parameter_has_no_owner() {
        // The C helper accepts the NULL/0 pair `ossl_ffc_params_init` leaves
        // behind and does nothing with it; that state is the absent owner here.
        // SAFETY: `from_raw_parts` explicitly admits a null pointer, which it
        // reports rather than adopting.
        let absent = unsafe { CVec::<u8, PublicParamFree>::from_raw_parts(ptr::null_mut(), 0) };
        assert!(absent.is_none());
    }
}

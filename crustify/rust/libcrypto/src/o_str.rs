//! Length-aware cloning for ordinary OpenSSL byte buffers.

use core::ptr::{self, NonNull};

use ffibox::{CCloned, CLenCloned};

use libcrypto_sys as ffi;

use crate::mem::{CryptoClearFree, CryptoFree};

/// Wraps: CRYPTO_strdup
// SAFETY: `CRYPTO_strdup` returns an independent OpenSSL string allocation,
// which the `CryptoFree` supertrait strategy releases with `CRYPTO_free`.
unsafe impl CCloned for CryptoFree {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract guarantees a live NUL-terminated source;
        // OpenSSL borrows it and accepts null diagnostic metadata.
        NonNull::new(unsafe { ffi::CRYPTO_strdup(obj.as_ptr().cast(), ptr::null(), 0).cast() })
    }
}

/// Wraps: CRYPTO_strdup
// SAFETY: the duplicate is allocator-compatible with `CRYPTO_clear_free`; its
// NUL terminator lets that strategy recover the byte count on drop.
unsafe impl CCloned for CryptoClearFree {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract guarantees a live NUL-terminated source;
        // OpenSSL borrows it and accepts null diagnostic metadata.
        NonNull::new(unsafe { ffi::CRYPTO_strdup(obj.as_ptr().cast(), ptr::null(), 0).cast() })
    }
}

/// Wraps: CRYPTO_memdup
// SAFETY: `CRYPTO_memdup` returns an independent byte copy allocated by the
// active OpenSSL allocator, whose matching drop strategy is `CryptoFree`.
unsafe impl CLenCloned for CryptoFree {
    unsafe fn c_clone_len(ptr: *mut u8, byte_len: usize) -> Option<NonNull<u8>> {
        // SAFETY: the trait contract guarantees `byte_len` readable bytes at
        // `ptr`; OpenSSL accepts null source metadata.
        NonNull::new(unsafe {
            ffi::CRYPTO_memdup(ptr.cast_const().cast(), byte_len, ptr::null(), 0).cast()
        })
    }
}

#[cfg(test)]
mod tests {
    use ffibox::CVec;

    use super::*;
    use crate::mem::{CryptoClearString, CryptoString};

    fn duplicate_string(source: &core::ffi::CStr) -> *mut core::ffi::c_char {
        // SAFETY: `source` is NUL-terminated and remains live for the call;
        // OpenSSL accepts null diagnostic metadata.
        unsafe { ffi::CRYPTO_strdup(source.as_ptr(), ptr::null(), 0) }
    }

    #[test]
    fn ordinary_buffer_clone_is_independent() {
        let source = [5_u8, 6, 7, 8];
        // SAFETY: `source` supplies its reported number of readable bytes.
        let raw = unsafe {
            ffi::CRYPTO_memdup(source.as_ptr().cast(), source.len(), ptr::null(), 0).cast()
        };
        // SAFETY: `raw` is a fresh OpenSSL allocation containing `source.len()`
        // initialized bytes, and ownership is transferred to the handle.
        let mut original = unsafe { CVec::<u8, CryptoFree>::from_raw_parts(raw, source.len()) }
            .expect("CRYPTO_memdup allocation");
        let copy = original.try_clone().expect("CRYPTO_memdup clone");

        original.as_mut_slice()[0] = 42;
        assert_eq!(copy.as_slice(), source);
        assert_eq!(original.as_slice(), [42, 6, 7, 8]);
    }

    #[test]
    fn openssl_string_strategies_clone_independently() {
        // SAFETY: the fresh NUL-terminated allocation transfers to CryptoFree.
        let ordinary = unsafe { CryptoString::from_raw(duplicate_string(c"openssl")) }
            .expect("CRYPTO_strdup allocation");
        let ordinary_copy = ordinary.try_clone().expect("CRYPTO_strdup clone");
        assert_eq!(ordinary_copy.as_c_str(), c"openssl");
        assert_ne!(ordinary.as_ptr(), ordinary_copy.as_ptr());

        // SAFETY: the fresh NUL-terminated allocation transfers to the
        // allocator-compatible clear-free string strategy.
        let clearing = unsafe { CryptoClearString::from_raw(duplicate_string(c"secret")) }
            .expect("CRYPTO_strdup allocation");
        let clearing_copy = clearing.try_clone().expect("CRYPTO_strdup clone");
        assert_eq!(clearing_copy.as_c_str(), c"secret");
        assert_ne!(clearing.as_ptr(), clearing_copy.as_ptr());
    }
}

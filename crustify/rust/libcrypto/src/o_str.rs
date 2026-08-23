//! Length-aware cloning for ordinary OpenSSL byte buffers.

use core::ptr::{self, NonNull};

use ffibox::{CCloned, CLenCloned};

use libcrypto_sys as ffi;

use crate::mem::{CryptoClearFree, CryptoFree};

/// Wraps: CRYPTO_strdup
//
// This impl carries a precondition the `CCloned` contract does not state on
// its own: `CRYPTO_strdup` copies up to the first NUL, so `obj` must denote a
// NUL-terminated OpenSSL allocation, not an arbitrary one. That matters more
// here than for a single-purpose strategy, because `CryptoFree` also serves
// `CVoidBox` and `CVec` storage that carries no terminator. It still holds for
// every reachable caller: `CryptoFree` is a deleter strategy rather than a
// `CCell`, so the only consumer of its `CCloned` impl is
// `CrustifyStr<CryptoFree>` (`CryptoString`), whose type invariant is exactly a
// live NUL-terminated string; `CVoidBox` exposes no clone at all and `CVec`
// clones through `CLenCloned` below.
//
// SAFETY: `CRYPTO_strdup` leaves its source untouched and returns an
// independent allocation of `strlen + 1` bytes from the active OpenSSL
// allocator, so the copy owes exactly one `CRYPTO_free` — the `CDropped`
// supertrait's `c_drop`; null means the copy failed.
unsafe impl CCloned for CryptoFree {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract guarantees a live NUL-terminated source,
        // which OpenSSL only reads. Null allocation-site metadata follows the
        // convention documented on the `mem` module.
        NonNull::new(unsafe { ffi::CRYPTO_strdup(obj.as_ptr().cast(), ptr::null(), 0).cast() })
    }
}

/// Wraps: CRYPTO_strdup
//
// The same unstated NUL-termination precondition as above, discharged the same
// way: `CrustifyStr<CryptoClearFree>` (`CryptoClearString`) is the only
// consumer of this impl.
//
// SAFETY: the duplicate comes from the same OpenSSL allocator, so it is
// releasable by the `CDropped` supertrait's `CRYPTO_clear_free`. It is exactly
// `strlen + 1` bytes long, so the byte count that strategy recovers from the
// terminator covers the whole copy and every byte of it is cleansed on drop.
unsafe impl CCloned for CryptoClearFree {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract guarantees a live NUL-terminated source,
        // which OpenSSL only reads. Null allocation-site metadata follows the
        // convention documented on the `mem` module.
        NonNull::new(unsafe { ffi::CRYPTO_strdup(obj.as_ptr().cast(), ptr::null(), 0).cast() })
    }
}

/// Wraps: CRYPTO_memdup
//
// `CRYPTO_memdup` refuses two byte lengths that are otherwise valid for a
// `CVec`, and reports both the same way it reports allocation failure, by
// returning NULL:
//
// - `byte_len >= INT_MAX`, rejected up front (`crypto/o_str.c`);
// - `byte_len == 0`, because it forwards to `CRYPTO_malloc`, which returns
//   NULL for a zero request under the default allocator (`crypto/mem.c`).
//
// So `CVec::<_, CryptoFree>::try_clone` yields `None` for an empty buffer, and
// `Clone::clone` — which cannot report failure — aborts on one. Callers that
// can hold an empty buffer must use `try_clone`.
//
// SAFETY: on success `CRYPTO_memdup` returns an independent `byte_len`-byte
// copy from the active OpenSSL allocator, releasable by the `CLenDropped`
// supertrait's `CRYPTO_free`, and it only reads its source.
unsafe impl CLenCloned for CryptoFree {
    unsafe fn c_clone_len(ptr: *mut u8, byte_len: usize) -> Option<NonNull<u8>> {
        // SAFETY: the trait contract guarantees `byte_len` readable bytes at
        // `ptr`. Null allocation-site metadata follows the convention
        // documented on the `mem` module.
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
        // OpenSSL only reads it and accepts null allocation-site metadata.
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
    fn zero_length_buffer_clone_reports_failure() {
        let source = [1_u8];
        // SAFETY: `source` supplies its reported number of readable bytes.
        let raw = unsafe {
            ffi::CRYPTO_memdup(source.as_ptr().cast(), source.len(), ptr::null(), 0).cast()
        };
        // SAFETY: `raw` is a fresh OpenSSL allocation of `source.len()`
        // initialized bytes, and ownership is transferred to the handle.
        let owned = unsafe { CVec::<u8, CryptoFree>::from_raw_parts(raw, source.len()) }
            .expect("CRYPTO_memdup allocation");

        // SAFETY: `owned` keeps a live OpenSSL allocation at this address, so
        // it trivially covers a zero-byte read.
        let empty = unsafe { CryptoFree::c_clone_len(owned.as_ptr(), 0) };
        assert!(
            empty.is_none(),
            "CRYPTO_memdup reports a zero-byte copy as a failure"
        );
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

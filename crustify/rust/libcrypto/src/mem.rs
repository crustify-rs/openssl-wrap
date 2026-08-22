//! Ownership strategies for ordinary OpenSSL allocations.

use core::ffi::CStr;
use core::ptr::{self, NonNull};

use ffibox::{CDropped, CLenDropped, CrustifyStr};

use libcrypto_sys as ffi;

/// Wraps: CRYPTO_free
/// Stateless lifecycle strategy for ordinary OpenSSL allocations.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoFree;

/// An owned NUL-terminated string allocated by OpenSSL.
pub type CryptoString = CrustifyStr<CryptoFree>;

// SAFETY: `c_drop` delegates to OpenSSL's allocator-matched release routine.
unsafe impl CDropped for CryptoFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the trait contract requires a uniquely owned allocation from
        // the active OpenSSL allocator. OpenSSL accepts null file metadata.
        unsafe { ffi::CRYPTO_free(obj.as_ptr().cast(), ptr::null(), 0) }
    }
}

// SAFETY: `CRYPTO_free` releases a buffer without needing its byte length.
unsafe impl CLenDropped for CryptoFree {
    unsafe fn c_drop_len(ptr: *mut u8, _byte_len: usize) {
        // SAFETY: the trait contract requires a uniquely owned allocation from
        // the active OpenSSL allocator. OpenSSL accepts null file metadata.
        unsafe { ffi::CRYPTO_free(ptr.cast(), ptr::null(), 0) }
    }
}

/// Wraps: CRYPTO_clear_free
/// Length-aware lifecycle strategy that cleanses an ordinary OpenSSL buffer.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoClearFree;

/// An owned OpenSSL string whose bytes are cleansed before release.
pub type CryptoClearString = CrustifyStr<CryptoClearFree>;

/// Wraps: CRYPTO_clear_free
// SAFETY: for this string strategy, the terminator makes the readable byte
// count recoverable before delegating to the allocator-matched clear-free.
unsafe impl CDropped for CryptoClearFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: this strategy is selected only for a live NUL-terminated
        // string, so scanning through its terminator is valid.
        let byte_len = unsafe { CStr::from_ptr(obj.as_ptr().cast()) }
            .to_bytes_with_nul()
            .len();
        // SAFETY: `byte_len` covers the live logical string including its NUL,
        // and the trait contract transfers its OpenSSL allocation exactly once.
        unsafe { ffi::CRYPTO_clear_free(obj.as_ptr().cast(), byte_len, ptr::null(), 0) }
    }
}

// SAFETY: the byte length supplied by `CVec` is exactly the allocation size,
// which is the contract required by `CRYPTO_clear_free` before release.
unsafe impl CLenDropped for CryptoClearFree {
    unsafe fn c_drop_len(ptr: *mut u8, byte_len: usize) {
        // SAFETY: the trait contract guarantees `byte_len` live bytes in an
        // allocation owned by the active OpenSSL allocator.
        unsafe { ffi::CRYPTO_clear_free(ptr.cast(), byte_len, ptr::null(), 0) }
    }
}

#[cfg(test)]
mod tests {
    use ffibox::{CVec, CVoidBox};

    use super::*;

    fn duplicate(bytes: &[u8]) -> *mut u8 {
        // SAFETY: `bytes` supplies `len` readable bytes for the duration of the
        // call; null source metadata is accepted by OpenSSL.
        unsafe { ffi::CRYPTO_memdup(bytes.as_ptr().cast(), bytes.len(), ptr::null(), 0).cast() }
    }

    #[test]
    fn ordinary_strategies_release_owned_storage() {
        let bytes = [1_u8, 2, 3, 4];

        // SAFETY: `duplicate` returns a unique ordinary OpenSSL allocation,
        // whose ownership is transferred to the erased handle.
        let erased = unsafe { CVoidBox::<CryptoFree>::from_raw(duplicate(&bytes).cast()) };
        assert!(erased.is_some());

        // SAFETY: `duplicate` returns `bytes.len()` initialized bytes and the
        // buffer is transferred to the matching length-aware strategy.
        let buffer =
            unsafe { CVec::<u8, CryptoClearFree>::from_raw_parts(duplicate(&bytes), bytes.len()) }
                .expect("CRYPTO_memdup allocation");
        assert_eq!(buffer.as_slice(), bytes);
    }

    #[test]
    fn clear_string_strategy_recovers_its_length() {
        // SAFETY: the C literal is NUL-terminated; OpenSSL returns a fresh
        // allocator-matched string or null.
        let raw = unsafe { ffi::CRYPTO_strdup(c"clear me".as_ptr(), ptr::null(), 0) };
        // SAFETY: the fresh allocation is NUL-terminated and ownership moves
        // to the matching OpenSSL clear-free strategy.
        let owned = unsafe { CryptoClearString::from_raw(raw) }.expect("CRYPTO_strdup allocation");
        assert_eq!(owned.as_c_str(), c"clear me");
    }
}

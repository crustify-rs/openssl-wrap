//! Ownership strategies for OpenSSL secure-memory allocations.

use core::ffi::CStr;
use core::ptr::{self, NonNull};

use ffibox::{CDropped, CLenDropped, CrustifyStr};

use libcrypto_sys as ffi;

/// Wraps: CRYPTO_secure_free
/// Stateless lifecycle strategy for OpenSSL secure-memory allocations.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoSecureFree;

/// An owned NUL-terminated string in OpenSSL secure storage.
pub type CryptoSecureString = CrustifyStr<CryptoSecureFree>;

// SAFETY: `CRYPTO_secure_free` accepts allocations made by the secure API and
// its ordinary-allocation fallback, and recovers secure allocation size.
unsafe impl CDropped for CryptoSecureFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the trait contract requires uniquely owned storage allocated
        // by OpenSSL's secure allocation API.
        unsafe { ffi::CRYPTO_secure_free(obj.as_ptr().cast(), ptr::null(), 0) }
    }
}

// SAFETY: `CRYPTO_secure_free` recovers the allocation size itself.
unsafe impl CLenDropped for CryptoSecureFree {
    unsafe fn c_drop_len(ptr: *mut u8, _byte_len: usize) {
        // SAFETY: the trait contract requires uniquely owned storage allocated
        // by OpenSSL's secure allocation API.
        unsafe { ffi::CRYPTO_secure_free(ptr.cast(), ptr::null(), 0) }
    }
}

/// Wraps: CRYPTO_secure_clear_free
/// Length-aware strategy for secure or fallback ordinary OpenSSL buffers.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoSecureClearFree;

/// An owned secure OpenSSL string cleansed before release.
pub type CryptoSecureClearString = CrustifyStr<CryptoSecureClearFree>;

/// Wraps: CRYPTO_secure_clear_free
// SAFETY: a NUL-terminated string exposes its live logical byte count; the C
// routine independently recovers the full size for true secure allocations.
unsafe impl CDropped for CryptoSecureClearFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: this strategy is selected only for a live NUL-terminated
        // string, so scanning through its terminator is valid.
        let byte_len = unsafe { CStr::from_ptr(obj.as_ptr().cast()) }
            .to_bytes_with_nul()
            .len();
        // SAFETY: the trait contract transfers one secure or fallback OpenSSL
        // allocation; the length covers the logical string and its terminator.
        unsafe { ffi::CRYPTO_secure_clear_free(obj.as_ptr().cast(), byte_len, ptr::null(), 0) }
    }
}

// SAFETY: the strategy supplies the exact byte length needed to cleanse an
// ordinary fallback allocation; secure allocation sizes are recovered by C.
unsafe impl CLenDropped for CryptoSecureClearFree {
    unsafe fn c_drop_len(ptr: *mut u8, byte_len: usize) {
        // SAFETY: the trait contract guarantees a uniquely owned OpenSSL secure
        // allocation (or its ordinary fallback) of `byte_len` bytes.
        unsafe { ffi::CRYPTO_secure_clear_free(ptr.cast(), byte_len, ptr::null(), 0) }
    }
}

#[cfg(test)]
mod tests {
    use ffibox::{CVec, CVoidBox};

    use super::*;

    fn secure_zeroed(byte_len: usize) -> *mut u8 {
        // SAFETY: this requests a fresh OpenSSL secure allocation and passes
        // null diagnostic metadata, which the allocator accepts.
        unsafe { ffi::CRYPTO_secure_zalloc(byte_len, ptr::null(), 0).cast() }
    }

    #[test]
    fn secure_strategies_release_secure_or_fallback_storage() {
        // SAFETY: ownership of the fresh secure allocation is transferred to
        // its matching size-recovering release strategy.
        let erased = unsafe { CVoidBox::<CryptoSecureFree>::from_raw(secure_zeroed(8).cast()) };
        assert!(erased.is_some());

        // SAFETY: secure_zalloc supplies eight initialized bytes, transferred
        // to the matching length-aware release strategy.
        let buffer =
            unsafe { CVec::<u8, CryptoSecureClearFree>::from_raw_parts(secure_zeroed(8), 8) }
                .expect("CRYPTO_secure_zalloc allocation");
        assert_eq!(buffer.as_slice(), [0; 8]);
    }

    #[test]
    fn secure_string_strategies_release_owned_storage() {
        let raw = secure_zeroed(8).cast();
        // SAFETY: secure_zeroed returns a fresh allocation whose first byte is
        // NUL, making it a valid empty string transferred to the secure strategy.
        let owned =
            unsafe { CryptoSecureString::from_raw(raw) }.expect("CRYPTO_secure_zalloc allocation");
        assert!(owned.is_empty());

        let raw = secure_zeroed(8).cast();
        // SAFETY: secure_zeroed returns a fresh allocation whose first byte is
        // NUL, making it a valid empty string transferred to the secure strategy.
        let owned = unsafe { CryptoSecureClearString::from_raw(raw) }
            .expect("CRYPTO_secure_zalloc allocation");
        assert!(owned.is_empty());
    }
}

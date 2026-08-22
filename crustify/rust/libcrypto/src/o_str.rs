//! Length-aware cloning for ordinary OpenSSL byte buffers.

use core::ptr::{self, NonNull};

use ffibox::CLenCloned;

use libcrypto_sys as ffi;

use crate::mem::CryptoFree;

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
}

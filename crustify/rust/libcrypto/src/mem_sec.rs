//! Ownership strategies for OpenSSL secure-memory allocations.
//!
//! # Which allocator actually served the buffer
//!
//! `CRYPTO_secure_malloc` and `CRYPTO_secure_zalloc` hand back arena storage
//! only while the secure heap is up; before `CRYPTO_secure_malloc_init` has
//! succeeded, and after `CRYPTO_secure_malloc_done` has torn it down, they fall
//! through to `CRYPTO_malloc` / `CRYPTO_zalloc` and return an ordinary
//! allocation (`crypto/mem_sec.c`). Nothing at the allocation site says which
//! happened, and the state that decides it is process-global.
//!
//! Both strategies here absorb that: `CRYPTO_secure_free` and
//! `CRYPTO_secure_clear_free` open by asking `CRYPTO_secure_allocated`, which
//! is an arena address-range test (`sh_allocated`), and take the arena branch
//! or the `CRYPTO_free` branch accordingly. So an owner built over a
//! `CRYPTO_secure_zalloc` result is correct without knowing which allocator ran.
//!
//! The converse does not hold, and it is the one pairing rule of this module:
//! **the storage of an owner that may be secure must be released by a strategy
//! from this module.** [`crate::mem::CryptoFree`] and
//! [`crate::mem::CryptoClearFree`] end at `CRYPTO_free`, which passes an arena
//! address straight to the installed `free_fn` — so they are correct for the
//! fallback branch and wrong for the arena one. In the other direction these
//! strategies are a strict superset: an ordinary OpenSSL allocation is released
//! correctly here, just uncleansed by [`CryptoSecureFree`].
//!
//! Allocation-site metadata follows the `(NULL, 0)` convention documented on
//! [`crate::mem`]. Neither routine reads the pair itself; it reaches
//! `CRYPTO_free` on the fallback branch only, and the arena branch drops it.
//!
//! # What gets cleansed
//!
//! On the arena branch both routines cleanse `sh_actual_size(ptr)` — the whole
//! buddy-allocator block, which is the requested size rounded up — and neither
//! consults a caller-supplied length. The strategies differ only on the
//! fallback branch, where [`CryptoSecureFree`] releases the bytes untouched and
//! [`CryptoSecureClearFree`] first cleanses the byte count its owner reports.
//!
//! A drop is also not guaranteed to happen at all: both routines return without
//! freeing if `CRYPTO_THREAD_write_lock` on the secure-heap lock fails, leaking
//! the block. That is OpenSSL's behaviour on a failing lock, and it is a leak
//! rather than a soundness problem — nothing else observes the release.

use core::ffi::CStr;
use core::ptr::{self, NonNull};

use ffibox::{CDropped, CLenDropped, CrustifyStr};

use libcrypto_sys as ffi;

/// Wraps: CRYPTO_secure_free
/// Stateless lifecycle strategy for OpenSSL secure-memory allocations.
///
/// Releases storage obtained from `CRYPTO_secure_malloc` or
/// `CRYPTO_secure_zalloc`, whichever branch served it, and needs no length:
/// the arena recovers the block size itself and the fallback branch is a plain
/// `CRYPTO_free`.
///
/// It cleanses only what the arena cleanses. Storage that came from the
/// fallback branch — every allocation made before the secure heap is
/// initialized — is freed with its bytes intact. An owner whose contents are
/// secret and whose allocator may have fallen back wants
/// [`CryptoSecureClearFree`], which cleanses on that branch too.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoSecureFree;

/// An owned NUL-terminated string in OpenSSL secure storage.
pub type CryptoSecureString = CrustifyStr<CryptoSecureFree>;

// SAFETY: `CRYPTO_secure_free` settles exactly the one ownership debt this
// contract transfers, on either branch: it cleanses and returns an arena block
// to the secure heap, or releases an ordinary allocation through `CRYPTO_free`,
// choosing by the pointer's own address rather than by anything the caller
// asserts.
unsafe impl CDropped for CryptoSecureFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the trait contract requires uniquely owned storage from
        // OpenSSL's secure allocation API, which covers both the arena and the
        // ordinary allocation it falls back to. Null allocation-site metadata
        // is the convention documented on `crate::mem`.
        unsafe { ffi::CRYPTO_secure_free(obj.as_ptr().cast(), ptr::null(), 0) }
    }
}

// SAFETY: `CRYPTO_secure_free` never takes a length; it releases the whole
// allocation either way, so discarding the byte length loses nothing the
// allocator needs. It does mean the length is not used to cleanse: a buffer
// served by the fallback branch is released with its bytes intact.
unsafe impl CLenDropped for CryptoSecureFree {
    unsafe fn c_drop_len(ptr: *mut u8, _byte_len: usize) {
        // SAFETY: the trait contract requires uniquely owned storage from
        // OpenSSL's secure allocation API, which covers both the arena and the
        // ordinary allocation it falls back to. Null allocation-site metadata
        // is the convention documented on `crate::mem`.
        unsafe { ffi::CRYPTO_secure_free(ptr.cast(), ptr::null(), 0) }
    }
}

/// Wraps: CRYPTO_secure_clear_free
/// Length-aware strategy for secure or fallback ordinary OpenSSL buffers.
///
/// Releases the same two kinds of storage as [`CryptoSecureFree`] and always
/// cleanses. The byte count an owner reports is not the allocation size and is
/// not always read: on the arena branch `CRYPTO_secure_clear_free` ignores it
/// and cleanses `sh_actual_size(ptr)` — the whole block, which is at least the
/// requested size — while on the fallback branch that count is exactly the
/// `OPENSSL_cleanse` length. So it must not exceed the live bytes, and it fixes
/// how much survives: bytes past it are freed untouched when the secure heap
/// was not up.
///
/// Unlike `CRYPTO_clear_free`, there is no `if (num)` guard around the cleanse
/// (`crypto/mem.c` against `crypto/mem_sec.c`), but a zero count still reaches
/// `OPENSSL_cleanse(ptr, 0)`, a no-op, leaving the call equivalent to
/// [`CryptoSecureFree`].
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoSecureClearFree;

/// An owned secure OpenSSL string cleansed before release.
pub type CryptoSecureClearString = CrustifyStr<CryptoSecureClearFree>;

// This impl carries a precondition `CDropped` does not state: it recovers the
// cleanse length by scanning for a terminator, so `obj` must denote a live
// NUL-terminated allocation from the secure API rather than an arbitrary one.
// Both owners that consume a `CDropped` strategy reach it.
// `CrustifyStr<CryptoSecureClearFree>` (`CryptoSecureClearString`) upholds it
// by construction, its type invariant being exactly a live NUL-terminated
// string. `CVoidBox<CryptoSecureClearFree>` leaves it to the caller, whose
// `from_raw` obligation is that this strategy is the correct destructor for the
// allocation — which here includes the terminator. An erased blob carrying no
// terminator belongs in `CVec<u8, CryptoSecureClearFree>` instead, which
// supplies the length rather than recovering it.
//
// The recovered length matters only on the ordinary-allocation branch, and
// there only the logical string and its NUL are cleansed; bytes of a longer
// allocation past the terminator are freed untouched. On the arena branch C
// cleanses the whole block regardless of what is passed.
//
// SAFETY: `CRYPTO_secure_clear_free` cleanses and then releases the allocation
// on whichever branch its address selects, settling exactly the one ownership
// debt this contract transfers.
unsafe impl CDropped for CryptoSecureClearFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: this strategy is selected only for a live NUL-terminated
        // string, so scanning through its terminator is valid.
        let byte_len = unsafe { CStr::from_ptr(obj.as_ptr().cast()) }
            .to_bytes_with_nul()
            .len();
        // SAFETY: the trait contract transfers one secure or fallback OpenSSL
        // allocation; `byte_len` covers the live logical string including its
        // NUL, so it cannot exceed the storage `OPENSSL_cleanse` writes over.
        unsafe { ffi::CRYPTO_secure_clear_free(obj.as_ptr().cast(), byte_len, ptr::null(), 0) }
    }
}

// SAFETY: on the fallback branch `CRYPTO_secure_clear_free` cleanses exactly
// the byte count it is handed; the `CLenDropped` contract bounds that count by
// the allocation, which is what keeps the write in bounds, and a zero count is
// inside the contract too. On the arena branch the count is ignored and C
// cleanses the recovered block size instead.
unsafe impl CLenDropped for CryptoSecureClearFree {
    unsafe fn c_drop_len(ptr: *mut u8, byte_len: usize) {
        // SAFETY: the trait contract guarantees a uniquely owned OpenSSL secure
        // allocation (or its ordinary fallback) of `byte_len` bytes.
        unsafe { ffi::CRYPTO_secure_clear_free(ptr.cast(), byte_len, ptr::null(), 0) }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Once;
    use std::sync::atomic::{AtomicBool, Ordering};

    use ffibox::{CVec, CVoidBox};

    use super::*;

    /// Brings the secure heap up once for this test binary, and reports whether
    /// it is live.
    ///
    /// The strategies under test dispatch on which allocator served a pointer,
    /// so the interesting branch only exists while the arena is up. Every test
    /// here goes through this gate before allocating, which keeps the
    /// unsynchronized `secure_mem_initialized` read in `CRYPTO_secure_malloc`
    /// ordered after the write in `CRYPTO_secure_malloc_init` even though cargo
    /// runs these tests on parallel threads. The heap is never torn down:
    /// `CRYPTO_secure_malloc_done` would unmap the arena out from under any
    /// allocation another test still holds.
    fn secure_arena() -> bool {
        static INIT: Once = Once::new();
        static LIVE: AtomicBool = AtomicBool::new(false);

        INIT.call_once(|| {
            // SAFETY: `CRYPTO_secure_malloc_init` is called exactly once, before
            // this binary makes any secure allocation, and 64 KiB is a power of
            // two as it requires. A zero minimum size asks for the allocator's
            // own minimum.
            let ret = unsafe { ffi::CRYPTO_secure_malloc_init(1 << 16, 0) };
            LIVE.store(ret != 0, Ordering::Relaxed);
        });
        LIVE.load(Ordering::Relaxed)
    }

    fn secure_zeroed(byte_len: usize) -> *mut u8 {
        assert!(secure_arena(), "CRYPTO_secure_malloc_init");
        // SAFETY: this requests a fresh OpenSSL secure allocation and passes
        // null diagnostic metadata, which the allocator accepts.
        unsafe { ffi::CRYPTO_secure_zalloc(byte_len, ptr::null(), 0).cast() }
    }

    fn is_secure(ptr: *const u8) -> bool {
        // SAFETY: `CRYPTO_secure_allocated` only compares the pointer against
        // the arena bounds; it never dereferences it.
        unsafe { ffi::CRYPTO_secure_allocated(ptr.cast()) != 0 }
    }

    #[test]
    fn secure_allocations_come_from_the_arena() {
        let raw = secure_zeroed(8);
        assert!(
            is_secure(raw),
            "the live arena must serve CRYPTO_secure_zalloc, so the tests below \
             exercise the branch that recovers the block size"
        );
        // SAFETY: ownership of the fresh secure allocation is transferred to
        // its matching size-recovering release strategy.
        drop(unsafe { CVoidBox::<CryptoSecureFree>::from_raw(raw.cast()) });
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

    #[test]
    fn erased_secure_clear_free_owner_releases_a_terminated_allocation() {
        let raw = secure_zeroed(8);
        // SAFETY: the allocation is eight zero bytes, so it reads as an empty
        // NUL-terminated string — the precondition this strategy's `CDropped`
        // impl adds on top of the trait's own contract.
        let erased = unsafe { CVoidBox::<CryptoSecureClearFree>::from_raw(raw.cast()) };
        assert!(erased.is_some());
    }

    #[test]
    fn empty_secure_buffer_release_cleanses_nothing() {
        // SAFETY: `secure_zeroed` returns a unique eight-byte allocation, which
        // covers the zero byte length claimed here; the arena branch cleanses
        // the recovered block size regardless, and the fallback branch would
        // cleanse nothing before releasing the storage.
        let empty =
            unsafe { CVec::<u8, CryptoSecureClearFree>::from_raw_parts(secure_zeroed(8), 0) }
                .expect("CRYPTO_secure_zalloc allocation");
        assert!(empty.is_empty());
    }

    #[test]
    fn absent_secure_allocation_has_no_owner() {
        // Both routines return before anything else on a null pointer, so the
        // absent owner is exactly the one `from_raw_parts` refuses to build.
        // SAFETY: `from_raw_parts` explicitly admits a null pointer, which it
        // reports rather than adopting.
        let absent = unsafe { CVec::<u8, CryptoSecureFree>::from_raw_parts(ptr::null_mut(), 0) };
        assert!(absent.is_none());
    }
}

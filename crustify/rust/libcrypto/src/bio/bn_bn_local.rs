//! Wrappers assigned from `crypto/bn/bn_local.h`.

use core::ptr::NonNull;

use ffibox::{CCloner, CDropper, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: bignum_st
    ///
    /// OpenSSL publishes `BIGNUM` as an opaque type. The wrapper nevertheless
    /// retains pointer layout compatibility for C-owned allocations while its
    /// borrowed handles carry Rust lifetimes.
    Bignum,
    BignumRef,
    BignumMut,
    ffi::bignum_st
);

impl_dropped!(Bignum, ffi::bignum_st, ffi::BN_free);
impl_cloned!(Bignum, ffi::bignum_st, dup = ffi::BN_dup);

/// Selects `BN_clear_free` for an owned `Bignum` allocation.
#[derive(Clone, Copy, Debug, Default)]
pub struct BignumClearFree;

// SAFETY: `BN_clear_free` is the public clearing destructor for a fully
// initialized, uniquely owned `BIGNUM` allocation.
unsafe impl CDropper<Bignum> for BignumClearFree {
    unsafe fn c_drop(&self, ptr: NonNull<Bignum>) {
        // SAFETY: the `CDropper` contract supplies unique ownership and the
        // layout wrapper is pointer-compatible with `ffi::bignum_st`.
        unsafe { ffi::BN_clear_free(ptr.as_ptr().cast()) }
    }
}

// SAFETY: `BN_dup` creates a fresh allocation without changing its source;
// that allocation is valid for the stronger `BN_clear_free` destructor.
unsafe impl CCloner<Bignum> for BignumClearFree {
    unsafe fn c_clone(&self, ptr: NonNull<Bignum>) -> Option<NonNull<Bignum>> {
        // SAFETY: the `CCloner` contract supplies a live source and `BN_dup`
        // returns either null or a fresh initialized allocation.
        let duplicate = unsafe { ffi::BN_dup(ptr.as_ptr().cast()) };
        NonNull::new(duplicate.cast())
    }
}

/// An owning `BIGNUM` handle that clears its allocation before releasing it.
pub type ClearBignum = ffibox::CBoxWith<Bignum, BignumClearFree>;

#[cfg(test)]
mod tests {
    use ffibox::{CBox, CBoxWith};

    use super::*;

    #[test]
    fn ordinary_owner_clones_and_borrows() {
        // SAFETY: OpenSSL returns either null or a fresh initialized BIGNUM.
        let raw = unsafe { ffi::BN_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner,
        // whose `Bignum` strategy uses the matching `BN_free` destructor.
        let mut number = unsafe { CBox::<Bignum>::from_raw(raw) }.expect("BN_new");

        assert_eq!(number.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(number.as_mut().as_mut_ptr(), raw);

        let duplicate = number.try_clone().expect("BN_dup");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn clearing_owner_preserves_its_drop_policy_when_cloned() {
        // SAFETY: OpenSSL returns either null or a fresh initialized BIGNUM.
        let raw = unsafe { ffi::BN_new() };
        // SAFETY: ownership of the fresh result transfers to the clearing
        // strategy, for which `BN_clear_free` is a valid matching destructor.
        let number: ClearBignum =
            unsafe { CBoxWith::from_raw(raw, BignumClearFree) }.expect("BN_new for clearing owner");

        let duplicate = number.try_clone().expect("BN_dup for clearing owner");
        assert_ne!(duplicate.as_ptr(), raw);
    }
}

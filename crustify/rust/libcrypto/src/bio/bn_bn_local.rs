//! Wrappers assigned from `crypto/bn/bn_local.h`.

use core::ptr::NonNull;

use ffibox::{CCloner, CDropper, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: bignum_st
    ///
    /// `BIGNUM` is opaque on OpenSSL's public API and the generated bindings
    /// reflect that: `ffi::bignum_st` declares no fields. The wrapper is
    /// therefore a pointer-compatible handle target and nothing more — the
    /// `d`/`top`/`dmax`/`neg`/`flags` layout in `crypto/bn/bn_local.h` stays
    /// invisible, and [`Bignum::zeroed`] does **not** produce a usable
    /// `BIGNUM`. Every owner below starts from a pointer OpenSSL allocated.
    ///
    /// Both public destructors are self-gating: `BN_free` and `BN_clear_free`
    /// release the word buffer only when `BN_FLG_STATIC_DATA` is clear, and
    /// release the header only when `BN_FLG_MALLOCED` is set. So either may be
    /// called on any well-formed `BIGNUM`, but only one produced by `BN_new`,
    /// `BN_secure_new` or `BN_dup` is actually *owned*. A `BN_with_flags`
    /// view, a static prime from `bn_const.c`, or a `BIGNUM` embedded by value
    /// in a `BN_MONT_CTX` or `BN_RECP_CTX` must not be adopted by
    /// [`CBox`](ffibox::CBox) or [`ClearBignum`]: on those the destructors act
    /// as in-place field disposers driven by the enclosing object, not as
    /// releasers of storage this handle owns.
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
///
/// The type's second releaser. `BN_clear_free` accepts exactly the allocations
/// `BN_free` does and differs only in cleansing the words and the header on
/// the way out, so it is a policy chosen at the wrapping site rather than a
/// distinct ownership contract — a [`CDropper`] rather than a second
/// [`CDropped`](ffibox::CDropped). The strategy is a ZST, so this owner stays
/// pointer-sized, and cloning it keeps the clearing policy.
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
    fn both_owners_stay_pointer_sized() {
        // A ZST `CDropper` keeps `CBoxWith` layout-compatible with the raw
        // pointer, which is what lets either owner cross the FFI seam.
        assert_eq!(
            core::mem::size_of::<CBox<Bignum>>(),
            core::mem::size_of::<*mut ffi::bignum_st>()
        );
        assert_eq!(
            core::mem::size_of::<ClearBignum>(),
            core::mem::size_of::<*mut ffi::bignum_st>()
        );
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

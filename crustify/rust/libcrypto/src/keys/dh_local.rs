//! Wrappers assigned from `crypto/dh/dh_local.h`.

use core::ffi::c_void;
use core::marker::PhantomData;

use ffibox::{CBox, CType, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: dh_st
    ///
    /// Pointer-compatible handle target for OpenSSL's legacy finite-field
    /// Diffie-Hellman key. The public API exposes `DH` only as an opaque
    /// forward declaration, so its private parameters, keys, method state,
    /// ex-data, library context, lock, and reference count remain behind
    /// OpenSSL's call surface.
    ///
    /// An owning [`CBox<Dh>`] carries one reference count and is deliberately
    /// not `Clone`: `DH_up_ref` creates another share of the same key, which
    /// must not grant a second exclusive handle. A share is represented by
    /// [`SharedDh`]. [`DhRef::try_dup_params`] instead creates an independent
    /// mutable object containing a deep copy of the domain parameters; it does
    /// not copy the key pair.
    ///
    /// A `DH` made with a non-default library context or a caller-supplied
    /// method table borrows those objects. Such producers use [`BorrowedDh`]
    /// to retain that dependency in Rust; adopting a raw pointer as a plain
    /// `CBox` takes on the obligation that its borrowed C dependencies outlive
    /// it.
    Dh,
    DhRef,
    DhMut,
    ffi::dh_st
);

// `DH_free` is the public down-reference operation. On the final count it runs
// the active method's finish hook, releases ex-data, the lock, FFC parameters,
// public and private keys, and the allocation.
impl_dropped!(Dh, ffi::dh_st, ffi::DH_free);

// `Dh` intentionally has no `CCloned` implementation. An `up_ref` clone would
// make `CBox::as_mut` available on two owners of the same allocation, while
// `DHparams_dup` is not a semantic `Clone` because it omits the key pair.

/// An independently owned key whose C dependencies are borrowed for `'a`.
#[must_use = "dropping the owner releases its DH reference"]
pub struct BorrowedDh<'a> {
    inner: CBox<Dh>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedDh<'_> {
    pub(crate) unsafe fn from_raw(raw: *mut ffi::dh_st) -> Option<Self> {
        // SAFETY: the caller transfers one fully initialized DH reference;
        // this owner settles it through the registered `DH_free` down-ref.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the key without write access.
    #[must_use]
    pub fn as_ref(&self) -> DhRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the independently owned key.
    #[must_use]
    pub fn as_mut(&mut self) -> DhMut<'_> {
        self.inner.as_mut()
    }
}

/// One extra reference count to a key, granting shared access only.
pub type SharedDh<'a> = crate::refcount::SharedRef<'a, Dh>;

impl DhRef<'_> {
    /// Deep-copy the domain parameters into a new default-context `DH`.
    ///
    /// The public and private key values are deliberately not copied.
    #[must_use]
    pub fn try_dup_params(self) -> Option<BorrowedDh<'static>> {
        // SAFETY: the handle carries a live shared borrow. `DHparams_dup` only
        // reads the source and returns null or a fresh, fully initialized DH
        // with an independent parameter set and reference count.
        let duplicate = unsafe { ffi::DHparams_dup(self.as_ptr()) };
        // SAFETY: a non-null result transfers one independent `DH_free`
        // obligation and uses the default context and method, so it retains no
        // dependency borrowed from the source.
        unsafe { BorrowedDh::from_raw(duplicate) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn opaque_owner_borrows_and_duplicates_parameters() {
        // SAFETY: OpenSSL returns null or a fresh fully initialized,
        // reference-count-one DH allocation using the default context.
        let raw = unsafe { ffi::DH_new() };
        // SAFETY: ownership of the fresh default-context result transfers once
        // to the owner whose registered down-reference is `DH_free`.
        let mut key = unsafe { CBox::<Dh>::from_raw(raw) }.expect("DH_new");

        assert_eq!(key.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(key.as_mut().as_mut_ptr(), raw);

        let duplicate = key.as_ref().try_dup_params().expect("DHparams_dup");
        assert_ne!(duplicate.as_ref().as_ptr(), raw.cast_const());
    }

    #[test]
    fn opaque_handles_and_owner_are_pointer_sized() {
        assert_eq!(size_of::<DhRef<'static>>(), size_of::<*const ffi::dh_st>());
        assert_eq!(size_of::<DhMut<'static>>(), size_of::<*mut ffi::dh_st>());
        assert_eq!(size_of::<CBox<Dh>>(), size_of::<*mut ffi::dh_st>());
    }
}

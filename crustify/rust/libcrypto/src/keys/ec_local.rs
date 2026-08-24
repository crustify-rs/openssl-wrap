//! Wrappers assigned from `crypto/ec/ec_local.h`.

use core::ffi::c_void;
use core::marker::PhantomData;

use ffibox::{CBox, CType, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: ec_key_st
    ///
    /// Pointer-compatible handle target for OpenSSL's legacy elliptic-curve
    /// key. The public API exposes `EC_KEY` only as an opaque forward
    /// declaration, so its private method, group, point, scalar, ex-data,
    /// library-context, and property-query fields remain behind OpenSSL's call
    /// surface.
    ///
    /// An owning [`CBox<EcKey>`] carries one reference count and is
    /// deliberately not `Clone`: `EC_KEY_up_ref` creates another share of the
    /// same key, which must not grant a second exclusive handle. A share is
    /// represented by [`SharedEcKey`], while [`EcKeyRef::try_dup`] creates an
    /// independent, mutable key.
    ///
    /// Keys made with a non-default library context or a caller-supplied
    /// method table borrow those objects. Such producers use
    /// [`BorrowedEcKey`] to retain that dependency in Rust; adopting a raw
    /// pointer as a plain `CBox` takes on the obligation that its borrowed C
    /// dependencies outlive it.
    EcKey,
    EcKeyRef,
    EcKeyMut,
    ffi::ec_key_st
);

// `EC_KEY_free` is the public down-reference operation. On the final count it
// runs the method hooks, releases the owned group, public point, private
// scalar, property query and ex-data, and clears the key allocation.
impl_dropped!(EcKey, ffi::ec_key_st, ffi::EC_KEY_free);

// `EcKey` intentionally has no `CCloned` implementation. An `up_ref` clone
// would make `CBox::as_mut` available on two owners of the same allocation.
// `SharedEcKey` is the shared-only owner for extra counts; deep duplication is
// exposed separately below.

/// An independently owned key whose C dependencies are borrowed for `'a`.
#[must_use = "dropping the owner releases its EC_KEY reference"]
pub struct BorrowedEcKey<'a> {
    inner: CBox<EcKey>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedEcKey<'_> {
    pub(crate) unsafe fn from_raw(raw: *mut ffi::ec_key_st) -> Option<Self> {
        // SAFETY: the caller transfers one fully initialized key reference;
        // this owner settles it through the registered `EC_KEY_free` down-ref.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the key without write access.
    #[must_use]
    pub fn as_ref(&self) -> EcKeyRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the independently owned key.
    #[must_use]
    pub fn as_mut(&mut self) -> EcKeyMut<'_> {
        self.inner.as_mut()
    }
}

/// One extra reference count to a key, granting shared access only.
pub type SharedEcKey<'a> = crate::refcount::SharedRef<'a, EcKey>;

impl<'a> EcKeyRef<'a> {
    /// Create an independently owned deep copy of this key.
    #[must_use]
    pub fn try_dup(self) -> Option<BorrowedEcKey<'a>> {
        // SAFETY: the handle carries a live shared borrow. `EC_KEY_dup` only
        // reads the source and returns null or a fresh initialized key with
        // its own reference count.
        let duplicate = unsafe { ffi::EC_KEY_dup(self.as_ptr()) };
        // SAFETY: a non-null result transfers one independent `EC_KEY_free`
        // obligation and retains no C borrow beyond those carried by `self`.
        unsafe { BorrowedEcKey::from_raw(duplicate) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn opaque_owner_borrows_and_duplicates_deeply() {
        // SAFETY: OpenSSL returns null or a fresh fully initialized,
        // reference-count-one EC_KEY allocation using the default context.
        let raw = unsafe { ffi::EC_KEY_new() };
        // SAFETY: ownership of the fresh default-context result transfers once
        // to the owner whose registered down-reference is `EC_KEY_free`.
        let mut key = unsafe { CBox::<EcKey>::from_raw(raw) }.expect("EC_KEY_new");

        assert_eq!(key.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(key.as_mut().as_mut_ptr(), raw);

        let duplicate = key.as_ref().try_dup().expect("EC_KEY_dup");
        assert_ne!(duplicate.as_ref().as_ptr(), raw.cast_const());
    }

    #[test]
    fn opaque_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<EcKeyRef<'static>>(),
            size_of::<*const ffi::ec_key_st>()
        );
        assert_eq!(
            size_of::<EcKeyMut<'static>>(),
            size_of::<*mut ffi::ec_key_st>()
        );
        assert_eq!(size_of::<CBox<EcKey>>(), size_of::<*mut ffi::ec_key_st>());
    }
}

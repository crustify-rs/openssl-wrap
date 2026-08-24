//! Wrappers assigned from `crypto/dsa/dsa_local.h`.

use core::ffi::c_void;
use core::marker::PhantomData;

use ffibox::{CBox, CType, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: dsa_st
    ///
    /// Pointer-compatible target for OpenSSL's legacy DSA key. The public API
    /// exposes `DSA` only as an opaque forward declaration, so parameters,
    /// key material, caches, ex-data, locking, library context, and method
    /// dispatch remain behind OpenSSL's call surface.
    ///
    /// An owning [`CBox<Dsa>`] carries one reference count and deliberately
    /// is not `Clone`: `DSA_up_ref` creates another share of the same key,
    /// which must not grant a second exclusive handle. Such a count is held
    /// by [`SharedDsa`]. [`DsaRef::try_dup_parameters`] instead makes an
    /// independent DSA containing a deep copy of the domain parameters.
    ///
    /// A DSA created with an external library context or method table borrows
    /// that dependency. Its Rust owner is [`BorrowedDsa`]; adopting such a
    /// pointer as a plain `CBox` requires the adopter to keep the dependencies
    /// alive for the owner's entire lifetime.
    Dsa,
    DsaRef,
    DsaMut,
    ffi::dsa_st
);

// `DSA_free` is OpenSSL's public down-reference operation. The final count
// releases the method hook, ex-data, lock, parameters, key material, and the
// allocation itself.
impl_dropped!(Dsa, ffi::dsa_st, ffi::DSA_free);

// An up-ref is intentionally not registered as `CCloned`: `CBox::as_mut`
// would then be reachable through two owners of the same allocation. Extra
// counts use `SharedDsa`, which exposes shared access only.

/// A DSA owner whose C method table or library context is borrowed for `'a`.
#[must_use = "dropping the owner releases its DSA reference"]
pub struct BorrowedDsa<'a> {
    inner: CBox<Dsa>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedDsa<'_> {
    /// Adopt one fully initialized DSA reference with borrowed dependencies.
    ///
    /// # Safety
    ///
    /// `raw` must be null or transfer exactly one live DSA reference. Every
    /// method table and library context retained by it must outlive the
    /// returned owner's inferred lifetime.
    pub unsafe fn from_raw(raw: *mut ffi::dsa_st) -> Option<Self> {
        // SAFETY: the caller transfers one fully initialized DSA reference;
        // this owner settles it through the registered `DSA_free` down-ref.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the DSA without write access.
    #[must_use]
    pub fn as_ref(&self) -> DsaRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow this independently owned DSA.
    #[must_use]
    pub fn as_mut(&mut self) -> DsaMut<'_> {
        self.inner.as_mut()
    }
}

/// One extra reference count to a DSA, granting shared access only.
pub type SharedDsa<'a> = crate::refcount::SharedRef<'a, Dsa>;

impl DsaRef<'_> {
    /// Deep-copy the domain parameters into a new, independently owned DSA.
    #[must_use]
    pub fn try_dup_parameters(self) -> Option<CBox<Dsa>> {
        // SAFETY: the handle carries a live shared borrow. `DSAparams_dup`
        // only reads it and returns null or a fresh reference-count-one DSA.
        let duplicate = unsafe { ffi::DSAparams_dup(self.as_ptr()) };
        // SAFETY: a non-null result transfers one fully initialized DSA
        // reference whose matching down-reference is `DSA_free`.
        unsafe { CBox::from_raw(duplicate) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use super::*;

    #[test]
    fn opaque_owner_borrows_duplicates_parameters_and_shares() {
        // SAFETY: OpenSSL returns null or a fresh, fully initialized,
        // reference-count-one DSA using the default context and method.
        let raw = unsafe { ffi::DSA_new() };
        // SAFETY: ownership of that fresh default-context result transfers
        // once to the owner whose registered down-reference is `DSA_free`.
        let mut dsa = unsafe { CBox::<Dsa>::from_raw(raw) }.expect("DSA_new");

        assert_eq!(dsa.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(dsa.as_mut().as_mut_ptr(), raw);

        // A fresh DSA has no domain parameters, so the ASN.1 parameter
        // duplicator reports failure without changing or consuming `dsa`.
        assert!(dsa.as_ref().try_dup_parameters().is_none());

        // SAFETY: `raw` remains live through `dsa`; success creates exactly
        // one additional reference count on that allocation.
        assert_eq!(unsafe { ffi::DSA_up_ref(raw) }, 1);
        // SAFETY: the successful increment transfers that extra count to a
        // shared-only owner bounded by the original DSA borrow.
        let shared = unsafe { SharedDsa::from_raw(raw) }.expect("DSA_up_ref pointer");
        assert_eq!(shared.as_ref().as_ptr(), dsa.as_ref().as_ptr());
    }

    #[test]
    fn opaque_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<DsaRef<'static>>(),
            size_of::<*const ffi::dsa_st>()
        );
        assert_eq!(size_of::<DsaMut<'static>>(), size_of::<*mut ffi::dsa_st>());
        assert_eq!(size_of::<CBox<Dsa>>(), size_of::<*mut ffi::dsa_st>());
        assert_eq!(
            size_of::<SharedDsa<'static>>(),
            size_of::<*mut ffi::dsa_st>()
        );
    }
}

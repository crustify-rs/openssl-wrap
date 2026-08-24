//! Wrappers assigned from `crypto/rsa/rsa_local.h`.

use ffibox::{define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: rsa_st
    ///
    /// Pointer-compatible handle target for OpenSSL's legacy RSA key. The
    /// public API exposes `RSA` only as an opaque forward declaration, so its
    /// key components, method table, library context, caches, blinding state,
    /// ex-data, and lock remain behind OpenSSL's call surface.
    ///
    /// An owning [`ffibox::CBox<Rsa>`] carries one reference count and is
    /// deliberately not `Clone`: [`RsaRef::try_share`] creates another count
    /// naming the same key, so it returns a shared-only [`SharedRsa`] that
    /// cannot produce an exclusive handle.
    Rsa,
    RsaRef,
    RsaMut,
    ffi::rsa_st
);

// `RSA_free` is the public down-reference operation. On the final count it
// invokes the method finish hook, clears the private key material, releases
// the public components, PSS and multiprime state, ex-data, blinding storage,
// lock, and the key allocation.
impl_dropped!(Rsa, ffi::rsa_st, ffi::RSA_free);

// An up-ref aliases the same mutable C allocation, so registering it as
// `CCloned` would let two `CBox<Rsa>` owners each produce an exclusive handle.
// Extra counts instead use the shared-only owner below.

/// One extra reference count to an RSA key, granting shared access only.
pub type SharedRsa<'a> = crate::refcount::SharedRef<'a, Rsa>;

impl<'a> RsaRef<'a> {
    /// Raise the key's reference count without granting write access.
    #[must_use]
    pub fn try_share(self) -> Option<SharedRsa<'a>> {
        let raw = self.as_ptr().cast_mut();
        // SAFETY: `self` carries a live shared borrow of `raw`; RSA's
        // reference count is explicitly safe to increment through a shared
        // handle and a successful call creates exactly one matching down-ref.
        if unsafe { ffi::RSA_up_ref(raw) } != 1 {
            return None;
        }
        // SAFETY: the successful up-ref transfers one new count. The returned
        // shared-only owner is lifetime-bound to the source borrow and settles
        // that count through `RSA_free`.
        unsafe { SharedRsa::from_raw(raw) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn opaque_owner_produces_typed_borrows_and_shared_counts() {
        assert_owned_cell::<Rsa>();

        // SAFETY: OpenSSL returns null or a fresh, fully initialized,
        // reference-count-one RSA allocation using the default context and
        // method table.
        let raw = unsafe { ffi::RSA_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner
        // whose registered down-reference operation is `RSA_free`.
        let mut key = unsafe { CBox::<Rsa>::from_raw(raw) }.expect("RSA_new");

        assert_eq!(key.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(key.as_mut().as_mut_ptr(), raw);

        let shared = key.as_ref().try_share().expect("RSA_up_ref");
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
        drop(shared);

        // Once the lifetime-bound share is gone, the original owner regains
        // its exclusive route.
        assert_eq!(key.as_mut().as_mut_ptr(), raw);
    }

    #[test]
    fn opaque_handles_and_owner_are_pointer_sized() {
        assert_eq!(
            size_of::<RsaRef<'static>>(),
            size_of::<*const ffi::rsa_st>()
        );
        assert_eq!(size_of::<RsaMut<'static>>(), size_of::<*mut ffi::rsa_st>());
        assert_eq!(size_of::<CBox<Rsa>>(), size_of::<*mut ffi::rsa_st>());
        assert_eq!(
            size_of::<SharedRsa<'static>>(),
            size_of::<*mut ffi::rsa_st>()
        );
    }
}

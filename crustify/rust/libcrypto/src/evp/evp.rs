//! Wrappers assigned from `include/crypto/evp.h`.

use ffibox::{CBox, define_ctype, impl_cloned, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: evp_pkey_st
    ///
    /// OpenSSL publishes `EVP_PKEY` as an opaque, reference-counted key
    /// container. Its allocation and fields remain C-owned; this layout
    /// wrapper only supplies the pointer-compatible target used by owning and
    /// lifetime-bound borrowed handles.
    ///
    /// An owning [`CBox<EvpPkey>`] carries one reference count. Cloning that
    /// owner calls `EVP_PKEY_up_ref`, so both owners identify the same key and
    /// each eventually pays one `EVP_PKEY_free`. Use [`EvpPkeyRef::try_dup`]
    /// when an independent deep copy is required instead.
    EvpPkey,
    EvpPkeyRef,
    EvpPkeyMut,
    ffi::evp_pkey_st
);

// `EVP_PKEY_free` is the public down-reference operation. It accepts null;
// for a live owner it decrements the atomic reference count and, on the final
// count, releases the provider or legacy key material, attributes, operation
// cache, ex-data, lock, and allocation.
impl_dropped!(EvpPkey, ffi::evp_pkey_st, ffi::EVP_PKEY_free);

// A cloned owner is another reference to the same object. `EVP_PKEY_up_ref`
// atomically increments the count and reports failure without creating an
// ownership debt, which is the refcounted form of the `CCloned` contract.
impl_cloned!(EvpPkey, ffi::evp_pkey_st, up_ref = ffi::EVP_PKEY_up_ref);

impl EvpPkeyRef<'_> {
    /// Create an independently owned deep copy of this key container.
    ///
    /// This differs from cloning an owning handle: `try_dup` copies the key
    /// material, attributes, and auxiliary data into a fresh `EVP_PKEY`, while
    /// an owner clone only increments this object's reference count.
    #[must_use]
    pub fn try_dup(&self) -> Option<CBox<EvpPkey>> {
        // SAFETY: the handle carries a live shared borrow. Although the C
        // declaration predates const-correctness, `EVP_PKEY_dup` only reads
        // its source and returns null or a fresh fully initialized allocation.
        let duplicate = unsafe { ffi::EVP_PKEY_dup(self.as_ptr().cast_mut()) };
        // SAFETY: a non-null duplicate transfers one independent
        // `EVP_PKEY_free` obligation to the caller.
        unsafe { CBox::from_raw(duplicate) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_clones_by_reference_and_duplicates_deeply() {
        // SAFETY: OpenSSL returns null or a fresh fully initialized,
        // reference-count-one `EVP_PKEY` allocation.
        let raw = unsafe { ffi::EVP_PKEY_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner,
        // whose registered down-reference is `EVP_PKEY_free`.
        let mut key = unsafe { CBox::<EvpPkey>::from_raw(raw) }.expect("EVP_PKEY_new");

        assert_eq!(key.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(key.as_mut().as_mut_ptr(), raw);

        let shared = key.try_clone().expect("EVP_PKEY_up_ref");
        assert_eq!(shared.as_ptr(), raw);
        drop(shared);

        let duplicate = key.as_ref().try_dup().expect("EVP_PKEY_dup");
        assert_ne!(duplicate.as_ptr(), raw);
        assert_eq!(duplicate.as_ref().as_ptr(), duplicate.as_ptr().cast_const());
    }
}

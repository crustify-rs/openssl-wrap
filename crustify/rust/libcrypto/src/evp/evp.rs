//! Wrappers assigned from `include/crypto/evp.h`.

use ffibox::{CBox, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: evp_pkey_st
    ///
    /// OpenSSL publishes `EVP_PKEY` as an opaque, reference-counted key
    /// container. Its allocation and fields remain C-owned; this layout
    /// wrapper only supplies the pointer-compatible target used by owning and
    /// lifetime-bound borrowed handles.
    ///
    /// An owning [`CBox<EvpPkey>`] carries one reference count and is
    /// deliberately not `Clone`: a second count names the same key, so every
    /// wrapper that raises one hands back a shared-only [`SharedEvpPkey`]
    /// rather than an owner with an exclusive handle. Use
    /// [`EvpPkeyRef::try_dup`] when an independent deep copy is required.
    ///
    /// The record itself stores no `OSSL_LIB_CTX`, but a provider-backed key
    /// reaches its library context through the `EVP_KEYMGMT` it holds. This
    /// owner does not track that dependency, so a key built in a non-default
    /// context relies on OpenSSL's own rule that the context outlives every
    /// object created from it. Containers that store the context pointer in a
    /// field instead express it in the type, as `BorrowedX509Pubkey` does.
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

// `EVP_PKEY` is reference counted, so it deliberately has **no** `CCloned`
// impl. Registering `EVP_PKEY_up_ref` there would give `CBox<EvpPkey>` a
// `Clone` taking only `&self`, and the resulting second owner's
// `CBox::as_mut` would assert an exclusivity the count cannot provide. Every
// wrapper that raises the count — `X509_get_pubkey`, `X509_PUBKEY_get` —
// returns [`SharedEvpPkey`] instead. [`EvpPkeyRef::try_dup`] remains the route
// to an independent, mutable copy.

/// One owned reference to a key that other owners may also hold.
///
/// A key reached by raising the reference count has no borrowed dependency of
/// its own — the record stores no `OSSL_LIB_CTX` — so the share is unbounded.
pub type SharedEvpPkey = crate::refcount::SharedRef<'static, EvpPkey>;

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
    fn owner_borrows_and_duplicates_deeply() {
        // SAFETY: OpenSSL returns null or a fresh fully initialized,
        // reference-count-one `EVP_PKEY` allocation.
        let raw = unsafe { ffi::EVP_PKEY_new() };
        // SAFETY: ownership of the fresh result transfers once to the owner,
        // whose registered down-reference is `EVP_PKEY_free`.
        let mut key = unsafe { CBox::<EvpPkey>::from_raw(raw) }.expect("EVP_PKEY_new");

        assert_eq!(key.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(key.as_mut().as_mut_ptr(), raw);

        let duplicate = key.as_ref().try_dup().expect("EVP_PKEY_dup");
        assert_ne!(duplicate.as_ptr(), raw);
        assert_eq!(duplicate.as_ref().as_ptr(), duplicate.as_ptr().cast_const());
    }
}

define_ctype!(
    /// Wraps: evp_cipher_st
    ///
    /// OpenSSL publishes `EVP_CIPHER` as an opaque cipher implementation.
    /// Provider-backed records retain their provider and are reference
    /// counted, while legacy records are static. Both kinds use the public
    /// `EVP_CIPHER_up_ref` / `EVP_CIPHER_free` pair: for cached or static
    /// records those operations are deliberately no-ops.
    ///
    /// An owning reference is exposed as [`SharedEvpCipher`], not as a public
    /// `CBox<EvpCipher>`, because fetches and reference-count increments may
    /// name the same record and therefore cannot grant exclusive access.
    EvpCipher,
    EvpCipherRef,
    EvpCipherMut,
    ffi::evp_cipher_st
);

// `EVP_CIPHER_free` is the public down-reference operation. Depending on the
// cipher's origin and cache policy it either decrements the dynamic record or
// is a no-op, exactly matching `EVP_CIPHER_up_ref`.
impl_dropped!(EvpCipher, ffi::evp_cipher_st, ffi::EVP_CIPHER_free);

// Do not register `EVP_CIPHER_up_ref` as `CCloned`: that would make
// `CBox<EvpCipher>` cloneable even though every clone could call `as_mut` on
// the same record. `SharedEvpCipher` intentionally grants shared access only.

/// One owned reference to a cipher implementation.
///
/// The lifetime carries the library-context dependency of a fetched cipher.
/// A cipher selected from the default context may use `'static`; a fetch from
/// an explicit context must use that context's borrow.
pub type SharedEvpCipher<'a> = crate::refcount::SharedRef<'a, EvpCipher>;

impl<'a> EvpCipherRef<'a> {
    /// Raise this cipher's public reference and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpCipher<'a>> {
        // SAFETY: the handle carries a live shared borrow. OpenSSL may update
        // the dynamic record's atomic reference count but does not otherwise
        // mutate it, and reports whether it created the matching public
        // release obligation.
        if unsafe { ffi::EVP_CIPHER_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful `EVP_CIPHER_up_ref` creates one matching
        // `EVP_CIPHER_free` obligation. The share retains the handle's
        // library-context lifetime and exposes no exclusive access.
        unsafe { SharedEvpCipher::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod cipher_tests {
    use core::ptr;

    use super::*;

    #[test]
    fn fetched_cipher_and_raised_reference_are_shared_only() {
        // SAFETY: null selects the process-wide default library context, the
        // algorithm name is a live NUL-terminated string, and a null property
        // query requests the default selection. A non-null result transfers
        // one public EVP_CIPHER reference.
        let raw =
            unsafe { ffi::EVP_CIPHER_fetch(ptr::null_mut(), c"AES-128-CBC".as_ptr(), ptr::null()) };
        // SAFETY: the default library context is process-wide, and the fresh
        // fetch result transfers one `EVP_CIPHER_free` obligation.
        let cipher: SharedEvpCipher<'static> =
            unsafe { SharedEvpCipher::from_raw(raw) }.expect("EVP_CIPHER_fetch");

        let shared = cipher.as_ref().try_share().expect("EVP_CIPHER_up_ref");
        assert_eq!(shared.as_ptr(), cipher.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }
}

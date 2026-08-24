//! Wrappers assigned from `crypto/evp/evp_local.h`.

use ffibox::{define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: evp_keymgmt_st
    ///
    /// Pointer-compatible target for OpenSSL's provider key-management method.
    /// The public API exposes `EVP_KEYMGMT` as an opaque handle, so its provider
    /// reference, names, reference count, and provider dispatch table remain
    /// behind OpenSSL's call surface.
    ///
    /// The method is reference counted. A sole owner may use
    /// [`ffibox::CBox<EvpKeymgmt>`], while a raised or fetched shared reference
    /// must use [`SharedEvpKeymgmt`] so safe code cannot obtain exclusive access
    /// to an allocation that another owner can reach.
    EvpKeymgmt,
    EvpKeymgmtRef,
    EvpKeymgmtMut,
    ffi::evp_keymgmt_st
);

// `EVP_KEYMGMT_free` is the public release operation. For an uncached method it
// decrements the reference count and, at zero, releases the owned name and
// provider reference before freeing the allocation. Cached methods deliberately
// retain their cache-owned lifetime and accept this operation as a no-op.
impl_dropped!(EvpKeymgmt, ffi::evp_keymgmt_st, ffi::EVP_KEYMGMT_free);

// Do not register `EVP_KEYMGMT_up_ref` as `CCloned`: cloning a CBox would give
// two owners exclusive `as_mut` access to the same reference-counted method.
/// One owned, shared-only reference to an `EVP_KEYMGMT` method.
pub type SharedEvpKeymgmt = crate::refcount::SharedRef<'static, EvpKeymgmt>;

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn opaque_keymgmt_has_typed_borrow_handles() {
        assert_owned_cell::<EvpKeymgmt>();

        assert_eq!(
            size_of::<EvpKeymgmtRef<'static>>(),
            size_of::<*const ffi::evp_keymgmt_st>()
        );
        assert_eq!(
            size_of::<EvpKeymgmtMut<'static>>(),
            size_of::<*mut ffi::evp_keymgmt_st>()
        );
        assert_eq!(
            size_of::<CBox<EvpKeymgmt>>(),
            size_of::<*mut ffi::evp_keymgmt_st>()
        );
    }
}
define_ctype!(
    /// Wraps: evp_signature_st
    ///
    /// OpenSSL publishes `EVP_SIGNATURE` as an opaque, reference-counted
    /// provider method record. The record retains its provider, which keeps
    /// its borrowed dispatch functions and description available, and owns a
    /// copy of its algorithm name.
    ///
    /// Public fetch and up-reference operations may return the same cached
    /// record, so safe owning APIs use [`SharedEvpSignature`] and expose only
    /// shared borrows. The layout wrapper remains available for embedding and
    /// for explicit lower-level interoperability, but callers must not turn a
    /// shared reference count into exclusive access.
    EvpSignature,
    EvpSignatureRef,
    EvpSignatureMut,
    ffi::evp_signature_st
);

// `EVP_SIGNATURE_free` is the public down-reference operation. For an
// uncached `no_store` record it releases the provider, copied name, and
// allocation on the final count; for a cached record it is deliberately a
// no-op matching `EVP_SIGNATURE_up_ref`.
impl_dropped!(EvpSignature, ffi::evp_signature_st, ffi::EVP_SIGNATURE_free);

// Do not register `EVP_SIGNATURE_up_ref` as `CCloned`: a cloned `CBox` would
// expose an exclusive handle to a record shared by several reference counts.

/// One owned, shared-only reference to a provider signature method.
///
/// The lifetime carries the library-context dependency of a fetched method.
/// A method selected from the default context may use `'static`; a fetch from
/// an explicit context must retain that context's borrow.
pub type SharedEvpSignature<'a> = crate::refcount::SharedRef<'a, EvpSignature>;

impl<'a> EvpSignatureRef<'a> {
    /// Raise this method's public reference and return a shared-only owner.
    #[must_use]
    pub fn try_share(&self) -> Option<SharedEvpSignature<'a>> {
        // SAFETY: the handle carries a live shared borrow. OpenSSL may update
        // the method's atomic reference count but does not otherwise mutate
        // it, and reports whether it created the matching release obligation.
        if unsafe { ffi::EVP_SIGNATURE_up_ref(self.as_ptr().cast_mut()) } != 1 {
            return None;
        }

        // SAFETY: successful `EVP_SIGNATURE_up_ref` creates one matching
        // `EVP_SIGNATURE_free` obligation (or the paired cached no-op). The
        // shared owner preserves the handle's library-context lifetime.
        unsafe { SharedEvpSignature::from_raw(self.as_ptr().cast_mut()) }
    }
}

#[cfg(test)]
mod signature_tests {
    use core::ptr;

    use super::*;

    #[test]
    fn fetched_signature_and_raised_reference_are_shared_only() {
        // SAFETY: null selects the process-wide default library context, the
        // algorithm name is a live NUL-terminated string, and a null property
        // query requests the default selection. A non-null result transfers
        // one public EVP_SIGNATURE reference.
        let raw =
            unsafe { ffi::EVP_SIGNATURE_fetch(ptr::null_mut(), c"RSA".as_ptr(), ptr::null()) };
        // SAFETY: the default library context is process-wide, and the fetch
        // result transfers one matching `EVP_SIGNATURE_free` obligation.
        let signature: SharedEvpSignature<'static> =
            unsafe { SharedEvpSignature::from_raw(raw) }.expect("EVP_SIGNATURE_fetch");

        let shared = signature
            .as_ref()
            .try_share()
            .expect("EVP_SIGNATURE_up_ref");
        assert_eq!(shared.as_ptr(), signature.as_ptr());
        assert_eq!(shared.as_ref().as_ptr(), raw.cast_const());
    }
}

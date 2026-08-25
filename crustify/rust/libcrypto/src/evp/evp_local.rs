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
///
/// The lifetime retains the library context from which a method was fetched.
/// A method fetched from the process-wide default context may use `'static`.
pub type SharedEvpKeymgmt<'a> = crate::refcount::SharedRef<'a, EvpKeymgmt>;

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

define_ctype!(
    /// Wraps: evp_skeymgmt_st
    ///
    /// Pointer-compatible target for OpenSSL's provider symmetric-key
    /// management method. The public API exposes `EVP_SKEYMGMT` as an opaque
    /// handle, so its provider reference, names, reference count, and provider
    /// dispatch table remain behind OpenSSL's call surface.
    ///
    /// The method is reference counted. A sole owner may use
    /// [`ffibox::CBox<EvpSkeymgmt>`], while a raised or fetched shared reference
    /// must use [`SharedEvpSkeymgmt`] so safe code cannot obtain exclusive
    /// access to an allocation that another owner can reach.
    EvpSkeymgmt,
    EvpSkeymgmtRef,
    EvpSkeymgmtMut,
    ffi::evp_skeymgmt_st
);

// `EVP_SKEYMGMT_free` is the public release operation. For an uncached method
// it decrements the reference count and, at zero, releases the owned name and
// provider reference before freeing the allocation. Cached methods deliberately
// retain their cache-owned lifetime and accept this operation as a no-op.
impl_dropped!(EvpSkeymgmt, ffi::evp_skeymgmt_st, ffi::EVP_SKEYMGMT_free);

// Do not register `EVP_SKEYMGMT_up_ref` as `CCloned`: cloning a CBox would give
// two owners exclusive `as_mut` access to the same reference-counted method.
/// One owned, shared-only reference to an `EVP_SKEYMGMT` method.
pub type SharedEvpSkeymgmt = crate::refcount::SharedRef<'static, EvpSkeymgmt>;

#[cfg(test)]
mod skeymgmt_tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn opaque_skeymgmt_has_typed_borrow_handles() {
        assert_owned_cell::<EvpSkeymgmt>();

        assert_eq!(
            size_of::<EvpSkeymgmtRef<'static>>(),
            size_of::<*const ffi::evp_skeymgmt_st>()
        );
        assert_eq!(
            size_of::<EvpSkeymgmtMut<'static>>(),
            size_of::<*mut ffi::evp_skeymgmt_st>()
        );
        assert_eq!(
            size_of::<CBox<EvpSkeymgmt>>(),
            size_of::<*mut ffi::evp_skeymgmt_st>()
        );
        assert_eq!(
            size_of::<SharedEvpSkeymgmt>(),
            size_of::<*mut ffi::evp_skeymgmt_st>()
        );
    }
}

define_ctype!(
    /// Wraps: evp_md_ctx_st
    ///
    /// Pointer-compatible target for OpenSSL's opaque digest context. The
    /// active digest, provider state, optional public-key context, and their
    /// runtime-dependent ownership remain behind the public `EVP_MD_CTX_*`
    /// call surface rather than becoming Rust field accessors.
    ///
    /// An owning [`ffibox::CBox<EvpMdCtx>`] uniquely owns the context header
    /// and settles its retained state through `EVP_MD_CTX_free`. It is
    /// deliberately not `Clone`: duplication is fallible, so it is offered as
    /// [`crate::evp::digest::EVP_MD_CTX_dup`], which creates an independent
    /// context and duplicates or raises the references that copy needs.
    ///
    /// The one contract this owner does not express is a non-default library
    /// context. `EVP_DigestInit_ex2` stores the supplied `EVP_MD` in
    /// `fetched_digest`, and under OpenSSL's default cached fetch
    /// `EVP_MD_up_ref` is a no-op for a stored record — the digest belongs to
    /// the `OSSL_LIB_CTX` it was fetched from. `CBox<EvpMdCtx>` carries no
    /// borrow parameter, so it cannot state that it must not outlive that
    /// context, the way [`crate::evp::pmeth_lib::BorrowedEvpPkeyCtx`] does for
    /// `EVP_PKEY_CTX`. This is latent rather than reachable: no safe
    /// constructor hands out an owned `CBox<OsslLibCtx>` today, so safe code
    /// cannot release a library context under a live digest context. A wrapper
    /// for `OSSL_LIB_CTX_new` must be landed together with a lifetime-bound
    /// owner for this type.
    EvpMdCtx,
    EvpMdCtxRef,
    EvpMdCtxMut,
    ffi::evp_md_ctx_st
);

// `EVP_MD_CTX_free` first resets the context, releasing its provider digest
// state, fetched digest reference, and normally its public-key context, then
// releases the uniquely owned context allocation. The KEEP_PKEY_CTX flag is
// the documented exception: that public-key context remains caller-owned.
impl_dropped!(EvpMdCtx, ffi::evp_md_ctx_st, ffi::EVP_MD_CTX_free);

// Digest contexts are not reference counted, but `EVP_MD_CTX_dup` is **not**
// registered as `CCloned`. `Clone` is infallible by trait contract, so
// `CBox::clone` aborts the process when the C routine returns null — and
// `EVP_MD_CTX_dup` reports ordinary "cannot copy this context" outcomes that
// way, not just allocation failure: `EVP_MD_CTX_copy_ex` refuses a legacy
// digest whose method has no `dupctx`, and its `EVP_PKEY_CTX_dup` of an
// attached public-key context fails outright for a generation operation.
// Duplication is therefore exposed only through the fallible
// `crate::evp::digest::EVP_MD_CTX_dup`, which yields an independent
// `CBox<EvpMdCtx>` that may be mutably borrowed and freed on its own.

#[cfg(test)]
mod md_ctx_tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn opaque_digest_context_borrows_and_deep_copies() {
        assert_owned_cell::<EvpMdCtx>();

        // SAFETY: a non-null result is a fresh, fully initialized empty digest
        // context with one matching `EVP_MD_CTX_free` obligation.
        let raw = unsafe { ffi::EVP_MD_CTX_new() };
        // SAFETY: ownership of the fresh result transfers exactly once to the
        // owner whose registered destructor is `EVP_MD_CTX_free`.
        let mut context = unsafe { CBox::<EvpMdCtx>::from_raw(raw) }.expect("EVP_MD_CTX_new");

        assert_eq!(context.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(context.as_mut().as_mut_ptr(), raw);

        let duplicate = crate::evp::digest::EVP_MD_CTX_dup(context.as_ref())
            .expect("EVP_MD_CTX_dup of an empty context");
        assert_ne!(duplicate.as_ptr(), raw);
    }

    #[test]
    fn opaque_digest_context_handles_are_pointer_sized() {
        assert_eq!(
            size_of::<EvpMdCtxRef<'static>>(),
            size_of::<*const ffi::evp_md_ctx_st>()
        );
        assert_eq!(
            size_of::<EvpMdCtxMut<'static>>(),
            size_of::<*mut ffi::evp_md_ctx_st>()
        );
        assert_eq!(
            size_of::<CBox<EvpMdCtx>>(),
            size_of::<*mut ffi::evp_md_ctx_st>()
        );
    }
}

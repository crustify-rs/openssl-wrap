//! Wrappers assigned from `crypto/evp/evp_local.h`.

use core::marker::PhantomData;

use ffibox::{CBox, define_ctype, impl_dropped};
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

define_ctype!(
    /// Wraps: evp_cipher_ctx_st
    ///
    /// Pointer-compatible target for OpenSSL's opaque cipher context. Its
    /// provider algorithm state is owned by the context; application data and
    /// legacy cipher data remain externally managed and are copied only as
    /// borrowed pointers.
    ///
    /// The retained cipher is *not* an unconditional keepalive. Reviewed
    /// against `crypto/evp/evp_enc.c`: `evp_cipher_init_internal` stores the
    /// selected record in `fetched_cipher` behind `EVP_CIPHER_up_ref`, and
    /// `EVP_CIPHER_CTX_reset` releases it with `EVP_CIPHER_free`, so the two
    /// obligations always match — but for a cached fetch or a legacy static
    /// record *both* are deliberate no-ops, because `evp_cipher_up_ref` and
    /// `evp_cipher_free` return early unless `origin == EVP_ORIG_DYNAMIC`.
    /// A cached record belongs to the method store of the `OSSL_LIB_CTX` it
    /// was fetched from, so an initialized context must not outlive that
    /// library context.
    ///
    /// `CBox<EvpCipherCtx>` carries no borrow parameter and cannot state that,
    /// exactly as [`EvpMdCtx`] cannot for `EVP_MD_CTX`. This is latent rather
    /// than reachable: no safe constructor hands out an owned
    /// `CBox<crate::bio::context::OsslLibCtx>` today, so every
    /// [`crate::evp::evp::EvpCipherRef`] safe code can build is backed by the
    /// process-wide default context. A wrapper for `OSSL_LIB_CTX_new` must be
    /// landed together with a lifetime-bound owner for this type — the shape
    /// [`BorrowedEvpCipherCtx`] already uses for duplication.
    ///
    /// An owning [`CBox<EvpCipherCtx>`] uniquely owns the context header and
    /// settles its retained state through `EVP_CIPHER_CTX_free`. It is not
    /// `Clone`: `EVP_CIPHER_CTX_dup` can fail for an uninitialized context or
    /// a provider without `dupctx`, and its result inherits the source's
    /// external-pointer and library-context dependencies. Use
    /// [`EvpCipherCtxRef::try_dup`] to preserve those dependencies explicitly.
    EvpCipherCtx,
    EvpCipherCtxRef,
    EvpCipherCtxMut,
    ffi::evp_cipher_ctx_st
);

// `EVP_CIPHER_CTX_free` resets the context first, releasing its provider
// algorithm state through the active cipher's runtime `freectx` callback and
// dropping its fetched cipher reference, then frees the unique header.
impl_dropped!(
    EvpCipherCtx,
    ffi::evp_cipher_ctx_st,
    ffi::EVP_CIPHER_CTX_free
);

/// An owned cipher context whose copied opaque pointers retain a source borrow.
///
/// `EVP_CIPHER_CTX_dup` duplicates provider state and raises the fetched cipher
/// reference, but copies `app_data` and `cipher_data` verbatim. This owner keeps
/// the source lifetime so safe duplication cannot outlive those external
/// dependencies (including the fetched cipher's library context).
#[must_use = "dropping the owner releases the EVP_CIPHER_CTX"]
pub struct BorrowedEvpCipherCtx<'a> {
    inner: CBox<EvpCipherCtx>,
    borrow: PhantomData<EvpCipherCtxRef<'a>>,
}

impl<'a> BorrowedEvpCipherCtx<'a> {
    pub(crate) unsafe fn from_raw(raw: *mut ffi::evp_cipher_ctx_st) -> Option<Self> {
        // SAFETY: the caller transfers a fully initialized duplicate and has
        // selected a lifetime covering every non-owning pointer it copied.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the context without write access.
    #[must_use]
    pub fn as_ref(&self) -> EvpCipherCtxRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the context.
    #[must_use]
    pub fn as_mut(&mut self) -> EvpCipherCtxMut<'_> {
        self.inner.as_mut()
    }

    /// Create another independently owned context with the same dependencies.
    #[must_use]
    pub fn try_dup(&self) -> Option<Self> {
        // SAFETY: the owner keeps the source live and shared for the call.
        // OpenSSL returns null or a distinct context with one free obligation.
        let raw = unsafe { ffi::EVP_CIPHER_CTX_dup(self.inner.as_ptr().cast_const()) };
        // SAFETY: a successful duplicate copies only dependencies already
        // bounded by this owner's `'a` and transfers its fresh free obligation.
        unsafe { Self::from_raw(raw) }
    }
}

impl<'a> EvpCipherCtxRef<'a> {
    /// Create an independently owned copy of this cipher context.
    ///
    /// Returns `None` when the source is uninitialized, its provider does not
    /// support context duplication, or allocation fails. The result retains
    /// this handle's lifetime because OpenSSL copies the externally managed
    /// application and legacy cipher pointers verbatim.
    #[must_use]
    pub fn try_dup(&self) -> Option<BorrowedEvpCipherCtx<'a>> {
        // SAFETY: the handle carries a live shared borrow for the synchronous
        // read. A non-null result is a distinct, fully initialized context.
        let raw = unsafe { ffi::EVP_CIPHER_CTX_dup(self.as_ptr()) };
        // SAFETY: successful duplication transfers one matching free
        // obligation, while `'a` covers every copied non-owning dependency.
        unsafe { BorrowedEvpCipherCtx::from_raw(raw) }
    }
}

#[cfg(test)]
mod cipher_ctx_tests {
    use core::mem::size_of;

    use ffibox::{CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn opaque_cipher_context_has_typed_borrow_handles() {
        assert_owned_cell::<EvpCipherCtx>();

        // SAFETY: a non-null result is a fresh, fully initialized empty cipher
        // context carrying one `EVP_CIPHER_CTX_free` obligation.
        let raw = unsafe { ffi::EVP_CIPHER_CTX_new() };
        // SAFETY: ownership of the fresh result transfers exactly once to the
        // owner whose registered destructor is `EVP_CIPHER_CTX_free`.
        let mut context =
            unsafe { CBox::<EvpCipherCtx>::from_raw(raw) }.expect("EVP_CIPHER_CTX_new");

        assert_eq!(context.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(context.as_mut().as_mut_ptr(), raw);
        assert!(context.as_ref().try_dup().is_none());
    }

    #[test]
    fn opaque_cipher_context_handles_are_pointer_sized() {
        assert_eq!(
            size_of::<EvpCipherCtxRef<'static>>(),
            size_of::<*const ffi::evp_cipher_ctx_st>()
        );
        assert_eq!(
            size_of::<EvpCipherCtxMut<'static>>(),
            size_of::<*mut ffi::evp_cipher_ctx_st>()
        );
        assert_eq!(
            size_of::<CBox<EvpCipherCtx>>(),
            size_of::<*mut ffi::evp_cipher_ctx_st>()
        );
        assert_eq!(
            size_of::<BorrowedEvpCipherCtx<'static>>(),
            size_of::<*mut ffi::evp_cipher_ctx_st>()
        );
    }
}

define_ctype!(
    /// Wraps: evp_kdf_ctx_st
    ///
    /// Pointer-compatible target for OpenSSL's opaque KDF operation context.
    /// The C implementation owns provider-specific state and one retained
    /// `EVP_KDF` method reference; `EVP_KDF_CTX_free` settles both.
    ///
    /// Duplication is fallible and provider-dependent, so it is exposed by
    /// [`EvpKdfCtxRef::try_dup`] rather than as an infallible `Clone`.
    EvpKdfCtx,
    EvpKdfCtxRef,
    EvpKdfCtxMut,
    ffi::evp_kdf_ctx_st
);

impl_dropped!(EvpKdfCtx, ffi::evp_kdf_ctx_st, ffi::EVP_KDF_CTX_free);

/// An independently allocated KDF context retaining its source dependencies.
///
/// Provider duplication creates new algorithm state and raises the method
/// reference, but the provider and cached method can still belong to the
/// source's library context. The borrow prevents the duplicate from escaping
/// that source lifetime.
#[must_use = "dropping the owner releases the EVP_KDF_CTX"]
pub struct BorrowedEvpKdfCtx<'a> {
    inner: CBox<EvpKdfCtx>,
    borrow: PhantomData<EvpKdfCtxRef<'a>>,
}

impl<'a> BorrowedEvpKdfCtx<'a> {
    unsafe fn from_raw(raw: *mut ffi::evp_kdf_ctx_st) -> Option<Self> {
        // SAFETY: the caller transfers a fully initialized duplicate and has
        // selected a lifetime covering the retained provider dependencies.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the duplicated context without write access.
    #[must_use]
    pub fn as_ref(&self) -> EvpKdfCtxRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the duplicated context.
    #[must_use]
    pub fn as_mut(&mut self) -> EvpKdfCtxMut<'_> {
        self.inner.as_mut()
    }

    /// Create another context with the same provider dependencies.
    #[must_use]
    pub fn try_dup(&self) -> Option<Self> {
        // SAFETY: the owner keeps a live source context throughout the call;
        // a non-null result owns distinct state and one free obligation.
        let raw = unsafe { ffi::EVP_KDF_CTX_dup(self.inner.as_ref().as_ptr()) };
        // SAFETY: the new context inherits only dependencies already covered
        // by this owner's lifetime and transfers its free obligation.
        unsafe { Self::from_raw(raw) }
    }
}

impl<'a> EvpKdfCtxRef<'a> {
    /// Attempt to duplicate this context and its provider-specific state.
    ///
    /// Returns `None` when the provider has no `dupctx`, when its duplication
    /// rejects the active state, or when allocation fails.
    #[must_use]
    pub fn try_dup(&self) -> Option<BorrowedEvpKdfCtx<'a>> {
        // SAFETY: the handle supplies a live shared source for the synchronous
        // call. A non-null result is a separate fully initialized context.
        let raw = unsafe { ffi::EVP_KDF_CTX_dup(self.as_ptr()) };
        // SAFETY: a successful duplicate transfers one matching free
        // obligation and retains no dependency beyond this handle's lifetime.
        unsafe { BorrowedEvpKdfCtx::from_raw(raw) }
    }
}

#[cfg(test)]
mod kdf_ctx_tests {
    use core::mem::size_of;
    use core::ptr;

    use crate::evp::evp::{EvpKdf, SharedEvpKdf};

    use super::*;

    #[test]
    fn context_owner_borrows_and_duplicates_provider_state() {
        // SAFETY: null selects the process-wide default context and properties;
        // the static algorithm name is NUL-terminated.
        let raw_kdf = unsafe { ffi::EVP_KDF_fetch(ptr::null_mut(), c"HKDF".as_ptr(), ptr::null()) };
        // SAFETY: a successful fetch transfers one public method reference.
        let kdf: SharedEvpKdf<'static> =
            unsafe { SharedEvpKdf::from_raw(raw_kdf) }.expect("EVP_KDF_fetch");

        // SAFETY: the borrowed method is live; a non-null result transfers a
        // fully initialized context and one `EVP_KDF_CTX_free` obligation.
        let raw_ctx = unsafe { ffi::EVP_KDF_CTX_new(kdf.as_ptr()) };
        // SAFETY: ownership of the fresh context transfers exactly once.
        let mut ctx = unsafe { CBox::<EvpKdfCtx>::from_raw(raw_ctx) }.expect("KDF context");
        let duplicate = ctx.as_ref().try_dup().expect("EVP_KDF_CTX_dup");

        assert_ne!(duplicate.as_ref().as_ptr(), ctx.as_ref().as_ptr());
        assert_eq!(ctx.as_mut().as_mut_ptr(), raw_ctx);
        assert_eq!(
            size_of::<CBox<EvpKdfCtx>>(),
            size_of::<*mut ffi::evp_kdf_ctx_st>()
        );
        assert_eq!(size_of::<EvpKdf>(), size_of::<ffi::evp_kdf_st>());
    }
}

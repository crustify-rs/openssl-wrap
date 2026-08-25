//! Wrappers assigned from `crypto/provider_core.c`.

use core::ptr::NonNull;

use ffibox::CDropped;
use libcrypto_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: ossl_provider_st
    ///
    /// Opaque marker for an OpenSSL provider object.
    ///
    /// The public headers forward-declare `ossl_provider_st`; its private
    /// layout and fields remain owned by `crypto/provider_core.c`. An active
    /// handle returned by `OSSL_PROVIDER_load` is represented by
    /// [`ffibox::CBox<OsslProvider>`], while shared and exclusive borrows use
    /// [`OsslProviderRef`] and [`OsslProviderMut`] without ever forming a Rust
    /// reference over storage that OpenSSL may mutate.
    ///
    /// Dropping the public owner calls `OSSL_PROVIDER_unload`, which first
    /// removes the matching activation and then releases its provider
    /// reference. OpenSSL also has an internal `ossl_provider_free` ownership
    /// class whose references carry no activation; those must not be adopted
    /// into this `CBox`, because unloading one would unbalance activation.
    /// Likewise, the internal `ossl_provider_up_ref` is deliberately not bound
    /// to `Clone`: it adds only a provider reference, not another activation.
    ///
    /// The provider's `libctx` field is a **borrowed** back-pointer: the
    /// library context's provider store retains providers while they are
    /// stored, but a provider reference does not retain the context. An owner
    /// adopted from a load against an explicit `OSSL_LIB_CTX` therefore must
    /// not outlive that context, and a plain [`ffibox::CBox<OsslProvider>`]
    /// cannot state that. Until a safe loader exists — no wrapper in this
    /// crate hands out an owner today, only the unsafe adoption seam — the
    /// obligation rests on the caller of `CBox::from_raw`; a loader that binds
    /// a context borrow must return a lifetime-carrying owner instead, as
    /// `X509_PUBKEY_new_ex` does. Borrowed handles already express it:
    /// `EVP_PKEY_get0_provider` returns an [`OsslProviderRef`] bounded by the
    /// key it came from.
    OsslProvider,
    OsslProviderRef,
    OsslProviderMut,
    ffi::ossl_provider_st
);

// SAFETY: for an active public handle returned by the OSSL_PROVIDER_load
// family, OSSL_PROVIDER_unload is the matching release operation: it removes
// one activation and then consumes one provider reference. `CBox` adoption is
// unsafe, so callers must not adopt the distinct internal, inactive reference
// class. If deactivation fails, OpenSSL retains the reference; that can leak
// but does not invalidate or double-release storage.
unsafe impl CDropped for OsslProvider {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the `CDropped` contract supplies the unique active ownership
        // obligation described above, and the transparent wrapper preserves
        // the exact pointer value expected by OpenSSL.
        let _ = unsafe { ffi::OSSL_PROVIDER_unload(obj.as_ptr().cast()) };
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::CBox;

    use super::*;
    use crate::bio::context::OsslLibCtx;

    #[test]
    fn opaque_provider_handles_stay_pointer_shaped() {
        assert_eq!(size_of::<ffi::ossl_provider_st>(), 0);
        assert_eq!(
            size_of::<CBox<OsslProvider>>(),
            size_of::<*mut ffi::ossl_provider_st>()
        );
        assert_eq!(
            size_of::<OsslProviderRef<'static>>(),
            size_of::<*mut ffi::ossl_provider_st>()
        );
        assert_eq!(
            size_of::<OsslProviderMut<'static>>(),
            size_of::<*mut ffi::ossl_provider_st>()
        );

        // SAFETY: null carries no ownership or borrowing obligation.
        assert!(unsafe { CBox::<OsslProvider>::from_raw(ptr::null_mut()) }.is_none());
        // SAFETY: null is explicitly represented as no shared handle.
        assert!(unsafe { OsslProviderRef::from_ptr(ptr::null_mut()) }.is_none());
        // SAFETY: null is explicitly represented as no exclusive handle.
        assert!(unsafe { OsslProviderMut::from_ptr(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn active_owner_produces_lifetime_bound_handles() {
        // Use a private context so explicitly loading a provider does not
        // disable fallback loading in the process-global context used by
        // other parallel tests.
        // SAFETY: a non-null result is a fresh context whose sole ownership
        // obligation transfers to the matching typed owner.
        let context = unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("create isolated library context");
        // SAFETY: `context` stays live through the provider owner below, and
        // the C string remains live for the duration of the call.
        let raw = unsafe { ffi::OSSL_PROVIDER_load(context.as_ptr(), c"default".as_ptr()) };
        // SAFETY: a non-null result is one active public provider handle whose
        // matching unload obligation transfers exactly once to the owner.
        let mut provider =
            unsafe { CBox::<OsslProvider>::from_raw(raw) }.expect("load default provider");

        assert_eq!(provider.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(provider.as_mut().as_mut_ptr(), raw);
        assert_eq!(provider.as_mut().as_ref().as_ptr(), raw.cast_const());

        // Reverse declaration order runs OSSL_PROVIDER_unload exactly once
        // before the private library context is freed.
    }
}

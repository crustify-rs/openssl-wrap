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
    /// [`SharedOsslProvider`], while shared and exclusive borrows use
    /// [`OsslProviderRef`] and [`OsslProviderMut`] without ever forming a Rust
    /// reference over storage that OpenSSL may mutate.
    ///
    /// Dropping the public owner calls `OSSL_PROVIDER_unload`, which first
    /// removes the matching activation and then releases its provider
    /// reference. OpenSSL also has an internal `ossl_provider_free` ownership
    /// class whose references carry no activation; those must not be adopted
    /// into this owner, because unloading one would unbalance activation.
    /// Likewise, the internal `ossl_provider_up_ref` is deliberately not bound
    /// to `Clone`: it adds only a provider reference, not another activation.
    ///
    /// An active handle is a *share*, not a sole allocation, which is why the
    /// owner is [`SharedOsslProvider`] rather than
    /// [`ffibox::CBox<OsslProvider>`]. `OSSL_PROVIDER_try_load_ex`
    /// (`crypto/provider.c`) begins at `ossl_provider_find`, which raises the
    /// reference count of the store entry already registered under that name;
    /// only a miss reaches `ossl_provider_new`. A second load therefore
    /// activates and returns the *same* object, so two active handles to one
    /// provider are ordinary. [`ffibox::CBox::from_raw`] requires unique
    /// ownership and its owner hands out an exclusive [`OsslProviderMut`], so
    /// adopting a load result into it would assert an exclusivity the C API
    /// does not grant. The shared owner exposes borrows only.
    ///
    /// The provider's `libctx` field is a **borrowed** back-pointer: the
    /// library context's provider store retains providers while they are
    /// stored, but a provider reference does not retain the context. An owner
    /// must therefore not outlive the context it was loaded against — when
    /// that context is freed, its store drops the store's references while a
    /// surviving handle keeps the object alive around a dangling `libctx`,
    /// and its eventual unload reaches released storage.
    /// [`SharedOsslProvider<'a>`](SharedOsslProvider) states exactly that
    /// coupling, so a future safe loader returns the context's borrow with the
    /// owner; a load against the default context may use `'static`. Borrowed
    /// handles already express it: `EVP_PKEY_get0_provider` returns an
    /// [`OsslProviderRef`] bounded by the key it came from.
    OsslProvider,
    OsslProviderRef,
    OsslProviderMut,
    ffi::ossl_provider_st
);

// SAFETY: for an active public handle returned by the OSSL_PROVIDER_load
// family, OSSL_PROVIDER_unload is the matching release operation: it removes
// one activation and then consumes one provider reference. Adoption is unsafe,
// so callers must not adopt the distinct internal, inactive reference class.
// If deactivation fails, OpenSSL retains the reference; that can leak but does
// not invalidate or double-release storage.
unsafe impl CDropped for OsslProvider {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the `CDropped` contract supplies the active ownership
        // obligation described above, and the transparent wrapper preserves
        // the exact pointer value expected by OpenSSL.
        let _ = unsafe { ffi::OSSL_PROVIDER_unload(obj.as_ptr().cast()) };
    }
}

/// One owned, active provider handle, granting shared access only.
///
/// This is what a successful `OSSL_PROVIDER_load` transfers: one activation
/// and one reference on an object the library context's provider store, and
/// possibly other active handles, also name. Dropping it runs
/// `OSSL_PROVIDER_unload` once.
///
/// The borrow parameter carries the library context the provider was loaded
/// against, because `ossl_provider_st.libctx` is a back-pointer the provider
/// does not retain.
pub type SharedOsslProvider<'a> = crate::refcount::SharedRef<'a, OsslProvider>;

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::CBox;

    use super::*;
    use crate::bio::context::{OsslLibCtx, OsslLibCtxRef};

    /// Loads the default provider, tying the owner to the context's borrow.
    fn load_default(context: OsslLibCtxRef<'_>) -> Option<SharedOsslProvider<'_>> {
        // SAFETY: the handle addresses a live library context and the literal
        // is a live NUL-terminated name. The call returns null or one active
        // public provider handle.
        let raw =
            unsafe { ffi::OSSL_PROVIDER_load(context.as_ptr().cast_mut(), c"default".as_ptr()) };
        // SAFETY: a non-null result transfers exactly one activation and one
        // reference, settled by the owner's single `OSSL_PROVIDER_unload`. The
        // returned borrow keeps `context` alive until then.
        unsafe { SharedOsslProvider::from_raw(raw) }
    }

    /// A private context keeps an explicit load from disabling fallback
    /// loading in the process-global context other parallel tests use.
    fn new_context() -> CBox<OsslLibCtx> {
        // SAFETY: a non-null result is a fresh context whose sole ownership
        // obligation transfers to the matching typed owner.
        unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("create isolated library context")
    }

    #[test]
    fn opaque_provider_handles_stay_pointer_shaped() {
        assert_eq!(size_of::<ffi::ossl_provider_st>(), 0);
        assert_eq!(
            size_of::<SharedOsslProvider<'static>>(),
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

        // SAFETY: null is explicitly represented as no shared handle.
        assert!(unsafe { OsslProviderRef::from_ptr(ptr::null_mut()) }.is_none());
        // SAFETY: null is explicitly represented as no exclusive handle.
        assert!(unsafe { OsslProviderMut::from_ptr(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn an_active_owner_produces_lifetime_bound_handles() {
        let context = new_context();
        let provider = load_default(context.as_ref()).expect("load default provider");

        let raw = provider.as_ptr();
        assert_eq!(provider.as_ref().as_ptr(), raw.cast_const());
        // A provider reaches its own object through the erased core-handle
        // seam — `ossl_provider_st` casts to and from `ossl_core_handle_st` —
        // and the borrowed handle round-trips such an erased pointer without
        // forming a reference to the C object.
        let erased = provider.as_ref().as_void_ptr().cast_mut();
        // SAFETY: `erased` was erased from this very provider, which the owner
        // keeps live for longer than the handle borrowed here.
        let reconstituted = unsafe { OsslProviderRef::from_void_ptr(erased) }.expect("non-null");
        assert_eq!(reconstituted.as_ptr(), raw.cast_const());

        // Reverse declaration order runs OSSL_PROVIDER_unload exactly once
        // before the private library context is freed.
    }

    /// The evidence for the shared owner: repeated loads name one object.
    #[test]
    fn every_active_handle_of_a_name_shares_one_provider_object() {
        let context = new_context();
        let first = load_default(context.as_ref()).expect("load default provider");
        let second = load_default(context.as_ref()).expect("second active handle");

        // `ossl_provider_find` hit the store entry instead of building a
        // second provider, so both owners address one allocation. Neither may
        // grant exclusive access to it, which is why the load result is not a
        // `CBox`.
        assert_eq!(first.as_ptr(), second.as_ptr());
        assert_eq!(first.as_ref().as_ptr(), second.as_ref().as_ptr());

        // Each owner still carries its own activation and reference, so both
        // unload here, before the context they borrow is freed. Dropping
        // `context` first does not compile — that borrow is the coupling a
        // plain `CBox<OsslProvider>` could not state.
        drop(second);
        drop(first);
    }
}

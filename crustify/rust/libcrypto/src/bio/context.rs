//! Wrappers assigned from `crypto/context.c`.

use core::ptr::NonNull;

use ffibox::CDropped;
use libcrypto_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: ossl_lib_ctx_st
    ///
    /// Opaque marker for an OpenSSL library context.
    /// Owned contexts are held in `ffibox::CBox<OsslLibCtx>`; shared and
    /// exclusive access stays lifetime-bound through the generated handles.
    ///
    /// Reviewed against `crypto/context.c`. The layout is private to that
    /// translation unit — `include/openssl/types.h` only forward-declares the
    /// tag — so `libcrypto-sys` binds it as a zero-sized incomplete type and
    /// the wrapper is handle-only: it exposes no field accessor, and the
    /// `zeroed` value `define_ctype!` emits addresses no context, since every
    /// path from a value to a usable handle goes through an unsafe adoption.
    /// Every pointer field is subsystem state that `context_init` allocates
    /// and `context_deinit_objs` releases, reachable outside the file only
    /// through `ossl_lib_ctx_get_data`; the sole exception, `ssl_imod`, is a
    /// borrowed back-reference to a `CONF_IMODULE` owned by the configuration
    /// module list.
    ///
    /// `OSSL_LIB_CTX_free` is the type's only release primitive, and no field
    /// holds a reference count — there is no `up_ref` and no `dup` — so
    /// [`ffibox::CDropped`] is the whole lifecycle contract and the owner is
    /// deliberately not `Clone`.
    ///
    /// The one contract this wrapper cannot express is C's *retained* free
    /// path: `OSSL_LIB_CTX_free` returns early for a null context and for
    /// `ossl_lib_ctx_is_default_nocreate`, which covers the static global
    /// default *and* any context the calling thread installed as its default
    /// with `OSSL_LIB_CTX_set0_default`. Releasing such a context leaks it
    /// rather than corrupting the heap, so the omission is not a soundness
    /// gap; a future wrapper for `OSSL_LIB_CTX_set0_default` must keep the
    /// owner alive past the point where it stops being the default, or the
    /// `CBox` teardown silently becomes a no-op.
    OsslLibCtx,
    OsslLibCtxRef,
    OsslLibCtxMut,
    ffi::ossl_lib_ctx_st
);

// SAFETY: `OSSL_LIB_CTX_free` is the matching destructor for a fully
// initialized, non-default context returned by the public context constructors:
// it runs `context_deinit` and `OPENSSL_free` on the allocation, and nothing
// else in the tree releases an `OSSL_LIB_CTX`.
unsafe impl CDropped for OsslLibCtx {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the `CDropped` contract supplies unique ownership of a live,
        // fully initialized context. Safe owners can only be created by an
        // unsafe adoption step, which excludes OpenSSL's borrowed defaults;
        // adopting one would leak rather than double free, since the C
        // implementation retains a default instead of releasing it.
        unsafe { ffi::OSSL_LIB_CTX_free(obj.as_ptr().cast()) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::CBox;

    use super::*;
    use crate::bio::bio_lib::BIO_new_ex;
    use crate::bio::bss_null::BIO_s_null;

    fn new_context() -> CBox<OsslLibCtx> {
        // SAFETY: the constructor returns either null or a fresh, fully
        // initialized context carrying one ownership obligation, which
        // transfers exactly once to `CBox`.
        unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("OSSL_LIB_CTX_new allocation")
    }

    #[test]
    fn the_opaque_context_stays_pointer_shaped() {
        // The public headers publish the tag without its body, so the binding
        // carries no layout at all and the wrapper can only ever be reached
        // through a pointer C allocated.
        assert_eq!(size_of::<ffi::ossl_lib_ctx_st>(), 0);
        assert_eq!(
            size_of::<CBox<OsslLibCtx>>(),
            size_of::<*mut ffi::OSSL_LIB_CTX>()
        );
        assert_eq!(
            size_of::<OsslLibCtxRef<'static>>(),
            size_of::<*mut ffi::OSSL_LIB_CTX>()
        );
        assert_eq!(
            size_of::<OsslLibCtxMut<'static>>(),
            size_of::<*mut ffi::OSSL_LIB_CTX>()
        );

        // A failed allocation yields no owner rather than a null one.
        // SAFETY: null transfers no ownership obligation.
        assert!(unsafe { CBox::<OsslLibCtx>::from_raw(ptr::null_mut()) }.is_none());
        // SAFETY: as above, for both borrowed handles.
        assert!(unsafe { OsslLibCtxRef::from_ptr(ptr::null_mut()) }.is_none());
        // SAFETY: as above.
        assert!(unsafe { OsslLibCtxMut::from_ptr(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn owned_context_produces_lifetime_bound_handles() {
        let mut owned = new_context();
        let raw = owned.as_ptr();

        assert_eq!(owned.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(owned.as_mut().as_mut_ptr(), raw);
        // The exclusive handle reborrows shared access rather than dereferencing.
        assert_eq!(owned.as_mut().as_ref().as_ptr(), raw.cast_const());

        // Providers receive a context as the erased `OSSL_CORE_CTX *` handle
        // and hand it back unchanged; the borrowed handle round-trips it
        // without forming a reference to the C object.
        let erased = owned.as_ref().as_void_ptr().cast_mut();
        // SAFETY: `erased` was erased from this very context, which `owned`
        // keeps live for longer than the handle borrowed here.
        let reconstituted = unsafe { OsslLibCtxRef::from_void_ptr(erased) }.expect("non-null");
        assert_eq!(reconstituted.as_ptr(), raw.cast_const());

        // `owned` runs `OSSL_LIB_CTX_free` here, exactly once.
    }

    #[test]
    fn owned_context_outlives_the_bio_that_borrows_it() {
        let context = new_context();
        let method = BIO_s_null().expect("BIO_s_null method table");

        // `BIO_new_ex` stores the context pointer in `bio->libctx` for the
        // BIO's whole life, so the wrapper ties the owner's borrow to the
        // returned BIO: dropping `context` first does not compile.
        let bio = BIO_new_ex(Some(context.as_ref()), method).expect("BIO_new_ex");
        assert_eq!(crate::bio::bio_lib::BIO_get_init(bio.as_ref()), 1);

        drop(bio);
        drop(context);
    }

    #[test]
    fn the_global_default_context_is_borrowed_not_owned() {
        let owned = new_context();

        // SAFETY: the getter has no caller-side pointer obligations; it runs
        // the library's initialization once and returns the address of the
        // process-global default context or null.
        let default = unsafe { ffi::OSSL_LIB_CTX_get0_global_default() };
        // SAFETY: the returned pointer addresses the static default context,
        // which lives for the rest of the process, so `'static` is honest and
        // no owner is constructed from it.
        let default: OsslLibCtxRef<'static> =
            unsafe { OsslLibCtxRef::from_ptr(default) }.expect("global default context");
        assert_ne!(default.as_ptr(), owned.as_ptr().cast_const());

        // The C release primitive is total, not exclusively owning: it
        // retains a default instead of freeing it. Were that not so, this
        // call would free static storage and take the process with it.
        // SAFETY: the default context is live; this call is the documented
        // no-op path of `OSSL_LIB_CTX_free`.
        unsafe { ffi::OSSL_LIB_CTX_free(default.as_ptr().cast_mut()) };

        // Still usable afterwards, which is why adopting a default into a
        // `CBox` would leak rather than corrupt.
        let method = BIO_s_null().expect("BIO_s_null method table");
        let bio = BIO_new_ex(Some(default), method).expect("BIO_new_ex on the default context");
        assert_eq!(crate::bio::bio_lib::BIO_get_init(bio.as_ref()), 1);
    }
}

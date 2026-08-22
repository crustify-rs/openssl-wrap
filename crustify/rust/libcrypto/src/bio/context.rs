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
    OsslLibCtx,
    OsslLibCtxRef,
    OsslLibCtxMut,
    ffi::ossl_lib_ctx_st
);

// SAFETY: `OSSL_LIB_CTX_free` is the matching destructor for a fully
// initialized, non-default context returned by the public context constructors.
unsafe impl CDropped for OsslLibCtx {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the `CDropped` contract supplies unique ownership of a live,
        // fully initialized context. Safe owners can only be created by an
        // unsafe adoption step, which excludes OpenSSL's borrowed default.
        unsafe { ffi::OSSL_LIB_CTX_free(obj.as_ptr().cast()) }
    }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn owned_context_produces_lifetime_bound_handles() {
        // SAFETY: the constructor returns either null or a fresh, fully
        // initialized context carrying one ownership obligation.
        let raw = unsafe { ffi::OSSL_LIB_CTX_new() };
        // SAFETY: ownership of the fresh constructor result transfers exactly
        // once to `CBox`, whose `OsslLibCtx` strategy uses the matching free.
        let mut owned =
            unsafe { CBox::<OsslLibCtx>::from_raw(raw) }.expect("OSSL_LIB_CTX_new allocation");

        assert_eq!(owned.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(owned.as_mut().as_mut_ptr(), raw);
        // `owned` runs `OSSL_LIB_CTX_free` here.
    }
}

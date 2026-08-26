//! Wrappers assigned from `crypto/hpke/hpke.c`.

use ffibox::{define_ctype, impl_dropped};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: ossl_hpke_ctx_st
    ///
    /// Opaque handle target for an OpenSSL HPKE sender or receiver context.
    /// The public header forward-declares the context, so its algorithm state,
    /// sequence number, borrowed library context, and owned key material remain
    /// behind OpenSSL's call surface. Owned contexts use
    /// [`ffibox::CBox<OsslHpkeCtx>`], while `OsslHpkeCtxRef` and
    /// `OsslHpkeCtxMut` carry shared and exclusive borrows without forming a
    /// Rust reference to the C object.
    ///
    /// `OSSL_HPKE_CTX_free` is the sole release primitive and the type has no
    /// clone or reference-count operation. It releases the fetched cipher and
    /// duplicated authentication key, clears each secret buffer before freeing
    /// it, and finally frees the context allocation. The wrapper is therefore
    /// an exclusive, non-`Clone` owner.
    ///
    /// The C constructor stores its optional `OSSL_LIB_CTX *` without taking a
    /// reference. Any future safe constructor wrapper must consequently bind
    /// the returned owner's lifetime to that borrowed library context; raw
    /// adoption remains unsafe and carries that obligation today.
    OsslHpkeCtx,
    OsslHpkeCtxRef,
    OsslHpkeCtxMut,
    ffi::ossl_hpke_ctx_st
);

impl_dropped!(OsslHpkeCtx, ffi::ossl_hpke_ctx_st, ffi::OSSL_HPKE_CTX_free);

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use core::ptr;

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    fn new_context() -> CBox<OsslHpkeCtx> {
        let suite = ffi::OSSL_HPKE_SUITE {
            kem_id: 0x20,
            kdf_id: 0x01,
            aead_id: 0xffff,
        };
        // SAFETY: these numeric values select base mode, the X25519/SHA-256
        // export-only suite, and the sender role. Null selects OpenSSL's
        // default library context and properties, so the result is null or a
        // fresh, fully initialized context with one ownership obligation.
        let raw = unsafe { ffi::OSSL_HPKE_CTX_new(0, suite, 0, ptr::null_mut(), ptr::null()) };
        // SAFETY: ownership of the fresh result transfers exactly once to the
        // owner whose registered destructor is `OSSL_HPKE_CTX_free`.
        unsafe { CBox::<OsslHpkeCtx>::from_raw(raw) }.expect("OSSL_HPKE_CTX_new")
    }

    #[test]
    fn opaque_context_stays_pointer_shaped() {
        assert_owned_cell::<OsslHpkeCtx>();
        assert_eq!(size_of::<ffi::ossl_hpke_ctx_st>(), 0);
        assert_eq!(
            size_of::<CBox<OsslHpkeCtx>>(),
            size_of::<*mut ffi::ossl_hpke_ctx_st>()
        );
        assert_eq!(
            size_of::<OsslHpkeCtxRef<'static>>(),
            size_of::<*mut ffi::ossl_hpke_ctx_st>()
        );
        assert_eq!(
            size_of::<OsslHpkeCtxMut<'static>>(),
            size_of::<*mut ffi::ossl_hpke_ctx_st>()
        );

        // SAFETY: null transfers no ownership obligation.
        assert!(unsafe { CBox::<OsslHpkeCtx>::from_raw(ptr::null_mut()) }.is_none());
        // SAFETY: null cannot name a borrowed context.
        assert!(unsafe { OsslHpkeCtxRef::from_ptr(ptr::null_mut()) }.is_none());
        // SAFETY: null cannot name an exclusively borrowed context.
        assert!(unsafe { OsslHpkeCtxMut::from_ptr(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn owned_context_produces_lifetime_bound_handles() {
        let mut context = new_context();
        let raw = context.as_ptr();

        assert_eq!(context.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(context.as_mut().as_mut_ptr(), raw);
        assert_eq!(context.as_mut().as_ref().as_ptr(), raw.cast_const());

        // `context` runs `OSSL_HPKE_CTX_free` exactly once here.
    }
}

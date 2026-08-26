//! Wrappers assigned from `crypto/hmac/hmac_local.h`.

use ffibox::define_ctype;
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: hmac_ctx_st
    ///
    /// Pointer-compatible target for OpenSSL's legacy HMAC context. The public
    /// API exposes `HMAC_CTX` only as an opaque forward declaration, so its
    /// selected digest, three owned digest contexts, and platform-specific
    /// state remain behind OpenSSL's call surface.
    ///
    /// A context owns its inner, outer, and working `EVP_MD_CTX` objects:
    /// `hmac_ctx_alloc_mds` allocates all three and `HMAC_CTX_free` releases
    /// them before the allocation. It only *borrows* the selected `EVP_MD` —
    /// `HMAC_Init_ex` stores the caller's pointer in `md` without raising a
    /// reference count, and only a reset clears it — so that digest must
    /// outlive every later use of the context.
    ///
    /// The owner cannot state that: the digest is chosen after construction,
    /// long after the owner's type is fixed, so no borrow parameter on
    /// [`ffibox::CBox<HmacCtx>`] could name it. The obligation is carried by
    /// the operations that install one instead —
    /// [`HMAC_Init_ex`](crate::hmac::hmac::HMAC_Init_ex) and
    /// [`HMAC_CTX_copy`](crate::hmac::hmac::HMAC_CTX_copy) are `unsafe fn` and
    /// document it as a caller contract.
    ///
    /// `HMAC_CTX` is uniquely owned: the API has neither an up-reference
    /// operation nor a constructor that returns a copied context. The
    /// destination-writing `HMAC_CTX_copy` therefore does not make this owner
    /// `Clone`.
    HmacCtx,
    HmacCtxRef,
    HmacCtxMut,
    ffi::hmac_ctx_st
);

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CDropped};

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn opaque_context_has_typed_borrow_handles_and_owner() {
        assert_owned_cell::<HmacCtx>();

        assert_eq!(
            size_of::<HmacCtxRef<'static>>(),
            size_of::<*const ffi::hmac_ctx_st>()
        );
        assert_eq!(
            size_of::<HmacCtxMut<'static>>(),
            size_of::<*mut ffi::hmac_ctx_st>()
        );
        assert_eq!(
            size_of::<CBox<HmacCtx>>(),
            size_of::<*mut ffi::hmac_ctx_st>()
        );

        // SAFETY: OpenSSL returns null or a fresh, fully initialized context
        // carrying exactly one `HMAC_CTX_free` obligation.
        let raw = unsafe { ffi::HMAC_CTX_new() };
        // SAFETY: ownership of the fresh result transfers exactly once to the
        // owner whose registered destructor is `HMAC_CTX_free`.
        let mut context = unsafe { CBox::<HmacCtx>::from_raw(raw) }.expect("HMAC_CTX_new");

        assert_eq!(context.as_ref().as_ptr(), raw.cast_const());
        assert_eq!(context.as_mut().as_mut_ptr(), raw);
    }
}

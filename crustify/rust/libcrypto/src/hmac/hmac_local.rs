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
    /// A context owns its inner, outer, and working `EVP_MD_CTX` objects. It
    /// borrows the selected `EVP_MD` without raising its reference count, so a
    /// fetched digest supplied to `HMAC_Init_ex` must outlive this context.
    /// Safe constructors for that operation must carry the dependency in
    /// their owner type; adopting a raw context as a plain [`ffibox::CBox`]
    /// retains that obligation at the unsafe adoption seam.
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

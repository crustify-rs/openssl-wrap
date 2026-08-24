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

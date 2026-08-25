//! Wrappers assigned from `include/openssl/types.h`.

use ffibox::define_ctype;
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: engine_st
    ///
    /// OpenSSL publishes `ENGINE` only as an opaque legacy handle. The public
    /// declaration supplies no layout or fields, so this wrapper is a target
    /// for pointer-compatible borrowed handles rather than embeddable storage.
    /// In particular, [`Engine::zeroed`] does not construct an engine.
    ///
    /// Engine support is gone from this OpenSSL tree. `include/openssl/engine.h`
    /// keeps `ENGINE_new`, `ENGINE_free` and `ENGINE_up_ref` only as
    /// source-compatibility declarations — either deprecated `ossl_inline`
    /// no-op stubs under `OPENSSL_ENGINE_STUBS`, or bare prototypes whose
    /// symbols libcrypto does not export at all. There is therefore no
    /// constructor, reference count or releaser to register: this type has no
    /// owner, and an engine pointer surfacing at a legacy seam stays borrowed
    /// from whatever C object keeps it alive.
    ///
    /// Every remaining `ENGINE *` parameter in the wrapped API is a slot that
    /// only ever receives null, so the borrowed handles exist to type that slot
    /// rather than to reach an engine.
    Engine,
    EngineRef,
    EngineMut,
    ffi::engine_st
);

#[cfg(test)]
mod tests {
    use core::{mem::size_of, ptr};

    use super::*;

    #[test]
    fn opaque_engine_handles_are_pointer_sized() {
        assert_eq!(size_of::<ffi::engine_st>(), 0);
        assert_eq!(
            size_of::<EngineRef<'static>>(),
            size_of::<*mut ffi::engine_st>()
        );
        assert_eq!(
            size_of::<EngineMut<'static>>(),
            size_of::<*mut ffi::engine_st>()
        );
    }

    #[test]
    fn null_engine_pointers_do_not_form_borrows() {
        // SAFETY: null is explicitly accepted and produces no handle.
        assert!(unsafe { EngineRef::from_ptr(ptr::null_mut()) }.is_none());
        // SAFETY: null is explicitly accepted and produces no handle.
        assert!(unsafe { EngineMut::from_ptr(ptr::null_mut()) }.is_none());
    }
}

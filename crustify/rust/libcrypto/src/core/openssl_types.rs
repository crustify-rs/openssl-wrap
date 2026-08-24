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
    /// This campaign is configured with deprecated APIs disabled, which
    /// removes the `ENGINE` constructor, reference-counting and release
    /// routines from the wrapped surface. Consequently there is no safe owner
    /// or lifecycle implementation here: an engine pointer obtained at a
    /// separately enabled legacy seam must remain borrowed from the C object
    /// that keeps it alive.
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

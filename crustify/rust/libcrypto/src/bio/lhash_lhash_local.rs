//! Wrappers assigned from `crypto/lhash/lhash_local.h`.

/// Wraps: lhash_st
///
/// OpenSSL erases every generated `LHASH_OF(T)` to this common private
/// layout. The generic wrapper retains `T` only as a zero-sized marker, while
/// its borrowed handles and owner continue to address an `OPENSSL_LHASH`.
/// The layout's fields stay private because the public API exposes the table
/// as an opaque handle.
pub use super::openssl_lhash::{LHash, LHashMut, LHashRef};

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::mem::size_of;

    use ffibox::{CBox, CCell, CDropped};
    use libcrypto_sys as ffi;

    use super::*;

    fn assert_owned_cell<T: CCell + CDropped>() {}

    #[test]
    fn common_layout_reuses_the_typed_lhash_surface() {
        assert_owned_cell::<LHash<c_void>>();
        assert_eq!(size_of::<LHash<c_void>>(), size_of::<ffi::OPENSSL_LHASH>());
        assert_eq!(
            size_of::<CBox<LHash<c_void>>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<LHashRef<'static, c_void>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            size_of::<LHashMut<'static, c_void>>(),
            size_of::<*mut ffi::OPENSSL_LHASH>()
        );
    }
}

//! Wrappers assigned from `/usr/include/x86_64-linux-gnu/bits/types/struct_FILE.h`.

use libc_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: _IO_FILE
    ///
    /// Layout-compatible storage for the C `FILE` implementation type. Its
    /// implementation fields are deliberately opaque; access is through C
    /// stdio operations using [`IoFileRef`] and [`IoFileMut`].
    IoFile,
    IoFileRef,
    IoFileMut,
    ffi::_IO_FILE
);

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use core::ptr::addr_of_mut;

    use super::*;

    #[test]
    fn layout_matches_raw_file_type() {
        assert_eq!(size_of::<IoFile>(), size_of::<ffi::_IO_FILE>());
        assert_eq!(align_of::<IoFile>(), align_of::<ffi::_IO_FILE>());
    }

    #[test]
    fn borrowed_handles_preserve_the_raw_pointer() {
        let mut storage = IoFile::zeroed();
        let raw = addr_of_mut!(storage).cast::<ffi::_IO_FILE>();

        // SAFETY: `storage` is an initialized, layout-compatible `IoFile` and
        // remains live for the handle's use below.
        let shared = unsafe { IoFileRef::from_ptr(raw) }.expect("non-null FILE pointer");
        assert_eq!(shared.as_ptr(), raw.cast_const());

        // The shared handle is not used after this point, so the raw object is
        // exclusively borrowed for the mutable handle's lifetime.
        // SAFETY: `raw` still addresses the live storage above and no other
        // handle is used while this exclusive handle is live.
        let mut exclusive = unsafe { IoFileMut::from_ptr(raw) }.expect("non-null FILE pointer");
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());

        // Keep the declaration visibly tied to its allocation without ever
        // forming a Rust reference to the C object.
        assert_eq!(raw, addr_of_mut!(storage).cast::<ffi::_IO_FILE>());
    }
}

//! Wrappers assigned from `/usr/include/x86_64-linux-gnu/bits/types/struct_FILE.h`.

use libc_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: _IO_FILE
    ///
    /// Layout-compatible storage for the C `FILE` implementation type, the
    /// stream object behind the `FILE` and `__FILE` typedefs.
    ///
    /// Every consumer in this tree — libcrypto, libssl, the apps and the tests
    /// — passes a `FILE *` as an opaque handle and never reads a member, so
    /// the bindings keep the layout opaque and this type publishes no field
    /// accessors. The members are C library implementation state: the read,
    /// write and backup pointers are interior pointers into a buffer the
    /// stream manages, and the lock, conversion and wide-character slots are
    /// released with the stream itself.
    ///
    /// A stream is created by `fopen`/`fdopen` and released by `fclose`, all
    /// of which stay on the C side, so this type has borrowed handles
    /// ([`IoFileRef`], [`IoFileMut`]) but no owning pointer form: Rust code
    /// borrows a stream that C, or the calling application, keeps open. That
    /// matches the wrapped OpenSSL surface, which writes to a caller's stream
    /// without closing it — libcrypto's `BIO_new_fp` wrapper passes
    /// `BIO_NOCLOSE`, and the owning `BIO_CLOSE` contract awaits an
    /// `fclose`-backed release strategy.
    IoFile,
    IoFileRef,
    IoFileMut,
    ffi::_IO_FILE
);

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use core::ptr::{self, addr_of_mut};

    use super::*;

    #[test]
    fn layout_matches_raw_file_type() {
        assert_eq!(size_of::<IoFile>(), size_of::<ffi::_IO_FILE>());
        assert_eq!(align_of::<IoFile>(), align_of::<ffi::_IO_FILE>());
    }

    #[test]
    fn borrowed_handles_are_pointer_sized_and_reject_null_streams() {
        assert_eq!(
            size_of::<IoFileRef<'_>>(),
            size_of::<*const ffi::_IO_FILE>()
        );
        assert_eq!(
            size_of::<Option<IoFileRef<'_>>>(),
            size_of::<*const ffi::_IO_FILE>()
        );
        assert_eq!(
            size_of::<Option<IoFileMut<'_>>>(),
            size_of::<*mut ffi::_IO_FILE>()
        );

        // A failed `fopen` hands back a null `FILE *`, so both handles must
        // refuse it rather than let a caller borrow nothing.
        // SAFETY: a null pointer satisfies `from_ptr`'s contract and yields
        // `None` without being dereferenced.
        assert!(unsafe { IoFileRef::from_ptr(ptr::null_mut()) }.is_none());
        // SAFETY: as above; no handle to any object is produced.
        assert!(unsafe { IoFileMut::from_ptr(ptr::null_mut()) }.is_none());
    }

    #[test]
    fn borrowed_handles_preserve_the_raw_pointer() {
        // Stack storage stands in for a stream: the handles only carry the
        // pointer, and no C stdio operation is invoked on it.
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

        // The exclusive handle is what every wrapped stream operation takes;
        // reborrowing it must keep addressing the same stream.
        let reborrow: &mut IoFileMut<'_> = &mut exclusive;
        assert_eq!(reborrow.as_mut_ptr(), raw);
        assert_eq!(reborrow.as_mut_void_ptr(), raw.cast());

        // Keep the declaration visibly tied to its allocation without ever
        // forming a Rust reference to the C object.
        assert_eq!(raw, addr_of_mut!(storage).cast::<ffi::_IO_FILE>());
    }
}

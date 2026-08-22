//! Wrappers assigned from `include/internal/bio_addr.h`.

use libcrypto_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: bio_addr_st
    ///
    /// Layout-compatible storage for OpenSSL's socket-address union. The union
    /// variants are deliberately opaque to safe Rust; access is mediated by
    /// the public `BIO_ADDR_*` operations.
    BioAddr,
    BioAddrRef,
    BioAddrMut,
    ffi::bio_addr_st
);

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use core::ptr::addr_of_mut;

    use super::*;

    #[test]
    fn layout_matches_raw_bio_addr_type() {
        assert_eq!(size_of::<BioAddr>(), size_of::<ffi::bio_addr_st>());
        assert_eq!(align_of::<BioAddr>(), align_of::<ffi::bio_addr_st>());
    }

    #[test]
    fn borrowed_handles_preserve_the_raw_pointer() {
        let mut storage = BioAddr::zeroed();
        let raw = addr_of_mut!(storage).cast::<ffi::bio_addr_st>();

        // SAFETY: `storage` is initialized layout-compatible storage and stays
        // live for the duration of this shared handle.
        let shared = unsafe { BioAddrRef::from_ptr(raw) }.expect("non-null BIO_ADDR pointer");
        assert_eq!(shared.as_ptr(), raw.cast_const());

        // The shared handle is not used after this point, leaving the storage
        // exclusively borrowed for the mutable handle's lifetime.
        // SAFETY: `raw` still points to live storage and no competing handle is
        // used while the exclusive handle is live.
        let mut exclusive =
            unsafe { BioAddrMut::from_ptr(raw) }.expect("non-null BIO_ADDR pointer");
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());
    }
}

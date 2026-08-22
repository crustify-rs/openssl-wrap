//! Wrappers assigned from `crypto/bio/bss_mem.c`.

use core::marker::PhantomData;

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::bio_bio_local::{Bio, BioMut, BioRef};
use super::internal_bio::{BioMethodRef, static_bio_method};

/// An owned memory BIO whose read-only storage is borrowed from Rust.
pub struct BorrowedMemBio<'a> {
    bio: CBox<Bio>,
    _buffer: PhantomData<&'a [u8]>,
}

impl BorrowedMemBio<'_> {
    /// Borrows the BIO immutably.
    #[must_use]
    pub fn as_ref(&self) -> BioRef<'_> {
        self.bio.as_ref()
    }

    /// Borrows the BIO exclusively.
    #[must_use]
    pub fn as_mut(&mut self) -> BioMut<'_> {
        self.bio.as_mut()
    }
}

/// Wraps: BIO_new_mem_buf
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_mem_buf(buffer: &[u8]) -> Option<BorrowedMemBio<'_>> {
    let len = i32::try_from(buffer.len()).ok()?;
    // SAFETY: `buffer` supplies `len` readable bytes; the returned wrapper
    // records that borrow for the full lifetime of the BIO.
    let raw = unsafe { ffi::BIO_new_mem_buf(buffer.as_ptr().cast(), len) };
    // SAFETY: a non-null result is a fresh BIO reference transferred to the
    // matching `BIO_free` owner.
    let bio = unsafe { CBox::from_raw(raw) }?;
    Some(BorrowedMemBio {
        bio,
        _buffer: PhantomData,
    })
}

/// Wraps: BIO_s_mem
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_mem() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector returns a process-lifetime table or null.
    static_bio_method(unsafe { ffi::BIO_s_mem() })
}

/// Wraps: BIO_s_secmem
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_secmem() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector returns a process-lifetime table or null.
    static_bio_method(unsafe { ffi::BIO_s_secmem() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::bio_lib::BIO_read_ex;

    #[test]
    fn memory_bio_keeps_the_input_borrow_and_reads_it() {
        let input = b"borrowed bytes";
        let mut bio = BIO_new_mem_buf(input).expect("memory BIO");
        let mut output = [0; 14];
        assert_eq!(BIO_read_ex(&mut bio.as_mut(), &mut output), Some(14));
        assert_eq!(&output, input);
    }
}

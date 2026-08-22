//! Wrappers assigned from `crypto/bio/bss_file.c`.

use core::ffi::CStr;

use ffibox::CBox;
use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;
use libcrypto_sys as ffi;

use super::bio_bio_local::Bio;
use super::bio_lib::BorrowedBio;

/// Wraps: BIO_new_file
/// Opens a file and transfers the stream into an owned BIO.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_file(filename: &CStr, mode: &CStr) -> Option<CBox<Bio>> {
    // SAFETY: both input strings remain live for the call; a non-null result
    // transfers a fresh BIO that owns its opened stream.
    unsafe { CBox::from_raw(ffi::BIO_new_file(filename.as_ptr(), mode.as_ptr())) }
}

/// Wraps: BIO_new_fp
/// Creates a BIO that borrows, but does not close, `stream`.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_fp<'a>(mut stream: IoFileMut<'a>) -> Option<BorrowedBio<'a>> {
    // SAFETY: the exclusive stream handle is lifetime-bound to the result;
    // BIO_NOCLOSE leaves stream ownership with the caller.
    unsafe {
        BorrowedBio::from_raw(ffi::BIO_new_fp(
            stream.as_mut_ptr().cast(),
            ffi::BIO_NOCLOSE as i32,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn file_constructor_owns_the_open_stream() {
        let path = std::env::temp_dir().join(format!("crustify-bio-{}", std::process::id()));
        std::fs::write(&path, b"BIO file test").expect("write fixture");
        let c_path = CString::new(path.as_os_str().as_encoded_bytes()).expect("path without NUL");
        let bio = BIO_new_file(&c_path, c"rb").expect("BIO_new_file");
        drop(bio);
        std::fs::remove_file(path).expect("remove fixture");
    }
}

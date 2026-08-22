//! Wrappers assigned from `crypto/bio/bio_dump.c`.

use core::ffi::{c_int, c_void};
use core::slice;
use std::panic::{AssertUnwindSafe, catch_unwind};

use libcrypto_sys as ffi;

use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;

use super::bio_bio_local::BioMut;

unsafe extern "C" fn dump_trampoline<F>(
    data: *const c_void,
    len: usize,
    context: *mut c_void,
) -> c_int
where
    F: FnMut(&[u8]) -> i32,
{
    // SAFETY: BIO invokes the callback synchronously with `len` readable bytes
    // and the same non-null context pointer supplied by the wrapper.
    let (bytes, callback) = unsafe {
        (
            slice::from_raw_parts(data.cast::<u8>(), len),
            &mut *context.cast::<F>(),
        )
    };
    catch_unwind(AssertUnwindSafe(|| callback(bytes))).unwrap_or(-1)
}

/// Wraps: BIO_dump_cb
/// Formats `data` and synchronously passes each output line to `callback`.
#[allow(non_snake_case)]
pub fn BIO_dump_cb<F>(data: &[u8], callback: &mut F) -> i32
where
    F: FnMut(&[u8]) -> i32,
{
    BIO_dump_indent_cb(data, 0, callback)
}

/// Wraps: BIO_dump_indent_cb
/// Formats `data` with an indentation clamped by OpenSSL to 0..=64.
#[allow(non_snake_case)]
pub fn BIO_dump_indent_cb<F>(data: &[u8], indent: i32, callback: &mut F) -> i32
where
    F: FnMut(&[u8]) -> i32,
{
    let Ok(len) = i32::try_from(data.len()) else {
        return -1;
    };
    // SAFETY: the byte slice remains readable and the callback context remains
    // exclusively borrowed for the synchronous duration of this call. The
    // trampoline catches Rust panics before they can cross the C ABI boundary.
    unsafe {
        ffi::BIO_dump_indent_cb(
            Some(dump_trampoline::<F>),
            core::ptr::from_mut(callback).cast(),
            data.as_ptr().cast(),
            len,
            indent,
        )
    }
}

/// Wraps: BIO_dump
#[allow(non_snake_case)]
pub fn BIO_dump(bio: &mut BioMut<'_>, data: &[u8]) -> i32 {
    BIO_dump_indent(bio, data, 0)
}

/// Wraps: BIO_dump_fp
#[allow(non_snake_case)]
pub fn BIO_dump_fp(file: &mut IoFileMut<'_>, data: &[u8]) -> i32 {
    BIO_dump_indent_fp(file, data, 0)
}

/// Wraps: BIO_dump_indent
#[allow(non_snake_case)]
pub fn BIO_dump_indent(bio: &mut BioMut<'_>, data: &[u8], indent: i32) -> i32 {
    let Ok(len) = i32::try_from(data.len()) else {
        return -1;
    };
    // SAFETY: the exclusive BIO stays live and `data` supplies exactly `len`
    // readable bytes for the synchronous formatting call.
    unsafe { ffi::BIO_dump_indent(bio.as_mut_ptr(), data.as_ptr().cast(), len, indent) }
}

/// Wraps: BIO_dump_indent_fp
#[allow(non_snake_case)]
pub fn BIO_dump_indent_fp(file: &mut IoFileMut<'_>, data: &[u8], indent: i32) -> i32 {
    let Ok(len) = i32::try_from(data.len()) else {
        return -1;
    };
    // SAFETY: the exclusive FILE handle stays live and `data` supplies exactly
    // `len` readable bytes. The independently generated FILE bindings describe
    // the same C ABI type.
    unsafe { ffi::BIO_dump_indent_fp(file.as_mut_ptr().cast(), data.as_ptr().cast(), len, indent) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_callback_receives_borrowed_lines() {
        let mut output = Vec::new();
        let result = BIO_dump_cb(b"ABC", &mut |line: &[u8]| {
            output.extend_from_slice(line);
            i32::try_from(line.len()).unwrap()
        });
        assert_eq!(usize::try_from(result).unwrap(), output.len());
        assert!(output.ends_with(b"ABC\n"));
    }

    #[test]
    fn dump_to_bio_accepts_a_byte_slice() {
        // SAFETY: both called constructors have no caller-side pointer inputs.
        let raw = unsafe { ffi::BIO_new(ffi::BIO_s_null()) };
        // SAFETY: a non-null result transfers one owned BIO reference.
        let mut bio: ffibox::CBox<super::super::bio_bio_local::Bio> =
            unsafe { ffibox::CBox::from_raw(raw) }.expect("BIO_new");
        assert!(BIO_dump(&mut bio.as_mut(), b"ABC") > 0);
    }
}

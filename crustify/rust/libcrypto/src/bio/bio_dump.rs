//! Wrappers assigned from `crypto/bio/bio_dump.c`.

use core::ffi::{c_int, c_void};
use core::slice;
use std::panic::{AssertUnwindSafe, catch_unwind};

use libcrypto_sys as ffi;

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
}

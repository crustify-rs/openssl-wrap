//! Wrappers assigned from `crypto/bio/bio_dump.c`.

use core::ffi::{c_int, c_void};
use core::slice;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;

use super::bio_bio_local::BioMut;

/// The exclusively borrowed closure plus the slot that carries a Rust panic
/// back across the C frames instead of losing it.
struct DumpContext<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
}

unsafe extern "C" fn dump_trampoline<F>(
    data: *const c_void,
    len: usize,
    context: *mut c_void,
) -> c_int
where
    F: FnMut(&[u8]) -> i32,
{
    // SAFETY: the wrapper supplies this exact context type and keeps it
    // exclusively borrowed for the complete synchronous C traversal.
    let context = unsafe { &mut *context.cast::<DumpContext<'_, F>>() };
    if context.panic.is_some() {
        return -1;
    }
    // SAFETY: BIO invokes the callback synchronously with `len` readable bytes
    // starting at the non-null formatting buffer it owns.
    let bytes = unsafe { slice::from_raw_parts(data.cast::<u8>(), len) };
    let outcome = catch_unwind(AssertUnwindSafe(|| (context.callback)(bytes)));
    match outcome {
        Ok(written) => written,
        Err(panic) => {
            // A negative result stops the C loop; the panic resumes in the
            // wrapper rather than crossing the C ABI here.
            context.panic = Some(panic);
            -1
        }
    }
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
    let mut context = DumpContext {
        callback,
        panic: None,
    };
    // SAFETY: the byte slice remains readable and the context remains
    // exclusively borrowed for the synchronous duration of this call. The
    // trampoline catches Rust panics before they can cross the C ABI boundary.
    let result = unsafe {
        ffi::BIO_dump_indent_cb(
            Some(dump_trampoline::<F>),
            core::ptr::from_mut(&mut context).cast(),
            data.as_ptr().cast(),
            len,
            indent,
        )
    };
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
    result
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

/// Wraps: BIO_hex_string
/// Writes `data` as colon-separated hexadecimal bytes.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_hex_string(mut output: BioMut<'_>, indent: i32, width: i32, data: &[u8]) -> bool {
    let Ok(length) = i32::try_from(data.len()) else {
        return false;
    };
    // SAFETY: the exclusive BIO handle remains live and `data` supplies
    // exactly `length` readable bytes for this synchronous formatting call.
    unsafe {
        ffi::BIO_hex_string(
            output.as_mut_ptr(),
            indent,
            width,
            data.as_ptr().cast(),
            length,
        ) == 1
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

    #[test]
    fn indented_dump_prefixes_every_produced_line() {
        let mut lines = Vec::new();
        let result = BIO_dump_indent_cb(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4, &mut |line: &[u8]| {
            lines.push(line.to_vec());
            i32::try_from(line.len()).unwrap()
        });
        assert!(result > 0);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|line| line.starts_with(b"    ")));
    }

    #[test]
    #[should_panic(expected = "dump callback failed")]
    fn a_panicking_callback_resumes_in_the_caller() {
        let _ = BIO_dump_cb(b"ABC", &mut |_: &[u8]| panic!("dump callback failed"));
    }

    /// The lines `BIO_dump_indent_cb` produces for `data`, concatenated.
    fn expected_dump(data: &[u8], indent: i32) -> Vec<u8> {
        let mut text = Vec::new();
        let written = BIO_dump_indent_cb(data, indent, &mut |line: &[u8]| {
            text.extend_from_slice(line);
            i32::try_from(line.len()).expect("a dump line is short")
        });
        assert_eq!(
            usize::try_from(written).expect("a non-negative dump"),
            text.len()
        );
        text
    }

    fn memory_bio() -> crate::bio::bio_lib::BorrowedBio<'static> {
        crate::bio::bio_lib::BIO_new(crate::bio::bss_mem::BIO_s_mem().expect("memory method"))
            .expect("memory BIO")
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

    #[test]
    fn dump_to_bio_writes_the_same_bytes_as_the_callback_form() {
        let data = b"the quick brown fox jumps over the lazy dog";

        let mut plain = memory_bio();
        assert!(BIO_dump(&mut plain.as_mut(), data) > 0);
        let mut written = [0_u8; 512];
        let len = crate::bio::bio_lib::BIO_read_ex(&mut plain.as_mut(), &mut written)
            .expect("dumped output");
        assert_eq!(&written[..len], expected_dump(data, 0).as_slice());

        let mut indented = memory_bio();
        assert!(BIO_dump_indent(&mut indented.as_mut(), data, 4) > 0);
        let mut written = [0_u8; 512];
        let len = crate::bio::bio_lib::BIO_read_ex(&mut indented.as_mut(), &mut written)
            .expect("dumped output");
        assert_eq!(&written[..len], expected_dump(data, 4).as_slice());
    }

    #[test]
    fn dump_to_a_stream_writes_the_same_bytes_as_the_callback_form() {
        let data = b"the quick brown fox jumps over the lazy dog";

        for indent in [0, 4] {
            // SAFETY: `tmpfile` takes no arguments and returns a new stream or
            // null; the process owns it until the `fclose` below.
            let raw = unsafe { libc_sys::tmpfile() };
            // SAFETY: a non-null result is a live stream, exclusively ours for
            // the handle's lifetime.
            let mut stream = unsafe { IoFileMut::from_ptr(raw) }.expect("temporary stream");

            let written = if indent == 0 {
                BIO_dump_fp(&mut stream, data)
            } else {
                BIO_dump_indent_fp(&mut stream, data, indent)
            };
            // `write_fp` returns fwrite's item count (1 per line), so the
            // stream form reports lines where the BIO form reports bytes.
            assert!(written > 0);
            // The handle only borrows the stream; `raw` stays valid below.

            let expected = expected_dump(data, indent);
            let mut readback = vec![0_u8; expected.len() + 1];
            // SAFETY: `raw` is still the live stream opened above, and
            // `readback` supplies its declared number of writable bytes.
            let read = unsafe {
                libc_sys::rewind(raw);
                libc_sys::fread(
                    readback.as_mut_ptr().cast(),
                    1,
                    core::ffi::c_ulong::try_from(readback.len()).expect("a small buffer"),
                    raw,
                )
            };
            let read = usize::try_from(read).expect("a byte count fits in a usize");
            // SAFETY: `raw` is the live stream and no handle to it survives.
            assert_eq!(unsafe { libc_sys::fclose(raw) }, 0);

            assert_eq!(&readback[..read], expected.as_slice());
        }
    }
}

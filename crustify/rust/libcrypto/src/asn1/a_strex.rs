//! Wrappers assigned from `crypto/asn1/a_strex.c`.

use core::ffi::c_ulong;
use core::ptr;

use ffibox::CVec;
use libcrypto_sys as ffi;

use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;

use crate::asn1::asn1::Asn1StringRef;
use crate::bio::bio_bio_local::BioMut;
use crate::mem::CryptoFree;

/// Wraps: ASN1_STRING_print_ex
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_print_ex(
    output: &mut BioMut<'_>,
    string: Asn1StringRef<'_>,
    flags: c_ulong,
) -> i32 {
    // SAFETY: the output BIO is exclusively borrowed, the string is shared and
    // live, and flags is passed by value for the synchronous formatting call.
    unsafe { ffi::ASN1_STRING_print_ex(output.as_mut_ptr(), string.as_ptr(), flags) }
}

/// Wraps: ASN1_STRING_print_ex_fp
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_print_ex_fp(
    output: &mut IoFileMut<'_>,
    string: Asn1StringRef<'_>,
    flags: c_ulong,
) -> i32 {
    // SAFETY: the FILE stream is exclusively borrowed and the independently
    // generated FILE wrapper has the same C ABI. The string remains live and
    // shared for the synchronous formatting call.
    unsafe { ffi::ASN1_STRING_print_ex_fp(output.as_mut_ptr().cast(), string.as_ptr(), flags) }
}

/// A successful UTF-8 conversion.
///
/// Empty output arrives in either of two shapes, which is why this is an enum
/// rather than a bare buffer. When the source already carries the output
/// encoding, `ASN1_mbstring_ncopy` takes its copy-across path and a zero-byte
/// copy leaves the slot null — [`Self::Empty`]. When it has to re-encode, it
/// allocates `outlen + 1` bytes unconditionally, so a zero-length result is a
/// live one-byte allocation the caller still owes a free for — [`Self::Bytes`]
/// holding no elements. An empty `V_ASN1_UTF8STRING` produces the first and an
/// empty `V_ASN1_BMPSTRING` the second.
pub enum Asn1Utf8 {
    /// OpenSSL produced no buffer at all.
    Empty,
    /// An owned conversion buffer, possibly of zero length.
    Bytes(CVec<u8, CryptoFree>),
}

impl Asn1Utf8 {
    /// Returns the converted bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Empty => &[],
            Self::Bytes(bytes) => bytes.as_slice(),
        }
    }
}

/// Wraps: ASN1_STRING_to_UTF8
/// Converts a string and owns the allocator-matched output buffer.
///
/// The error carries OpenSSL's negative result, which covers a null or
/// non-string input type as well as a conversion or allocation failure.
#[allow(non_snake_case)]
pub fn ASN1_STRING_to_UTF8(string: Asn1StringRef<'_>) -> Result<Asn1Utf8, i32> {
    let mut output = ptr::null_mut();
    // SAFETY: `output` is a live write slot and `string` is a live shared
    // handle. On success OpenSSL transfers its new allocation through the slot.
    let length = unsafe { ffi::ASN1_STRING_to_UTF8(&mut output, string.as_ptr()) };
    if length < 0 {
        return Err(length);
    }
    let length = usize::try_from(length).expect("nonnegative conversion length");
    if output.is_null() {
        debug_assert_eq!(length, 0);
        return Ok(Asn1Utf8::Empty);
    }
    // SAFETY: successful conversion reports exactly `length` initialized bytes
    // in a fresh ordinary OpenSSL allocation transferred to the caller.
    let bytes =
        unsafe { CVec::from_raw_parts(output, length) }.expect("non-null UTF-8 output was checked");
    Ok(Asn1Utf8::Bytes(bytes))
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::asn1::asn1::Asn1String;
    use crate::asn1::asn1_lib::{ASN1_STRING_set1_data, ASN1_STRING_type_new};

    /// A fresh owned string of `string_type` carrying exactly `data`.
    fn typed_string(string_type: i32, data: &[u8]) -> CBox<Asn1String> {
        let mut string = ASN1_STRING_type_new(string_type).expect("typed ASN1 string");
        assert!(ASN1_STRING_set1_data(&mut string.as_mut(), data));
        string
    }

    fn memory_bio() -> crate::bio::bio_lib::BorrowedBio<'static> {
        crate::bio::bio_lib::BIO_new(crate::bio::bss_mem::BIO_s_mem().expect("memory method"))
            .expect("memory BIO")
    }

    #[test]
    fn octet_text_converts_to_owned_utf8() {
        let string = typed_string(ffi::V_ASN1_UTF8STRING as i32, b"hello");
        let converted = ASN1_STRING_to_UTF8(string.as_ref()).expect("UTF-8 conversion");
        assert_eq!(converted.as_bytes(), b"hello");
    }

    #[test]
    fn a_wide_source_is_transcoded_into_a_fresh_buffer() {
        // "hi" as a BMPString: two big-endian UTF-16 code units.
        let string = typed_string(ffi::V_ASN1_BMPSTRING as i32, b"\x00h\x00i");
        let converted = ASN1_STRING_to_UTF8(string.as_ref()).expect("UTF-8 conversion");
        assert_eq!(converted.as_bytes(), b"hi");
    }

    #[test]
    fn both_empty_output_shapes_are_owned_correctly() {
        // Same encoding in and out: OpenSSL copies across and leaves no buffer.
        let same = typed_string(ffi::V_ASN1_UTF8STRING as i32, b"");
        let converted = ASN1_STRING_to_UTF8(same.as_ref()).expect("UTF-8 conversion");
        assert!(matches!(converted, Asn1Utf8::Empty));
        assert_eq!(converted.as_bytes(), b"");

        // Re-encoding: the terminator allocation exists even with no output,
        // so the owner must take it and release it rather than drop it.
        let wide = typed_string(ffi::V_ASN1_BMPSTRING as i32, b"");
        let converted = ASN1_STRING_to_UTF8(wide.as_ref()).expect("UTF-8 conversion");
        let Asn1Utf8::Bytes(bytes) = &converted else {
            panic!("an empty re-encoding still owns its terminator allocation");
        };
        assert_eq!(bytes.count(), 0);
        assert_eq!(converted.as_bytes(), b"");
    }

    #[test]
    fn a_non_string_type_is_rejected_before_conversion() {
        assert!(ASN1_STRING_type_new(ffi::V_ASN1_BOOLEAN as i32).is_none());
    }

    #[test]
    fn the_bio_and_stream_forms_print_the_same_bytes() {
        let string = typed_string(ffi::V_ASN1_UTF8STRING as i32, b"hello");

        let mut bio = memory_bio();
        let written = ASN1_STRING_print_ex(&mut bio.as_mut(), string.as_ref(), 0);
        assert_eq!(written, 5);
        let mut buffer = [0_u8; 32];
        let read = crate::bio::bio_lib::BIO_read_ex(&mut bio.as_mut(), &mut buffer)
            .expect("formatted output");
        assert_eq!(&buffer[..read], b"hello");

        // SAFETY: `tmpfile` takes no arguments and returns a new stream or
        // null; the process owns it until the `fclose` below.
        let raw = unsafe { libc_sys::tmpfile() };
        // SAFETY: a non-null result is a live stream, exclusively ours for the
        // handle's lifetime.
        let mut stream = unsafe { IoFileMut::from_ptr(raw) }.expect("temporary stream");
        assert_eq!(
            ASN1_STRING_print_ex_fp(&mut stream, string.as_ref(), 0),
            written
        );
        // The handle only borrows the stream, so `raw` stays valid below.

        let mut readback = [0_u8; 32];
        // SAFETY: `raw` is still the live stream opened above and `readback`
        // supplies its declared number of writable bytes.
        let count = unsafe {
            libc_sys::rewind(raw);
            libc_sys::fread(
                readback.as_mut_ptr().cast(),
                1,
                core::ffi::c_ulong::try_from(readback.len()).expect("a small buffer"),
                raw,
            )
        };
        // SAFETY: `raw` is the live stream and no handle to it survives.
        assert_eq!(unsafe { libc_sys::fclose(raw) }, 0);
        assert_eq!(
            &readback[..usize::try_from(count).expect("a byte count")],
            b"hello"
        );
    }

    #[test]
    fn escaping_flags_reach_the_formatter() {
        // `ASN1_STRFLGS_ESC_CTRL` is `0x2` in `<openssl/asn1.h>`; a control
        // byte then leaves as a backslash escape instead of verbatim.
        const ESC_CTRL: c_ulong = 0x2;

        let string = typed_string(ffi::V_ASN1_UTF8STRING as i32, b"a\nb");
        let mut bio = memory_bio();
        assert!(ASN1_STRING_print_ex(&mut bio.as_mut(), string.as_ref(), ESC_CTRL) > 3);
        let mut buffer = [0_u8; 32];
        let read = crate::bio::bio_lib::BIO_read_ex(&mut bio.as_mut(), &mut buffer)
            .expect("formatted output");
        assert_eq!(&buffer[..read], b"a\\0Ab");
    }
}

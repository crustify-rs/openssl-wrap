//! Wrappers assigned from `crypto/asn1/a_strex.c`.

use core::ffi::c_ulong;
use core::ptr;

use ffibox::CVec;
use libcrypto_sys as ffi;

use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;

use crate::asn1::asn1::Asn1StringRef;
use crate::bio::bio_bio_local::BioMut;
use crate::mem::CryptoFree;
use crate::x509::x509_internal::X509NameRef;

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

/// A successful distinguished-name formatting call.
///
/// `X509_NAME_print_ex` reports its result under two different conventions,
/// selected by `flags`. `XN_FLAG_COMPAT` — numerically zero — delegates to
/// `X509_NAME_print`, which only distinguishes success from failure. Every
/// other flag combination runs the extended formatter, which reports the
/// number of characters the name occupied. A single integer cannot say which
/// convention produced it, so the two are separate variants here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X509NamePrinted {
    /// The `XN_FLAG_COMPAT` path succeeded and reported no length.
    Compat,
    /// The extended formatter accounted for this many characters.
    Written(usize),
}

/// Wraps: X509_NAME_print_ex
/// Formats a distinguished name, optionally into a BIO.
///
/// A `None` sink runs the formatter for its character count without writing
/// anything: the C sink callback reports success for a null argument, so the
/// extended path still accumulates and returns the length. That does not hold
/// under `XN_FLAG_COMPAT`, whose delegate writes through `BIO_write` directly
/// and reports failure for a null BIO; it also ignores `indent`.
///
/// A negative `indent` is clamped to zero before formatting. `None` reports
/// OpenSSL's failure code under whichever convention `flags` selected, which
/// covers an unsupported separator selection as well as a write or overflow
/// failure.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_print_ex(
    output: Option<&mut BioMut<'_>>,
    name: X509NameRef<'_>,
    indent: i32,
    flags: c_ulong,
) -> Option<X509NamePrinted> {
    let output = output.map_or(ptr::null_mut(), |bio| bio.as_mut_ptr());
    // SAFETY: the sink is null or an exclusively borrowed live BIO written
    // synchronously, and the name remains live and shared throughout
    // formatting. Both paths tolerate the null sink without dereferencing it.
    let result = unsafe { ffi::X509_NAME_print_ex(output, name.as_ptr(), indent, flags) };
    if flags == c_ulong::from(ffi::XN_FLAG_COMPAT) {
        return (result == 1).then_some(X509NamePrinted::Compat);
    }
    usize::try_from(result).ok().map(X509NamePrinted::Written)
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::asn1::asn1::Asn1String;
    use crate::asn1::asn1_lib::{ASN1_STRING_set1_data, ASN1_STRING_type_new};
    use crate::x509::x_name::{X509_NAME_free, d2i_X509_NAME};

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

    /// The DER of the one-entry distinguished name `CN=x`.
    const NAME_DER: &[u8] = b"\x30\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01x";
    /// Chooses the extended formatter over the compatibility path.
    const SEP_COMMA_PLUS: c_ulong = ffi::XN_FLAG_SEP_COMMA_PLUS as c_ulong;

    #[test]
    fn distinguished_name_printing_writes_through_the_typed_bio() {
        let mut input = NAME_DER;
        let name = d2i_X509_NAME(&mut input).expect("name DER");
        let mut bio = memory_bio();
        assert_eq!(
            X509_NAME_print_ex(Some(&mut bio.as_mut()), name.as_ref(), 0, SEP_COMMA_PLUS),
            Some(X509NamePrinted::Written(4))
        );
        let mut buffer = [0_u8; 16];
        let read = crate::bio::bio_lib::BIO_read_ex(&mut bio.as_mut(), &mut buffer)
            .expect("formatted name");
        assert_eq!(&buffer[..read], b"CN=x");
        X509_NAME_free(name);
    }

    #[test]
    fn a_null_sink_counts_the_characters_without_writing() {
        let mut input = NAME_DER;
        let name = d2i_X509_NAME(&mut input).expect("name DER");

        assert_eq!(
            X509_NAME_print_ex(None, name.as_ref(), 0, SEP_COMMA_PLUS),
            Some(X509NamePrinted::Written(4))
        );
        // The leading indent is counted even though the separator selection
        // then drops it from the per-entry indentation.
        assert_eq!(
            X509_NAME_print_ex(None, name.as_ref(), 3, SEP_COMMA_PLUS),
            Some(X509NamePrinted::Written(7))
        );
        // A negative indent is clamped rather than shortening the count.
        assert_eq!(
            X509_NAME_print_ex(None, name.as_ref(), -3, SEP_COMMA_PLUS),
            Some(X509NamePrinted::Written(4))
        );

        X509_NAME_free(name);
    }

    #[test]
    fn the_compatibility_path_reports_success_rather_than_a_length() {
        let mut input = NAME_DER;
        let name = d2i_X509_NAME(&mut input).expect("name DER");
        let compat = c_ulong::from(ffi::XN_FLAG_COMPAT);

        let mut bio = memory_bio();
        assert_eq!(
            X509_NAME_print_ex(Some(&mut bio.as_mut()), name.as_ref(), 0, compat),
            Some(X509NamePrinted::Compat)
        );
        let mut buffer = [0_u8; 16];
        let read = crate::bio::bio_lib::BIO_read_ex(&mut bio.as_mut(), &mut buffer)
            .expect("formatted name");
        assert_eq!(&buffer[..read], b"CN=x");

        // `X509_NAME_print` writes through the BIO unconditionally, so the
        // counting sink is a plain failure here and not a zero-length success.
        assert_eq!(X509_NAME_print_ex(None, name.as_ref(), 0, compat), None);

        X509_NAME_free(name);
    }

    #[test]
    fn an_unsupported_separator_selection_fails() {
        let mut input = NAME_DER;
        let name = d2i_X509_NAME(&mut input).expect("name DER");
        // Non-zero flags that leave `XN_FLAG_SEP_MASK` empty reach the
        // formatter's rejected default rather than the compatibility path.
        const DN_REV: c_ulong = 1 << 20;

        let mut bio = memory_bio();
        assert_eq!(
            X509_NAME_print_ex(Some(&mut bio.as_mut()), name.as_ref(), 0, DN_REV),
            None
        );

        X509_NAME_free(name);
    }
}

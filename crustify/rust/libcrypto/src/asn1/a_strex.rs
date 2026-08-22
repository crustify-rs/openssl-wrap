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

/// A successful UTF-8 conversion. OpenSSL represents empty output as null.
pub enum Asn1Utf8 {
    Empty,
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
    use super::*;

    #[test]
    fn octet_text_converts_to_owned_utf8() {
        let mut string = crate::asn1::asn1_lib::ASN1_STRING_type_new(ffi::V_ASN1_UTF8STRING as i32)
            .expect("UTF8 ASN1 string");
        assert!(crate::asn1::asn1_lib::ASN1_STRING_set1_data(
            &mut string.as_mut(),
            b"hello"
        ));
        let converted = ASN1_STRING_to_UTF8(string.as_ref()).expect("UTF-8 conversion");
        assert_eq!(converted.as_bytes(), b"hello");
    }
}

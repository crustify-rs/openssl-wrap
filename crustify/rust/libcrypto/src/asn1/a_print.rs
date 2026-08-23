//! Wrappers assigned from `crypto/asn1/a_print.c`.

use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1StringRef;
use crate::bio::bio_bio_local::BioMut;

/// Wraps: ASN1_STRING_print
/// Writes printable bytes to `output`, replacing control bytes with dots.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_print(output: &mut BioMut<'_>, string: Option<Asn1StringRef<'_>>) -> bool {
    let string = string.map_or(core::ptr::null(), |value| value.as_ptr());
    // SAFETY: `output` is exclusively borrowed for the write and `string` is
    // either null (an explicitly supported failure case) or a live shared
    // ASN.1 string for the synchronous call.
    unsafe { ffi::ASN1_STRING_print(output.as_mut_ptr(), string) == 1 }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;

    #[test]
    fn null_input_is_rejected_without_touching_the_bio() {
        // SAFETY: these constructors take no caller-side pointers and return
        // process-lifetime method metadata plus a fresh BIO allocation.
        let raw = unsafe { ffi::BIO_new(ffi::BIO_s_null()) };
        // SAFETY: a non-null `BIO_new` result transfers one owned reference.
        let mut bio: CBox<crate::bio::bio_bio_local::Bio> =
            unsafe { CBox::from_raw(raw) }.expect("null BIO");
        assert!(!ASN1_STRING_print(&mut bio.as_mut(), None));
    }

    #[test]
    fn unprintable_bytes_become_dots_and_newlines_survive() {
        let mut string = crate::asn1::asn1_lib::ASN1_STRING_new().expect("ASN1_STRING_new");
        // `\n` and `\r` pass through; everything below a space, above `~`, or
        // with the high bit set (`char` is signed here) prints as a dot.
        let source = b"ab\x01c\x7f\n\r\xff";
        assert!(crate::asn1::asn1_lib::ASN1_STRING_set1_data(
            &mut string.as_mut(),
            source
        ));

        let mut bio =
            crate::bio::bio_lib::BIO_new(crate::bio::bss_mem::BIO_s_mem().expect("memory method"))
                .expect("memory BIO");
        assert!(ASN1_STRING_print(&mut bio.as_mut(), Some(string.as_ref())));

        let mut buffer = [0_u8; 32];
        let read = crate::bio::bio_lib::BIO_read_ex(&mut bio.as_mut(), &mut buffer)
            .expect("printed output");
        assert_eq!(&buffer[..read], b"ab.c.\n\r.");
    }

    #[test]
    fn an_empty_string_writes_nothing_and_still_succeeds() {
        let string = crate::asn1::asn1_lib::ASN1_STRING_new().expect("ASN1_STRING_new");
        let mut bio =
            crate::bio::bio_lib::BIO_new(crate::bio::bss_mem::BIO_s_mem().expect("memory method"))
                .expect("memory BIO");
        assert!(ASN1_STRING_print(&mut bio.as_mut(), Some(string.as_ref())));

        let mut buffer = [0_u8; 8];
        assert_eq!(
            crate::bio::bio_lib::BIO_read_ex(&mut bio.as_mut(), &mut buffer),
            None
        );
    }
}

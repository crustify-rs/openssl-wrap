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
}

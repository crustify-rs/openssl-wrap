//! Wrappers assigned from `crypto/asn1/a_strnid.c`.

use core::ffi::CStr;

use libcrypto_sys as ffi;

/// Wraps: ASN1_STRING_TABLE_add
/// Adds or updates the string constraints for `nid`.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_TABLE_add(
    nid: i32,
    min_size: i64,
    max_size: i64,
    mask: u64,
    flags: u64,
) -> bool {
    // SAFETY: this call has only by-value scalar arguments.
    unsafe { ffi::ASN1_STRING_TABLE_add(nid, min_size, max_size, mask, flags) == 1 }
}

/// Wraps: ASN1_STRING_get_default_mask
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_get_default_mask() -> u64 {
    // SAFETY: the getter has no caller-side memory obligations.
    unsafe { ffi::ASN1_STRING_get_default_mask() }
}

/// Wraps: ASN1_STRING_set_default_mask
#[allow(non_snake_case)]
pub fn ASN1_STRING_set_default_mask(mask: u64) {
    // SAFETY: the setter has only a by-value scalar argument.
    unsafe { ffi::ASN1_STRING_set_default_mask(mask) }
}

/// Wraps: ASN1_STRING_set_default_mask_asc
/// Selects a predefined mask or parses a `MASK:` value.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set_default_mask_asc(value: &CStr) -> bool {
    // SAFETY: `value` provides a live, immutable NUL-terminated string for the call.
    unsafe { ffi::ASN1_STRING_set_default_mask_asc(value.as_ptr()) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_round_trips_and_ascii_presets_are_checked() {
        let saved = ASN1_STRING_get_default_mask();
        ASN1_STRING_set_default_mask(0x1234);
        assert_eq!(ASN1_STRING_get_default_mask(), 0x1234);
        assert!(ASN1_STRING_set_default_mask_asc(c"utf8only"));
        assert!(!ASN1_STRING_set_default_mask_asc(c"not-a-mask"));
        ASN1_STRING_set_default_mask(saved);
    }
}

//! Wrappers assigned from `crypto/asn1/a_strnid.c`.

use core::ffi::CStr;

use libcrypto_sys as ffi;

use super::openssl_asn1::Asn1StringTableRef;

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

    #[test]
    fn table_lookup_returns_a_detached_scalar_snapshot() {
        let nid = crate::objects::obj_dat::OBJ_sn2nid(c"CN");
        let values = ASN1_STRING_TABLE_get(nid).expect("commonName table entry");
        assert_eq!(values.nid, nid);
        assert!(values.max_size >= values.min_size);
    }
}

/// A copied, Rust-owned view of one ASN.1 string-table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1StringTableValues {
    pub nid: i32,
    pub min_size: core::ffi::c_long,
    pub max_size: core::ffi::c_long,
    pub mask: core::ffi::c_ulong,
    pub flags: core::ffi::c_ulong,
}

/// Wraps: ASN1_STRING_TABLE_cleanup
///
/// # Safety
/// No C code may concurrently access the process-global ASN.1 string table.
/// The call invalidates pointers previously returned by the raw C getter.
#[allow(non_snake_case)]
pub unsafe fn ASN1_STRING_TABLE_cleanup() {
    // SAFETY: the caller excludes concurrent and outstanding raw C users.
    unsafe { ffi::ASN1_STRING_TABLE_cleanup() }
}

/// Wraps: ASN1_STRING_TABLE_get
/// Copies an entry so no borrow of cleanup-sensitive global storage escapes.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_TABLE_get(nid: i32) -> Option<Asn1StringTableValues> {
    // SAFETY: the lookup takes a scalar and returns either null or a live table
    // entry long enough to synchronously copy its scalar fields.
    let raw = unsafe { ffi::ASN1_STRING_TABLE_get(nid) };
    // SAFETY: a non-null result is initialized for the duration of these reads.
    let table = unsafe { Asn1StringTableRef::from_ptr(raw) }?;
    Some(Asn1StringTableValues {
        nid: table.nid(),
        min_size: table.min_size(),
        max_size: table.max_size(),
        mask: table.mask(),
        flags: table.flags(),
    })
}

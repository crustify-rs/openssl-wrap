//! Wrappers assigned from `crypto/asn1/a_strnid.c`.

use core::ffi::{CStr, c_long, c_ulong};
use std::sync::{Mutex, MutexGuard};

use libcrypto_sys as ffi;

use super::openssl_asn1::Asn1StringTableRef;

/// Serializes every safe Rust access to OpenSSL's unsynchronized global mask
/// and dynamic ASN.1 string table. Calls made directly from C remain outside
/// this lock and must be coordinated by the embedding application.
static STRING_TABLE_LOCK: Mutex<()> = Mutex::new(());

fn lock_string_table() -> MutexGuard<'static, ()> {
    STRING_TABLE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Serializes multi-call assertions without recursively taking the production
/// mutex. Every test that exercises this module participates.
#[cfg(test)]
static STRING_TABLE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Wraps: ASN1_STRING_TABLE_add
/// Adds or updates the string constraints for `nid`.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_TABLE_add(
    nid: i32,
    min_size: c_long,
    max_size: c_long,
    mask: c_ulong,
    flags: c_ulong,
) -> bool {
    let _guard = lock_string_table();
    // SAFETY: this call has only by-value scalar arguments, and the mutex
    // excludes every other safe Rust access to the process-global table.
    unsafe { ffi::ASN1_STRING_TABLE_add(nid, min_size, max_size, mask, flags) == 1 }
}

/// Wraps: ASN1_STRING_get_default_mask
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_get_default_mask() -> c_ulong {
    let _guard = lock_string_table();
    // SAFETY: the getter has no caller-side memory obligations, and the mutex
    // excludes safe Rust writers of the process-global scalar.
    unsafe { ffi::ASN1_STRING_get_default_mask() }
}

/// Wraps: ASN1_STRING_set_default_mask
#[allow(non_snake_case)]
pub fn ASN1_STRING_set_default_mask(mask: c_ulong) {
    let _guard = lock_string_table();
    // SAFETY: the setter has only a by-value scalar argument, and the mutex
    // excludes every other safe Rust access to the process-global scalar.
    unsafe { ffi::ASN1_STRING_set_default_mask(mask) }
}

/// Wraps: ASN1_STRING_set_default_mask_asc
/// Selects a predefined mask or parses a `MASK:` value.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set_default_mask_asc(value: &CStr) -> bool {
    let _guard = lock_string_table();
    // SAFETY: `value` provides a live, immutable NUL-terminated string for the
    // call, and the mutex excludes every other safe Rust mask access.
    unsafe { ffi::ASN1_STRING_set_default_mask_asc(value.as_ptr()) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_round_trips_and_ascii_presets_are_checked() {
        let _guard = STRING_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let saved = ASN1_STRING_get_default_mask();
        ASN1_STRING_set_default_mask(0x1234);
        assert_eq!(ASN1_STRING_get_default_mask(), 0x1234);
        assert!(ASN1_STRING_set_default_mask_asc(c"utf8only"));
        assert!(!ASN1_STRING_set_default_mask_asc(c"not-a-mask"));
        ASN1_STRING_set_default_mask(saved);
    }

    #[test]
    fn table_lookup_returns_a_detached_scalar_snapshot() {
        let _guard = STRING_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let nid = crate::objects::obj_dat::OBJ_sn2nid(c"CN");
        let values = ASN1_STRING_TABLE_get(nid).expect("commonName table entry");
        assert_eq!(values.nid, nid);
        assert!(values.max_size >= values.min_size);
    }

    #[test]
    fn added_constraints_are_visible_and_invalid_ranges_are_rejected() {
        /// `B_ASN1_UTF8STRING` from `<openssl/asn1.h>`.
        const MASK: c_ulong = 0x2000;

        let _guard = STRING_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let nid = crate::objects::obj_dat::OBJ_create(
            Some(c"1.3.6.1.4.1.57264.9002"),
            Some(c"crustifyStringTable"),
            Some(c"crustify string table entry"),
        );
        assert_ne!(nid, 0);

        assert!(ASN1_STRING_TABLE_add(nid, 2, 8, MASK, 0));
        let values = ASN1_STRING_TABLE_get(nid).expect("added table entry");
        assert_eq!(values.nid, nid);
        assert_eq!(values.min_size, 2);
        assert_eq!(values.max_size, 8);
        assert_eq!(values.mask, MASK);

        // A non-positive NID and an inverted size range are both refused.
        assert!(!ASN1_STRING_TABLE_add(0, 1, 2, MASK, 0));
        assert!(!ASN1_STRING_TABLE_add(nid, 9, 8, MASK, 0));
        assert_eq!(ASN1_STRING_TABLE_get(nid).map(|v| v.max_size), Some(8));
    }

    #[test]
    fn safe_table_access_is_serialized_across_threads() {
        /// `B_ASN1_UTF8STRING` from `<openssl/asn1.h>`.
        const MASK: c_ulong = 0x2000;

        let _guard = STRING_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let nid = crate::objects::obj_dat::OBJ_create(
            Some(c"1.3.6.1.4.1.57264.9003"),
            Some(c"crustifyConcurrentStringTable"),
            Some(c"crustify concurrent string table entry"),
        );
        assert_ne!(nid, 0);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers = (0..8)
            .map(|_| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for _ in 0..128 {
                        assert!(ASN1_STRING_TABLE_add(nid, 0, 8, MASK, 0));
                        assert_eq!(ASN1_STRING_TABLE_get(nid).map(|v| v.nid), Some(nid));
                    }
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            worker.join().expect("string-table worker");
        }
    }
}

/// A copied, Rust-owned view of one ASN.1 string-table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Asn1StringTableValues {
    pub nid: i32,
    pub min_size: c_long,
    pub max_size: c_long,
    pub mask: c_ulong,
    pub flags: c_ulong,
}

/// Wraps: ASN1_STRING_TABLE_cleanup
///
/// # Safety
/// No C code may concurrently access the process-global ASN.1 string table.
/// The call invalidates pointers previously returned by the raw C getter.
#[allow(non_snake_case)]
pub unsafe fn ASN1_STRING_TABLE_cleanup() {
    let _guard = lock_string_table();
    // SAFETY: the caller excludes concurrent and outstanding raw C users; the
    // mutex additionally excludes all safe Rust table access.
    unsafe { ffi::ASN1_STRING_TABLE_cleanup() }
}

/// Wraps: ASN1_STRING_TABLE_get
/// Copies an entry so no borrow of cleanup-sensitive global storage escapes.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_TABLE_get(nid: i32) -> Option<Asn1StringTableValues> {
    let _guard = lock_string_table();
    // SAFETY: the lookup takes a scalar and returns either null or a live table
    // entry long enough to synchronously copy its scalar fields. The mutex
    // excludes every other safe Rust access while the pointer is read.
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

/// Wraps: ASN1_STRING_set_by_NID
/// Allocates a new constrained ASN.1 string for `input`.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set_by_NID(
    input: &[u8],
    input_format: i32,
    nid: i32,
) -> Option<ffibox::CBox<crate::asn1::asn1::Asn1String>> {
    let input_length = i32::try_from(input.len()).ok()?;
    let _guard = lock_string_table();
    // SAFETY: a null output slot requests a new allocation. `input` supplies
    // exactly `input_length` readable bytes for this synchronous conversion;
    // the mutex protects its global table and mask lookups.
    let raw = unsafe {
        ffi::ASN1_STRING_set_by_NID(
            core::ptr::null_mut(),
            input.as_ptr(),
            input_length,
            input_format,
            nid,
        )
    };
    // SAFETY: with no caller-provided output slot, a non-null success result is
    // a fresh fully initialized string transferred to the caller.
    unsafe { ffibox::CBox::from_raw(raw) }
}

/// Wraps: ASN1_STRING_set_by_NID
/// Reuses an existing owned ASN.1 string for the constrained conversion.
///
/// The second of this symbol's two safe contracts. A non-null `*out` selects
/// OpenSSL's reuse branch, which empties the supplied string with
/// `ASN1_STRING_set0` and refills it in place, so the caller keeps ownership
/// and the result is a success flag rather than a new owner.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set_by_NID_into(
    output: &mut crate::asn1::asn1::Asn1StringMut<'_>,
    input: &[u8],
    input_format: i32,
    nid: i32,
) -> bool {
    let Ok(input_length) = i32::try_from(input.len()) else {
        return false;
    };
    let expected = output.as_mut_ptr();
    let mut slot = expected;
    let _guard = lock_string_table();
    // SAFETY: the in/out slot contains the exclusively borrowed live string,
    // which OpenSSL reuses rather than replacing. `input` supplies its reported
    // number of readable bytes for the conversion, and the mutex protects the
    // global table and mask lookups.
    let result = unsafe {
        ffi::ASN1_STRING_set_by_NID(&mut slot, input.as_ptr(), input_length, input_format, nid)
    };
    debug_assert_eq!(slot, expected);
    result == expected
}

#[cfg(test)]
mod set_by_nid_tests {
    use super::*;

    #[test]
    fn creates_and_reuses_constrained_strings() {
        let _guard = STRING_TABLE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let nid = crate::objects::obj_dat::OBJ_sn2nid(c"CN");
        let mut string = ASN1_STRING_set_by_NID(b"example", ffi::MBSTRING_ASC as i32, nid)
            .expect("constrained common name");
        assert!(ASN1_STRING_set_by_NID_into(
            &mut string.as_mut(),
            b"updated",
            ffi::MBSTRING_ASC as i32,
            nid,
        ));
        assert_eq!(
            crate::asn1::asn1_lib::ASN1_STRING_get_length(string.as_ref()),
            7
        );
    }
}

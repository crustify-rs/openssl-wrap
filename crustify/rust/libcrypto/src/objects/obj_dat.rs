//! Wrappers assigned from `crypto/objects/obj_dat.c`.

use core::ffi::{CStr, c_void};
use core::mem::size_of;
use core::ptr::{self, NonNull};
use std::ffi::CString;

use ffibox::{CBox, CSlice};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1Object, Asn1ObjectRef};
use crate::bio::bio_bio_local::BioMut;
use crate::stack::openssl_stack::OpenSslSkCompFunc;

fn bsearch_result<T>(base: &[T], result: *const c_void) -> Option<&T> {
    if result.is_null() || base.is_empty() || size_of::<T>() == 0 {
        return None;
    }
    let start = base.as_ptr().addr();
    let byte_len = base.len().checked_mul(size_of::<T>())?;
    let end = start.checked_add(byte_len)?;
    let address = result.addr();
    if address < start || address >= end {
        return None;
    }
    let offset = address - start;
    if !offset.is_multiple_of(size_of::<T>()) {
        return None;
    }
    base.get(offset / size_of::<T>())
}

/// Wraps: OBJ_bsearch_
/// Searches a sorted typed slice with an erased C comparator.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_bsearch_<'a, K, T>(
    key: &K,
    base: &'a [T],
    comparator: OpenSslSkCompFunc<K, T>,
) -> Option<&'a T> {
    let count = i32::try_from(base.len()).ok()?;
    let element_size = i32::try_from(size_of::<T>()).ok()?;
    if element_size == 0 {
        return None;
    }
    // SAFETY: `key` and all `base` elements remain shared and live for the
    // synchronous call. The comparator's unsafe constructor established its
    // concrete argument types. Count and element size exactly describe `base`.
    let result = unsafe {
        ffi::OBJ_bsearch_(
            ptr::from_ref(key).cast(),
            base.as_ptr().cast(),
            count,
            element_size,
            comparator.as_raw(),
        )
    };
    bsearch_result(base, result)
}

/// Wraps: OBJ_bsearch_ex_
/// Searches with OpenSSL's integer bsearch option flags.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_bsearch_ex_<'a, K, T>(
    key: &K,
    base: &'a [T],
    comparator: OpenSslSkCompFunc<K, T>,
    flags: i32,
) -> Option<&'a T> {
    let count = i32::try_from(base.len()).ok()?;
    let element_size = i32::try_from(size_of::<T>()).ok()?;
    if element_size == 0 {
        return None;
    }
    // SAFETY: the shared operands, comparator contract, count, and element
    // size satisfy the same invariants as `OBJ_bsearch_`; flags are by value.
    let result = unsafe {
        ffi::OBJ_bsearch_ex_(
            ptr::from_ref(key).cast(),
            base.as_ptr().cast(),
            count,
            element_size,
            comparator.as_raw(),
            flags,
        )
    };
    bsearch_result(base, result)
}

/// Wraps: OBJ_create
/// Adds a dynamic OID/name entry and returns its NID (`0` on failure).
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_create(oid: Option<&CStr>, short_name: Option<&CStr>, long_name: Option<&CStr>) -> i32 {
    let raw = |value: Option<&CStr>| value.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: every non-null argument is a live immutable C string. OpenSSL
    // copies successful inputs into its registry rather than retaining them.
    unsafe { ffi::OBJ_create(raw(oid), raw(short_name), raw(long_name)) }
}

/// Wraps: OBJ_ln2nid
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_ln2nid(long_name: &CStr) -> i32 {
    // SAFETY: `long_name` is a live immutable C string for the call.
    unsafe { ffi::OBJ_ln2nid(long_name.as_ptr()) }
}

/// Wraps: OBJ_new_nid
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_new_nid(count: i32) -> i32 {
    // SAFETY: the allocator takes only a by-value count.
    unsafe { ffi::OBJ_new_nid(count) }
}

/// Wraps: OBJ_nid2ln
/// Copies the registry-owned long name into Rust-owned storage.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_nid2ln(nid: i32) -> Option<CString> {
    // SAFETY: the lookup takes only a by-value NID.
    let raw = unsafe { ffi::OBJ_nid2ln(nid) };
    if raw.is_null() {
        None
    } else {
        // SAFETY: a non-null result is a live NUL-terminated registry string,
        // copied before its borrow can escape this wrapper.
        Some(unsafe { CStr::from_ptr(raw) }.to_owned())
    }
}

/// Wraps: OBJ_nid2sn
/// Copies the registry-owned short name into Rust-owned storage.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_nid2sn(nid: i32) -> Option<CString> {
    // SAFETY: the lookup takes only a by-value NID.
    let raw = unsafe { ffi::OBJ_nid2sn(nid) };
    if raw.is_null() {
        None
    } else {
        // SAFETY: a non-null result is a live NUL-terminated registry string,
        // copied before its borrow can escape this wrapper.
        Some(unsafe { CStr::from_ptr(raw) }.to_owned())
    }
}

/// Wraps: OBJ_sn2nid
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_sn2nid(short_name: &CStr) -> i32 {
    // SAFETY: `short_name` is a live immutable C string for the call.
    unsafe { ffi::OBJ_sn2nid(short_name.as_ptr()) }
}

/// Wraps: OBJ_create_objects
/// Reads textual object definitions from `input` and returns the number added.
#[allow(non_snake_case)]
pub fn OBJ_create_objects(input: &mut BioMut<'_>) -> i32 {
    // SAFETY: the exclusive handle supplies a live BIO for the synchronous
    // parser call. OpenSSL advances it but neither retains nor releases it.
    unsafe { ffi::OBJ_create_objects(input.as_mut_ptr()) }
}

fn detached_object(raw: *mut ffi::ASN1_OBJECT) -> Option<CBox<Asn1Object>> {
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is a live object for these synchronous scalar/pointer
    // getters; the creator immediately deep-copies the reported byte run.
    let (nid, length, data) = unsafe {
        (
            ffi::OBJ_obj2nid(raw),
            ffi::OBJ_length(raw),
            ffi::OBJ_get0_data(raw),
        )
    };
    let length = i32::try_from(length).ok()?;
    // SAFETY: the source object guarantees `data` describes `length` bytes;
    // null names are supported and a non-null result is a fresh dynamic object.
    unsafe {
        CBox::from_raw(ffi::ASN1_OBJECT_create(
            nid,
            data.cast_mut(),
            length,
            ptr::null(),
            ptr::null(),
        ))
    }
}

/// Wraps: OBJ_add_object
/// Registers a detached copy, so the supplied borrow is never retained.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_add_object(object: Asn1ObjectRef<'_>) -> Option<i32> {
    let copy = detached_object(object.as_ptr().cast_mut())?;
    // SAFETY: `copy` is a live dynamic object. OpenSSL deep-copies it into the
    // registry before returning and does not consume this temporary owner.
    let nid = unsafe { ffi::OBJ_add_object(copy.as_ptr()) };
    (nid != 0).then_some(nid)
}

/// Wraps: OBJ_get0_data
/// Returns the object's non-owning byte run tied to the source borrow.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_get0_data<'a>(object: Asn1ObjectRef<'a>) -> Option<CSlice<'a, u8>> {
    // SAFETY: the shared object handle is live and the getter does not mutate it.
    let data = unsafe { ffi::OBJ_get0_data(object.as_ptr()) }.cast_mut();
    // SAFETY: a non-null object data pointer addresses `OBJ_length` initialized
    // bytes for the source handle's lifetime.
    NonNull::new(data)
        .map(|data| unsafe { CSlice::from_raw_parts(data, ffi::OBJ_length(object.as_ptr())) })
}

/// Wraps: OBJ_length
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_length(object: Option<Asn1ObjectRef<'_>>) -> usize {
    let raw = object.map_or(ptr::null(), |object| object.as_ptr());
    // SAFETY: the optional handle supplies null or a live shared object.
    unsafe { ffi::OBJ_length(raw) }
}

/// Wraps: OBJ_nid2obj
/// Returns a dynamic detached copy rather than borrowing cleanup-sensitive
/// process-global registry storage.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_nid2obj(nid: i32) -> Option<CBox<Asn1Object>> {
    // SAFETY: the lookup takes a scalar and returns null or borrowed registry storage.
    let raw = unsafe { ffi::OBJ_nid2obj(nid) };
    detached_object(raw)
}

/// Wraps: OBJ_obj2nid
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_obj2nid(object: Option<Asn1ObjectRef<'_>>) -> i32 {
    let raw = object.map_or(ptr::null(), |object| object.as_ptr());
    // SAFETY: the optional handle supplies null or a live shared object.
    unsafe { ffi::OBJ_obj2nid(raw) }
}

/// Wraps: OBJ_obj2txt
/// Returns the full output length reported by OpenSSL; the buffer is always
/// passed with its exact writable extent.
#[allow(non_snake_case)]
pub fn OBJ_obj2txt(output: &mut [u8], object: Asn1ObjectRef<'_>, numeric: bool) -> Option<usize> {
    let length = i32::try_from(output.len()).ok()?;
    let output = if output.is_empty() {
        ptr::null_mut()
    } else {
        output.as_mut_ptr().cast()
    };
    // SAFETY: the output pointer describes exactly `length` writable bytes and
    // the object remains shared and live for the synchronous conversion.
    let written = unsafe { ffi::OBJ_obj2txt(output, length, object.as_ptr(), i32::from(numeric)) };
    usize::try_from(written).ok()
}

/// Wraps: OBJ_txt2nid
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_txt2nid(text: &CStr) -> i32 {
    // SAFETY: `text` is a live immutable NUL-terminated string for this call.
    unsafe { ffi::OBJ_txt2nid(text.as_ptr()) }
}

/// Wraps: OBJ_txt2obj
/// Parses either names or numeric OIDs and returns a detached dynamic owner.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_txt2obj(text: &CStr, numeric_only: bool) -> Option<CBox<Asn1Object>> {
    // SAFETY: the string remains live for parsing. The raw result may be a
    // fresh dynamic object or borrowed registry storage.
    let raw = unsafe { ffi::OBJ_txt2obj(text.as_ptr(), i32::from(numeric_only)) };
    let result = detached_object(raw);
    // SAFETY: the C API permits every non-null result to be passed to this
    // releaser; it is a no-op for the borrowed registry/static case.
    unsafe { ffi::ASN1_OBJECT_free(raw) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::bss_mem::BIO_new_mem_buf;

    #[test]
    fn textual_definitions_are_registered_line_by_line() {
        // `OBJ_create_objects` overwrites the last byte of every line it reads,
        // so each definition has to be newline-terminated.
        let definitions = concat!(
            "1.3.6.1.4.1.57264.9101 crustifyReviewObjOne crustify review object one\n",
            "1.3.6.1.4.1.57264.9102 crustifyReviewObjTwo crustify review object two\n",
        );
        let mut input = BIO_new_mem_buf(definitions.as_bytes()).expect("memory BIO");
        assert_eq!(OBJ_create_objects(&mut input.as_mut()), 2);

        let first = OBJ_sn2nid(c"crustifyReviewObjOne");
        assert_ne!(first, 0);
        assert_eq!(OBJ_txt2nid(c"1.3.6.1.4.1.57264.9101"), first);
        assert_eq!(OBJ_ln2nid(c"crustify review object one"), first);
        assert_ne!(OBJ_sn2nid(c"crustifyReviewObjTwo"), 0);
    }

    #[test]
    fn parsing_stops_at_the_first_line_that_is_not_a_definition() {
        // A line whose first byte is not alphanumeric ends the scan, so the
        // definition behind it is never reached.
        let definitions = concat!(
            "# crustify review comment\n",
            "1.3.6.1.4.1.57264.9103 crustifyReviewObjThree unreachable\n",
        );
        let mut input = BIO_new_mem_buf(definitions.as_bytes()).expect("memory BIO");
        assert_eq!(OBJ_create_objects(&mut input.as_mut()), 0);
        assert_eq!(OBJ_sn2nid(c"crustifyReviewObjThree"), 0);
    }

    unsafe extern "C" fn compare_i32(left: *const c_void, right: *const c_void) -> i32 {
        // SAFETY: the test associates this callback only with live `i32` values.
        let (left, right) = unsafe { (*(left.cast::<i32>()), *(right.cast::<i32>())) };
        left.cmp(&right) as i32
    }

    #[test]
    fn typed_bsearch_ties_result_to_the_input_slice() {
        // SAFETY: `compare_i32` reads two live `i32` values and does not retain them.
        let comparator = unsafe { OpenSslSkCompFunc::from_raw(Some(compare_i32)) }.unwrap();
        let values = [1, 3, 5, 7];
        assert_eq!(OBJ_bsearch_(&5, &values, comparator), Some(&5));
        assert_eq!(OBJ_bsearch_(&4, &values, comparator), None);
    }

    #[test]
    fn bsearch_ex_can_report_the_element_the_search_stopped_at() {
        /// `OBJ_BSEARCH_VALUE_ON_NOMATCH` from `<openssl/objects.h>`.
        const VALUE_ON_NOMATCH: i32 = 0x01;

        // SAFETY: `compare_i32` reads two live `i32` values and does not retain them.
        let comparator = unsafe { OpenSslSkCompFunc::from_raw(Some(compare_i32)) }.unwrap();
        let values = [1, 3, 5, 7];
        assert_eq!(OBJ_bsearch_ex_(&5, &values, comparator, 0), Some(&5));
        assert_eq!(OBJ_bsearch_ex_(&4, &values, comparator, 0), None);
        // The result stays inside the borrowed slice even without a match.
        assert_eq!(
            OBJ_bsearch_ex_(&4, &values, comparator, VALUE_ON_NOMATCH),
            Some(&3)
        );
    }

    #[test]
    fn a_dynamic_object_is_reachable_by_both_of_its_names() {
        let nid = OBJ_create(
            Some(c"1.3.6.1.4.1.57264.9001"),
            Some(c"crustifyReview"),
            Some(c"crustify review object"),
        );
        assert_ne!(nid, 0);
        assert_eq!(OBJ_sn2nid(c"crustifyReview"), nid);
        assert_eq!(OBJ_ln2nid(c"crustify review object"), nid);
        assert_eq!(OBJ_nid2sn(nid).unwrap().as_c_str(), c"crustifyReview");
        assert_eq!(
            OBJ_nid2ln(nid).unwrap().as_c_str(),
            c"crustify review object"
        );
        // Re-registering the same names is refused rather than duplicated.
        assert_eq!(OBJ_create(None, Some(c"crustifyReview"), None), 0);
    }

    #[test]
    fn new_nid_hands_out_strictly_increasing_identifiers() {
        let first = OBJ_new_nid(1);
        let second = OBJ_new_nid(2);
        assert!(first > 0);
        assert!(second > first);
        assert!(OBJ_new_nid(1) > second);
    }

    #[test]
    fn nid_names_are_copied() {
        let common_name = OBJ_sn2nid(c"CN");
        assert_ne!(common_name, 0);
        assert_eq!(OBJ_nid2sn(common_name).unwrap().as_c_str(), c"CN");
    }

    #[test]
    fn object_lookups_and_text_parsing_return_detached_owners() {
        let rsa_nid = OBJ_txt2nid(c"rsaEncryption");
        let by_nid = OBJ_nid2obj(rsa_nid).expect("registered object");
        assert_eq!(OBJ_obj2nid(Some(by_nid.as_ref())), rsa_nid);

        let parsed = OBJ_txt2obj(c"1.2.840.113549.1.1.1", true).expect("numeric OID");
        assert_eq!(OBJ_obj2nid(Some(parsed.as_ref())), rsa_nid);
        let mut output = [0_u8; 64];
        let length = OBJ_obj2txt(&mut output, parsed.as_ref(), true).expect("OID text");
        assert_eq!(&output[..length], b"1.2.840.113549.1.1.1");
    }
}

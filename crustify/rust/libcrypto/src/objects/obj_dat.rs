//! Wrappers assigned from `crypto/objects/obj_dat.c`.

use core::ffi::{CStr, c_void};
use core::mem::size_of;
use core::ptr;
use std::ffi::CString;

use libcrypto_sys as ffi;

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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn nid_names_are_copied() {
        let common_name = OBJ_sn2nid(c"CN");
        assert_ne!(common_name, 0);
        assert_eq!(OBJ_nid2sn(common_name).unwrap().as_c_str(), c"CN");
    }
}

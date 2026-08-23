//! Wrappers assigned from `crypto/x509/x509name.c`.

use core::ptr;

use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1ObjectRef;
use crate::x509::x509_internal::{X509NameEntryRef, X509NameRef};

fn last_position(position: Option<usize>) -> Option<i32> {
    position.map_or(Some(-1), |position| i32::try_from(position).ok())
}

/// Wraps: X509_NAME_ENTRY_get_object
/// Borrows the object identifier retained by an optional name entry.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_ENTRY_get_object<'a>(
    entry: Option<X509NameEntryRef<'a>>,
) -> Option<Asn1ObjectRef<'a>> {
    let entry = entry.map_or(ptr::null(), |entry| entry.as_ptr());
    // SAFETY: the input is null or a live shared entry. The returned object is
    // retained by that entry and therefore shares the entry handle's lifetime.
    unsafe { Asn1ObjectRef::from_ptr(ffi::X509_NAME_ENTRY_get_object(entry).cast_mut()) }
}

/// Wraps: X509_NAME_entry_count
/// Returns the number of entries, or zero for a null name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_entry_count(name: Option<X509NameRef<'_>>) -> usize {
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the argument is null or a live shared name; the C function
    // guarantees a nonnegative result, including zero for null.
    usize::try_from(unsafe { ffi::X509_NAME_entry_count(name) })
        .expect("X509_NAME_entry_count is nonnegative")
}

/// Wraps: X509_NAME_get_entry
/// Borrows the entry at `index` from an optional distinguished name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_get_entry<'a>(
    name: Option<X509NameRef<'a>>,
    index: usize,
) -> Option<X509NameEntryRef<'a>> {
    let index = i32::try_from(index).ok()?;
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the name is null or live and shared. A non-null result is an
    // internal entry retained by the name for the input handle lifetime.
    unsafe { X509NameEntryRef::from_ptr(ffi::X509_NAME_get_entry(name, index).cast_mut()) }
}

/// An invalid object-identifier number supplied to
/// [`X509_NAME_get_index_by_NID`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidNid;

/// Wraps: X509_NAME_get_index_by_NID
/// Finds the first matching entry after `last`.
#[allow(non_snake_case)]
pub fn X509_NAME_get_index_by_NID(
    name: Option<X509NameRef<'_>>,
    nid: i32,
    last: Option<usize>,
) -> Result<Option<usize>, InvalidNid> {
    let Some(last) = last_position(last) else {
        return Ok(None);
    };
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the name is null or live and shared; all other arguments are
    // plain values and OpenSSL retains every object it examines.
    match unsafe { ffi::X509_NAME_get_index_by_NID(name, nid, last) } {
        -2 => Err(InvalidNid),
        -1 => Ok(None),
        index => Ok(usize::try_from(index).ok()),
    }
}

/// Wraps: X509_NAME_get_index_by_OBJ
/// Finds the first entry with `object` after `last`.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_get_index_by_OBJ(
    name: Option<X509NameRef<'_>>,
    object: Asn1ObjectRef<'_>,
    last: Option<usize>,
) -> Option<usize> {
    let last = last_position(last)?;
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the name is null or live and shared, while `object` is a live
    // shared identifier for all synchronous comparisons.
    usize::try_from(unsafe { ffi::X509_NAME_get_index_by_OBJ(name, object.as_ptr(), last) }).ok()
}

/// Wraps: X509_NAME_get_text_by_NID
/// Copies the first matching field verbatim, or queries its length with a
/// `None` output buffer.
#[allow(non_snake_case)]
pub fn X509_NAME_get_text_by_NID(
    name: Option<X509NameRef<'_>>,
    nid: i32,
    output: Option<&mut [u8]>,
) -> Option<usize> {
    let (output, length) = match output {
        Some(output) => (
            output.as_mut_ptr().cast(),
            i32::try_from(output.len()).ok()?,
        ),
        None => (ptr::null_mut(), 0),
    };
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the name is null or shared and live. The output is null or a
    // writable array whose byte extent is exactly `length`.
    usize::try_from(unsafe { ffi::X509_NAME_get_text_by_NID(name, nid, output, length) }).ok()
}

/// Wraps: X509_NAME_get_text_by_OBJ
/// Copies the first field matching `object` verbatim, or queries its length
/// with a `None` output buffer.
#[allow(non_snake_case)]
pub fn X509_NAME_get_text_by_OBJ(
    name: Option<X509NameRef<'_>>,
    object: Asn1ObjectRef<'_>,
    output: Option<&mut [u8]>,
) -> Option<usize> {
    let (output, length) = match output {
        Some(output) => (
            output.as_mut_ptr().cast(),
            i32::try_from(output.len()).ok()?,
        ),
        None => (ptr::null_mut(), 0),
    };
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the name is null or shared and live, the object is live for the
    // lookup, and the output is null or writable for exactly `length` bytes.
    usize::try_from(unsafe {
        ffi::X509_NAME_get_text_by_OBJ(name, object.as_ptr(), output, length)
    })
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::x_name::{X509_NAME_free, d2i_X509_NAME};

    const NAME_DER: &[u8] = b"\x30\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01x";

    #[test]
    fn entries_objects_and_indices_remain_borrowed_from_the_name() {
        let mut input = NAME_DER;
        let name = d2i_X509_NAME(&mut input).expect("name DER");
        assert_eq!(X509_NAME_entry_count(Some(name.as_ref())), 1);
        assert_eq!(X509_NAME_entry_count(None), 0);

        let entry = X509_NAME_get_entry(Some(name.as_ref()), 0).expect("entry");
        assert!(X509_NAME_get_entry(Some(name.as_ref()), 1).is_none());
        let object = X509_NAME_ENTRY_get_object(Some(entry)).expect("object");
        assert_eq!(
            X509_NAME_get_index_by_OBJ(Some(name.as_ref()), object, None),
            Some(0)
        );
        assert_eq!(
            X509_NAME_get_index_by_OBJ(Some(name.as_ref()), object, Some(0)),
            None
        );
        // OpenSSL's stable NID for commonName is 13.
        assert_eq!(
            X509_NAME_get_index_by_NID(Some(name.as_ref()), 13, None),
            Ok(Some(0))
        );
        assert_eq!(
            X509_NAME_get_index_by_NID(Some(name.as_ref()), i32::MAX, None),
            Err(InvalidNid)
        );
        assert!(X509_NAME_ENTRY_get_object(None).is_none());
        X509_NAME_free(name);
    }

    #[test]
    fn deprecated_text_getters_bound_the_output_buffer() {
        let mut input = NAME_DER;
        let name = d2i_X509_NAME(&mut input).expect("name DER");
        let entry = X509_NAME_get_entry(Some(name.as_ref()), 0).expect("entry");
        let object = X509_NAME_ENTRY_get_object(Some(entry)).expect("object");

        assert_eq!(
            X509_NAME_get_text_by_OBJ(Some(name.as_ref()), object, None),
            Some(1)
        );
        let mut output = [0xff; 2];
        assert_eq!(
            X509_NAME_get_text_by_NID(Some(name.as_ref()), 13, Some(&mut output)),
            Some(1)
        );
        assert_eq!(output, [b'x', 0]);
        X509_NAME_free(name);
    }
}

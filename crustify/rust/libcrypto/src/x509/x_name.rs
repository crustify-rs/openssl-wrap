//! Wrappers assigned from `crypto/x509/x_name.c`.

use core::ffi::c_long;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CSlice};
use libcrypto_sys as ffi;

use crate::x509::x_pubkey::encode_der;
use crate::x509::x509_internal::{X509Name, X509NameEntry, X509NameEntryRef, X509NameRef};

/// Wraps: X509_NAME_ENTRY_dup
/// Deep-copies an optional distinguished-name entry.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_ENTRY_dup(entry: Option<X509NameEntryRef<'_>>) -> Option<CBox<X509NameEntry>> {
    let entry = entry.map_or(ptr::null(), |entry| entry.as_ptr());
    // SAFETY: the input is null or a live shared entry. A non-null result is
    // an independent allocation with one `X509_NAME_ENTRY_free` obligation.
    unsafe { CBox::from_raw(ffi::X509_NAME_ENTRY_dup(entry)) }
}

/// Wraps: X509_NAME_ENTRY_free
/// Consumes one complete distinguished-name entry allocation.
#[allow(non_snake_case)]
pub fn X509_NAME_ENTRY_free(entry: CBox<X509NameEntry>) {
    drop(entry);
}

/// Wraps: X509_NAME_ENTRY_new
/// Allocates a fully initialized empty distinguished-name entry.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_ENTRY_new() -> Option<CBox<X509NameEntry>> {
    // SAFETY: a non-null result is a fresh complete entry carrying one
    // ownership obligation registered on `X509NameEntry`.
    unsafe { CBox::from_raw(ffi::X509_NAME_ENTRY_new()) }
}

/// Wraps: X509_NAME_dup
/// Deep-copies an optional distinguished name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_dup(name: Option<X509NameRef<'_>>) -> Option<CBox<X509Name>> {
    let name = name.map_or(ptr::null(), |name| name.as_ptr());
    // SAFETY: the input is null or a live shared name. A non-null result is a
    // fresh independent name with one `X509_NAME_free` obligation.
    unsafe { CBox::from_raw(ffi::X509_NAME_dup(name)) }
}

/// Wraps: X509_NAME_free
/// Consumes one complete distinguished-name allocation.
#[allow(non_snake_case)]
pub fn X509_NAME_free(name: CBox<X509Name>) {
    drop(name);
}

/// Wraps: X509_NAME_get0_der
/// Borrows the name's cached DER encoding.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_get0_der<'a>(name: X509NameRef<'a>) -> Option<CSlice<'a, u8>> {
    let mut data = ptr::null();
    let mut length = 0;
    // SAFETY: `name` is live and retains the internal encoding, while both
    // local variables are valid scalar output slots.
    let success = unsafe { ffi::X509_NAME_get0_der(name.as_ptr(), &mut data, &mut length) };
    if success == 0 {
        return None;
    }
    let data = NonNull::new(data.cast_mut())?;
    // SAFETY: success reports `length` initialized bytes retained by `name`;
    // the returned view carries exactly that name-borrow lifetime.
    Some(unsafe { CSlice::from_raw_parts(data, length) })
}

/// Wraps: X509_NAME_new
/// Allocates an empty, fully initialized distinguished name.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_NAME_new() -> Option<CBox<X509Name>> {
    // SAFETY: a non-null result is a fresh complete name whose matching
    // destructor is registered on `X509Name`.
    unsafe { CBox::from_raw(ffi::X509_NAME_new()) }
}

/// Wraps: d2i_X509_NAME
/// Decodes one DER distinguished name and advances `input` past it.
#[must_use]
#[allow(non_snake_case)]
pub fn d2i_X509_NAME(input: &mut &[u8]) -> Option<CBox<X509Name>> {
    decode_der(input, |cursor, length| {
        // SAFETY: `decode_der` supplies a cursor over exactly `length`
        // readable bytes and requests a fresh destination allocation.
        unsafe { ffi::d2i_X509_NAME(ptr::null_mut(), cursor, length) }
    })
}

/// Wraps: d2i_X509_NAME_ENTRY
/// Decodes one DER distinguished-name entry and advances `input` past it.
#[must_use]
#[allow(non_snake_case)]
pub fn d2i_X509_NAME_ENTRY(input: &mut &[u8]) -> Option<CBox<X509NameEntry>> {
    decode_der(input, |cursor, length| {
        // SAFETY: `decode_der` supplies a cursor over exactly `length`
        // readable bytes and requests a fresh destination allocation.
        unsafe { ffi::d2i_X509_NAME_ENTRY(ptr::null_mut(), cursor, length) }
    })
}

fn decode_der<T>(
    input: &mut &[u8],
    decode: impl FnOnce(&mut *const u8, c_long) -> *mut <T as ffibox::CCell>::C,
) -> Option<CBox<T>>
where
    T: ffibox::CCell + ffibox::CDropped,
{
    let source = *input;
    let length = c_long::try_from(source.len()).ok()?;
    let start = source.as_ptr();
    let mut cursor = start;
    let raw = decode(&mut cursor, length);
    // SAFETY: each caller's decoder transfers its non-null complete result to
    // the corresponding owner type and registered destructor.
    let decoded = unsafe { CBox::from_raw(raw) }?;
    let consumed = cursor.addr().wrapping_sub(start.addr());
    if consumed > source.len() {
        return None;
    }
    *input = &source[consumed..];
    Some(decoded)
}

/// Wraps: i2d_X509_NAME
/// Encodes a complete distinguished name into a Rust-owned DER vector.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_X509_NAME(name: X509NameRef<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the shared name is live and `encode_der` supplies null for
        // the length pass and then an exactly sized writable buffer.
        unsafe { ffi::i2d_X509_NAME(name.as_ptr(), output) }
    })
}

/// Wraps: i2d_X509_NAME_ENTRY
/// Encodes a complete distinguished-name entry into a Rust-owned DER vector.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_X509_NAME_ENTRY(entry: X509NameEntryRef<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the shared entry is live and `encode_der` supplies null for
        // the length pass and then an exactly sized writable buffer.
        unsafe { ffi::i2d_X509_NAME_ENTRY(entry.as_ptr(), output) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY_DER: &[u8] = b"\x30\x08\x06\x03\x55\x04\x03\x0c\x01x";
    const NAME_DER: &[u8] = b"\x30\x0c\x31\x0a\x30\x08\x06\x03\x55\x04\x03\x0c\x01x";

    #[test]
    fn name_lifecycle_der_and_internal_encoding_are_typed() {
        let name = X509_NAME_new().expect("name");
        assert_eq!(
            i2d_X509_NAME(name.as_ref()).expect("empty DER"),
            b"\x30\x00"
        );
        let cached = X509_NAME_get0_der(name.as_ref()).expect("cached DER");
        assert_eq!(cached.elems().collect::<Vec<_>>(), b"\x30\x00");

        let duplicate = X509_NAME_dup(Some(name.as_ref())).expect("duplicate");
        assert_ne!(duplicate.as_ptr(), name.as_ptr());
        assert!(X509_NAME_dup(None).is_none());
        X509_NAME_free(duplicate);
        X509_NAME_free(name);
    }

    #[test]
    fn both_der_decoders_advance_and_round_trip() {
        let mut name_input = NAME_DER;
        let name = d2i_X509_NAME(&mut name_input).expect("name DER");
        assert!(name_input.is_empty());
        assert_eq!(i2d_X509_NAME(name.as_ref()).as_deref(), Some(NAME_DER));

        let mut entry_input = ENTRY_DER;
        let entry = d2i_X509_NAME_ENTRY(&mut entry_input).expect("entry DER");
        assert!(entry_input.is_empty());
        assert_eq!(
            i2d_X509_NAME_ENTRY(entry.as_ref()).as_deref(),
            Some(ENTRY_DER)
        );
        let duplicate = X509_NAME_ENTRY_dup(Some(entry.as_ref())).expect("entry duplicate");
        assert_ne!(duplicate.as_ptr(), entry.as_ptr());

        X509_NAME_ENTRY_free(duplicate);
        X509_NAME_ENTRY_free(entry);
        X509_NAME_free(name);
    }

    #[test]
    fn failed_decodes_do_not_advance_and_empty_entry_is_not_encodable() {
        let invalid = [0_u8, 1, 2];
        let mut name_input = invalid.as_slice();
        assert!(d2i_X509_NAME(&mut name_input).is_none());
        assert_eq!(name_input, invalid);

        let mut entry_input = invalid.as_slice();
        assert!(d2i_X509_NAME_ENTRY(&mut entry_input).is_none());
        assert_eq!(entry_input, invalid);

        let entry = X509_NAME_ENTRY_new().expect("entry");
        assert!(i2d_X509_NAME_ENTRY(entry.as_ref()).is_none());
        assert!(X509_NAME_ENTRY_dup(None).is_none());
        X509_NAME_ENTRY_free(entry);
    }
}

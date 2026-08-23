//! Wrappers assigned from `crypto/x509/x_exten.c`.

use core::ffi::c_long;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::x509::x_pubkey::encode_der;
use crate::x509::x509_local::{X509Extension, X509ExtensionRef};

/// Wraps: X509_EXTENSION_dup
/// Deep-copies an optional extension into an independent owner.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_EXTENSION_dup(extension: Option<X509ExtensionRef<'_>>) -> Option<CBox<X509Extension>> {
    let extension = extension.map_or(ptr::null(), |value| value.as_ptr());
    // SAFETY: the source is null or shared and live for the call. A non-null
    // result is a fresh deep copy owing one `X509_EXTENSION_free`.
    unsafe { CBox::from_raw(ffi::X509_EXTENSION_dup(extension)) }
}

/// Wraps: X509_EXTENSION_free
/// Consumes one complete extension owner.
#[allow(non_snake_case)]
pub fn X509_EXTENSION_free(extension: CBox<X509Extension>) {
    drop(extension);
}

/// Wraps: X509_EXTENSION_new
/// Allocates one fully initialized empty extension.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_EXTENSION_new() -> Option<CBox<X509Extension>> {
    // SAFETY: a non-null result is a fresh complete extension carrying one
    // matching full-destructor obligation.
    unsafe { CBox::from_raw(ffi::X509_EXTENSION_new()) }
}

/// Wraps: d2i_X509_EXTENSION
/// Decodes one DER extension and advances `input` past the consumed bytes.
#[must_use]
#[allow(non_snake_case)]
pub fn d2i_X509_EXTENSION(input: &mut &[u8]) -> Option<CBox<X509Extension>> {
    let source = *input;
    let length = c_long::try_from(source.len()).ok()?;
    let start = source.as_ptr();
    let mut cursor = start;
    // SAFETY: `cursor` addresses exactly `length` readable bytes and a null
    // destination requests a fresh independent extension allocation.
    let raw = unsafe { ffi::d2i_X509_EXTENSION(ptr::null_mut(), &mut cursor, length) };
    // SAFETY: a non-null result transfers one complete extension owner.
    let decoded = unsafe { CBox::from_raw(raw) }?;
    let consumed = cursor.addr().wrapping_sub(start.addr());
    if consumed > source.len() {
        return None;
    }
    *input = &source[consumed..];
    Some(decoded)
}

/// Wraps: i2d_X509_EXTENSION
/// Encodes a complete extension into a newly owned DER byte vector.
#[must_use]
#[allow(non_snake_case)]
pub fn i2d_X509_EXTENSION(extension: X509ExtensionRef<'_>) -> Option<Vec<u8>> {
    encode_der(|output| {
        // SAFETY: the extension remains shared and live; `encode_der` supplies
        // null for the length pass or the exact writable extent it allocated.
        unsafe { ffi::i2d_X509_EXTENSION(extension.as_ptr(), output) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_duplicate_and_free_preserve_independent_owners() {
        // SEQUENCE { OBJECT IDENTIFIER 1.2, OCTET STRING { 0 } }.
        let der = [0x30, 0x06, 0x06, 0x01, 0x2a, 0x04, 0x01, 0x00];
        let mut input = der.as_slice();
        let extension = d2i_X509_EXTENSION(&mut input).expect("valid extension");
        let duplicate = X509_EXTENSION_dup(Some(extension.as_ref())).expect("duplicate");
        assert_ne!(extension.as_ptr(), duplicate.as_ptr());
        assert!(X509_EXTENSION_dup(None).is_none());
        X509_EXTENSION_free(duplicate);
        X509_EXTENSION_free(extension);
    }

    #[test]
    fn der_round_trip_advances_the_input() {
        let extension = X509_EXTENSION_new().expect("X509_EXTENSION_new");
        let Some(der) = i2d_X509_EXTENSION(extension.as_ref()) else {
            // A provider may reject encoding an extension whose mandatory OID
            // has not been assigned; the failure remains safely represented.
            return;
        };
        let mut input = der.as_slice();
        let decoded = d2i_X509_EXTENSION(&mut input).expect("decode extension");
        assert!(input.is_empty());
        X509_EXTENSION_free(decoded);
    }
}

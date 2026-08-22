//! Wrappers assigned from `crypto/asn1/a_object.c`.

use core::ffi::CStr;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::asn1::Asn1Object;

/// Wraps: ASN1_OBJECT_create
/// Creates a dynamic object after copying all supplied bytes and names.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_OBJECT_create(
    nid: i32,
    data: &[u8],
    short_name: Option<&CStr>,
    long_name: Option<&CStr>,
) -> Option<CBox<Asn1Object>> {
    let length = i32::try_from(data.len()).ok()?;
    let data = if data.is_empty() {
        ptr::null_mut()
    } else {
        data.as_ptr().cast_mut()
    };
    let short_name = short_name.map_or(ptr::null(), CStr::as_ptr);
    let long_name = long_name.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the slice and optional strings are live for this call. OpenSSL
    // deep-copies all non-null inputs into a fresh complete object.
    unsafe {
        CBox::from_raw(ffi::ASN1_OBJECT_create(
            nid, data, length, short_name, long_name,
        ))
    }
}

/// Wraps: ASN1_OBJECT_free
/// Consumes one owned object; freeing a built-in object remains a C no-op.
#[allow(non_snake_case)]
pub fn ASN1_OBJECT_free(object: CBox<Asn1Object>) {
    drop(object);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::objects::obj_dat::{OBJ_get0_data, OBJ_length};

    #[test]
    fn create_copies_the_oid_bytes() {
        let bytes = [0x2a, 0x03, 0x04];
        let object = ASN1_OBJECT_create(10_001, &bytes, Some(c"short"), Some(c"long"))
            .expect("ASN1_OBJECT_create");
        assert_eq!(OBJ_length(Some(object.as_ref())), bytes.len());
        let view = OBJ_get0_data(object.as_ref()).expect("OID bytes");
        let mut copied = [0; 3];
        assert!(view.copy_to_slice(&mut copied));
        assert_eq!(copied, bytes);
        ASN1_OBJECT_free(object);
    }
}

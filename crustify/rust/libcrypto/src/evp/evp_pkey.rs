//! Wrappers assigned from `crypto/evp/evp_pkey.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;

use libcrypto_sys as ffi;

use ffibox::CBox;

use crate::asn1::asn1::Asn1ObjectRef;
use crate::evp::evp::{EvpPkeyMut, EvpPkeyRef};
use crate::provider::provider_core::OsslProviderRef;
use crate::x509::x509_local::{X509Attribute, X509AttributeRef};

/// Wraps: EVP_PKEY_add1_attr_by_NID
/// Adds a copied attribute value identified by numeric object identifier.
pub fn EVP_PKEY_add1_attr_by_NID(
    key: &mut EvpPkeyMut<'_>,
    nid: i32,
    attribute_type: i32,
    bytes: &[u8],
) -> bool {
    let Ok(len) = i32::try_from(bytes.len()) else {
        return false;
    };
    // SAFETY: the exclusive key is live and `bytes` supplies exactly `len`
    // readable bytes. OpenSSL copies the attribute value on success.
    unsafe {
        ffi::EVP_PKEY_add1_attr_by_NID(key.as_mut_ptr(), nid, attribute_type, bytes.as_ptr(), len)
            == 1
    }
}

/// Wraps: EVP_PKEY_add1_attr_by_txt
/// Adds a copied attribute value identified by a NUL-terminated object name.
pub fn EVP_PKEY_add1_attr_by_txt(
    key: &mut EvpPkeyMut<'_>,
    attribute_name: &CStr,
    attribute_type: i32,
    bytes: &[u8],
) -> bool {
    let Ok(len) = i32::try_from(bytes.len()) else {
        return false;
    };
    // SAFETY: all borrowed inputs are live for the call and OpenSSL copies the
    // name interpretation and value into the key's owned attribute stack.
    unsafe {
        ffi::EVP_PKEY_add1_attr_by_txt(
            key.as_mut_ptr(),
            attribute_name.as_ptr(),
            attribute_type,
            bytes.as_ptr(),
            len,
        ) == 1
    }
}

/// Wraps: EVP_PKEY_get0_provider
/// Borrows the provider retained by a provider-backed key.
#[must_use]
pub fn EVP_PKEY_get0_provider<'a>(key: EvpPkeyRef<'a>) -> Option<OsslProviderRef<'a>> {
    // SAFETY: the shared key handle is live; the returned provider is retained
    // by the key management method and therefore cannot outlive `key`.
    let raw = unsafe { ffi::EVP_PKEY_get0_provider(key.as_ptr()) };
    // SAFETY: null is absence; a non-null result is live for the key borrow and
    // is borrowed rather than adopted as an active provider owner.
    unsafe { OsslProviderRef::from_ptr(raw.cast_mut()) }
}

/// Wraps: EVP_PKEY_get0_type_name
/// Borrows the key type name stored by its method table.
#[must_use]
pub fn EVP_PKEY_get0_type_name<'a>(key: EvpPkeyRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the key is live and retains the returned NUL-terminated method
    // name for at least the handle's lifetime.
    let raw = unsafe { ffi::EVP_PKEY_get0_type_name(key.as_ptr()) };
    if raw.is_null() {
        None
    } else {
        // SAFETY: the C API promises a borrowed NUL-terminated type name.
        Some(unsafe { CStr::from_ptr(raw) })
    }
}

/// Wraps: EVP_PKEY_get_attr_by_NID
/// Returns the next matching attribute index after `last_position`.
#[must_use]
pub fn EVP_PKEY_get_attr_by_NID(pkey: EvpPkeyRef<'_>, nid: i32, last_position: i32) -> i32 {
    // SAFETY: the shared key keeps its attribute stack live for the lookup.
    unsafe { ffi::EVP_PKEY_get_attr_by_NID(pkey.as_ptr(), nid, last_position) }
}

/// Wraps: EVP_PKEY_get_attr_count
#[must_use]
pub fn EVP_PKEY_get_attr_count(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key keeps its attribute stack live for the count.
    unsafe { ffi::EVP_PKEY_get_attr_count(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_add1_attr
/// Deep-copies `attribute` into the key's owned attribute stack.
pub fn EVP_PKEY_add1_attr(key: &mut EvpPkeyMut<'_>, attribute: X509AttributeRef<'_>) -> bool {
    // SAFETY: both typed handles are live for the call. OpenSSL duplicates the
    // attribute before storing it, so no borrow is retained.
    unsafe { ffi::EVP_PKEY_add1_attr(key.as_mut_ptr(), attribute.as_ptr().cast_mut()) == 1 }
}

/// Wraps: EVP_PKEY_add1_attr_by_OBJ
/// Adds a copied attribute value identified by an object identifier.
pub fn EVP_PKEY_add1_attr_by_OBJ(
    key: &mut EvpPkeyMut<'_>,
    object: Asn1ObjectRef<'_>,
    attribute_type: i32,
    bytes: &[u8],
) -> bool {
    let Ok(len) = i32::try_from(bytes.len()) else {
        return false;
    };
    // SAFETY: all handles and the byte run are live for the call. OpenSSL
    // constructs and stores independent copies rather than retaining inputs.
    unsafe {
        ffi::EVP_PKEY_add1_attr_by_OBJ(
            key.as_mut_ptr(),
            object.as_ptr(),
            attribute_type,
            bytes.as_ptr(),
            len,
        ) == 1
    }
}

/// Wraps: EVP_PKEY_delete_attr
/// Detaches the attribute at `location` and transfers its ownership.
#[must_use]
pub fn EVP_PKEY_delete_attr(
    key: &mut EvpPkeyMut<'_>,
    location: i32,
) -> Option<CBox<X509Attribute>> {
    // SAFETY: the exclusive key handle permits removal from its attribute
    // stack. A non-null result transfers the detached attribute allocation.
    let raw = unsafe { ffi::EVP_PKEY_delete_attr(key.as_mut_ptr(), location) };
    // SAFETY: null denotes failure; otherwise the caller owns the returned
    // attribute and its registered destructor matches the transfer contract.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_get_attr
/// Borrows the attribute at `location` from its retaining key.
#[must_use]
pub fn EVP_PKEY_get_attr<'a>(key: EvpPkeyRef<'a>, location: i32) -> Option<X509AttributeRef<'a>> {
    // SAFETY: the key remains live for `'a` and retains every attribute still
    // present in its stack.
    let raw = unsafe { ffi::EVP_PKEY_get_attr(key.as_ptr(), location) };
    // SAFETY: null denotes an invalid location; a non-null result is borrowed
    // from `key`, which supplies the returned handle lifetime.
    unsafe { X509AttributeRef::from_ptr(raw) }
}

/// Wraps: EVP_PKEY_get_attr_by_OBJ
/// Returns the next matching attribute index after `last_position`.
#[must_use]
pub fn EVP_PKEY_get_attr_by_OBJ(
    key: EvpPkeyRef<'_>,
    object: Asn1ObjectRef<'_>,
    last_position: i32,
) -> i32 {
    // SAFETY: both shared handles are live for the synchronous lookup.
    unsafe { ffi::EVP_PKEY_get_attr_by_OBJ(key.as_ptr(), object.as_ptr(), last_position) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::p_lib::EVP_PKEY_new;
    use crate::objects::obj_dat::OBJ_txt2obj;

    #[test]
    fn fresh_key_has_no_attributes() {
        let key = EVP_PKEY_new().expect("EVP_PKEY_new");
        assert_eq!(EVP_PKEY_get_attr_count(key.as_ref()), -1);
        assert_eq!(EVP_PKEY_get_attr_by_NID(key.as_ref(), 1, -1), -1);
    }

    #[test]
    fn object_attribute_can_be_added_borrowed_detached_and_readded() {
        let mut key = EVP_PKEY_new().expect("EVP_PKEY_new");
        let object = OBJ_txt2obj(c"1.2.840.113549.1.9.7", true).expect("object identifier");

        assert!(EVP_PKEY_add1_attr_by_OBJ(
            &mut key.as_mut(),
            object.as_ref(),
            ffi::V_ASN1_OCTET_STRING as i32,
            b"secret",
        ));
        assert_eq!(
            EVP_PKEY_get_attr_by_OBJ(key.as_ref(), object.as_ref(), -1),
            0
        );
        assert!(EVP_PKEY_get_attr(key.as_ref(), 0).is_some());

        let detached = EVP_PKEY_delete_attr(&mut key.as_mut(), 0).expect("detached attribute");
        assert_eq!(EVP_PKEY_get_attr_count(key.as_ref()), 0);
        assert!(EVP_PKEY_add1_attr(&mut key.as_mut(), detached.as_ref()));
        assert_eq!(EVP_PKEY_get_attr_count(key.as_ref()), 1);
        assert!(EVP_PKEY_delete_attr(&mut key.as_mut(), 9).is_none());
    }
}

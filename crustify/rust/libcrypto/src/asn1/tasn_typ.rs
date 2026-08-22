//! Wrappers assigned from `crypto/asn1/tasn_typ.c`.

use libcrypto_sys as ffi;

use super::openssl_asn1t::Asn1ItemRef;

/// Wraps: ASN1_OBJECT_it
/// Returns OpenSSL's immutable process-lifetime ASN.1 object descriptor.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_OBJECT_it() -> Asn1ItemRef<'static> {
    // SAFETY: this generated item accessor always returns the address of an
    // immutable static ASN1_ITEM that lives for the process lifetime.
    unsafe { Asn1ItemRef::from_ptr(ffi::ASN1_OBJECT_it()) }
        .expect("ASN1_OBJECT_it is a non-null static item")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_item_is_static() {
        assert_eq!(ASN1_OBJECT_it().as_ptr(), ASN1_OBJECT_it().as_ptr());
        assert_eq!(ASN1_OBJECT_it().underlying_type(), 6);
    }
}

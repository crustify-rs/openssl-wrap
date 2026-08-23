//! Wrappers assigned from `crypto/asn1/asn1_lib.c`.

use core::cmp::Ordering;
use core::ffi::{CStr, c_int};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CSlice, CVec};
use libcrypto_sys as ffi;

use crate::asn1::asn1::{Asn1String, Asn1StringMut, Asn1StringRef};
use crate::asn1::openssl_asn1::Asn1TypeKind;
use crate::mem::CryptoClearFree;

/// An owned ASN.1 header whose data remains borrowed from a Rust byte slice.
///
/// Dropping this value frees only the header: OpenSSL marks the data as not
/// owned, while the lifetime parameter prevents the header from outliving it.
pub struct BorrowedAsn1String<'a> {
    inner: CBox<Asn1String>,
    _data: PhantomData<&'a [u8]>,
}

impl BorrowedAsn1String<'_> {
    /// Borrows the ASN.1 string header and its retained bytes.
    #[must_use]
    pub fn as_ref(&self) -> Asn1StringRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrows the ASN.1 string header.
    #[must_use]
    pub fn as_mut(&mut self) -> Asn1StringMut<'_> {
        self.inner.as_mut()
    }
}

/// Wraps: ASN1_STRING_clear_free
/// Consumes an owned string and clears its contents before releasing it.
#[allow(non_snake_case)]
pub fn ASN1_STRING_clear_free(string: CBox<Asn1String>) {
    let raw = string.into_raw();
    // SAFETY: `into_raw` transfers the sole owned string allocation and
    // `ASN1_STRING_clear_free` accepts every fully initialized ASN.1 string.
    unsafe { ffi::ASN1_STRING_clear_free(raw) }
}

/// Wraps: ASN1_STRING_cmp
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_cmp(a: Asn1StringRef<'_>, b: Asn1StringRef<'_>) -> Ordering {
    // SAFETY: both shared handles remain live and immutable for this call.
    let result = unsafe { ffi::ASN1_STRING_cmp(a.as_ptr(), b.as_ptr()) };
    result.cmp(&0)
}

/// Wraps: ASN1_STRING_copy
/// Deep-copies `source` into `destination`.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_copy(destination: &mut Asn1StringMut<'_>, source: Asn1StringRef<'_>) -> bool {
    // SAFETY: the destination is exclusively borrowed and the source is live
    // and shared for the synchronous deep-copy operation.
    unsafe { ffi::ASN1_STRING_copy(destination.as_mut_ptr(), source.as_ptr()) == 1 }
}

/// Wraps: ASN1_STRING_dup
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_dup(string: Asn1StringRef<'_>) -> Option<CBox<Asn1String>> {
    // SAFETY: the shared source is live and OpenSSL returns either null or a
    // fresh fully initialized string carrying one free obligation.
    unsafe { CBox::from_raw(ffi::ASN1_STRING_dup(string.as_ptr())) }
}

/// Wraps: ASN1_STRING_free
/// Consumes an owned ASN.1 string using its registered OpenSSL destructor.
#[allow(non_snake_case)]
pub fn ASN1_STRING_free(string: CBox<Asn1String>) {
    drop(string);
}

/// Wraps: ASN1_STRING_get0_data
/// Returns a non-owning byte view tied to the ASN.1 string's lifetime.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_get0_data<'a>(string: Asn1StringRef<'a>) -> Option<CSlice<'a, u8>> {
    let length = ASN1_STRING_get_length(string);
    if length > c_int::MAX as usize {
        return None;
    }
    // SAFETY: the shared string handle is live for `'a`; OpenSSL reports a
    // buffer of exactly `length` initialized bytes. Empty strings may use null,
    // for which a dangling pointer is valid because no byte is accessible.
    let raw = unsafe { ffi::ASN1_STRING_get0_data(string.as_ptr()) }.cast_mut();
    let data = if length == 0 {
        NonNull::new(raw).unwrap_or_else(NonNull::dangling)
    } else {
        NonNull::new(raw)?
    };
    // SAFETY: `data` addresses `length` initialized bytes owned or borrowed by
    // the live string, and the returned view carries the same lifetime.
    Some(unsafe { CSlice::from_raw_parts(data, length) })
}

/// Wraps: ASN1_STRING_get_length
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_get_length(string: Asn1StringRef<'_>) -> usize {
    // SAFETY: the shared handle denotes a live initialized string.
    unsafe { ffi::ASN1_STRING_get_length(string.as_ptr()) }
}

/// Wraps: ASN1_STRING_new
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_new() -> Option<CBox<Asn1String>> {
    // SAFETY: a non-null result is a fresh fully initialized allocation whose
    // matching destructor is registered on `Asn1String`.
    unsafe { CBox::from_raw(ffi::ASN1_STRING_new()) }
}

/// Wraps: ASN1_STRING_new_not_owned
/// Creates an owned header that retains, but never releases, `data`.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_new_not_owned(
    string_type: c_int,
    data: &[u8],
) -> Option<BorrowedAsn1String<'_>> {
    if data.is_empty() || !Asn1TypeKind::from_raw(string_type).holds_string() {
        return None;
    }
    // SAFETY: `data` is nonempty and readable for the returned value's
    // lifetime. OpenSSL marks it not-owned and returns a fresh header or null.
    let raw = unsafe { ffi::ASN1_STRING_new_not_owned(string_type, data.as_ptr(), data.len()) };
    // SAFETY: a non-null result transfers ownership of the initialized header;
    // its internal data borrow is tracked by `BorrowedAsn1String`.
    let inner = unsafe { CBox::from_raw(raw) }?;
    Some(BorrowedAsn1String {
        inner,
        _data: PhantomData,
    })
}

/// Wraps: ASN1_STRING_set0
/// Transfers an OpenSSL-allocated buffer into `string`.
#[allow(non_snake_case)]
pub fn ASN1_STRING_set0(
    string: &mut Asn1StringMut<'_>,
    data: CVec<u8, CryptoClearFree>,
) -> Result<(), CVec<u8, CryptoClearFree>> {
    let Ok(length) = c_int::try_from(data.count()) else {
        return Err(data);
    };
    let (raw, count) = data.into_raw_parts();
    debug_assert_eq!(usize::try_from(length).ok(), Some(count));
    // SAFETY: the exclusive string receives unique ownership of the
    // allocator-compatible buffer and its exact `c_int` byte length.
    unsafe { ffi::ASN1_STRING_set0(string.as_mut_ptr(), raw.cast(), length) }
    Ok(())
}

/// Wraps: ASN1_STRING_set0
/// Clears the current data while preserving the ASN.1 string allocation.
///
/// The second of this symbol's two safe contracts: `ASN1_STRING_set0` above
/// transfers a buffer in, and the null/zero argument pair that OpenSSL
/// documents as a reset has no owned buffer to take, so it gets its own name.
pub fn clear_data(string: &mut Asn1StringMut<'_>) {
    // SAFETY: a null zero-length replacement is explicitly supported and the
    // exclusive handle permits OpenSSL to release the old owned data.
    unsafe { ffi::ASN1_STRING_set0(string.as_mut_ptr(), ptr::null_mut(), 0) }
}

/// Wraps: ASN1_STRING_set1_data
/// Deep-copies `data` into `string`.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set1_data(string: &mut Asn1StringMut<'_>, data: &[u8]) -> bool {
    // SAFETY: the exclusive string is live and `data` provides exactly its
    // reported number of readable bytes for the synchronous copy.
    unsafe { ffi::ASN1_STRING_set1_data(string.as_mut_ptr(), data.as_ptr(), data.len()) == 1 }
}

/// Wraps: ASN1_STRING_set1_string
/// Deep-copies the bytes before the source's NUL terminator.
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_set1_string(string: &mut Asn1StringMut<'_>, value: &CStr) -> bool {
    // SAFETY: the exclusive string is live and `value` is a live immutable
    // NUL-terminated C string for the duration of the copy.
    unsafe { ffi::ASN1_STRING_set1_string(string.as_mut_ptr(), value.as_ptr()) == 1 }
}

/// Wraps: ASN1_STRING_type
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_type(string: Asn1StringRef<'_>) -> c_int {
    // SAFETY: the shared handle denotes a live initialized string.
    unsafe { ffi::ASN1_STRING_type(string.as_ptr()) }
}

/// Wraps: ASN1_STRING_type_new
#[must_use]
#[allow(non_snake_case)]
pub fn ASN1_STRING_type_new(string_type: c_int) -> Option<CBox<Asn1String>> {
    if !Asn1TypeKind::from_raw(string_type).holds_string() {
        return None;
    }
    // SAFETY: a non-null result is fresh and fully initialized for the
    // registered ASN.1 string destructor. The check above excludes tags whose
    // payload representation is not `asn1_string_st`.
    unsafe { CBox::from_raw(ffi::ASN1_STRING_type_new(string_type)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_copy_compare_and_borrow_data() {
        let mut first = ASN1_STRING_new().expect("ASN1_STRING_new");
        assert!(ASN1_STRING_set1_data(&mut first.as_mut(), b"hello"));
        assert_eq!(ASN1_STRING_get_length(first.as_ref()), 5);
        let bytes = ASN1_STRING_get0_data(first.as_ref()).expect("valid string data");
        assert_eq!(bytes.elems().collect::<Vec<_>>(), b"hello");

        let mut second =
            ASN1_STRING_type_new(ffi::V_ASN1_OCTET_STRING as c_int).expect("ASN1_STRING_type_new");
        assert!(ASN1_STRING_copy(&mut second.as_mut(), first.as_ref()));
        assert_eq!(
            ASN1_STRING_cmp(first.as_ref(), second.as_ref()),
            Ordering::Equal
        );

        let duplicate = ASN1_STRING_dup(first.as_ref()).expect("ASN1_STRING_dup");
        assert_ne!(duplicate.as_ptr(), first.as_ptr());
        assert_eq!(
            ASN1_STRING_cmp(first.as_ref(), duplicate.as_ref()),
            Ordering::Equal
        );
    }

    #[test]
    fn non_owned_header_keeps_its_borrow_explicit() {
        let source = b"borrowed";
        let string = ASN1_STRING_new_not_owned(ffi::V_ASN1_OCTET_STRING as c_int, source)
            .expect("borrowed ASN.1 header");
        let bytes = ASN1_STRING_get0_data(string.as_ref()).expect("valid string data");
        assert_eq!(bytes.elems().collect::<Vec<_>>(), source);
    }

    #[test]
    fn string_constructors_reject_non_string_payload_tags() {
        for tag in [
            ffi::V_ASN1_UNDEF,
            ffi::V_ASN1_BOOLEAN as c_int,
            ffi::V_ASN1_NULL as c_int,
            ffi::V_ASN1_OBJECT as c_int,
            ffi::V_ASN1_ANY,
        ] {
            assert!(ASN1_STRING_type_new(tag).is_none());
            assert!(ASN1_STRING_new_not_owned(tag, b"value").is_none());
        }

        assert!(ASN1_STRING_type_new(ffi::V_ASN1_OCTET_STRING as c_int).is_some());
    }

    #[test]
    fn comparison_orders_by_length_then_bytes_then_type() {
        let string = |string_type: c_int, data: &[u8]| {
            let mut value = ASN1_STRING_type_new(string_type).expect("typed ASN1 string");
            assert!(ASN1_STRING_set1_data(&mut value.as_mut(), data));
            value
        };
        let octet = ffi::V_ASN1_OCTET_STRING as c_int;

        // Length dominates, then the bytes, then the type tag.
        let longer = string(octet, b"abc");
        let shorter = string(octet, b"ab");
        assert_eq!(
            ASN1_STRING_cmp(longer.as_ref(), shorter.as_ref()),
            Ordering::Greater
        );

        let higher = string(octet, b"abd");
        assert_eq!(
            ASN1_STRING_cmp(longer.as_ref(), higher.as_ref()),
            Ordering::Less
        );

        let retyped = string(ffi::V_ASN1_UTF8STRING as c_int, b"abc");
        assert_eq!(
            ASN1_STRING_cmp(retyped.as_ref(), longer.as_ref()),
            Ordering::Greater
        );
        assert_eq!(
            ASN1_STRING_cmp(longer.as_ref(), longer.as_ref()),
            Ordering::Equal
        );
    }

    #[test]
    fn clearing_data_releases_the_buffer_and_keeps_the_header() {
        let mut string = ASN1_STRING_new().expect("ASN1_STRING_new");
        assert!(ASN1_STRING_set1_data(&mut string.as_mut(), b"payload"));
        assert_eq!(ASN1_STRING_get_length(string.as_ref()), 7);

        clear_data(&mut string.as_mut());
        assert_eq!(ASN1_STRING_get_length(string.as_ref()), 0);
        assert_eq!(
            ASN1_STRING_get0_data(string.as_ref())
                .expect("an emptied string still has a valid view")
                .elems()
                .collect::<Vec<_>>(),
            b""
        );
        // The header survived its buffer, so the ordinary destructor still owns
        // exactly one allocation here.
        ASN1_STRING_free(string);
    }

    #[test]
    fn clearing_free_consumes_a_normal_owner() {
        let mut string = ASN1_STRING_new().expect("ASN1_STRING_new");
        assert!(ASN1_STRING_set1_string(&mut string.as_mut(), c"secret"));
        ASN1_STRING_clear_free(string);
    }

    #[test]
    fn set0_transfers_an_allocator_matched_buffer() {
        let source = b"owned";
        // SAFETY: `source` supplies its reported number of readable bytes and
        // OpenSSL returns a fresh ordinary allocation or null.
        let raw = unsafe {
            ffi::CRYPTO_memdup(source.as_ptr().cast(), source.len(), ptr::null(), 0).cast()
        };
        // SAFETY: the fresh allocation holds `source.len()` initialized bytes
        // and transfers to the compatible clearing strategy.
        let buffer = unsafe { CVec::<u8, CryptoClearFree>::from_raw_parts(raw, source.len()) }
            .expect("CRYPTO_memdup");
        let mut string = ASN1_STRING_new().expect("ASN1_STRING_new");
        ASN1_STRING_set0(&mut string.as_mut(), buffer).expect("length fits c_int");
        assert_eq!(
            ASN1_STRING_type(string.as_ref()),
            ffi::V_ASN1_OCTET_STRING as c_int
        );
        assert_eq!(
            ASN1_STRING_get0_data(string.as_ref())
                .expect("valid string data")
                .elems()
                .collect::<Vec<_>>(),
            source
        );
    }
}

//! Wrappers assigned from `crypto/evp/p_lib.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_char, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull, null_mut};

use ffibox::{CBox, CSlice, CType, CVal, CVec};
use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1PctxMut;
use crate::bio::bio_bio_local::BioMut;
use crate::bio::bn_bn_local::{Bignum, BignumRef};
use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{OsslParam, OsslParamListMut, OsslParamRef, terminated_param_len};
use crate::evp::evp::{EvpCipherRef, EvpPkey, EvpPkeyMut, EvpPkeyRef};
use crate::evp::evp_local::EvpKeymgmtRef;
#[cfg(feature = "deprecated-3-0")]
use crate::keys::dh_local::{DhRef, SharedDh};
#[cfg(feature = "deprecated-3-0")]
use crate::keys::dsa_local::{DsaRef, SharedDsa};
#[cfg(feature = "deprecated-3-0")]
use crate::keys::ec_local::EcKey;
use crate::mem::CryptoFree;
use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;

/// An EVP key whose provider-side dependencies borrow a library context.
#[must_use = "dropping the owner releases its EVP_PKEY reference"]
pub struct BorrowedEvpPkey<'a> {
    inner: CBox<EvpPkey>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedEvpPkey<'_> {
    pub(crate) unsafe fn from_raw(raw: *mut ffi::evp_pkey_st) -> Option<Self> {
        // SAFETY: the caller transfers one fully initialized EVP_PKEY reference.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the key without write access.
    #[must_use]
    pub fn as_ref(&self) -> EvpPkeyRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the key.
    #[must_use]
    pub fn as_mut(&mut self) -> EvpPkeyMut<'_> {
        self.inner.as_mut()
    }
}

/// A type-erased application pointer borrowed from an EVP key's ex-data table.
#[derive(Clone, Copy)]
pub struct EvpPkeyExData<'a> {
    pointer: NonNull<c_void>,
    borrow: PhantomData<EvpPkeyRef<'a>>,
}

impl EvpPkeyExData<'_> {
    /// Reinterpret the stored application pointer.
    ///
    /// # Safety
    ///
    /// The application must have stored a live, aligned `T` at this index and
    /// must prevent mutation or release that conflicts with the returned use.
    #[must_use]
    pub unsafe fn cast<T>(self) -> NonNull<T> {
        self.pointer.cast()
    }
}

/// A borrowed, key-terminated table returned by `EVP_PKEY_gettable_params`.
pub struct GettableParams<'a> {
    next: NonNull<ffi::ossl_param_st>,
    borrow: PhantomData<EvpPkeyRef<'a>>,
}

impl<'a> Iterator for GettableParams<'a> {
    type Item = OsslParamRef<'a, 'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = self.next;
        // SAFETY: OpenSSL publishes this result as a key-terminated contiguous
        // OSSL_PARAM table that remains live with the borrowed key management
        // implementation. `current` starts at the table and advances only one
        // initialized descriptor at a time.
        let item: OsslParamRef<'a, 'a> =
            unsafe { OsslParamRef::from_ptr(current.as_ptr()) }.expect("non-null table entry");
        item.key()?;
        // SAFETY: a non-null key proves this is not the terminator, so the next
        // initialized descriptor in the published table follows it.
        self.next = unsafe { NonNull::new_unchecked(current.as_ptr().add(1)) };
        Some(item)
    }
}

/// Wraps: EVP_PKEY_get1_encoded_public_key
/// Returns a newly allocated encoded public key released with `CRYPTO_free`.
#[allow(non_snake_case)]
pub fn EVP_PKEY_get1_encoded_public_key(pkey: &mut EvpPkeyMut<'_>) -> Option<CVec<u8, CryptoFree>> {
    let mut output = ptr::null_mut();
    // SAFETY: the exclusive key handle is live and the local output slot is
    // writable. A positive result transfers a `CRYPTO_free` allocation.
    let len = unsafe { ffi::EVP_PKEY_get1_encoded_public_key(pkey.as_mut_ptr(), &mut output) };
    if len == 0 {
        return None;
    }
    // SAFETY: a positive return documents exactly `len` initialized bytes in
    // the fresh OpenSSL allocation placed in `output`.
    unsafe { CVec::from_raw_parts(output, len) }
}

/// Wraps: EVP_PKEY_get_base_id
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_base_id(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared handle identifies a live key and the call reads its type.
    unsafe { ffi::EVP_PKEY_get_base_id(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_bits
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_bits(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared handle remains live for the scalar query.
    unsafe { ffi::EVP_PKEY_get_bits(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_default_digest_name
/// Writes a NUL-terminated digest name when the returned status is positive.
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_default_digest_name(pkey: EvpPkeyRef<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the key is live, and `output` supplies exactly its reported
    // writable capacity. The operation only performs a logical key query.
    unsafe {
        ffi::EVP_PKEY_get_default_digest_name(
            pkey.as_ptr().cast_mut(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    }
}

/// Wraps: EVP_PKEY_get_default_digest_nid
/// Returns the C status together with the identifier when C initialized it.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_default_digest_nid(pkey: EvpPkeyRef<'_>) -> (i32, Option<i32>) {
    let mut nid = 0;
    // SAFETY: the key is live and the local scalar output is writable.
    let status =
        unsafe { ffi::EVP_PKEY_get_default_digest_nid(pkey.as_ptr().cast_mut(), &mut nid) };
    (status, (status > 0).then_some(nid))
}

/// Wraps: EVP_PKEY_get_ec_point_conv_form
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_ec_point_conv_form(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key remains live for the query.
    unsafe { ffi::EVP_PKEY_get_ec_point_conv_form(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_ex_data
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_ex_data<'a>(pkey: EvpPkeyRef<'a>, index: i32) -> Option<EvpPkeyExData<'a>> {
    // SAFETY: the key header and ex-data table remain live for this lookup.
    let pointer = unsafe { ffi::EVP_PKEY_get_ex_data(pkey.as_ptr(), index) };
    NonNull::new(pointer).map(|pointer| EvpPkeyExData {
        pointer,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_PKEY_get_field_type
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_field_type(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key remains live for the query.
    unsafe { ffi::EVP_PKEY_get_field_type(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_group_name
/// Returns an independently owned Rust copy of the provider group name.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_group_name(pkey: EvpPkeyRef<'_>) -> Option<std::ffi::CString> {
    let mut required = usize::MAX;
    // SAFETY: null with zero capacity is the documented sizing form; the local
    // output length remains writable.
    unsafe {
        ffi::EVP_PKEY_get_group_name(pkey.as_ptr(), ptr::null_mut(), 0, &mut required);
    }
    if required == usize::MAX {
        return None;
    }
    let capacity = required.checked_add(1)?;
    let mut bytes = vec![0_u8; capacity];
    let mut written = 0;
    // SAFETY: `bytes` supplies `capacity` writable bytes and the scalar slot is live.
    let ok = unsafe {
        ffi::EVP_PKEY_get_group_name(
            pkey.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            &mut written,
        )
    };
    if ok != 1 || written > required {
        return None;
    }
    bytes.truncate(written.checked_add(1)?);
    std::ffi::CString::from_vec_with_nul(bytes).ok()
}

/// Wraps: EVP_PKEY_get_id
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_id(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared handle identifies a live key and the call reads its type.
    unsafe { ffi::EVP_PKEY_get_id(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_int_param
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_int_param(pkey: EvpPkeyRef<'_>, name: &CStr) -> Option<i32> {
    let mut output = 0;
    // SAFETY: the key and NUL-terminated name are live and `output` is writable.
    let ok = unsafe { ffi::EVP_PKEY_get_int_param(pkey.as_ptr(), name.as_ptr(), &mut output) };
    (ok == 1).then_some(output)
}

/// Wraps: EVP_PKEY_get_octet_string_param
/// Copies the complete parameter into Rust-owned storage.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_octet_string_param(pkey: EvpPkeyRef<'_>, name: &CStr) -> Option<Vec<u8>> {
    let mut required = usize::MAX;
    // SAFETY: null with zero capacity asks only for the required size.
    unsafe {
        ffi::EVP_PKEY_get_octet_string_param(
            pkey.as_ptr(),
            name.as_ptr(),
            ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == usize::MAX {
        return None;
    }
    let mut output = vec![0_u8; required];
    let mut written = 0;
    // SAFETY: the key/name are live, and `output` has exactly the capacity passed.
    let ok = unsafe {
        ffi::EVP_PKEY_get_octet_string_param(
            pkey.as_ptr(),
            name.as_ptr(),
            output.as_mut_ptr(),
            output.len(),
            &mut written,
        )
    };
    if ok != 1 || written > output.len() {
        return None;
    }
    output.truncate(written);
    Some(output)
}

/// Wraps: EVP_PKEY_get_params
/// Applies a terminated array of caller-owned parameter descriptors.
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_params<'data>(
    pkey: EvpPkeyRef<'_>,
    params: &mut [CVal<OsslParam<'data>>],
) -> bool {
    // The validated list derives its array pointer from the borrow covering
    // the whole run, so C may walk every descriptor through it; a pointer
    // taken from `params[0]` would only be valid for that one descriptor.
    let Some(mut params) = OsslParamListMut::from_values(params) else {
        return false;
    };
    // SAFETY: the list is nonempty, contiguous and ends in the required null
    // key descriptor. Its exclusive borrow covers every descriptor and data
    // buffer while C fills them synchronously.
    unsafe { ffi::EVP_PKEY_get_params(pkey.as_ptr(), params.as_mut_ptr()) == 1 }
}

fn get_raw_key(
    pkey: EvpPkeyRef<'_>,
    getter: unsafe extern "C" fn(*const ffi::evp_pkey_st, *mut u8, *mut usize) -> i32,
) -> Option<Vec<u8>> {
    let mut required = 0;
    // SAFETY: the live key and writable size slot satisfy the getter's sizing form.
    if unsafe { getter(pkey.as_ptr(), ptr::null_mut(), &mut required) } != 1 {
        return None;
    }
    let mut output = vec![0_u8; required];
    let mut written = output.len();
    // SAFETY: `output` supplies the advertised writable extent and `written`
    // is a live in/out capacity slot.
    if unsafe { getter(pkey.as_ptr(), output.as_mut_ptr(), &mut written) } != 1
        || written > output.len()
    {
        return None;
    }
    output.truncate(written);
    Some(output)
}

/// Wraps: EVP_PKEY_get_raw_private_key
/// Copies raw private-key bytes into Rust-owned storage.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_raw_private_key(pkey: EvpPkeyRef<'_>) -> Option<Vec<u8>> {
    get_raw_key(pkey, ffi::EVP_PKEY_get_raw_private_key)
}

/// Wraps: EVP_PKEY_get_raw_public_key
/// Copies raw public-key bytes into Rust-owned storage.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_raw_public_key(pkey: EvpPkeyRef<'_>) -> Option<Vec<u8>> {
    get_raw_key(pkey, ffi::EVP_PKEY_get_raw_public_key)
}

/// Wraps: EVP_PKEY_get_security_bits
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_security_bits(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key remains live for the scalar query.
    unsafe { ffi::EVP_PKEY_get_security_bits(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_security_category
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_security_category(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key remains live for the scalar query.
    unsafe { ffi::EVP_PKEY_get_security_category(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_size
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_size(pkey: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the shared key remains live for the scalar query.
    unsafe { ffi::EVP_PKEY_get_size(pkey.as_ptr()) }
}

/// Wraps: EVP_PKEY_get_size_t_param
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_size_t_param(pkey: EvpPkeyRef<'_>, name: &CStr) -> Option<usize> {
    let mut output = 0;
    // SAFETY: the key and NUL-terminated name are live and `output` is writable.
    let ok = unsafe { ffi::EVP_PKEY_get_size_t_param(pkey.as_ptr(), name.as_ptr(), &mut output) };
    (ok == 1).then_some(output)
}

/// Wraps: EVP_PKEY_get_utf8_string_param
/// Copies the complete UTF-8 parameter into an owned C string.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_get_utf8_string_param(
    pkey: EvpPkeyRef<'_>,
    name: &CStr,
) -> Option<std::ffi::CString> {
    let mut required = usize::MAX;
    // SAFETY: null with zero capacity is used only to obtain the required size.
    unsafe {
        ffi::EVP_PKEY_get_utf8_string_param(
            pkey.as_ptr(),
            name.as_ptr(),
            ptr::null_mut(),
            0,
            &mut required,
        );
    }
    if required == usize::MAX {
        return None;
    }
    let capacity = required.checked_add(1)?;
    let mut output = vec![0_u8; capacity];
    let mut written = 0;
    // SAFETY: `output` includes one byte beyond the reported string length for
    // the terminator that the C implementation writes.
    let ok = unsafe {
        ffi::EVP_PKEY_get_utf8_string_param(
            pkey.as_ptr(),
            name.as_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
            &mut written,
        )
    };
    if ok != 1 || written > required {
        return None;
    }
    output.truncate(written.checked_add(1)?);
    std::ffi::CString::from_vec_with_nul(output).ok()
}

/// Wraps: EVP_PKEY_gettable_params
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_gettable_params<'a>(pkey: EvpPkeyRef<'a>) -> Option<GettableParams<'a>> {
    // SAFETY: the shared key retains its key-management implementation while
    // the returned const table is borrowed.
    let table = unsafe { ffi::EVP_PKEY_gettable_params(pkey.as_ptr()) };
    NonNull::new(table.cast_mut()).map(|next| GettableParams {
        next,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_PKEY_is_a
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_is_a(pkey: EvpPkeyRef<'_>, name: &CStr) -> bool {
    // SAFETY: both borrowed inputs are live and the name is NUL-terminated.
    unsafe { ffi::EVP_PKEY_is_a(pkey.as_ptr(), name.as_ptr()) == 1 }
}

/// Wraps: EVP_PKEY_missing_parameters
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_missing_parameters(pkey: EvpPkeyRef<'_>) -> bool {
    // SAFETY: the shared key remains live for the query.
    unsafe { ffi::EVP_PKEY_missing_parameters(pkey.as_ptr()) != 0 }
}

/// Wraps: EVP_PKEY_new
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new() -> Option<CBox<EvpPkey>> {
    // SAFETY: a non-null result transfers one fully initialized key reference.
    unsafe { CBox::from_raw(ffi::EVP_PKEY_new()) }
}

/// Wraps: EVP_PKEY_new_CMAC_key
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_CMAC_key(key: &[u8], cipher: EvpCipherRef<'_>) -> Option<CBox<EvpPkey>> {
    // SAFETY: null is the only supported ENGINE argument, the byte slice and
    // cipher handle remain live, and a non-null result transfers ownership.
    let raw = unsafe {
        ffi::EVP_PKEY_new_CMAC_key(ptr::null_mut(), key.as_ptr(), key.len(), cipher.as_ptr())
    };
    // SAFETY: a non-null result is one fully initialized EVP_PKEY reference.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_new_raw_private_key
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_raw_private_key(key_type: i32, key: &[u8]) -> Option<CBox<EvpPkey>> {
    // SAFETY: null is the required ENGINE value and the byte slice is readable
    // for the call; OpenSSL copies it into a fresh key.
    let raw = unsafe {
        ffi::EVP_PKEY_new_raw_private_key(key_type, ptr::null_mut(), key.as_ptr(), key.len())
    };
    // SAFETY: a non-null result transfers one initialized key reference.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_new_raw_private_key_ex
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_raw_private_key_ex<'a>(
    context: Option<OsslLibCtxRef<'a>>,
    key_type: &CStr,
    properties: Option<&CStr>,
    key: &[u8],
) -> Option<BorrowedEvpPkey<'a>> {
    let context = context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: every pointer is null or backed by the corresponding live borrow;
    // OpenSSL copies key bytes and a non-null result transfers ownership.
    let raw = unsafe {
        ffi::EVP_PKEY_new_raw_private_key_ex(
            context,
            key_type.as_ptr(),
            properties,
            key.as_ptr(),
            key.len(),
        )
    };
    // SAFETY: the context lifetime carried by the result covers provider-side
    // dependencies, and a non-null raw pointer transfers one key reference.
    unsafe { BorrowedEvpPkey::from_raw(raw) }
}

/// Wraps: EVP_PKEY_new_raw_public_key
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_raw_public_key(key_type: i32, key: &[u8]) -> Option<CBox<EvpPkey>> {
    // SAFETY: null is the required ENGINE value and OpenSSL synchronously copies
    // the readable key bytes into a fresh result.
    let raw = unsafe {
        ffi::EVP_PKEY_new_raw_public_key(key_type, ptr::null_mut(), key.as_ptr(), key.len())
    };
    // SAFETY: a non-null result transfers one initialized key reference.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_new_raw_public_key_ex
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_raw_public_key_ex<'a>(
    context: Option<OsslLibCtxRef<'a>>,
    key_type: &CStr,
    properties: Option<&CStr>,
    key: &[u8],
) -> Option<BorrowedEvpPkey<'a>> {
    let context = context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: every pointer is null or backed by a live borrow, and OpenSSL
    // copies the key bytes before returning the owned result.
    let raw = unsafe {
        ffi::EVP_PKEY_new_raw_public_key_ex(
            context,
            key_type.as_ptr(),
            properties,
            key.as_ptr(),
            key.len(),
        )
    };
    // SAFETY: the result carries the context dependency and adopts one reference.
    unsafe { BorrowedEvpPkey::from_raw(raw) }
}

/// Wraps: EVP_PKEY_parameters_eq
/// Preserves OpenSSL's equality and unsupported/error status values.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_parameters_eq(a: EvpPkeyRef<'_>, b: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: both shared key handles remain live for the comparison.
    unsafe { ffi::EVP_PKEY_parameters_eq(a.as_ptr(), b.as_ptr()) }
}

/// Wraps: EVP_PKEY_print_params
#[allow(non_snake_case)]
pub fn EVP_PKEY_print_params(
    output: &mut BioMut<'_>,
    pkey: EvpPkeyRef<'_>,
    indent: i32,
    context: Option<&mut Asn1PctxMut<'_>>,
) -> i32 {
    // SAFETY: the output is exclusively borrowed, the key is live, and the
    // optional print context remains exclusively borrowed for the call.
    unsafe {
        ffi::EVP_PKEY_print_params(
            output.as_mut_ptr(),
            pkey.as_ptr(),
            indent,
            context.map_or(ptr::null_mut(), Asn1PctxMut::as_mut_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_print_params_fp
#[allow(non_snake_case)]
pub fn EVP_PKEY_print_params_fp(
    output: &mut IoFileMut<'_>,
    pkey: EvpPkeyRef<'_>,
    indent: i32,
    context: Option<&mut Asn1PctxMut<'_>>,
) -> i32 {
    // SAFETY: the stream is live and exclusively borrowed; the other typed
    // handles remain live for this synchronous formatting operation.
    unsafe {
        ffi::EVP_PKEY_print_params_fp(
            output.as_mut_ptr().cast(),
            pkey.as_ptr(),
            indent,
            context.map_or(ptr::null_mut(), Asn1PctxMut::as_mut_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_print_private
#[allow(non_snake_case)]
pub fn EVP_PKEY_print_private(
    output: &mut BioMut<'_>,
    pkey: EvpPkeyRef<'_>,
    indent: i32,
    context: Option<&mut Asn1PctxMut<'_>>,
) -> i32 {
    // SAFETY: all typed handles remain live and the writable ones are exclusive.
    unsafe {
        ffi::EVP_PKEY_print_private(
            output.as_mut_ptr(),
            pkey.as_ptr(),
            indent,
            context.map_or(ptr::null_mut(), Asn1PctxMut::as_mut_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_print_private_fp
#[allow(non_snake_case)]
pub fn EVP_PKEY_print_private_fp(
    output: &mut IoFileMut<'_>,
    pkey: EvpPkeyRef<'_>,
    indent: i32,
    context: Option<&mut Asn1PctxMut<'_>>,
) -> i32 {
    // SAFETY: the stream is exclusively borrowed and every other pointer comes
    // from a live typed handle for this call.
    unsafe {
        ffi::EVP_PKEY_print_private_fp(
            output.as_mut_ptr().cast(),
            pkey.as_ptr(),
            indent,
            context.map_or(ptr::null_mut(), Asn1PctxMut::as_mut_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_print_public
#[allow(non_snake_case)]
pub fn EVP_PKEY_print_public(
    output: &mut BioMut<'_>,
    pkey: EvpPkeyRef<'_>,
    indent: i32,
    context: Option<&mut Asn1PctxMut<'_>>,
) -> i32 {
    // SAFETY: all typed handles remain live and the writable ones are exclusive.
    unsafe {
        ffi::EVP_PKEY_print_public(
            output.as_mut_ptr(),
            pkey.as_ptr(),
            indent,
            context.map_or(ptr::null_mut(), Asn1PctxMut::as_mut_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_print_public_fp
#[allow(non_snake_case)]
pub fn EVP_PKEY_print_public_fp(
    output: &mut IoFileMut<'_>,
    pkey: EvpPkeyRef<'_>,
    indent: i32,
    context: Option<&mut Asn1PctxMut<'_>>,
) -> i32 {
    // SAFETY: the stream is exclusively borrowed and every other pointer comes
    // from a live typed handle for this call.
    unsafe {
        ffi::EVP_PKEY_print_public_fp(
            output.as_mut_ptr().cast(),
            pkey.as_ptr(),
            indent,
            context.map_or(ptr::null_mut(), Asn1PctxMut::as_mut_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_save_parameters
/// Returns the previous setting, matching OpenSSL's scalar API.
#[allow(non_snake_case)]
pub fn EVP_PKEY_save_parameters(pkey: &mut EvpPkeyMut<'_>, mode: i32) -> i32 {
    // SAFETY: the exclusive key handle permits updating this legacy setting.
    unsafe { ffi::EVP_PKEY_save_parameters(pkey.as_mut_ptr(), mode) }
}

/// Wraps: EVP_PKEY_set1_encoded_public_key
#[allow(non_snake_case)]
pub fn EVP_PKEY_set1_encoded_public_key(pkey: &mut EvpPkeyMut<'_>, public_key: &[u8]) -> bool {
    // SAFETY: the exclusive key handle and byte slice remain live for the
    // synchronous call, which copies the encoded key rather than storing it.
    unsafe {
        ffi::EVP_PKEY_set1_encoded_public_key(
            pkey.as_mut_ptr(),
            public_key.as_ptr(),
            public_key.len(),
        ) == 1
    }
}

/// Wraps: EVP_PKEY_set_ex_data
///
/// # Safety
///
/// OpenSSL stores `data` without a Rust lifetime. Its type, lifetime, and any
/// registered ex-data duplication or cleanup callback must agree for `index`.
#[allow(non_snake_case)]
pub unsafe fn EVP_PKEY_set_ex_data<T>(
    key: &mut EvpPkeyMut<'_>,
    index: i32,
    data: Option<NonNull<T>>,
) -> bool {
    // SAFETY: the exclusive key handle permits replacement and the caller
    // upholds the indexed registry's erased type and lifetime contract.
    unsafe {
        ffi::EVP_PKEY_set_ex_data(
            key.as_mut_ptr(),
            index,
            data.map_or(null_mut(), |data| data.as_ptr().cast::<c_void>()),
        ) == 1
    }
}

/// Wraps: EVP_PKEY_set_int_param
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_int_param(pkey: &mut EvpPkeyMut<'_>, key_name: &CStr, value: i32) -> bool {
    // SAFETY: both borrows are live for the call. OpenSSL constructs a
    // transient descriptor and copies the scalar into provider state.
    unsafe { ffi::EVP_PKEY_set_int_param(pkey.as_mut_ptr(), key_name.as_ptr(), value) == 1 }
}

/// Wraps: EVP_PKEY_set_octet_string_param
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_octet_string_param(
    pkey: &mut EvpPkeyMut<'_>,
    key_name: &CStr,
    value: &[u8],
) -> bool {
    // SAFETY: the exclusive key, name, and byte run remain live for this
    // synchronous setter, which does not retain the descriptor's data pointer.
    unsafe {
        ffi::EVP_PKEY_set_octet_string_param(
            pkey.as_mut_ptr(),
            key_name.as_ptr(),
            value.as_ptr(),
            value.len(),
        ) == 1
    }
}

/// Wraps: EVP_PKEY_set_params
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_params(
    pkey: &mut EvpPkeyMut<'_>,
    params: &mut OsslParamListMut<'_, '_>,
) -> bool {
    // SAFETY: the list type guarantees an initialized null-key terminator and
    // carries exclusive access to every descriptor for the duration of C use.
    unsafe { ffi::EVP_PKEY_set_params(pkey.as_mut_ptr(), params.as_mut_ptr()) == 1 }
}

/// Wraps: EVP_PKEY_set_size_t_param
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_size_t_param(pkey: &mut EvpPkeyMut<'_>, key_name: &CStr, value: usize) -> bool {
    // SAFETY: the live name and exclusive key are borrowed for the synchronous
    // call; provider state receives the copied scalar value.
    unsafe { ffi::EVP_PKEY_set_size_t_param(pkey.as_mut_ptr(), key_name.as_ptr(), value) == 1 }
}

/// Wraps: EVP_PKEY_set_type
///
/// `None` performs OpenSSL's documented availability query without modifying
/// a key. `Some` clears any previous key material before selecting the type.
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_type(pkey: Option<&mut EvpPkeyMut<'_>>, key_type: i32) -> bool {
    let pkey = pkey.map_or(null_mut(), EvpPkeyMut::as_mut_ptr);
    // SAFETY: null is the documented query form; otherwise the exclusive
    // handle permits OpenSSL to replace the key's selected implementation.
    unsafe { ffi::EVP_PKEY_set_type(pkey, key_type) == 1 }
}

/// Wraps: EVP_PKEY_set_type_by_keymgmt
///
/// OpenSSL raises its own reference to `keymgmt`; the caller retains its share.
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_type_by_keymgmt(
    pkey: Option<&mut EvpPkeyMut<'_>>,
    keymgmt: EvpKeymgmtRef<'_>,
) -> bool {
    let pkey = pkey.map_or(null_mut(), EvpPkeyMut::as_mut_ptr);
    // SAFETY: null is the documented query form for `pkey`. The method handle
    // is live and OpenSSL raises a reference before storing it in a real key.
    unsafe { ffi::EVP_PKEY_set_type_by_keymgmt(pkey, keymgmt.as_ptr().cast_mut()) == 1 }
}

/// Wraps: EVP_PKEY_set_type_str
///
/// The type name is length-delimited and need not carry a trailing NUL.
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_type_str(pkey: Option<&mut EvpPkeyMut<'_>>, type_name: &[u8]) -> bool {
    let Ok(len) = i32::try_from(type_name.len()) else {
        return false;
    };
    let pkey = pkey.map_or(null_mut(), EvpPkeyMut::as_mut_ptr);
    // SAFETY: the byte run is live for the explicit length and OpenSSL does
    // not retain it; null `pkey` is the documented availability-query form.
    unsafe { ffi::EVP_PKEY_set_type_str(pkey, type_name.as_ptr().cast::<c_char>(), len) == 1 }
}

/// Wraps: EVP_PKEY_set_utf8_string_param
///
/// `None` passes a null parameter value. OpenSSL's API does not itself validate
/// that the non-null C string contains well-formed UTF-8.
#[allow(non_snake_case)]
pub fn EVP_PKEY_set_utf8_string_param(
    pkey: &mut EvpPkeyMut<'_>,
    key_name: &CStr,
    value: Option<&CStr>,
) -> bool {
    let value = value.map_or(core::ptr::null(), CStr::as_ptr);
    // SAFETY: the exclusive key and strings remain live for this synchronous
    // setter; the transient descriptor is not retained by the provider call.
    unsafe { ffi::EVP_PKEY_set_utf8_string_param(pkey.as_mut_ptr(), key_name.as_ptr(), value) == 1 }
}

/// Wraps: EVP_PKEY_settable_params
///
/// Returns the provider-owned descriptor run before its terminator. The key's
/// borrow keeps the key-management method and provider behind the run alive.
#[allow(non_snake_case)]
pub fn EVP_PKEY_settable_params<'key>(
    pkey: EvpPkeyRef<'key>,
) -> Option<CSlice<'key, OsslParam<'key>>> {
    // SAFETY: the key handle is live. A provider-backed key returns a
    // provider-owned, initialized, null-key-terminated descriptor array.
    let params = unsafe { ffi::EVP_PKEY_settable_params(pkey.as_ptr()) };
    // SAFETY: a non-null result follows the terminated-array contract above.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'key>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator, and `pkey` retains their provider for `'key`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_PKEY_type_names_do_all
///
/// Calls `callback` synchronously for every name and returns whether OpenSSL
/// considered the key typed and completed enumeration successfully.
#[allow(non_snake_case)]
pub fn EVP_PKEY_type_names_do_all<F: FnMut(&CStr)>(pkey: EvpPkeyRef<'_>, callback: F) -> bool {
    struct State<F> {
        callback: F,
        valid: bool,
    }

    unsafe extern "C" fn trampoline<F: FnMut(&CStr)>(name: *const c_char, data: *mut c_void) {
        // SAFETY: this function is passed a unique pointer to `State<F>` for
        // the synchronous enumeration and OpenSSL does not retain it.
        let state = unsafe { &mut *data.cast::<State<F>>() };
        if name.is_null() {
            state.valid = false;
            return;
        }
        // SAFETY: OpenSSL's name callback contract supplies a live
        // NUL-terminated algorithm name for the duration of this call.
        (state.callback)(unsafe { CStr::from_ptr(name) });
    }

    let mut state = State {
        callback,
        valid: true,
    };
    // SAFETY: the key handle is live, and the callback/data pair stays live
    // and uniquely borrowed until synchronous enumeration returns.
    let ok = unsafe {
        ffi::EVP_PKEY_type_names_do_all(
            pkey.as_ptr(),
            Some(trampoline::<F>),
            core::ptr::from_mut(&mut state).cast(),
        ) == 1
    };
    ok && state.valid
}

#[cfg(feature = "deprecated-3-0")]
/// A borrowed, runtime-typed legacy key payload.
///
/// The payload deliberately exposes no raw pointer or typed access: callers
/// should use a type-specific `get0` wrapper when that type has been wrapped.
pub struct LegacyEvpPkeyRef<'a> {
    ptr: NonNull<c_void>,
    borrow: PhantomData<EvpPkeyRef<'a>>,
}

#[cfg(feature = "deprecated-3-0")]
impl LegacyEvpPkeyRef<'_> {
    /// Whether this borrowed legacy payload is present.
    #[must_use]
    pub const fn is_present(&self) -> bool {
        let _ = self.ptr;
        true
    }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_assign
/// Transfers an independently owned legacy EC key into an EVP container.
pub fn EVP_PKEY_assign_EC_KEY(
    pkey: &mut EvpPkeyMut<'_>,
    key: CBox<EcKey>,
) -> Result<(), CBox<EcKey>> {
    let raw = key.into_raw();
    // SAFETY: the destination is exclusive and `raw` transfers one EC_KEY
    // ownership obligation only if the C function reports success.
    if unsafe {
        ffi::EVP_PKEY_assign(
            pkey.as_mut_ptr(),
            ffi::EVP_PKEY_EC as i32,
            raw.cast::<c_void>(),
        )
    } == 1
    {
        Ok(())
    } else {
        // SAFETY: failure leaves the non-null input ownership unconsumed.
        Err(unsafe { CBox::from_raw(raw) }.expect("non-null EC key"))
    }
}

/// Wraps: EVP_PKEY_can_sign
#[must_use]
pub fn EVP_PKEY_can_sign(pkey: EvpPkeyRef<'_>) -> bool {
    // SAFETY: the shared handle supplies a live key and the query retains no
    // borrowed pointer.
    unsafe { ffi::EVP_PKEY_can_sign(pkey.as_ptr()) == 1 }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_cmp
#[must_use]
pub fn EVP_PKEY_cmp(a: EvpPkeyRef<'_>, b: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: both shared key handles remain live for the comparison.
    unsafe { ffi::EVP_PKEY_cmp(a.as_ptr(), b.as_ptr()) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_cmp_parameters
#[must_use]
pub fn EVP_PKEY_cmp_parameters(a: EvpPkeyRef<'_>, b: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: both shared key handles remain live for the comparison.
    unsafe { ffi::EVP_PKEY_cmp_parameters(a.as_ptr(), b.as_ptr()) }
}

/// Wraps: EVP_PKEY_copy_parameters
pub fn EVP_PKEY_copy_parameters(to: &mut EvpPkeyMut<'_>, from: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: the destination is exclusive, the source is shared and live,
    // and OpenSSL duplicates or raises every stored dependency it retains.
    unsafe { ffi::EVP_PKEY_copy_parameters(to.as_mut_ptr(), from.as_ptr()) }
}

/// Wraps: EVP_PKEY_digestsign_supports_digest
#[must_use]
pub fn EVP_PKEY_digestsign_supports_digest(
    pkey: &mut EvpPkeyMut<'_>,
    library_context: Option<OsslLibCtxRef<'_>>,
    digest_name: &CStr,
    property_query: Option<&CStr>,
) -> i32 {
    let library_context =
        library_context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the exclusive key and every optional borrowed pointer remain
    // live for the transient digest-sign initialization query.
    unsafe {
        ffi::EVP_PKEY_digestsign_supports_digest(
            pkey.as_mut_ptr(),
            library_context,
            digest_name.as_ptr(),
            property_query,
        )
    }
}

/// Wraps: EVP_PKEY_eq
#[must_use]
pub fn EVP_PKEY_eq(a: EvpPkeyRef<'_>, b: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: both shared key handles remain live for the comparison.
    unsafe { ffi::EVP_PKEY_eq(a.as_ptr(), b.as_ptr()) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0
#[must_use]
pub fn EVP_PKEY_get0<'a>(pkey: EvpPkeyRef<'a>) -> Option<LegacyEvpPkeyRef<'a>> {
    // SAFETY: the key is live; the result is borrowed from its legacy payload.
    let raw = unsafe { ffi::EVP_PKEY_get0(pkey.as_ptr()) };
    NonNull::new(raw).map(|ptr| LegacyEvpPkeyRef {
        ptr,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_PKEY_get0_description
#[must_use]
pub fn EVP_PKEY_get0_description<'a>(pkey: EvpPkeyRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the key retains the returned static or method-owned description.
    let raw = unsafe { ffi::EVP_PKEY_get0_description(pkey.as_ptr()) };
    if raw.is_null() {
        None
    } else {
        // SAFETY: the API returns a NUL-terminated string borrowed from `pkey`.
        Some(unsafe { CStr::from_ptr(raw) })
    }
}

#[cfg(feature = "deprecated-3-0")]
fn legacy_octets<'a>(
    pkey: EvpPkeyRef<'a>,
    call: unsafe extern "C" fn(*const ffi::evp_pkey_st, *mut usize) -> *const u8,
) -> Option<CSlice<'a, u8>> {
    let mut len = 0;
    // SAFETY: the key is live and `len` is a writable scalar out-slot.
    let raw = unsafe { call(pkey.as_ptr(), &mut len) };
    NonNull::new(raw.cast_mut()).map(|raw| {
        // SAFETY: a non-null result addresses the `len` bytes stored in the
        // key's retained ASN.1 string for the key borrow's lifetime.
        unsafe { CSlice::from_raw_parts(raw, len) }
    })
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0_hmac
#[must_use]
pub fn EVP_PKEY_get0_hmac<'a>(pkey: EvpPkeyRef<'a>) -> Option<CSlice<'a, u8>> {
    legacy_octets(pkey, ffi::EVP_PKEY_get0_hmac)
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0_poly1305
#[must_use]
pub fn EVP_PKEY_get0_poly1305<'a>(pkey: EvpPkeyRef<'a>) -> Option<CSlice<'a, u8>> {
    legacy_octets(pkey, ffi::EVP_PKEY_get0_poly1305)
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0_siphash
#[must_use]
pub fn EVP_PKEY_get0_siphash<'a>(pkey: EvpPkeyRef<'a>) -> Option<CSlice<'a, u8>> {
    legacy_octets(pkey, ffi::EVP_PKEY_get0_siphash)
}

#[cfg(test)]
mod tests {
    use core::ffi::c_int;
    use core::mem::{MaybeUninit, size_of};

    use super::*;

    #[test]
    fn fresh_key_has_empty_attributes_and_scalar_identity() {
        let key = EVP_PKEY_new().expect("EVP_PKEY_new");
        assert_eq!(EVP_PKEY_get_id(key.as_ref()), 0);
        assert_eq!(EVP_PKEY_get_base_id(key.as_ref()), 0);
        assert!(!EVP_PKEY_is_a(key.as_ref(), c"RSA"));
    }

    #[test]
    fn raw_ed25519_private_key_round_trips() {
        let bytes = [7_u8; 32];
        let key = EVP_PKEY_new_raw_private_key_ex(None, c"ED25519", None, &bytes)
            .expect("raw ED25519 private key");
        assert!(EVP_PKEY_is_a(key.as_ref(), c"ED25519"));
        assert_eq!(
            EVP_PKEY_get_raw_private_key(key.as_ref()).as_deref(),
            Some(bytes.as_slice())
        );
        assert!(EVP_PKEY_get_raw_public_key(key.as_ref()).is_some());
        assert!(EVP_PKEY_gettable_params(key.as_ref()).is_some());
    }

    /// Reclaims a filled `OSSL_PARAM_INTEGER` descriptor's buffer and reads
    /// back the native integer OpenSSL wrote into it.
    fn filled_int(param: &mut CVal<OsslParam<'_>>) -> c_int {
        let written = param.as_mut().take_data().expect("stored integer buffer");
        let mut source = [MaybeUninit::uninit(); size_of::<c_int>()];
        assert!(written.as_ref().copy_to_slice(&mut source));
        let mut native = [0_u8; size_of::<c_int>()];
        for (byte, filled) in native.iter_mut().zip(source) {
            // SAFETY: OpenSSL reported writing exactly `size_of::<c_int>()`
            // bytes of an `OSSL_PARAM_INTEGER` into this buffer, so every byte
            // of the native integer it holds is initialized.
            *byte = unsafe { filled.assume_init() };
        }
        c_int::from_ne_bytes(native)
    }

    #[test]
    fn get_params_fills_every_descriptor_of_the_run() {
        const OSSL_PARAM_INTEGER: u32 = 1;

        let bytes = [7_u8; 32];
        let key = EVP_PKEY_new_raw_private_key_ex(None, c"ED25519", None, &bytes)
            .expect("raw ED25519 private key");

        let mut bits = [MaybeUninit::<u8>::uninit(); size_of::<c_int>()];
        let mut security_bits = [MaybeUninit::<u8>::uninit(); size_of::<c_int>()];
        let mut params = [
            OsslParam::for_slice(c"bits", OSSL_PARAM_INTEGER, &mut bits).expect("byte descriptor"),
            OsslParam::for_slice(c"security-bits", OSSL_PARAM_INTEGER, &mut security_bits)
                .expect("byte descriptor"),
            OsslParam::end(),
        ];
        assert!(EVP_PKEY_get_params(key.as_ref(), &mut params));

        // The second descriptor is only reached by walking past the first, so
        // its filled `return_size` is what proves the array pointer handed to
        // C covers the whole run rather than one element.
        assert_eq!(params[0].as_ref().return_size(), size_of::<c_int>());
        assert_eq!(params[1].as_ref().return_size(), size_of::<c_int>());
        // Reclaim each descriptor's buffer borrow to read what C wrote.
        assert_eq!(filled_int(&mut params[0]), 256);
        assert_eq!(filled_int(&mut params[1]), 128);
    }

    #[test]
    fn get_params_rejects_a_run_without_the_published_terminator() {
        const OSSL_PARAM_INTEGER: u32 = 1;

        let key = EVP_PKEY_new().expect("EVP_PKEY_new");
        let mut bits = [MaybeUninit::<u8>::uninit(); size_of::<c_int>()];
        let mut unterminated =
            [OsslParam::for_slice(c"bits", OSSL_PARAM_INTEGER, &mut bits)
                .expect("byte descriptor")];
        assert!(!EVP_PKEY_get_params(key.as_ref(), &mut unterminated));

        let mut empty: [CVal<OsslParam<'static>>; 0] = [];
        assert!(!EVP_PKEY_get_params(key.as_ref(), &mut empty));
    }
}

#[cfg(test)]
mod setter_tests {
    use ffibox::CBox;

    use super::*;
    use crate::evp::evp::EvpPkey;

    #[test]
    fn type_selection_and_name_callback_use_safe_borrows() {
        // SAFETY: a non-null result is a fresh fully initialized PKEY carrying
        // one `EVP_PKEY_free` obligation.
        let mut key =
            unsafe { CBox::<EvpPkey>::from_raw(ffi::EVP_PKEY_new()) }.expect("EVP_PKEY_new");

        assert!(EVP_PKEY_set_type(
            Some(&mut key.as_mut()),
            ffi::EVP_PKEY_RSA as i32,
        ));
        let mut names = Vec::new();
        assert!(EVP_PKEY_type_names_do_all(key.as_ref(), |name| {
            names.push(name.to_bytes().to_vec());
        }));
        assert!(!names.is_empty());
    }

    #[test]
    fn scalar_setters_report_failure_for_an_unassigned_key() {
        // SAFETY: a non-null result transfers one fresh PKEY reference.
        let mut key =
            unsafe { CBox::<EvpPkey>::from_raw(ffi::EVP_PKEY_new()) }.expect("EVP_PKEY_new");
        assert!(!EVP_PKEY_set_int_param(&mut key.as_mut(), c"bits", 2048));
        assert!(!EVP_PKEY_set_size_t_param(&mut key.as_mut(), c"bits", 2048,));
        assert!(!EVP_PKEY_set_octet_string_param(
            &mut key.as_mut(),
            c"encoded-pub-key",
            &[1, 2, 3],
        ));
    }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0_DH
/// Borrows the legacy DH key retained by an EVP key container.
#[must_use]
pub fn EVP_PKEY_get0_DH<'a>(pkey: EvpPkeyRef<'a>) -> Option<DhRef<'a>> {
    // SAFETY: the shared container remains live and retains any returned DH.
    let raw = unsafe { ffi::EVP_PKEY_get0_DH(pkey.as_ptr()) };
    // SAFETY: null is absence; a non-null result is borrowed from `pkey`.
    unsafe { DhRef::from_ptr(raw.cast_mut()) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get0_DSA
/// Borrows the legacy DSA key retained by an EVP key container.
#[must_use]
pub fn EVP_PKEY_get0_DSA<'a>(pkey: EvpPkeyRef<'a>) -> Option<DsaRef<'a>> {
    // SAFETY: the shared container remains live and retains any returned DSA.
    let raw = unsafe { ffi::EVP_PKEY_get0_DSA(pkey.as_ptr()) };
    // SAFETY: null is absence; a non-null result is borrowed from `pkey`.
    unsafe { DsaRef::from_ptr(raw.cast_mut()) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get1_DH
/// Raises and owns one shared-only DH reference.
#[must_use]
pub fn EVP_PKEY_get1_DH<'a>(pkey: EvpPkeyRef<'a>) -> Option<SharedDh<'a>> {
    // SAFETY: the live container permits synchronized legacy-cache lookup and
    // a reference-count increment without transferring the container.
    let raw = unsafe { ffi::EVP_PKEY_get1_DH(pkey.as_ptr().cast_mut()) };
    // SAFETY: a non-null result transfers one DH_free obligation and remains
    // conservatively bounded by the PKEY borrow.
    unsafe { SharedDh::from_raw(raw) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_get1_DSA
/// Raises and owns one shared-only DSA reference.
#[must_use]
pub fn EVP_PKEY_get1_DSA<'a>(pkey: EvpPkeyRef<'a>) -> Option<SharedDsa<'a>> {
    // SAFETY: the live container permits synchronized legacy-cache lookup and
    // a reference-count increment without transferring the container.
    let raw = unsafe { ffi::EVP_PKEY_get1_DSA(pkey.as_ptr().cast_mut()) };
    // SAFETY: a non-null result transfers one DSA_free obligation and remains
    // conservatively bounded by the PKEY borrow.
    unsafe { SharedDsa::from_raw(raw) }
}

/// Wraps: EVP_PKEY_get_bn_param
/// Returns an independently allocated parameter value.
#[must_use]
pub fn EVP_PKEY_get_bn_param(pkey: EvpPkeyRef<'_>, key_name: &CStr) -> Option<CBox<Bignum>> {
    let mut raw = ptr::null_mut();
    // SAFETY: the key and name are live, and `raw` is a writable owner slot
    // initialized to null. Success transfers a fresh BIGNUM allocation.
    let ok = unsafe { ffi::EVP_PKEY_get_bn_param(pkey.as_ptr(), key_name.as_ptr(), &mut raw) };
    // SAFETY: any non-null output carries one BN_free obligation, even on an
    // unexpected failing-provider path, so adopting it prevents a leak.
    let output = unsafe { CBox::<Bignum>::from_raw(raw) };
    if ok == 1 { output } else { None }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_set1_DH
/// Stores a separately reference-counted share of `key` in `pkey`.
pub fn EVP_PKEY_set1_DH(pkey: &mut EvpPkeyMut<'_>, key: DhRef<'_>) -> bool {
    // SAFETY: both handles are live. OpenSSL raises the DH reference count
    // before replacing the exclusively borrowed PKEY's key material.
    unsafe { ffi::EVP_PKEY_set1_DH(pkey.as_mut_ptr(), key.as_ptr().cast_mut()) == 1 }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_PKEY_set1_DSA
/// Stores a separately reference-counted share of `key` in `pkey`.
pub fn EVP_PKEY_set1_DSA(pkey: &mut EvpPkeyMut<'_>, key: DsaRef<'_>) -> bool {
    // SAFETY: both handles are live. OpenSSL raises the DSA reference count
    // before replacing the exclusively borrowed PKEY's key material.
    unsafe { ffi::EVP_PKEY_set1_DSA(pkey.as_mut_ptr(), key.as_ptr().cast_mut()) == 1 }
}

/// Wraps: EVP_PKEY_set_bn_param
/// Copies a big-number value into the named provider parameter.
pub fn EVP_PKEY_set_bn_param(
    pkey: &mut EvpPkeyMut<'_>,
    key_name: &CStr,
    value: BignumRef<'_>,
) -> bool {
    // SAFETY: all typed borrows remain live for the synchronous conversion and
    // provider call. OpenSSL retains neither the name nor the BIGNUM pointer.
    unsafe { ffi::EVP_PKEY_set_bn_param(pkey.as_mut_ptr(), key_name.as_ptr(), value.as_ptr()) == 1 }
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;

    #[test]
    fn big_number_access_rejects_an_unassigned_key() {
        // SAFETY: a non-null result transfers one fresh PKEY reference.
        let mut key =
            unsafe { CBox::<EvpPkey>::from_raw(ffi::EVP_PKEY_new()) }.expect("EVP_PKEY_new");
        // SAFETY: a non-null result transfers one fresh BIGNUM allocation.
        let number = unsafe { CBox::<Bignum>::from_raw(ffi::BN_new()) }.expect("BN_new");

        assert!(EVP_PKEY_get_bn_param(key.as_ref(), c"n").is_none());
        assert!(!EVP_PKEY_set_bn_param(
            &mut key.as_mut(),
            c"n",
            number.as_ref(),
        ));
    }

    #[cfg(feature = "deprecated-3-0")]
    #[test]
    fn dh_and_dsa_setters_and_getters_preserve_shared_ownership() {
        use crate::keys::dh_local::Dh;
        use crate::keys::dsa_local::Dsa;

        // SAFETY: each non-null constructor result transfers one public free
        // obligation for a fully initialized default-context object.
        let mut dh_pkey =
            unsafe { CBox::<EvpPkey>::from_raw(ffi::EVP_PKEY_new()) }.expect("EVP_PKEY_new");
        // SAFETY: as above, for a DH allocation.
        let dh = unsafe { CBox::<Dh>::from_raw(ffi::DH_new()) }.expect("DH_new");
        assert!(EVP_PKEY_set1_DH(&mut dh_pkey.as_mut(), dh.as_ref()));
        assert_eq!(
            EVP_PKEY_get0_DH(dh_pkey.as_ref())
                .expect("get0 DH")
                .as_ptr(),
            dh.as_ref().as_ptr(),
        );
        let dh_shared = EVP_PKEY_get1_DH(dh_pkey.as_ref()).expect("get1 DH");
        assert_eq!(dh_shared.as_ref().as_ptr(), dh.as_ref().as_ptr());

        // SAFETY: each non-null constructor result transfers one public free
        // obligation for a fully initialized default-context object.
        let mut dsa_pkey =
            unsafe { CBox::<EvpPkey>::from_raw(ffi::EVP_PKEY_new()) }.expect("EVP_PKEY_new");
        // SAFETY: as above, for a DSA allocation.
        let dsa = unsafe { CBox::<Dsa>::from_raw(ffi::DSA_new()) }.expect("DSA_new");
        assert!(EVP_PKEY_set1_DSA(&mut dsa_pkey.as_mut(), dsa.as_ref()));
        assert_eq!(
            EVP_PKEY_get0_DSA(dsa_pkey.as_ref())
                .expect("get0 DSA")
                .as_ptr(),
            dsa.as_ref().as_ptr(),
        );
        let dsa_shared = EVP_PKEY_get1_DSA(dsa_pkey.as_ref()).expect("get1 DSA");
        assert_eq!(dsa_shared.as_ref().as_ptr(), dsa.as_ref().as_ptr());
    }
}

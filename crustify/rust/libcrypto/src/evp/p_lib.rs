//! Wrappers assigned from `crypto/evp/p_lib.c`.

use core::ffi::{CStr, c_char, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull, null_mut};

use ffibox::{CBox, CSlice, CType, CVal, CVec};
use libcrypto_sys as ffi;

use crate::asn1::asn1::Asn1PctxMut;
use crate::bio::bio_bio_local::BioMut;
use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{OsslParam, OsslParamListMut, OsslParamRef, terminated_param_len};
use crate::evp::evp::{EvpCipherRef, EvpPkey, EvpPkeyMut, EvpPkeyRef};
use crate::evp::evp_local::EvpKeymgmtRef;
use crate::mem::CryptoFree;
use libc::x86_64_linux_gnu_bits_types_struct_file::IoFileMut;

/// An EVP key whose provider-side dependencies borrow a library context.
#[must_use = "dropping the owner releases its EVP_PKEY reference"]
pub struct BorrowedEvpPkey<'a> {
    inner: CBox<EvpPkey>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedEvpPkey<'_> {
    unsafe fn from_raw(raw: *mut ffi::evp_pkey_st) -> Option<Self> {
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
    if !params
        .last()
        .is_some_and(|terminator| terminator.as_ref().key().is_none())
    {
        return false;
    }
    let raw = params[0].as_mut().as_mut_ptr();
    // SAFETY: the slice is nonempty, contiguous and ends in the required null
    // key descriptor. Its exclusive borrow covers every descriptor and data
    // buffer while C fills them synchronously.
    unsafe { ffi::EVP_PKEY_get_params(pkey.as_ptr(), raw) == 1 }
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

#[cfg(test)]
mod tests {
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

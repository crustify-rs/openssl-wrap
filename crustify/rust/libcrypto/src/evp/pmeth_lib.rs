//! Wrappers assigned from `crypto/evp/pmeth_lib.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CSlice, CType, CVec};
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{OsslParam, OsslParamListMut, terminated_param_len};
use crate::evp::evp::{EvpMdRef, EvpPkeyCtx, EvpPkeyCtxMut, EvpPkeyCtxRef, EvpPkeyRef};
use crate::mem::CryptoFree;
use crate::provider::provider_core::OsslProviderRef;

/// An owned EVP operation context whose provider state borrows another object.
#[must_use = "dropping the owner releases the EVP_PKEY_CTX"]
pub struct BorrowedEvpPkeyCtx<'a> {
    inner: CBox<EvpPkeyCtx>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl Clone for BorrowedEvpPkeyCtx<'_> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            borrow: PhantomData,
        }
    }
}

impl BorrowedEvpPkeyCtx<'_> {
    unsafe fn from_raw(raw: *mut ffi::evp_pkey_ctx_st) -> Option<Self> {
        // SAFETY: the caller transfers one fully initialized context and has
        // chosen a lifetime covering every non-owning dependency it stores.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the context without write access.
    #[must_use]
    pub fn as_ref(&self) -> EvpPkeyCtxRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the context.
    #[must_use]
    pub fn as_mut(&mut self) -> EvpPkeyCtxMut<'_> {
        self.inner.as_mut()
    }
}

/// Failure from a `set0` operation that did not consume its OpenSSL buffer.
#[must_use]
pub struct Set0BufferError {
    status: i32,
    buffer: CVec<u8, CryptoFree>,
}

impl Set0BufferError {
    /// Original OpenSSL status.
    #[must_use]
    pub fn status(&self) -> i32 {
        self.status
    }

    /// Recover the buffer whose ownership did not transfer.
    #[must_use]
    pub fn into_buffer(self) -> CVec<u8, CryptoFree> {
        self.buffer
    }
}

/// Opaque application or legacy data stored in an EVP context.
#[derive(Clone, Copy)]
pub struct EvpPkeyCtxData<'a> {
    pointer: NonNull<c_void>,
    borrow: PhantomData<EvpPkeyCtxRef<'a>>,
}

impl EvpPkeyCtxData<'_> {
    /// Reinterpret the application-managed pointer.
    ///
    /// # Safety
    ///
    /// The external code that installed the pointer must keep a live, aligned
    /// `T` there and prevent conflicting access for the returned use.
    #[must_use]
    pub unsafe fn cast<T>(self) -> NonNull<T> {
        self.pointer.cast()
    }
}

pub(crate) fn set0_buffer<F>(buffer: CVec<u8, CryptoFree>, call: F) -> Result<(), Set0BufferError>
where
    F: FnOnce(*mut u8, i32) -> i32,
{
    let Ok(len) = i32::try_from(buffer.count()) else {
        return Err(Set0BufferError { status: -1, buffer });
    };
    let (raw, count) = buffer.into_raw_parts();
    let status = call(raw, len);
    if status == 1 {
        Ok(())
    } else {
        // SAFETY: every relevant set0 implementation frees the allocation only
        // on status 1. On this failure path ownership therefore remains here,
        // with the unchanged pointer and element count just surrendered above.
        let buffer = unsafe { CVec::from_raw_parts(raw, count) }
            .expect("an owned CVec always has a non-null pointer");
        Err(Set0BufferError { status, buffer })
    }
}

/// Wraps: EVP_PKEY_CTX_add1_hkdf_info
pub fn EVP_PKEY_CTX_add1_hkdf_info(ctx: &mut EvpPkeyCtxMut<'_>, info: &[u8]) -> i32 {
    let Ok(len) = i32::try_from(info.len()) else {
        return -1;
    };
    // SAFETY: the exclusive context and readable byte run remain live for the
    // synchronous call; OpenSSL copies the input before returning.
    unsafe { ffi::EVP_PKEY_CTX_add1_hkdf_info(ctx.as_mut_ptr(), info.as_ptr(), len) }
}

/// Wraps: EVP_PKEY_CTX_add1_tls1_prf_seed
pub fn EVP_PKEY_CTX_add1_tls1_prf_seed(ctx: &mut EvpPkeyCtxMut<'_>, seed: &[u8]) -> i32 {
    let Ok(len) = i32::try_from(seed.len()) else {
        return -1;
    };
    // SAFETY: the exclusive context and readable seed remain live; OpenSSL
    // appends a copy rather than retaining the slice pointer.
    unsafe { ffi::EVP_PKEY_CTX_add1_tls1_prf_seed(ctx.as_mut_ptr(), seed.as_ptr(), len) }
}

/// Wraps: EVP_PKEY_CTX_ctrl
///
/// # Safety
///
/// `operand` must have the command-specific shape, initialization, lifetime,
/// mutability, and ownership contract selected by `command`. Some commands
/// write through it or take ownership, while others only read it.
pub unsafe fn EVP_PKEY_CTX_ctrl(
    ctx: &mut EvpPkeyCtxMut<'_>,
    key_type: i32,
    operation_type: i32,
    command: i32,
    value: i32,
    operand: Option<NonNull<c_void>>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and the remaining untyped
    // command contract is precisely the caller obligation documented above.
    unsafe {
        ffi::EVP_PKEY_CTX_ctrl(
            ctx.as_mut_ptr(),
            key_type,
            operation_type,
            command,
            value,
            operand.map_or(ptr::null_mut(), NonNull::as_ptr),
        )
    }
}

/// Wraps: EVP_PKEY_CTX_ctrl_str
pub fn EVP_PKEY_CTX_ctrl_str(ctx: &mut EvpPkeyCtxMut<'_>, name: &CStr, value: &CStr) -> i32 {
    // SAFETY: the context is exclusive and both NUL-terminated strings remain
    // readable for this synchronous control operation.
    unsafe { ffi::EVP_PKEY_CTX_ctrl_str(ctx.as_mut_ptr(), name.as_ptr(), value.as_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_ctrl_uint64
pub fn EVP_PKEY_CTX_ctrl_uint64(
    ctx: &mut EvpPkeyCtxMut<'_>,
    key_type: i32,
    operation_type: i32,
    command: i32,
    value: u64,
) -> i32 {
    // SAFETY: the exclusive context is live and the scalar is passed by value.
    unsafe {
        ffi::EVP_PKEY_CTX_ctrl_uint64(ctx.as_mut_ptr(), key_type, operation_type, command, value)
    }
}

/// Wraps: EVP_PKEY_CTX_get0_libctx
#[must_use]
pub fn EVP_PKEY_CTX_get0_libctx<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<OsslLibCtxRef<'a>> {
    // SAFETY: the context remains live and its construction contract keeps its
    // borrowed library context alive for at least the same lifetime.
    let raw = unsafe { ffi::EVP_PKEY_CTX_get0_libctx(ctx.as_ptr().cast_mut()) };
    // SAFETY: the returned pointer is null or the context's borrowed libctx.
    unsafe { OsslLibCtxRef::from_ptr(raw) }
}

/// Wraps: EVP_PKEY_CTX_get0_peerkey
#[must_use]
pub fn EVP_PKEY_CTX_get0_peerkey<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<EvpPkeyRef<'a>> {
    // SAFETY: this reads the retained peer-key pointer from a live context.
    let raw = unsafe { ffi::EVP_PKEY_CTX_get0_peerkey(ctx.as_ptr().cast_mut()) };
    // SAFETY: the context retains its key reference for the returned lifetime.
    unsafe { EvpPkeyRef::from_ptr(raw) }
}

/// Wraps: EVP_PKEY_CTX_get0_pkey
#[must_use]
pub fn EVP_PKEY_CTX_get0_pkey<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<EvpPkeyRef<'a>> {
    // SAFETY: this reads the retained key pointer from a live context.
    let raw = unsafe { ffi::EVP_PKEY_CTX_get0_pkey(ctx.as_ptr().cast_mut()) };
    // SAFETY: the context retains its key reference for the returned lifetime.
    unsafe { EvpPkeyRef::from_ptr(raw) }
}

/// Wraps: EVP_PKEY_CTX_get0_propq
#[must_use]
pub fn EVP_PKEY_CTX_get0_propq<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the context is live and owns the optional NUL-terminated property
    // query for its complete lifetime.
    let raw = unsafe { ffi::EVP_PKEY_CTX_get0_propq(ctx.as_ptr()) };
    (!raw.is_null()).then(|| {
        // SAFETY: a non-null result is context-owned and NUL-terminated.
        unsafe { CStr::from_ptr(raw) }
    })
}

/// Wraps: EVP_PKEY_CTX_get0_provider
#[must_use]
pub fn EVP_PKEY_CTX_get0_provider<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<OsslProviderRef<'a>> {
    // SAFETY: the context retains the active operation method and therefore
    // the provider behind the borrowed result.
    let raw = unsafe { ffi::EVP_PKEY_CTX_get0_provider(ctx.as_ptr()) };
    // SAFETY: null means no provider; otherwise the live context keeps it alive.
    unsafe { OsslProviderRef::from_ptr(raw.cast_mut()) }
}

/// Wraps: EVP_PKEY_CTX_get1_id_len
#[must_use]
pub fn EVP_PKEY_CTX_get1_id_len(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<usize>) {
    let mut len = 0usize;
    // SAFETY: the context is exclusive and the local scalar output is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get1_id_len(ctx.as_mut_ptr(), &mut len) };
    (status, (status > 0).then_some(len))
}

/// Wraps: EVP_PKEY_CTX_get1_id
/// Returns an independently owned copy of the context identifier.
pub fn EVP_PKEY_CTX_get1_id(ctx: &mut EvpPkeyCtxMut<'_>) -> Result<Vec<u8>, i32> {
    let (status, len) = EVP_PKEY_CTX_get1_id_len(ctx);
    let Some(len) = len else {
        return Err(status);
    };
    let mut id = vec![0_u8; len];
    // SAFETY: the preceding query reported the stored identifier length and
    // `id` provides exactly that many initialized writable bytes.
    let status = unsafe { ffi::EVP_PKEY_CTX_get1_id(ctx.as_mut_ptr(), id.as_mut_ptr().cast()) };
    if status > 0 { Ok(id) } else { Err(status) }
}

/// Wraps: EVP_PKEY_CTX_get_app_data
#[must_use]
pub fn EVP_PKEY_CTX_get_app_data<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<EvpPkeyCtxData<'a>> {
    // SAFETY: the function only reads the opaque application pointer slot.
    let pointer = unsafe { ffi::EVP_PKEY_CTX_get_app_data(ctx.as_ptr().cast_mut()) };
    NonNull::new(pointer).map(|pointer| EvpPkeyCtxData {
        pointer,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_PKEY_CTX_get_data
#[must_use]
pub fn EVP_PKEY_CTX_get_data<'a>(ctx: EvpPkeyCtxRef<'a>) -> Option<EvpPkeyCtxData<'a>> {
    // SAFETY: the function only reads the opaque legacy-data pointer slot.
    let pointer = unsafe { ffi::EVP_PKEY_CTX_get_data(ctx.as_ptr()) };
    NonNull::new(pointer).map(|pointer| EvpPkeyCtxData {
        pointer,
        borrow: PhantomData,
    })
}

/// Wraps: EVP_PKEY_CTX_get_operation
#[must_use]
pub fn EVP_PKEY_CTX_get_operation(ctx: EvpPkeyCtxRef<'_>) -> i32 {
    // SAFETY: the call only reads the operation discriminator.
    unsafe { ffi::EVP_PKEY_CTX_get_operation(ctx.as_ptr().cast_mut()) }
}

/// Wraps: EVP_PKEY_CTX_get_params
pub fn EVP_PKEY_CTX_get_params(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: &mut OsslParamListMut<'_, '_>,
) -> i32 {
    // SAFETY: the context is exclusive and the list guarantees an initialized,
    // writable, null-key-terminated descriptor run for the synchronous call.
    unsafe { ffi::EVP_PKEY_CTX_get_params(ctx.as_mut_ptr(), params.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_get_signature_md
#[must_use]
pub fn EVP_PKEY_CTX_get_signature_md<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> (i32, Option<EvpMdRef<'a>>) {
    let mut md = ptr::null();
    // SAFETY: the context is exclusive and the pointer output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_signature_md(ctx.as_mut_ptr(), &mut md) };
    // SAFETY: a non-null result is retained by context/provider state for this borrow.
    let md = unsafe { EvpMdRef::from_ptr(md.cast_mut()) };
    (status, (status > 0).then_some(md).flatten())
}

/// Wraps: EVP_PKEY_CTX_gettable_params
#[must_use]
pub fn EVP_PKEY_CTX_gettable_params<'a>(
    ctx: EvpPkeyCtxRef<'a>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the live context returns a provider-owned, initialized,
    // null-key-terminated descriptor array or null.
    let params = unsafe { ffi::EVP_PKEY_CTX_gettable_params(ctx.as_ptr()) };
    // SAFETY: a non-null result follows the terminated-array contract above.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'a>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator, all retained by the context for `'a`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_PKEY_CTX_hex2ctrl
pub fn EVP_PKEY_CTX_hex2ctrl(ctx: &mut EvpPkeyCtxMut<'_>, command: i32, hex: &CStr) -> i32 {
    // SAFETY: the context is exclusive and the NUL-terminated hex input stays live.
    unsafe { ffi::EVP_PKEY_CTX_hex2ctrl(ctx.as_mut_ptr(), command, hex.as_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_is_a
#[must_use]
pub fn EVP_PKEY_CTX_is_a(ctx: EvpPkeyCtxRef<'_>, key_type: &CStr) -> bool {
    // SAFETY: both the shared context and NUL-terminated algorithm name are live.
    unsafe { ffi::EVP_PKEY_CTX_is_a(ctx.as_ptr().cast_mut(), key_type.as_ptr()) == 1 }
}

/// Wraps: EVP_PKEY_CTX_md
pub fn EVP_PKEY_CTX_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    operation_type: i32,
    command: i32,
    digest: &CStr,
) -> i32 {
    // SAFETY: the context is exclusive and the digest name remains readable.
    unsafe { ffi::EVP_PKEY_CTX_md(ctx.as_mut_ptr(), operation_type, command, digest.as_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_new
#[must_use]
pub fn EVP_PKEY_CTX_new<'a>(pkey: EvpPkeyRef<'a>) -> Option<BorrowedEvpPkeyCtx<'a>> {
    // SAFETY: null is the required ENGINE argument. OpenSSL raises a retained
    // key reference, and a non-null result transfers one context ownership.
    let raw = unsafe { ffi::EVP_PKEY_CTX_new(pkey.as_ptr().cast_mut(), ptr::null_mut()) };
    // SAFETY: the result is tied to the key borrow, conservatively covering the
    // library-context dependency behind provider-backed key material.
    unsafe { BorrowedEvpPkeyCtx::from_raw(raw) }
}

/// Wraps: EVP_PKEY_CTX_new_from_name
#[must_use]
pub fn EVP_PKEY_CTX_new_from_name<'a>(
    library_context: Option<OsslLibCtxRef<'a>>,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<BorrowedEvpPkeyCtx<'a>> {
    let library_context =
        library_context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: all pointers are null or backed by the corresponding live
    // borrows; a non-null result transfers one initialized context.
    let raw =
        unsafe { ffi::EVP_PKEY_CTX_new_from_name(library_context, name.as_ptr(), properties) };
    // SAFETY: the owner carries the selected library-context lifetime.
    unsafe { BorrowedEvpPkeyCtx::from_raw(raw) }
}

/// Wraps: EVP_PKEY_CTX_new_from_pkey
#[must_use]
pub fn EVP_PKEY_CTX_new_from_pkey<'a>(
    library_context: Option<OsslLibCtxRef<'a>>,
    pkey: EvpPkeyRef<'a>,
    properties: Option<&CStr>,
) -> Option<BorrowedEvpPkeyCtx<'a>> {
    let library_context =
        library_context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the optional context, key, and property query are live. OpenSSL
    // raises its own key reference and returns a separately owned context.
    let raw = unsafe {
        ffi::EVP_PKEY_CTX_new_from_pkey(library_context, pkey.as_ptr().cast_mut(), properties)
    };
    // SAFETY: `'a` covers both possible sources of provider-context dependency.
    unsafe { BorrowedEvpPkeyCtx::from_raw(raw) }
}

/// Wraps: EVP_PKEY_CTX_new_id
#[must_use]
pub fn EVP_PKEY_CTX_new_id(id: i32) -> Option<CBox<EvpPkeyCtx>> {
    // SAFETY: null is the required ENGINE argument; a non-null return transfers
    // one fully initialized, default-context operation context.
    let raw = unsafe { ffi::EVP_PKEY_CTX_new_id(id, ptr::null_mut()) };
    // SAFETY: a non-null result carries exactly one EVP_PKEY_CTX_free obligation.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_CTX_set0_keygen_info
///
/// # Safety
///
/// OpenSSL stores `data` without copying it. The array must remain allocated
/// and exclusively available to the context until this function is called
/// again with `None` or the context is destroyed.
pub unsafe fn EVP_PKEY_CTX_set0_keygen_info(
    ctx: &mut EvpPkeyCtxMut<'_>,
    data: Option<&mut [i32]>,
) -> bool {
    let len = data.as_ref().map_or(0, |data| data.len());
    let Ok(len) = i32::try_from(len) else {
        return false;
    };
    let data = data.map_or(ptr::null_mut(), <[i32]>::as_mut_ptr);
    // SAFETY: the exclusive context and stored-array obligation are supplied
    // by the caller; null with zero length clears the stored run.
    unsafe { ffi::EVP_PKEY_CTX_set0_keygen_info(ctx.as_mut_ptr(), data, len) };
    true
}

/// Wraps: EVP_PKEY_CTX_set1_hkdf_key
pub fn EVP_PKEY_CTX_set1_hkdf_key(ctx: &mut EvpPkeyCtxMut<'_>, key: &[u8]) -> i32 {
    let Ok(len) = i32::try_from(key.len()) else {
        return -1;
    };
    // SAFETY: the exclusive context is live and OpenSSL copies the input bytes.
    unsafe { ffi::EVP_PKEY_CTX_set1_hkdf_key(ctx.as_mut_ptr(), key.as_ptr(), len) }
}

/// Wraps: EVP_PKEY_CTX_set1_hkdf_salt
pub fn EVP_PKEY_CTX_set1_hkdf_salt(ctx: &mut EvpPkeyCtxMut<'_>, salt: &[u8]) -> i32 {
    let Ok(len) = i32::try_from(salt.len()) else {
        return -1;
    };
    // SAFETY: the exclusive context is live and OpenSSL copies the salt bytes.
    unsafe { ffi::EVP_PKEY_CTX_set1_hkdf_salt(ctx.as_mut_ptr(), salt.as_ptr(), len) }
}

/// Wraps: EVP_PKEY_CTX_set1_id
pub fn EVP_PKEY_CTX_set1_id(ctx: &mut EvpPkeyCtxMut<'_>, id: &[u8]) -> i32 {
    let Ok(len) = i32::try_from(id.len()) else {
        return -1;
    };
    // SAFETY: the context is exclusive and OpenSSL copies the identifier bytes.
    unsafe { ffi::EVP_PKEY_CTX_set1_id(ctx.as_mut_ptr(), id.as_ptr().cast::<c_void>(), len) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_N
pub fn EVP_PKEY_CTX_set_scrypt_N(ctx: &mut EvpPkeyCtxMut<'_>, n: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context; the scalar is
    // copied into provider or legacy operation state before the call returns.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_N(ctx.as_mut_ptr(), n) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_maxmem_bytes
pub fn EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: &mut EvpPkeyCtxMut<'_>, maxmem_bytes: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context and OpenSSL copies
    // the scalar value synchronously.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx.as_mut_ptr(), maxmem_bytes) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_p
pub fn EVP_PKEY_CTX_set_scrypt_p(ctx: &mut EvpPkeyCtxMut<'_>, p: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context and OpenSSL copies
    // the scalar value synchronously.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_p(ctx.as_mut_ptr(), p) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_r
pub fn EVP_PKEY_CTX_set_scrypt_r(ctx: &mut EvpPkeyCtxMut<'_>, r: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context and OpenSSL copies
    // the scalar value synchronously.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_r(ctx.as_mut_ptr(), r) }
}

fn md_ptr(md: Option<EvpMdRef<'static>>) -> *const ffi::evp_md_st {
    md.map_or(core::ptr::null(), |md| md.as_ptr())
}

/// Wraps: EVP_PKEY_CTX_set_signature_md
///
/// A legacy operation may retain the digest pointer without raising its
/// reference count, so the safe surface accepts only an immortal digest
/// implementation. `None` selects OpenSSL's documented empty digest value.
pub fn EVP_PKEY_CTX_set_signature_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    md: Option<EvpMdRef<'static>>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and a non-null digest is
    // live for the rest of the process, covering both provider copying and a
    // legacy method retaining the pointer.
    unsafe { ffi::EVP_PKEY_CTX_set_signature_md(ctx.as_mut_ptr(), md_ptr(md)) }
}

/// Wraps: EVP_PKEY_CTX_set_tls1_prf_md
///
/// A legacy operation may retain the digest pointer without raising its
/// reference count, so the safe surface accepts only an immortal digest
/// implementation. `None` selects OpenSSL's documented empty digest value.
pub fn EVP_PKEY_CTX_set_tls1_prf_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    md: Option<EvpMdRef<'static>>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and a non-null digest is
    // immortal, satisfying either a synchronous provider copy or a retained
    // legacy pointer.
    unsafe { ffi::EVP_PKEY_CTX_set_tls1_prf_md(ctx.as_mut_ptr(), md_ptr(md)) }
}

/// Wraps: EVP_PKEY_CTX_settable_params
///
/// Borrows the provider's null-key-terminated table of accepted descriptors.
#[must_use]
pub fn EVP_PKEY_CTX_settable_params<'a>(
    ctx: EvpPkeyCtxRef<'a>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the shared context handle is live; OpenSSL returns null or a
    // provider-owned terminated descriptor table retained by context state.
    let raw = unsafe { ffi::EVP_PKEY_CTX_settable_params(ctx.as_ptr()) };
    let start = NonNull::new(raw.cast_mut().cast::<OsslParam<'a>>())?;
    // SAFETY: the public return contract promises a reachable null-key
    // terminator on every non-null result.
    let len = unsafe { terminated_param_len(raw) }?;
    // SAFETY: the scan established exactly `len` initialized descriptors, and
    // their provider storage remains live for the context handle's lifetime.
    unsafe { Some(CSlice::from_raw_parts(start, len)) }
}

/// Wraps: EVP_PKEY_CTX_str2ctrl
pub fn EVP_PKEY_CTX_str2ctrl(ctx: &mut EvpPkeyCtxMut<'_>, command: i32, value: &CStr) -> i32 {
    // SAFETY: the exclusive context and NUL-terminated string remain live for
    // the synchronous legacy control operation.
    unsafe { ffi::EVP_PKEY_CTX_str2ctrl(ctx.as_mut_ptr(), command, value.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(name: &CStr) -> BorrowedEvpPkeyCtx<'static> {
        EVP_PKEY_CTX_new_from_name(None, name, None).expect("EVP_PKEY_CTX_new_from_name")
    }

    fn rsa_context() -> BorrowedEvpPkeyCtx<'static> {
        context(c"RSA")
    }

    #[test]
    fn scrypt_scalars_use_an_exclusive_context() {
        let mut ctx = context(c"SCRYPT");
        // SAFETY: the context is live and exclusively borrowed; derive-init
        // initializes its provider operation state before the setters run.
        let status = unsafe { ffi::EVP_PKEY_derive_init(ctx.as_mut().as_mut_ptr()) };
        assert_eq!(status, 1);
        let mut ctx = ctx.as_mut();
        assert_eq!(EVP_PKEY_CTX_set_scrypt_N(&mut ctx, 1024), 1);
        assert_eq!(EVP_PKEY_CTX_set_scrypt_r(&mut ctx, 8), 1);
        assert_eq!(EVP_PKEY_CTX_set_scrypt_p(&mut ctx, 1), 1);
        assert_eq!(
            EVP_PKEY_CTX_set_scrypt_maxmem_bytes(&mut ctx, 1024 * 1024),
            1
        );
        assert!(EVP_PKEY_CTX_settable_params(ctx.as_ref()).is_some());
    }

    #[test]
    fn nullable_digest_and_string_control_are_typed() {
        let mut ctx = context(c"RSA");
        let mut ctx = ctx.as_mut();
        assert!(EVP_PKEY_CTX_set_signature_md(&mut ctx, None) <= 0);
        assert!(EVP_PKEY_CTX_set_tls1_prf_md(&mut ctx, None) <= 0);
        assert!(EVP_PKEY_CTX_str2ctrl(&mut ctx, 0, c"value") <= 0);
    }

    #[test]
    fn constructors_and_borrowed_getters_are_typed() {
        let mut context = rsa_context();
        assert!(EVP_PKEY_CTX_is_a(context.as_ref(), c"RSA"));
        assert!(EVP_PKEY_CTX_get0_libctx(context.as_ref()).is_none());
        assert_eq!(EVP_PKEY_CTX_get_operation(context.as_ref()), 0);
        assert!(EVP_PKEY_CTX_get0_pkey(context.as_ref()).is_none());
        assert!(EVP_PKEY_CTX_get0_peerkey(context.as_ref()).is_none());
        assert!(EVP_PKEY_CTX_get_app_data(context.as_ref()).is_none());
        assert!(EVP_PKEY_CTX_get_data(context.as_ref()).is_none());
        let mut handle = context.as_mut();
        assert!(EVP_PKEY_CTX_set1_id(&mut handle, b"id") <= 1);
    }

    #[test]
    fn control_strings_use_cstrs() {
        let mut context = rsa_context();
        let mut handle = context.as_mut();
        let status = EVP_PKEY_CTX_ctrl_str(&mut handle, c"rsa_padding_mode", c"pkcs1");
        assert!(status <= 1);
    }
}

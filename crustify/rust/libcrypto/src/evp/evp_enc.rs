//! Wrappers assigned from `crypto/evp/evp_enc.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_int, c_void};
use core::ptr::{self, NonNull};
use std::any::Any;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::vec::Vec;

use ffibox::{CBox, CSlice};
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{
    OsslParam, OsslParamListMut, OsslParamListRef, terminated_param_len,
};
use crate::evp::evp::{EvpCipherRef, EvpSkeyRef, SharedEvpCipher};
use crate::evp::evp_lib::{
    EVP_CIPHER_CTX_get_block_size, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length,
};
use crate::evp::evp_local::{BorrowedEvpCipherCtx, EvpCipherCtx, EvpCipherCtxMut, EvpCipherCtxRef};

fn optional_cstr(value: Option<&CStr>) -> *const core::ffi::c_char {
    value.map_or(ptr::null(), CStr::as_ptr)
}

unsafe fn cipher_params<'ctx>(
    params: *const ffi::OSSL_PARAM,
) -> Option<CSlice<'ctx, OsslParam<'ctx>>> {
    // SAFETY: the caller supplies a provider-owned, null-key-terminated table.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'ctx>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the caller supplies the lifetime retaining the provider.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_CIPHER_CTX_copy
/// Creates an independent context while retaining the source's dependencies.
#[must_use]
pub fn EVP_CIPHER_CTX_copy<'a>(source: EvpCipherCtxRef<'a>) -> Option<BorrowedEvpCipherCtx<'a>> {
    // SAFETY: OpenSSL returns null or fresh empty context storage.
    let raw = unsafe { ffi::EVP_CIPHER_CTX_new() };
    // SAFETY: a non-null fresh result transfers one free obligation.
    let output = unsafe { CBox::<EvpCipherCtx>::from_raw(raw) }?;
    // SAFETY: `output` is exclusively owned, `source` is live, and the C copy
    // either leaves a reusable context or installs independently owned state.
    if unsafe { ffi::EVP_CIPHER_CTX_copy(output.as_ptr(), source.as_ptr()) } != 1 {
        return None;
    }
    let raw = output.into_raw();
    // SAFETY: successful copy produced a complete context whose copied
    // non-owning pointers remain bounded by `source`'s lifetime.
    unsafe { BorrowedEvpCipherCtx::from_raw(raw) }
}

/// Wraps: EVP_CIPHER_CTX_ctrl
/// Invokes the legacy type-erased control interface.
///
/// # Safety
///
/// `data` must have the direction, layout, initialization, and byte extent
/// required by `control` and `argument`, and it must remain valid for the
/// complete synchronous call.
pub unsafe fn EVP_CIPHER_CTX_ctrl(
    ctx: &mut EvpCipherCtxMut<'_>,
    control: c_int,
    argument: c_int,
    data: Option<NonNull<c_void>>,
) -> c_int {
    // SAFETY: the exclusive context is live; the remaining control-specific
    // pointer contract is the caller obligation stated above.
    unsafe {
        ffi::EVP_CIPHER_CTX_ctrl(
            ctx.as_mut_ptr(),
            control,
            argument,
            data.map_or(ptr::null_mut(), NonNull::as_ptr),
        )
    }
}

/// Wraps: EVP_CIPHER_CTX_dup
#[must_use]
pub fn EVP_CIPHER_CTX_dup<'a>(ctx: EvpCipherCtxRef<'a>) -> Option<BorrowedEvpCipherCtx<'a>> {
    ctx.try_dup()
}

/// Wraps: EVP_CIPHER_CTX_free
/// Explicitly releases a uniquely owned cipher context.
pub fn EVP_CIPHER_CTX_free(ctx: CBox<EvpCipherCtx>) {
    drop(ctx);
}

/// Wraps: EVP_CIPHER_CTX_get_params
pub fn EVP_CIPHER_CTX_get_params(
    ctx: &mut EvpCipherCtxMut<'_>,
    params: &mut OsslParamListMut<'_, '_>,
) -> c_int {
    // SAFETY: both values are exclusively borrowed and the list is validated
    // through its reachable terminator.
    unsafe { ffi::EVP_CIPHER_CTX_get_params(ctx.as_mut_ptr(), params.as_mut_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_gettable_params
#[must_use]
pub fn EVP_CIPHER_CTX_gettable_params<'a>(
    ctx: &'a mut EvpCipherCtxMut<'_>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the exclusive reborrow keeps the context/provider live while C
    // selects its constant advertised parameter table.
    let params = unsafe { ffi::EVP_CIPHER_CTX_gettable_params(ctx.as_mut_ptr()) };
    // SAFETY: a non-null result is a provider-owned terminated table retained
    // by the context for this reborrow.
    unsafe { cipher_params(params) }
}

/// Wraps: EVP_CIPHER_CTX_new
#[must_use]
pub fn EVP_CIPHER_CTX_new() -> Option<CBox<EvpCipherCtx>> {
    // SAFETY: a non-null result is fresh initialized context storage with one
    // matching `EVP_CIPHER_CTX_free` obligation.
    unsafe { CBox::from_raw(ffi::EVP_CIPHER_CTX_new()) }
}

/// Wraps: EVP_CIPHER_CTX_rand_key
/// Fills `key` only when it is large enough for the active cipher.
pub fn EVP_CIPHER_CTX_rand_key(ctx: &mut EvpCipherCtxMut<'_>, key: &mut [u8]) -> c_int {
    // The safe metadata query retains no pointer.
    let required = EVP_CIPHER_CTX_get_key_length(ctx.as_ref());
    if required < 0 || usize::try_from(required).map_or(true, |len| key.len() < len) {
        return 0;
    }
    // SAFETY: the preceding query established the number of bytes C writes,
    // and `key` supplies at least that much writable storage.
    unsafe { ffi::EVP_CIPHER_CTX_rand_key(ctx.as_mut_ptr(), key.as_mut_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_reset
pub fn EVP_CIPHER_CTX_reset(ctx: &mut EvpCipherCtxMut<'_>) -> c_int {
    // SAFETY: exclusive access permits disposing all retained state in place.
    unsafe { ffi::EVP_CIPHER_CTX_reset(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_set_key_length
pub fn EVP_CIPHER_CTX_set_key_length(ctx: &mut EvpCipherCtxMut<'_>, length: c_int) -> c_int {
    // SAFETY: the context is exclusively borrowed; the scalar is passed by value.
    unsafe { ffi::EVP_CIPHER_CTX_set_key_length(ctx.as_mut_ptr(), length) }
}

/// Wraps: EVP_CIPHER_CTX_set_padding
pub fn EVP_CIPHER_CTX_set_padding(ctx: &mut EvpCipherCtxMut<'_>, padding: bool) -> c_int {
    // SAFETY: the context is exclusively borrowed and C normalizes the flag.
    unsafe { ffi::EVP_CIPHER_CTX_set_padding(ctx.as_mut_ptr(), c_int::from(padding)) }
}

/// Wraps: EVP_CIPHER_CTX_set_params
pub fn EVP_CIPHER_CTX_set_params(
    ctx: &mut EvpCipherCtxMut<'_>,
    params: &OsslParamListRef<'_, '_>,
) -> c_int {
    // SAFETY: the context is exclusive and the read-only list is validated
    // through its terminator; all descriptor data borrows cover the call.
    unsafe { ffi::EVP_CIPHER_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_settable_params
#[must_use]
pub fn EVP_CIPHER_CTX_settable_params<'a>(
    ctx: &'a mut EvpCipherCtxMut<'_>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the exclusive reborrow retains the active provider.
    let params = unsafe { ffi::EVP_CIPHER_CTX_settable_params(ctx.as_mut_ptr()) };
    // SAFETY: a non-null result is a provider-owned terminated table retained
    // by the context for this reborrow.
    unsafe { cipher_params(params) }
}

/// Wraps: EVP_CIPHER_can_pipeline
#[must_use]
pub fn EVP_CIPHER_can_pipeline(cipher: EvpCipherRef<'_>, encrypt: bool) -> bool {
    // SAFETY: the cipher handle is live and only its immutable dispatch table
    // is inspected.
    unsafe { ffi::EVP_CIPHER_can_pipeline(cipher.as_ptr(), c_int::from(encrypt)) == 1 }
}

struct CallbackContext<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
    valid: bool,
}

/// Wraps: EVP_CIPHER_do_all_provided
/// Synchronously visits ciphers activated in the selected library context.
pub fn EVP_CIPHER_do_all_provided<F>(libctx: Option<OsslLibCtxRef<'_>>, callback: &mut F) -> bool
where
    F: for<'cipher> FnMut(EvpCipherRef<'cipher>),
{
    unsafe extern "C" fn trampoline<F>(cipher: *mut ffi::EVP_CIPHER, arg: *mut c_void)
    where
        F: for<'cipher> FnMut(EvpCipherRef<'cipher>),
    {
        // SAFETY: the outer call passes this exact uniquely borrowed state.
        let context = unsafe { &mut *arg.cast::<CallbackContext<'_, F>>() };
        if context.panic.is_some() {
            return;
        }
        // SAFETY: OpenSSL supplies a live cipher for this callback invocation.
        let Some(cipher) = (unsafe { EvpCipherRef::from_ptr(cipher) }) else {
            context.valid = false;
            return;
        };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (context.callback)(cipher))) {
            context.panic = Some(panic);
        }
    }

    let mut context = CallbackContext {
        callback,
        panic: None,
        valid: true,
    };
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the optional context and trampoline state remain live and C does
    // not retain the callback after this synchronous traversal.
    unsafe {
        ffi::EVP_CIPHER_do_all_provided(
            libctx,
            Some(trampoline::<F>),
            core::ptr::from_mut(&mut context).cast(),
        );
    }
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
    context.valid
}

/// Wraps: EVP_CIPHER_fetch
#[must_use]
pub fn EVP_CIPHER_fetch<'a>(
    libctx: Option<OsslLibCtxRef<'a>>,
    algorithm: &CStr,
    properties: Option<&CStr>,
) -> Option<SharedEvpCipher<'a>> {
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: context and strings are null or live for the synchronous fetch.
    let cipher =
        unsafe { ffi::EVP_CIPHER_fetch(libctx, algorithm.as_ptr(), optional_cstr(properties)) };
    // SAFETY: a non-null result transfers one public cipher reference and the
    // lifetime retains an explicitly supplied library context.
    unsafe { SharedEvpCipher::from_raw(cipher) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_empty_context_resets_and_rejects_duplication() {
        let mut context = EVP_CIPHER_CTX_new().expect("cipher context");
        assert!(EVP_CIPHER_CTX_dup(context.as_ref()).is_none());
        assert_eq!(EVP_CIPHER_CTX_reset(&mut context.as_mut()), 1);
    }

    #[test]
    fn fetch_metadata_and_provider_enumeration_are_typed() {
        let cipher = EVP_CIPHER_fetch(None, c"AES-128-CBC", None).expect("cipher");
        let _pipeline_capable = super::EVP_CIPHER_can_pipeline(cipher.as_ref(), true);
        let mut count = 0usize;
        assert!(EVP_CIPHER_do_all_provided(None, &mut |_| count += 1));
        assert!(count > 0);
    }
}

fn cipher_ptr(cipher: Option<EvpCipherRef<'_>>) -> *const ffi::evp_cipher_st {
    cipher.map_or(ptr::null(), |cipher| cipher.as_ptr())
}

fn bytes_ptr(bytes: Option<&[u8]>) -> *const u8 {
    bytes.map_or(ptr::null(), <[u8]>::as_ptr)
}

fn params_ptr(params: Option<&OsslParamListRef<'_, '_>>) -> *const ffi::ossl_param_st {
    params.map_or(ptr::null(), OsslParamListRef::as_ptr)
}

fn params_change_lengths(params: Option<&OsslParamListRef<'_, '_>>) -> bool {
    params.is_some_and(|params| {
        params.values().iter().any(|param| {
            param
                .key()
                .is_some_and(|key| key == c"keylen" || key == c"ivlen")
        })
    })
}

fn expected_lengths(ctx: &EvpCipherCtxMut<'_>, cipher: Option<EvpCipherRef<'_>>) -> (i32, i32) {
    cipher.map_or_else(
        || {
            (
                EVP_CIPHER_CTX_get_key_length(ctx.as_ref()),
                EVP_CIPHER_CTX_get_iv_length(ctx.as_ref()),
            )
        },
        |cipher| {
            (
                EVP_CIPHER_get_key_length(cipher),
                EVP_CIPHER_get_iv_length(cipher),
            )
        },
    )
}

fn init_buffers_fit(
    ctx: &EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> bool {
    let (key_len, iv_len) = expected_lengths(ctx, cipher);
    key.is_none_or(|key| key_len >= 0 && key.len() >= key_len as usize)
        && iv.is_none_or(|iv| iv_len >= 0 && iv.len() >= iv_len as usize)
}

fn block_size(ctx: &EvpCipherCtxMut<'_>) -> Option<usize> {
    // SAFETY: the context handle is live and the getter retains nothing.
    let size = EVP_CIPHER_CTX_get_block_size(ctx.as_ref());
    usize::try_from(size).ok().filter(|size| *size != 0)
}

fn update_capacity(ctx: &EvpCipherCtxMut<'_>, input_len: usize) -> Option<usize> {
    let block = block_size(ctx)?;
    input_len.checked_add(if block == 1 { 0 } else { block })
}

fn final_capacity(ctx: &EvpCipherCtxMut<'_>) -> Option<usize> {
    block_size(ctx).map(|block| if block == 1 { 0 } else { block })
}

fn checked_update(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
    call: unsafe extern "C" fn(
        *mut ffi::evp_cipher_ctx_st,
        *mut u8,
        *mut i32,
        *const u8,
        i32,
    ) -> i32,
) -> Result<usize, i32> {
    let input_len = i32::try_from(input.len()).map_err(|_| 0)?;
    let required = update_capacity(ctx, input.len()).ok_or(0)?;
    if output.len() < required {
        return Err(0);
    }
    let output = output.as_mut_ptr();
    let mut written = 0;
    // SAFETY: the exclusive context is live; `input` supplies the exact
    // readable extent, and the output has the C routine's documented worst-case capacity.
    let status = unsafe {
        call(
            ctx.as_mut_ptr(),
            output,
            &mut written,
            input.as_ptr(),
            input_len,
        )
    };
    if status <= 0 {
        return Err(status);
    }
    usize::try_from(written)
        .ok()
        .filter(|written| *written <= required)
        .ok_or(0)
}

fn checked_final(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    call: unsafe extern "C" fn(*mut ffi::evp_cipher_ctx_st, *mut u8, *mut i32) -> i32,
) -> Result<usize, i32> {
    let required = final_capacity(ctx).ok_or(0)?;
    if output.len() < required {
        return Err(0);
    }
    let mut written = 0;
    // SAFETY: the exclusive context is live and `output` has at least the
    // maximum final block capacity derived from that context.
    let status = unsafe { call(ctx.as_mut_ptr(), output.as_mut_ptr(), &mut written) };
    if status <= 0 {
        return Err(status);
    }
    usize::try_from(written)
        .ok()
        .filter(|written| *written <= output.len())
        .ok_or(0)
}

/// Wraps: EVP_CIPHER_get_params
/// Fills a validated, terminated parameter descriptor list.
pub fn EVP_CIPHER_get_params(
    cipher: Option<EvpCipherRef<'_>>,
    params: &mut OsslParamListMut<'_, '_>,
) -> i32 {
    // SAFETY: the optional cipher is live, and the exclusive parameter list is
    // initialized, terminated, and writable throughout the synchronous call.
    unsafe { ffi::EVP_CIPHER_get_params(cipher_ptr(cipher).cast_mut(), params.as_mut_ptr()) }
}

/// Wraps: EVP_CIPHER_gettable_ctx_params
#[must_use]
pub fn EVP_CIPHER_gettable_ctx_params<'cipher>(
    cipher: Option<EvpCipherRef<'cipher>>,
) -> Option<ffibox::CSlice<'cipher, crate::core::openssl_core::OsslParam<'cipher>>> {
    // SAFETY: a live cipher retains its provider and dispatch table; null is
    // explicitly accepted. A non-null result is provider-owned and terminated.
    let params = unsafe { ffi::EVP_CIPHER_gettable_ctx_params(cipher_ptr(cipher)) };
    // SAFETY: the result's storage is retained by the cipher/provider borrow.
    unsafe { cipher_params(params) }
}

/// Wraps: EVP_CIPHER_gettable_params
#[must_use]
pub fn EVP_CIPHER_gettable_params<'cipher>(
    cipher: Option<EvpCipherRef<'cipher>>,
) -> Option<ffibox::CSlice<'cipher, crate::core::openssl_core::OsslParam<'cipher>>> {
    // SAFETY: as `EVP_CIPHER_gettable_ctx_params`.
    let params = unsafe { ffi::EVP_CIPHER_gettable_params(cipher_ptr(cipher)) };
    // SAFETY: the result's storage is retained by the cipher/provider borrow.
    unsafe { cipher_params(params) }
}

/// Wraps: EVP_CIPHER_settable_ctx_params
#[must_use]
pub fn EVP_CIPHER_settable_ctx_params<'cipher>(
    cipher: Option<EvpCipherRef<'cipher>>,
) -> Option<ffibox::CSlice<'cipher, crate::core::openssl_core::OsslParam<'cipher>>> {
    // SAFETY: as `EVP_CIPHER_gettable_ctx_params`.
    let params = unsafe { ffi::EVP_CIPHER_settable_ctx_params(cipher_ptr(cipher)) };
    // SAFETY: the result's storage is retained by the cipher/provider borrow.
    unsafe { cipher_params(params) }
}

/// Direction requested by the generic cipher initializer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CipherDirection {
    Encrypt,
    Decrypt,
    Unchanged,
}

impl CipherDirection {
    const fn as_c_int(self) -> i32 {
        match self {
            Self::Encrypt => 1,
            Self::Decrypt => 0,
            Self::Unchanged => -1,
        }
    }
}

/// Wraps: EVP_CipherInit
pub fn EVP_CipherInit(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    direction: CipherDirection,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv) {
        return 0;
    }
    // SAFETY: the exclusive context and all optional borrows are live. Length
    // checks cover the implicit key and IV extents; OpenSSL retains neither
    // byte buffer and raises any cipher reference stored in the context.
    unsafe {
        ffi::EVP_CipherInit(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            bytes_ptr(key),
            bytes_ptr(iv),
            direction.as_c_int(),
        )
    }
}

/// Wraps: EVP_CipherInit_ex
/// The legacy ENGINE argument is intentionally omitted because this build only accepts null.
pub fn EVP_CipherInit_ex(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    direction: CipherDirection,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv) {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit`; null is the only supported ENGINE value.
    unsafe {
        ffi::EVP_CipherInit_ex(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            ptr::null_mut(),
            bytes_ptr(key),
            bytes_ptr(iv),
            direction.as_c_int(),
        )
    }
}

/// Wraps: EVP_CipherInit_ex2
/// Key and IV slices are rejected only when the parameter list changes their implicit extents.
pub fn EVP_CipherInit_ex2(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
    direction: CipherDirection,
) -> i32 {
    if (params_change_lengths(params) && (key.is_some() || iv.is_some()))
        || !init_buffers_fit(ctx, cipher, key, iv)
    {
        return 0;
    }
    // SAFETY: all handles and the optional terminated list remain live for the
    // synchronous call. The byte runs meet the currently selected cipher's
    // published lengths; callers changing those lengths initialize in stages.
    unsafe {
        ffi::EVP_CipherInit_ex2(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            bytes_ptr(key),
            bytes_ptr(iv),
            direction.as_c_int(),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_CipherInit_SKEY
pub fn EVP_CipherInit_SKEY(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<EvpSkeyRef<'_>>,
    iv: Option<&[u8]>,
    direction: CipherDirection,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    let key = key.map_or(ptr::null_mut(), |key| key.as_ptr().cast_mut());
    let (iv, iv_len) = iv.map_or((ptr::null(), 0), |iv| (iv.as_ptr(), iv.len()));
    // SAFETY: all typed handles, the explicitly sized IV, and the optional
    // terminated parameter list remain live for the synchronous provider init.
    unsafe {
        ffi::EVP_CipherInit_SKEY(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            key,
            iv,
            iv_len,
            direction.as_c_int(),
            params_ptr(params),
        )
    }
}

/// An exclusively borrowed cipher context initialized for a fixed pipe count.
pub struct CipherPipeline<'ctx, 'context> {
    ctx: &'ctx mut EvpCipherCtxMut<'context>,
    pipes: usize,
}

fn pipeline_init<'ctx, 'context>(
    ctx: &'ctx mut EvpCipherCtxMut<'context>,
    cipher: Option<EvpCipherRef<'_>>,
    key: &[u8],
    ivs: &[&[u8]],
    call: unsafe extern "C" fn(
        *mut ffi::evp_cipher_ctx_st,
        *const ffi::evp_cipher_st,
        *const u8,
        usize,
        usize,
        *mut *const u8,
        usize,
    ) -> i32,
) -> Result<CipherPipeline<'ctx, 'context>, i32> {
    let iv_len = ivs.first().map_or(0, |iv| iv.len());
    if ivs.iter().any(|iv| iv.len() != iv_len) {
        return Err(0);
    }
    let mut iv_ptrs: Vec<*const u8> = ivs.iter().map(|iv| iv.as_ptr()).collect();
    // SAFETY: the exclusive context and optional cipher are live. `key` and
    // every IV provide the exact extents passed alongside their pointer arrays;
    // all are consumed synchronously and the pipe count equals the array length.
    let status = unsafe {
        call(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            key.as_ptr(),
            key.len(),
            ivs.len(),
            iv_ptrs.as_mut_ptr(),
            iv_len,
        )
    };
    if status <= 0 {
        Err(status)
    } else {
        Ok(CipherPipeline {
            ctx,
            pipes: ivs.len(),
        })
    }
}

/// Wraps: EVP_CipherPipelineDecryptInit
pub fn EVP_CipherPipelineDecryptInit<'ctx, 'context>(
    ctx: &'ctx mut EvpCipherCtxMut<'context>,
    cipher: Option<EvpCipherRef<'_>>,
    key: &[u8],
    ivs: &[&[u8]],
) -> Result<CipherPipeline<'ctx, 'context>, i32> {
    pipeline_init(ctx, cipher, key, ivs, ffi::EVP_CipherPipelineDecryptInit)
}

/// Wraps: EVP_CipherPipelineEncryptInit
pub fn EVP_CipherPipelineEncryptInit<'ctx, 'context>(
    ctx: &'ctx mut EvpCipherCtxMut<'context>,
    cipher: Option<EvpCipherRef<'_>>,
    key: &[u8],
    ivs: &[&[u8]],
) -> Result<CipherPipeline<'ctx, 'context>, i32> {
    pipeline_init(ctx, cipher, key, ivs, ffi::EVP_CipherPipelineEncryptInit)
}

/// Wraps: EVP_CipherPipelineUpdate
pub fn EVP_CipherPipelineUpdate(
    pipeline: &mut CipherPipeline<'_, '_>,
    outputs: &mut [&mut [u8]],
    inputs: &[&[u8]],
) -> Result<Vec<usize>, i32> {
    if outputs.len() != pipeline.pipes || inputs.len() != pipeline.pipes {
        return Err(0);
    }
    let mut output_ptrs: Vec<*mut u8> = outputs.iter_mut().map(|out| out.as_mut_ptr()).collect();
    let output_sizes: Vec<usize> = outputs.iter().map(|out| out.len()).collect();
    let mut input_ptrs: Vec<*const u8> = inputs.iter().map(|input| input.as_ptr()).collect();
    let input_sizes: Vec<usize> = inputs.iter().map(|input| input.len()).collect();
    let mut written = vec![0; pipeline.pipes];
    // SAFETY: each pointer array has exactly the pipe count captured by the
    // exclusive initialization token, and every pointee has its corresponding
    // readable or writable extent in the sibling size array.
    let status = unsafe {
        ffi::EVP_CipherPipelineUpdate(
            pipeline.ctx.as_mut_ptr(),
            output_ptrs.as_mut_ptr(),
            written.as_mut_ptr(),
            output_sizes.as_ptr(),
            input_ptrs.as_mut_ptr(),
            input_sizes.as_ptr(),
        )
    };
    if status <= 0 || written.iter().zip(&output_sizes).any(|(n, cap)| n > cap) {
        Err(status.min(0))
    } else {
        Ok(written)
    }
}

/// Wraps: EVP_CipherPipelineFinal
pub fn EVP_CipherPipelineFinal(
    pipeline: &mut CipherPipeline<'_, '_>,
    outputs: &mut [&mut [u8]],
) -> Result<Vec<usize>, i32> {
    if outputs.len() != pipeline.pipes {
        return Err(0);
    }
    let mut output_ptrs: Vec<*mut u8> = outputs.iter_mut().map(|out| out.as_mut_ptr()).collect();
    let output_sizes: Vec<usize> = outputs.iter().map(|out| out.len()).collect();
    let mut written = vec![0; pipeline.pipes];
    // SAFETY: the exclusive pipeline token fixes the pointer-array count, and
    // every output has its exact writable extent in `output_sizes`.
    let status = unsafe {
        ffi::EVP_CipherPipelineFinal(
            pipeline.ctx.as_mut_ptr(),
            output_ptrs.as_mut_ptr(),
            written.as_mut_ptr(),
            output_sizes.as_ptr(),
        )
    };
    if status <= 0 || written.iter().zip(&output_sizes).any(|(n, cap)| n > cap) {
        Err(status.min(0))
    } else {
        Ok(written)
    }
}

/// Wraps: EVP_CipherUpdate
pub fn EVP_CipherUpdate(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
) -> Result<usize, i32> {
    checked_update(ctx, output, input, ffi::EVP_CipherUpdate)
}

/// Wraps: EVP_EncryptUpdate
pub fn EVP_EncryptUpdate(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
) -> Result<usize, i32> {
    checked_update(ctx, output, input, ffi::EVP_EncryptUpdate)
}

/// Wraps: EVP_DecryptUpdate
pub fn EVP_DecryptUpdate(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
) -> Result<usize, i32> {
    checked_update(ctx, output, input, ffi::EVP_DecryptUpdate)
}

/// Wraps: EVP_CipherFinal
pub fn EVP_CipherFinal(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_CipherFinal)
}

/// Wraps: EVP_CipherFinal_ex
pub fn EVP_CipherFinal_ex(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_CipherFinal_ex)
}

/// Wraps: EVP_EncryptFinal
pub fn EVP_EncryptFinal(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_EncryptFinal)
}

/// Wraps: EVP_EncryptFinal_ex
pub fn EVP_EncryptFinal_ex(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_EncryptFinal_ex)
}

/// Wraps: EVP_DecryptFinal
pub fn EVP_DecryptFinal(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_DecryptFinal)
}

/// Wraps: EVP_DecryptFinal_ex
pub fn EVP_DecryptFinal_ex(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_DecryptFinal_ex)
}

/// Wraps: EVP_EncryptInit
pub fn EVP_EncryptInit(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv) {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit`, with the direction fixed to encryption.
    unsafe {
        ffi::EVP_EncryptInit(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            bytes_ptr(key),
            bytes_ptr(iv),
        )
    }
}

/// Wraps: EVP_EncryptInit_ex
pub fn EVP_EncryptInit_ex(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv) {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit_ex`; null is the only supported ENGINE.
    unsafe {
        ffi::EVP_EncryptInit_ex(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            ptr::null_mut(),
            bytes_ptr(key),
            bytes_ptr(iv),
        )
    }
}

/// Wraps: EVP_EncryptInit_ex2
pub fn EVP_EncryptInit_ex2(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    if (params_change_lengths(params) && (key.is_some() || iv.is_some()))
        || !init_buffers_fit(ctx, cipher, key, iv)
    {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit_ex2`, with the direction fixed to encryption.
    unsafe {
        ffi::EVP_EncryptInit_ex2(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            bytes_ptr(key),
            bytes_ptr(iv),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_DecryptInit
pub fn EVP_DecryptInit(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv) {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit`, with the direction fixed to decryption.
    unsafe {
        ffi::EVP_DecryptInit(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            bytes_ptr(key),
            bytes_ptr(iv),
        )
    }
}

/// Wraps: EVP_DecryptInit_ex
pub fn EVP_DecryptInit_ex(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv) {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit_ex`; null is the only supported ENGINE.
    unsafe {
        ffi::EVP_DecryptInit_ex(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            ptr::null_mut(),
            bytes_ptr(key),
            bytes_ptr(iv),
        )
    }
}

/// Wraps: EVP_DecryptInit_ex2
pub fn EVP_DecryptInit_ex2(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    if (params_change_lengths(params) && (key.is_some() || iv.is_some()))
        || !init_buffers_fit(ctx, cipher, key, iv)
    {
        return 0;
    }
    // SAFETY: as `EVP_CipherInit_ex2`, with the direction fixed to decryption.
    unsafe {
        ffi::EVP_DecryptInit_ex2(
            ctx.as_mut_ptr(),
            cipher_ptr(cipher),
            bytes_ptr(key),
            bytes_ptr(iv),
            params_ptr(params),
        )
    }
}

#[cfg(test)]
mod cipher_operations_tests {
    use ffibox::CBox;

    use super::*;
    use crate::evp::evp::{EvpCipher, SharedEvpCipher};
    use crate::evp::evp_local::EvpCipherCtx;

    fn cipher() -> SharedEvpCipher<'static> {
        EVP_CIPHER_fetch(None, c"AES-128-CBC", None).expect("AES-128-CBC")
    }

    fn context() -> CBox<EvpCipherCtx> {
        EVP_CIPHER_CTX_new().expect("EVP_CIPHER_CTX_new")
    }

    #[test]
    fn encrypt_and_decrypt_round_trip_with_checked_capacities() {
        let cipher = cipher();
        let key = [0x42; 16];
        let iv = [0x24; 16];
        let plaintext = b"a safely bounded EVP cipher operation";

        let mut enc = context();
        assert_eq!(
            EVP_EncryptInit_ex2(
                &mut enc.as_mut(),
                Some(cipher.as_ref()),
                Some(&key),
                Some(&iv),
                None,
            ),
            1
        );
        assert!(EVP_EncryptUpdate(&mut enc.as_mut(), &mut [0; 1], plaintext).is_err());
        let mut encrypted = vec![0; plaintext.len() + 32];
        let first = EVP_EncryptUpdate(&mut enc.as_mut(), &mut encrypted, plaintext)
            .expect("encrypt update");
        let last =
            EVP_EncryptFinal_ex(&mut enc.as_mut(), &mut encrypted[first..]).expect("encrypt final");
        encrypted.truncate(first + last);

        let mut dec = context();
        assert_eq!(
            EVP_DecryptInit_ex2(
                &mut dec.as_mut(),
                Some(cipher.as_ref()),
                Some(&key),
                Some(&iv),
                None,
            ),
            1
        );
        let mut clear = vec![0; encrypted.len() + 16];
        let first =
            EVP_DecryptUpdate(&mut dec.as_mut(), &mut clear, &encrypted).expect("decrypt update");
        let last =
            EVP_DecryptFinal_ex(&mut dec.as_mut(), &mut clear[first..]).expect("decrypt final");
        clear.truncate(first + last);
        assert_eq!(clear, plaintext);
    }

    #[test]
    fn metadata_lists_are_lifetime_bound_to_the_cipher() {
        let cipher = cipher();
        let list = EVP_CIPHER_gettable_params(Some(cipher.as_ref())).expect("gettable params");
        assert!(!list.is_empty());
        let _: core::marker::PhantomData<EvpCipher> = core::marker::PhantomData;
    }
}

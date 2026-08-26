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
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_get_mode, EVP_CIPHER_is_a,
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

/// Derives the key and IV extents the C initializer will hand the provider.
///
/// `evp_cipher_init_internal` passes `EVP_CIPHER_CTX_get_key_length(ctx)` and
/// `EVP_CIPHER_CTX_get_iv_length(ctx)` as the extents of `key` and `iv`, and it
/// evaluates both *after* installing the cipher and after applying any
/// `keylen` / `ivlen` entry of `params`. Those are not the cipher's published
/// lengths: AES-128-CCM publishes a 12-byte IV while its context reports the
/// 7-byte nonce the provider actually reads.
///
/// With no cipher to install, the caller's context already publishes the
/// extents. Otherwise a scratch context installs the same cipher and the same
/// parameters with both buffers null, which reproduces exactly the state the
/// caller's context is about to reach while reading no caller memory and
/// leaving the caller's context untouched. `None` means that installation
/// failed, so no extent is known and no buffer may be handed over.
fn expected_lengths(
    ctx: &EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
    direction: c_int,
) -> Option<(c_int, c_int)> {
    let Some(cipher) = cipher else {
        return Some((
            EVP_CIPHER_CTX_get_key_length(ctx.as_ref()),
            EVP_CIPHER_CTX_get_iv_length(ctx.as_ref()),
        ));
    };
    // `-1` means "keep the context's direction", which the scratch context
    // cannot know, so resolve it against the caller's context first.
    let direction = if direction < 0 {
        c_int::from(EVP_CIPHER_CTX_is_encrypting(ctx.as_ref()))
    } else {
        direction
    };
    let mut probe = EVP_CIPHER_CTX_new()?;
    let mut probe = probe.as_mut();
    // SAFETY: the scratch context is exclusively owned by this frame, the
    // cipher handle is live, both buffer arguments are null so nothing is
    // read through them, and the optional parameter list stays live and
    // terminated for the synchronous call.
    let installed = unsafe {
        ffi::EVP_CipherInit_ex2(
            probe.as_mut_ptr(),
            cipher.as_ptr(),
            ptr::null(),
            ptr::null(),
            direction,
            params_ptr(params),
        )
    };
    if installed != 1 {
        return None;
    }
    Some((
        EVP_CIPHER_CTX_get_key_length(probe.as_ref()),
        EVP_CIPHER_CTX_get_iv_length(probe.as_ref()),
    ))
}

/// Reports whether every supplied buffer covers the extent the provider reads.
fn init_buffers_fit(
    ctx: &EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
    direction: c_int,
) -> bool {
    if key.is_none() && iv.is_none() {
        // The initializer reads no caller buffer, so there is no extent to
        // establish and no reason to pay for a scratch installation.
        return true;
    }
    let Some((key_len, iv_len)) = expected_lengths(ctx, cipher, params, direction) else {
        return false;
    };
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

/// The shared `EVP_*Update` ABI: context, output, written count, input, length.
type CipherUpdate =
    unsafe extern "C" fn(*mut ffi::evp_cipher_ctx_st, *mut u8, *mut i32, *const u8, i32) -> i32;

/// Reports whether the context's cipher documents a null output as an
/// additional-authenticated-data update.
///
/// The AEAD flag alone does not decide this: `AES-128-CBC-HMAC-SHA1` and
/// `RC4-HMAC-MD5` also publish it, yet their update routine writes through
/// `out` unconditionally. Only the modes listed here, plus
/// ChaCha20-Poly1305, branch on a null output, so anything else is refused.
fn accepts_aad_update(ctx: &EvpCipherCtxMut<'_>) -> bool {
    EVP_CIPHER_CTX_get0_cipher(ctx.as_ref()).is_some_and(|cipher| {
        u32::try_from(EVP_CIPHER_get_mode(cipher)).is_ok_and(|mode| {
            matches!(
                mode,
                ffi::EVP_CIPH_GCM_MODE
                    | ffi::EVP_CIPH_CCM_MODE
                    | ffi::EVP_CIPH_OCB_MODE
                    | ffi::EVP_CIPH_SIV_MODE
                    | ffi::EVP_CIPH_GCM_SIV_MODE
            )
        }) || EVP_CIPHER_is_a(Some(cipher), c"ChaCha20-Poly1305")
    })
}

/// Reports whether the context's cipher is a CCM mode, the only mode whose
/// provider reads a null input as the declaration of the total message length.
fn is_ccm(ctx: &EvpCipherCtxMut<'_>) -> bool {
    EVP_CIPHER_CTX_get0_cipher(ctx.as_ref()).is_some_and(|cipher| {
        u32::try_from(EVP_CIPHER_get_mode(cipher)).is_ok_and(|mode| mode == ffi::EVP_CIPH_CCM_MODE)
    })
}

/// Feeds additional authenticated data by passing the null output that AEAD
/// providers read as the AAD selector.
fn checked_aad_update(
    ctx: &mut EvpCipherCtxMut<'_>,
    aad: &[u8],
    call: CipherUpdate,
) -> Result<usize, i32> {
    if !accepts_aad_update(ctx) {
        return Err(0);
    }
    let aad_len = i32::try_from(aad.len()).map_err(|_| 0)?;
    let mut written = 0;
    // SAFETY: the exclusive context is live and its cipher is one of the AEAD
    // implementations that branch on a null output, so no ciphertext is
    // written anywhere; `aad` supplies the exact readable extent it is paired
    // with, and the provider retains neither pointer past the call.
    let status = unsafe {
        call(
            ctx.as_mut_ptr(),
            ptr::null_mut(),
            &mut written,
            aad.as_ptr(),
            aad_len,
        )
    };
    if status <= 0 {
        return Err(status);
    }
    usize::try_from(written)
        .ok()
        .filter(|written| *written <= aad.len())
        .ok_or(0)
}

/// Declares the total CCM message length by passing the null input and output
/// pair that the CCM provider reads as a length declaration.
fn checked_total_length(
    ctx: &mut EvpCipherCtxMut<'_>,
    total: usize,
    call: CipherUpdate,
) -> Result<(), i32> {
    if !is_ccm(ctx) {
        return Err(0);
    }
    let total = i32::try_from(total).map_err(|_| 0)?;
    let mut written = 0;
    // SAFETY: the exclusive context is live and holds a CCM cipher, whose
    // update routine reads the null input and output pair as a length
    // declaration and dereferences neither; only `written` is written.
    let status = unsafe {
        call(
            ctx.as_mut_ptr(),
            ptr::null_mut(),
            &mut written,
            ptr::null(),
            total,
        )
    };
    if status <= 0 { Err(status) } else { Ok(()) }
}

fn checked_update(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
    call: CipherUpdate,
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
        .filter(|written| *written <= required)
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
    if !init_buffers_fit(ctx, cipher, key, iv, None, direction.as_c_int()) {
        return 0;
    }
    // SAFETY: the exclusive context and all optional borrows are live. The
    // admission check established the implicit key and IV extents; OpenSSL
    // retains neither byte buffer and raises any cipher reference it stores.
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
    if !init_buffers_fit(ctx, cipher, key, iv, None, direction.as_c_int()) {
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
/// A `keylen` or `ivlen` entry of `params` takes effect before the key material is read, so
/// the slices are measured against the extents it selects.
pub fn EVP_CipherInit_ex2(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
    direction: CipherDirection,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv, params, direction.as_c_int()) {
        return 0;
    }
    // SAFETY: all handles and the optional terminated list remain live for the
    // synchronous call, and the byte runs cover the extents the same cipher and
    // the same parameters publish once installed.
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
/// Encrypts `input`, which needs `input.len()` plus one block of output room.
pub fn EVP_EncryptUpdate(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
) -> Result<usize, i32> {
    checked_update(ctx, output, input, ffi::EVP_EncryptUpdate)
}

/// Wraps: EVP_EncryptUpdate
/// The null-output form of the same call: `aad` is authenticated but not
/// encrypted, and the count returned is the number of AAD bytes consumed.
/// Rejected unless the context holds a cipher whose provider reads a null
/// output as AAD.
pub fn EVP_EncryptUpdate_aad(ctx: &mut EvpCipherCtxMut<'_>, aad: &[u8]) -> Result<usize, i32> {
    checked_aad_update(ctx, aad, ffi::EVP_EncryptUpdate)
}

/// Wraps: EVP_EncryptUpdate
/// The null-input-and-output form of the same call. CCM requires the total
/// plaintext length before any AAD is supplied; rejected for every other mode.
pub fn EVP_EncryptUpdate_total_length(
    ctx: &mut EvpCipherCtxMut<'_>,
    total: usize,
) -> Result<(), i32> {
    checked_total_length(ctx, total, ffi::EVP_EncryptUpdate)
}

/// Wraps: EVP_DecryptUpdate
/// Decrypts `input`, which needs `input.len()` plus one block of output room.
pub fn EVP_DecryptUpdate(
    ctx: &mut EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: &[u8],
) -> Result<usize, i32> {
    checked_update(ctx, output, input, ffi::EVP_DecryptUpdate)
}

/// Wraps: EVP_DecryptUpdate
/// The null-output form of the same call: `aad` is authenticated but not
/// decrypted, and the count returned is the number of AAD bytes consumed.
/// Rejected unless the context holds a cipher whose provider reads a null
/// output as AAD.
pub fn EVP_DecryptUpdate_aad(ctx: &mut EvpCipherCtxMut<'_>, aad: &[u8]) -> Result<usize, i32> {
    checked_aad_update(ctx, aad, ffi::EVP_DecryptUpdate)
}

/// Wraps: EVP_DecryptUpdate
/// The null-input-and-output form of the same call. CCM requires the total
/// ciphertext length before any AAD is supplied; rejected for every other mode.
pub fn EVP_DecryptUpdate_total_length(
    ctx: &mut EvpCipherCtxMut<'_>,
    total: usize,
) -> Result<(), i32> {
    checked_total_length(ctx, total, ffi::EVP_DecryptUpdate)
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
/// `output` needs one block of room; an AEAD context, whose block size is one
/// and which emits nothing here, accepts an empty slice in place of C's null.
pub fn EVP_EncryptFinal(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    checked_final(ctx, output, ffi::EVP_EncryptFinal)
}

/// Wraps: EVP_EncryptFinal_ex
/// `output` needs one block of room; an AEAD context, whose block size is one
/// and which emits nothing here, accepts an empty slice in place of C's null.
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
    if !init_buffers_fit(ctx, cipher, key, iv, None, 1) {
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
/// The legacy ENGINE argument is intentionally omitted because C asserts it is null.
pub fn EVP_EncryptInit_ex(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv, None, 1) {
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
/// A `keylen` or `ivlen` entry of `params` takes effect before the key material is read, so
/// the slices are measured against the extents it selects.
pub fn EVP_EncryptInit_ex2(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv, params, 1) {
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
    if !init_buffers_fit(ctx, cipher, key, iv, None, 0) {
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
/// The legacy ENGINE argument is intentionally omitted because C asserts it is null.
pub fn EVP_DecryptInit_ex(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv, None, 0) {
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
/// A `keylen` or `ivlen` entry of `params` takes effect before the key material is read, so
/// the slices are measured against the extents it selects.
pub fn EVP_DecryptInit_ex2(
    ctx: &mut EvpCipherCtxMut<'_>,
    cipher: Option<EvpCipherRef<'_>>,
    key: Option<&[u8]>,
    iv: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    if !init_buffers_fit(ctx, cipher, key, iv, params, 0) {
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
    use core::mem::MaybeUninit;

    use ffibox::CBox;

    use super::*;
    use crate::core::openssl_core::OsslParamArray;
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

    /// `OSSL_PARAM_OCTET_STRING`, per `include/openssl/core.h`.
    const OCTET_STRING: u32 = 5;
    const TAG_LEN: usize = 16;

    fn read_tag(params: &OsslParamArray<'_>) -> [u8; TAG_LEN] {
        let values = params.as_list().values();
        let tag = values.get(0).expect("the tag descriptor");
        assert_eq!(tag.return_size(), TAG_LEN);
        let written = tag.data().expect("the filled run");
        let mut bytes = [0_u8; TAG_LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: `return_size` reports that the provider initialized the
            // whole run, so every byte of it now holds a value.
            *byte = unsafe { written.elem(index).expect("in range").assume_init() };
        }
        bytes
    }

    /// `OSSL_PARAM_UNSIGNED_INTEGER`, per `include/openssl/core.h`.
    const UNSIGNED_INTEGER: u32 = 2;

    #[test]
    fn init_measures_buffers_against_the_installed_context() {
        let ccm = EVP_CIPHER_fetch(None, c"AES-128-CCM", None).expect("AES-128-CCM");
        let key = [0x01; 16];

        // AES-128-CCM publishes a 12-byte IV, but the context it installs
        // reports the 7-byte nonce the provider reads, which is the extent the
        // guard has to measure against.
        let mut accepted = context();
        let mut ctx = accepted.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(
                &mut ctx,
                Some(ccm.as_ref()),
                Some(&key),
                Some(&[0x02; 7]),
                None
            ),
            1
        );
        assert_eq!(EVP_CIPHER_CTX_get_iv_length(ctx.as_ref()), 7);

        // Anything shorter than the installed extent is still refused, on
        // either buffer.
        let mut refused = context();
        let mut ctx = refused.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(
                &mut ctx,
                Some(ccm.as_ref()),
                Some(&key),
                Some(&[0x02; 6]),
                None
            ),
            0
        );
        assert_eq!(
            EVP_DecryptInit_ex2(
                &mut ctx,
                Some(ccm.as_ref()),
                Some(&key[..8]),
                Some(&[0x02; 7]),
                None,
            ),
            0
        );
    }

    #[test]
    fn init_follows_a_length_parameter_that_takes_effect_first() {
        let gcm = EVP_CIPHER_fetch(None, c"AES-128-GCM", None).expect("AES-128-GCM");
        let key = [0x03; 16];
        let iv = [0x04; 16];

        // The `ivlen` entry is applied before the provider reads `iv`, so a
        // 16-byte IV that the published 12-byte length would have accepted
        // anyway becomes the exact requirement.
        let mut storage = 16_usize.to_ne_bytes().map(MaybeUninit::new);
        let params = OsslParamArray::new([OsslParam::for_slice(
            c"ivlen",
            UNSIGNED_INTEGER,
            &mut storage,
        )]);

        let mut accepted = context();
        let mut ctx = accepted.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(
                &mut ctx,
                Some(gcm.as_ref()),
                Some(&key),
                Some(&iv),
                Some(&params.as_list()),
            ),
            1
        );
        assert_eq!(EVP_CIPHER_CTX_get_iv_length(ctx.as_ref()), 16);

        // The same 12-byte IV that suits plain GCM is now too short.
        let mut refused = context();
        assert_eq!(
            EVP_EncryptInit_ex2(
                &mut refused.as_mut(),
                Some(gcm.as_ref()),
                Some(&key),
                Some(&iv[..12]),
                Some(&params.as_list()),
            ),
            0
        );
    }

    #[test]
    fn aead_round_trip_authenticates_associated_data() {
        let cipher = EVP_CIPHER_fetch(None, c"AES-128-GCM", None).expect("AES-128-GCM");
        let key = [0x11; 16];
        let iv = [0x22; 12];
        let aad = b"authenticated but not encrypted";
        let plaintext = b"secret payload";

        let mut enc = context();
        let mut ctx = enc.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(&mut ctx, Some(cipher.as_ref()), Some(&key), Some(&iv), None),
            1
        );
        assert_eq!(EVP_EncryptUpdate_aad(&mut ctx, aad), Ok(aad.len()));
        let mut encrypted = vec![0; plaintext.len() + TAG_LEN];
        let written =
            EVP_EncryptUpdate(&mut ctx, &mut encrypted, plaintext).expect("encrypt update");
        encrypted.truncate(written);
        // GCM has a block size of one and emits nothing here, so the empty
        // slice stands in for the null output the C API also accepts.
        assert_eq!(EVP_EncryptFinal_ex(&mut ctx, &mut []), Ok(0));

        let mut storage = [MaybeUninit::new(0_u8); TAG_LEN];
        let mut produced =
            OsslParamArray::new([OsslParam::for_slice(c"tag", OCTET_STRING, &mut storage)]);
        assert_eq!(
            EVP_CIPHER_CTX_get_params(&mut ctx, &mut produced.as_list_mut()),
            1
        );
        let tag = read_tag(&produced);

        let decrypt_with = |aad: &[u8]| -> Result<usize, i32> {
            let mut dec = context();
            let mut ctx = dec.as_mut();
            assert_eq!(
                EVP_DecryptInit_ex2(&mut ctx, Some(cipher.as_ref()), Some(&key), Some(&iv), None),
                1
            );
            assert_eq!(EVP_DecryptUpdate_aad(&mut ctx, aad), Ok(aad.len()));
            let mut clear = vec![0; encrypted.len() + TAG_LEN];
            let written =
                EVP_DecryptUpdate(&mut ctx, &mut clear, &encrypted).expect("decrypt update");
            clear.truncate(written);

            let mut expected = tag.map(MaybeUninit::new);
            let wanted =
                OsslParamArray::new([OsslParam::for_slice(c"tag", OCTET_STRING, &mut expected)]);
            assert_eq!(EVP_CIPHER_CTX_set_params(&mut ctx, &wanted.as_list()), 1);
            let result = EVP_DecryptFinal_ex(&mut ctx, &mut []);
            if result.is_ok() {
                assert_eq!(clear, plaintext);
            }
            result
        };

        assert_eq!(decrypt_with(aad), Ok(0));
        // The AAD really reached the tag computation: altering it invalidates
        // the same ciphertext and tag.
        assert!(decrypt_with(b"a different associated string").is_err());
    }

    #[test]
    fn ccm_declares_its_total_length_before_associated_data() {
        let cipher = EVP_CIPHER_fetch(None, c"AES-128-CCM", None).expect("AES-128-CCM");
        let key = [0x33; 16];
        let iv = [0x44; 7];
        let aad = b"ccm associated data";
        let plaintext = b"ccm payload";

        let mut enc = context();
        let mut ctx = enc.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(&mut ctx, Some(cipher.as_ref()), Some(&key), Some(&iv), None),
            1
        );
        // CCM refuses AAD until the total message length is declared.
        assert!(EVP_EncryptUpdate_aad(&mut ctx, aad).is_err());
        assert_eq!(
            EVP_EncryptUpdate_total_length(&mut ctx, plaintext.len()),
            Ok(())
        );
        assert_eq!(EVP_EncryptUpdate_aad(&mut ctx, aad), Ok(aad.len()));
        let mut encrypted = vec![0; plaintext.len() + TAG_LEN];
        let written =
            EVP_EncryptUpdate(&mut ctx, &mut encrypted, plaintext).expect("encrypt update");
        assert_eq!(written, plaintext.len());
    }

    #[test]
    fn null_output_forms_are_refused_outside_their_modes() {
        let cbc = cipher();
        let key = [0x55; 16];
        let iv = [0x66; 16];

        let mut ctx = context();
        let mut ctx = ctx.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(&mut ctx, Some(cbc.as_ref()), Some(&key), Some(&iv), None),
            1
        );
        // AES-128-CBC writes through `out` unconditionally, so the AAD form
        // must refuse instead of handing its provider a null pointer.
        assert_eq!(EVP_EncryptUpdate_aad(&mut ctx, b"aad"), Err(0));
        assert_eq!(EVP_EncryptUpdate_total_length(&mut ctx, 16), Err(0));

        // GCM takes AAD but has no message-length declaration.
        let gcm = EVP_CIPHER_fetch(None, c"AES-128-GCM", None).expect("AES-128-GCM");
        let mut ctx = context();
        let mut ctx = ctx.as_mut();
        assert_eq!(
            EVP_EncryptInit_ex2(
                &mut ctx,
                Some(gcm.as_ref()),
                Some(&key),
                Some(&[0x77; 12]),
                None,
            ),
            1
        );
        assert_eq!(EVP_EncryptUpdate_aad(&mut ctx, b"aad"), Ok(3));
        assert_eq!(EVP_EncryptUpdate_total_length(&mut ctx, 16), Err(0));

        // An empty context has no cipher at all.
        let mut empty = context();
        assert_eq!(EVP_DecryptUpdate_aad(&mut empty.as_mut(), b"aad"), Err(0));
    }

    #[test]
    fn metadata_lists_are_lifetime_bound_to_the_cipher() {
        let cipher = cipher();
        let list = EVP_CIPHER_gettable_params(Some(cipher.as_ref())).expect("gettable params");
        assert!(!list.is_empty());
        let _: core::marker::PhantomData<EvpCipher> = core::marker::PhantomData;
    }
}

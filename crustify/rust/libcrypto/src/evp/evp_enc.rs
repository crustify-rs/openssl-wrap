//! Wrappers assigned from `crypto/evp/evp_enc.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_int, c_void};
use core::ptr::{self, NonNull};
use std::any::Any;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use ffibox::{CBox, CSlice};
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{
    OsslParam, OsslParamListMut, OsslParamListRef, terminated_param_len,
};
use crate::evp::evp::{EvpCipherRef, SharedEvpCipher};
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
    // SAFETY: the context is live and the query retains no pointer.
    let required = unsafe { ffi::EVP_CIPHER_CTX_get_key_length(ctx.as_ref().as_ptr()) };
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

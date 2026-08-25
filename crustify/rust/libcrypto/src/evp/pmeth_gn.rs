//! Wrappers assigned from `crypto/evp/pmeth_gn.c`.

#![allow(non_snake_case)]

use core::ptr;
use core::ptr::NonNull;

use ffibox::{CBox, CLenDropped, CSlice, CVec};
use libcrypto_sys as ffi;

use crate::core::openssl_core::{OsslCallback, OsslParam, OsslParamArray, terminated_param_len};
use crate::evp::evp::{EvpPkey, EvpPkeyCtxMut, EvpPkeyCtxRef, EvpPkeyGenCallback, EvpPkeyRef};
use crate::evp::p_lib::BorrowedEvpPkey;

fn generate(
    context: &mut EvpPkeyCtxMut<'_>,
    operation: unsafe extern "C" fn(*mut ffi::evp_pkey_ctx_st, *mut *mut ffi::evp_pkey_st) -> i32,
) -> Result<CBox<EvpPkey>, i32> {
    let mut output = ptr::null_mut();
    // SAFETY: the exclusive context is live, and the local owner slot starts
    // null so OpenSSL either creates a fresh key or leaves no ownership behind.
    let status = unsafe { operation(context.as_mut_ptr(), &mut output) };
    if status <= 0 {
        if let Some(unexpected) =
            // SAFETY: if a failing provider nevertheless left a key in the
            // caller-owned slot, adopting and immediately dropping it prevents
            // a leak while preserving the reported failure.
            unsafe { CBox::<EvpPkey>::from_raw(output) }
        {
            drop(unexpected);
        }
        return Err(status);
    }
    // SAFETY: successful generation stores one fresh, fully initialized key
    // reference in the required output slot.
    unsafe { CBox::from_raw(output) }.ok_or(status)
}

/// Wraps: EVP_PKEY_keygen
/// Generates a fresh key and returns the original OpenSSL status on failure.
#[allow(non_snake_case)]
pub fn EVP_PKEY_keygen(context: &mut EvpPkeyCtxMut<'_>) -> Result<CBox<EvpPkey>, i32> {
    generate(context, ffi::EVP_PKEY_keygen)
}

/// Wraps: EVP_PKEY_keygen_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_keygen_init(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context permits replacing its active operation state.
    unsafe { ffi::EVP_PKEY_keygen_init(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_new_mac_key
/// The unsupported legacy ENGINE argument is fixed to null.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_mac_key(key_type: i32, key: &[u8]) -> Option<CBox<EvpPkey>> {
    let key_len = i32::try_from(key.len()).ok()?;
    // SAFETY: null is the implementation's required ENGINE value, and the key
    // slice remains readable while OpenSSL copies it into the fresh result.
    let raw =
        unsafe { ffi::EVP_PKEY_new_mac_key(key_type, ptr::null_mut(), key.as_ptr(), key_len) };
    // SAFETY: a non-null result transfers one initialized EVP_PKEY reference.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_paramgen
/// Generates a fresh parameter key and returns the C status on failure.
#[allow(non_snake_case)]
pub fn EVP_PKEY_paramgen(context: &mut EvpPkeyCtxMut<'_>) -> Result<CBox<EvpPkey>, i32> {
    generate(context, ffi::EVP_PKEY_paramgen)
}

/// Wraps: EVP_PKEY_paramgen_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_paramgen_init(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context permits replacing its active operation state.
    unsafe { ffi::EVP_PKEY_paramgen_init(context.as_mut_ptr()) }
}

/// Release policy for the duplicated array returned by `EVP_PKEY_todata`.
pub struct OsslParamArrayFree;

// SAFETY: this strategy is used only with the base pointer returned through
// `EVP_PKEY_todata`; `OSSL_PARAM_free` releases that complete duplicated,
// terminated array and does not require the recovered byte length.
unsafe impl CLenDropped for OsslParamArrayFree {
    unsafe fn c_drop_len(ptr: *mut u8, _byte_len: usize) {
        // SAFETY: guaranteed by the strategy's construction contract above.
        unsafe { ffi::OSSL_PARAM_free(ptr.cast()) }
    }
}

/// Owned duplicated parameter descriptors returned by `EVP_PKEY_todata`.
pub type OwnedOsslParams = CVec<OsslParam<'static>, OsslParamArrayFree>;

/// Wraps: EVP_PKEY_todata
///
/// Duplicates the selected key material into an owned parameter array. The
/// returned owner releases descriptor keys, data, and array storage together
/// with `OSSL_PARAM_free`.
#[allow(non_snake_case)]
pub fn EVP_PKEY_todata(pkey: EvpPkeyRef<'_>, selection: i32) -> Result<OwnedOsslParams, i32> {
    let mut params = ptr::null_mut();
    // SAFETY: the key handle is live and `params` is a writable out-slot.
    // Success transfers the newly duplicated array to this function.
    let status = unsafe { ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params) };
    if status != 1 {
        return Err(status);
    }

    // SAFETY: success promises a live null-key-terminated duplicated array.
    let Some(len) = (unsafe { terminated_param_len(params) }) else {
        // Defensive only: a successful null result violates the C contract.
        return Err(0);
    };
    // SAFETY: the successful call transfers the base pointer exactly once;
    // the scan established `len` initialized descriptors before its terminator,
    // and this policy releases the whole allocation without needing the length.
    unsafe { CVec::from_raw_parts(params.cast::<OsslParam<'static>>(), len) }.ok_or(0)
}

/// Wraps: EVP_PKEY_fromdata
/// Imports one independently owned key from a terminated parameter array.
pub fn EVP_PKEY_fromdata<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
    selection: i32,
    params: &mut OsslParamArray<'_>,
) -> Result<BorrowedEvpPkey<'a>, i32> {
    let mut raw = ptr::null_mut();
    // SAFETY: the output slot is writable, the context is exclusive, and the
    // parameter owner supplies a live terminated mutable descriptor array.
    let status = unsafe {
        ffi::EVP_PKEY_fromdata(ctx.as_mut_ptr(), &mut raw, selection, params.as_mut_ptr())
    };
    // SAFETY: any non-null output transfers one `EVP_PKEY_free` obligation.
    let key = unsafe { BorrowedEvpPkey::from_raw(raw) };
    if status > 0 {
        key.ok_or(status)
    } else {
        drop(key);
        Err(status)
    }
}

/// Wraps: EVP_PKEY_fromdata_init
pub fn EVP_PKEY_fromdata_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle supplies a live operation context.
    unsafe { ffi::EVP_PKEY_fromdata_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_fromdata_settable
/// Borrows the provider's null-key-terminated table of accepted descriptors.
#[must_use]
pub fn EVP_PKEY_fromdata_settable<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
    selection: i32,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the context is exclusively borrowed and retains the returned
    // provider method table for the duration of this borrow.
    let raw = unsafe { ffi::EVP_PKEY_fromdata_settable(ctx.as_mut_ptr(), selection) };
    let start = NonNull::new(raw.cast_mut().cast::<OsslParam<'a>>())?;
    // SAFETY: OpenSSL's return contract is a valid null-key-terminated
    // OSSL_PARAM table, so its terminator is reachable from `raw`.
    let len = unsafe { terminated_param_len(raw) }?;
    // SAFETY: `terminated_param_len` counted exactly the descriptors before
    // the terminator, and the provider keeps them live for the `ctx` borrow.
    unsafe { Some(CSlice::from_raw_parts(start, len)) }
}

/// Wraps: EVP_PKEY_generate
/// Runs the initialized generation operation and adopts its fresh key.
pub fn EVP_PKEY_generate<'a>(ctx: &'a mut EvpPkeyCtxMut<'_>) -> Result<BorrowedEvpPkey<'a>, i32> {
    let mut raw = ptr::null_mut();
    // SAFETY: the context is exclusive and `raw` is a writable owner out-slot.
    let status = unsafe { ffi::EVP_PKEY_generate(ctx.as_mut_ptr(), &mut raw) };
    // SAFETY: any non-null output transfers one `EVP_PKEY_free` obligation.
    let key = unsafe { BorrowedEvpPkey::from_raw(raw) };
    if status > 0 {
        key.ok_or(status)
    } else {
        drop(key);
        Err(status)
    }
}

/// Wraps: EVP_PKEY_export
/// Invokes `callback` synchronously with the selected key parameters.
pub fn EVP_PKEY_export<F>(
    pkey: EvpPkeyRef<'_>,
    selection: i32,
    callback: &mut OsslCallback<'_, F>,
) -> i32
where
    F: for<'params> FnMut(CSlice<'params, OsslParam<'params>>) -> i32,
{
    // SAFETY: `raw_parts` is consumed only by this synchronous FFI call while
    // the callback remains exclusively borrowed; OpenSSL does not retain it.
    let (function, argument) = unsafe { callback.raw_parts() };
    // SAFETY: the key is live, and the callback/function state pair is valid
    // and uniquely borrowed for the complete synchronous export operation.
    unsafe { ffi::EVP_PKEY_export(pkey.as_ptr(), selection, function, argument) }
}

/// Wraps: EVP_PKEY_CTX_get_keygen_info
///
/// `None` returns the number of key-generation information entries. An index
/// outside that run returns zero without invoking C; this also closes the C
/// implementation's `index == count` out-of-bounds edge.
#[must_use]
pub fn EVP_PKEY_CTX_get_keygen_info(ctx: EvpPkeyCtxRef<'_>, index: Option<usize>) -> i32 {
    // SAFETY: `-1` is the documented count query and the function only reads
    // the live context's stored information run.
    let count = unsafe { ffi::EVP_PKEY_CTX_get_keygen_info(ctx.as_ptr().cast_mut(), -1) };
    let Some(index) = index else {
        return count;
    };
    let Ok(index) = i32::try_from(index) else {
        return 0;
    };
    if index < 0 || index >= count {
        return 0;
    }
    // SAFETY: the preceding query proved `0 <= index < count`, avoiding the C
    // implementation's otherwise unchecked `index == count` access.
    unsafe { ffi::EVP_PKEY_CTX_get_keygen_info(ctx.as_ptr().cast_mut(), index) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::p_lib::EVP_PKEY_is_a;

    unsafe extern "C" fn accepts_generation_context(ctx: *mut ffi::evp_pkey_ctx_st) -> i32 {
        i32::from(!ctx.is_null())
    }

    #[test]
    fn provider_keygen_returns_an_owned_key() {
        // SAFETY: null selects the default process context, both C strings are
        // live, and a non-null result is a uniquely owned operation context.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"ED25519".as_ptr(), ptr::null())
        };
        // SAFETY: ownership of the fresh context transfers to its registered destructor.
        let mut context = unsafe { CBox::<crate::evp::evp::EvpPkeyCtx>::from_raw(raw) }
            .expect("EVP_PKEY_CTX_new_from_name");

        let mut context_mut = context.as_mut();
        assert_eq!(EVP_PKEY_keygen_init(&mut context_mut), 1);
        let key = EVP_PKEY_keygen(&mut context_mut).expect("ED25519 keygen");
        assert!(EVP_PKEY_is_a(key.as_ref(), c"ED25519"));
    }

    #[test]
    fn provider_key_can_be_exported_through_a_safe_callback() {
        // SAFETY: null selects the default process context, both C strings are
        // live, and a non-null result is a fresh operation context.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"ED25519".as_ptr(), ptr::null())
        };
        // SAFETY: ownership of the fresh context transfers to its destructor.
        let mut context = unsafe { CBox::<crate::evp::evp::EvpPkeyCtx>::from_raw(raw) }
            .expect("EVP_PKEY_CTX_new_from_name");
        let mut context_mut = context.as_mut();
        assert_eq!(EVP_PKEY_keygen_init(&mut context_mut), 1);
        let key = EVP_PKEY_keygen(&mut context_mut).expect("ED25519 keygen");

        let mut parameter_count = 0usize;
        let mut closure = |params: CSlice<'_, OsslParam<'_>>| {
            parameter_count = params.len();
            1
        };
        let mut callback = OsslCallback::new(&mut closure);
        assert_eq!(EVP_PKEY_export(key.as_ref(), 0x03, &mut callback), 1);
        assert!(parameter_count > 0);
    }

    #[test]
    fn generation_callback_round_trips_through_the_context() {
        // SAFETY: this callback accepts every non-null live context, retains
        // nothing, returns a valid C int, and cannot unwind.
        let callback = unsafe { EvpPkeyGenCallback::from_raw(Some(accepts_generation_context)) }
            .expect("non-null callback");
        // SAFETY: null selects the default library context, the algorithm name
        // is static, and null selects the default property query.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"RSA".as_ptr(), ptr::null())
        };
        // SAFETY: a non-null result transfers one complete context owner.
        let mut ctx =
            unsafe { CBox::<crate::evp::evp::EvpPkeyCtx>::from_raw(raw) }.expect("RSA context");

        EVP_PKEY_CTX_set_cb(&mut ctx.as_mut(), Some(callback));
        let stored = EVP_PKEY_CTX_get_cb(ctx.as_ref()).expect("stored callback");
        assert_eq!(stored.call(&mut ctx.as_mut()), 1);

        EVP_PKEY_CTX_set_cb(&mut ctx.as_mut(), None);
        assert!(EVP_PKEY_CTX_get_cb(ctx.as_ref()).is_none());
    }
}

/// Wraps: EVP_PKEY_CTX_get_cb
#[must_use]
pub fn EVP_PKEY_CTX_get_cb(ctx: EvpPkeyCtxRef<'_>) -> Option<EvpPkeyGenCallback> {
    // SAFETY: the shared handle supplies a live context and the C getter only
    // reads its callback field despite the legacy non-const signature.
    let raw = unsafe { ffi::EVP_PKEY_CTX_get_cb(ctx.as_ptr().cast_mut()) };
    // SAFETY: a callback stored by a live OpenSSL context satisfies the same
    // C ABI invocation contract required by the callable handle.
    unsafe { EvpPkeyGenCallback::from_raw(raw) }
}

/// Wraps: EVP_PKEY_CTX_set_cb
pub fn EVP_PKEY_CTX_set_cb(ctx: &mut EvpPkeyCtxMut<'_>, callback: Option<EvpPkeyGenCallback>) {
    let raw = callback.and_then(EvpPkeyGenCallback::as_raw);
    // SAFETY: the context is exclusively borrowed and `raw` is null or a
    // callback whose construction established the stored invocation contract.
    unsafe { ffi::EVP_PKEY_CTX_set_cb(ctx.as_mut_ptr(), raw) }
}

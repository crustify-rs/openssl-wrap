//! Wrappers assigned from `crypto/evp/signature.c`.

use core::mem::MaybeUninit;
use core::ptr;

use libcrypto_sys as ffi;

use crate::core::openssl_core::OsslParamListRef;
use crate::evp::evp::EvpPkeyCtxMut;
use crate::evp::evp_local::EvpSignatureRef;

fn params_ptr(params: Option<&OsslParamListRef<'_, '_>>) -> *const ffi::OSSL_PARAM {
    params.map_or(ptr::null(), OsslParamListRef::as_ptr)
}

fn signature_ptr(signature: Option<EvpSignatureRef<'_>>) -> *mut ffi::EVP_SIGNATURE {
    signature.map_or(ptr::null_mut(), |signature| signature.as_ptr().cast_mut())
}

fn output_call(
    output: &mut [MaybeUninit<u8>],
    call: impl FnOnce(*mut u8, *mut usize) -> i32,
) -> Result<&mut [u8], i32> {
    let capacity = output.len();
    let mut length = capacity;
    let status = call(output.as_mut_ptr().cast(), &mut length);
    if status <= 0 {
        return Err(status);
    }
    if length > capacity {
        return Err(0);
    }
    // SAFETY: a successful OpenSSL output operation promises it initialized
    // exactly the first `length` bytes, and the check keeps them in bounds.
    Ok(unsafe { core::slice::from_raw_parts_mut(output.as_mut_ptr().cast::<u8>(), length) })
}

fn output_size(call: impl FnOnce(*mut usize) -> i32) -> Result<usize, i32> {
    let mut length = MaybeUninit::<usize>::uninit();
    let status = call(length.as_mut_ptr());
    if status <= 0 {
        return Err(status);
    }
    // SAFETY: successful size-query operations promise to initialize the
    // required-length out-slot.
    Ok(unsafe { length.assume_init() })
}

/// Wraps: EVP_PKEY_sign
///
/// Writes a signature into `output` and returns its initialized prefix.
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign<'out>(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: &'out mut [MaybeUninit<u8>],
    to_be_signed: &[u8],
) -> Result<&'out mut [u8], i32> {
    output_call(output, |signature, signature_len| {
        // SAFETY: the exclusive context is live, the output pointer has its
        // supplied capacity, and the input slice is readable for its length.
        unsafe {
            ffi::EVP_PKEY_sign(
                ctx.as_mut_ptr(),
                signature,
                signature_len,
                to_be_signed.as_ptr(),
                to_be_signed.len(),
            )
        }
    })
}

/// A size-query variant of [`EVP_PKEY_sign`].
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_size(ctx: &mut EvpPkeyCtxMut<'_>, to_be_signed: &[u8]) -> Result<usize, i32> {
    output_size(|signature_len| {
        // SAFETY: null output selects the documented size query, the out-slot
        // is writable, and the input slice is readable for its length.
        unsafe {
            ffi::EVP_PKEY_sign(
                ctx.as_mut_ptr(),
                ptr::null_mut(),
                signature_len,
                to_be_signed.as_ptr(),
                to_be_signed.len(),
            )
        }
    })
}

/// Wraps: EVP_PKEY_sign_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle permits replacement of operation state.
    unsafe { ffi::EVP_PKEY_sign_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_sign_init_ex
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: the exclusive context is live; the optional list is initialized,
    // terminated, and borrowed for the complete synchronous call.
    unsafe { ffi::EVP_PKEY_sign_init_ex(ctx.as_mut_ptr(), params_ptr(params)) }
}

/// Wraps: EVP_PKEY_sign_init_ex2
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_init_ex2(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: Option<EvpSignatureRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: all handles and the optional terminated list are live for the
    // call. OpenSSL raises any algorithm reference it retains in the context.
    unsafe {
        ffi::EVP_PKEY_sign_init_ex2(
            ctx.as_mut_ptr(),
            signature_ptr(algorithm),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_PKEY_sign_message_final
///
/// Finalizes a streamed message signature into `output`.
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_message_final<'out>(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: &'out mut [MaybeUninit<u8>],
) -> Result<&'out mut [u8], i32> {
    output_call(output, |signature, signature_len| {
        // SAFETY: the exclusive context and output buffer are live; the
        // helper initializes the capacity and validates the returned length.
        unsafe { ffi::EVP_PKEY_sign_message_final(ctx.as_mut_ptr(), signature, signature_len) }
    })
}

/// A size-query variant of [`EVP_PKEY_sign_message_final`].
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_message_final_size(ctx: &mut EvpPkeyCtxMut<'_>) -> Result<usize, i32> {
    output_size(|signature_len| {
        // SAFETY: null output selects the documented size query and the length
        // out-slot is writable for this synchronous operation.
        unsafe {
            ffi::EVP_PKEY_sign_message_final(ctx.as_mut_ptr(), ptr::null_mut(), signature_len)
        }
    })
}

/// Wraps: EVP_PKEY_sign_message_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_message_init(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: Option<EvpSignatureRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: all handles and the terminated parameter list are live for the
    // call; OpenSSL raises any algorithm reference retained by the context.
    unsafe {
        ffi::EVP_PKEY_sign_message_init(
            ctx.as_mut_ptr(),
            signature_ptr(algorithm),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_PKEY_sign_message_update
#[allow(non_snake_case)]
pub fn EVP_PKEY_sign_message_update(ctx: &mut EvpPkeyCtxMut<'_>, input: &[u8]) -> i32 {
    // SAFETY: the exclusive context and readable input run remain live for the
    // synchronous provider update.
    unsafe { ffi::EVP_PKEY_sign_message_update(ctx.as_mut_ptr(), input.as_ptr(), input.len()) }
}

/// Wraps: EVP_PKEY_verify
///
/// Returns `1` for a valid signature, `0` for an invalid signature, and the
/// negative OpenSSL status values for operation errors.
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify(ctx: &mut EvpPkeyCtxMut<'_>, signature: &[u8], to_be_signed: &[u8]) -> i32 {
    // SAFETY: the exclusive context and both readable slices remain live for
    // the synchronous verification call.
    unsafe {
        ffi::EVP_PKEY_verify(
            ctx.as_mut_ptr(),
            signature.as_ptr(),
            signature.len(),
            to_be_signed.as_ptr(),
            to_be_signed.len(),
        )
    }
}

/// Wraps: EVP_PKEY_verify_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle permits replacement of operation state.
    unsafe { ffi::EVP_PKEY_verify_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_verify_init_ex
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: the exclusive context and optional terminated list remain live
    // for the synchronous initialization call.
    unsafe { ffi::EVP_PKEY_verify_init_ex(ctx.as_mut_ptr(), params_ptr(params)) }
}

/// Wraps: EVP_PKEY_verify_init_ex2
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_init_ex2(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: Option<EvpSignatureRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: all handles and the optional terminated list are live; OpenSSL
    // raises any algorithm reference retained by the context.
    unsafe {
        ffi::EVP_PKEY_verify_init_ex2(
            ctx.as_mut_ptr(),
            signature_ptr(algorithm),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_PKEY_verify_message_final
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_message_final(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context is live and initialized operation state is
    // validated by OpenSSL before provider dispatch.
    unsafe { ffi::EVP_PKEY_verify_message_final(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_verify_message_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_message_init(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: Option<EvpSignatureRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: all handles and the optional terminated list remain live; any
    // retained algorithm receives its own OpenSSL reference.
    unsafe {
        ffi::EVP_PKEY_verify_message_init(
            ctx.as_mut_ptr(),
            signature_ptr(algorithm),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_PKEY_verify_message_update
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_message_update(ctx: &mut EvpPkeyCtxMut<'_>, input: &[u8]) -> i32 {
    // SAFETY: the exclusive context and readable byte run are live for the
    // synchronous provider update.
    unsafe { ffi::EVP_PKEY_verify_message_update(ctx.as_mut_ptr(), input.as_ptr(), input.len()) }
}

/// Wraps: EVP_PKEY_verify_recover
///
/// Recovers data into `output` and returns its initialized prefix.
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_recover<'out>(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: &'out mut [MaybeUninit<u8>],
    signature: &[u8],
) -> Result<&'out mut [u8], i32> {
    output_call(output, |recovered, recovered_len| {
        // SAFETY: the exclusive context, writable output capacity, and
        // readable signature all remain live for the synchronous call.
        unsafe {
            ffi::EVP_PKEY_verify_recover(
                ctx.as_mut_ptr(),
                recovered,
                recovered_len,
                signature.as_ptr(),
                signature.len(),
            )
        }
    })
}

/// A size-query variant of [`EVP_PKEY_verify_recover`].
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_recover_size(
    ctx: &mut EvpPkeyCtxMut<'_>,
    signature: &[u8],
) -> Result<usize, i32> {
    output_size(|recovered_len| {
        // SAFETY: null output selects the documented size query, while the
        // out-slot and readable signature remain live for the call.
        unsafe {
            ffi::EVP_PKEY_verify_recover(
                ctx.as_mut_ptr(),
                ptr::null_mut(),
                recovered_len,
                signature.as_ptr(),
                signature.len(),
            )
        }
    })
}

/// Wraps: EVP_PKEY_verify_recover_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_recover_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle permits replacement of operation state.
    unsafe { ffi::EVP_PKEY_verify_recover_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_verify_recover_init_ex
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_recover_init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: the exclusive context and optional terminated list remain live
    // for the synchronous initialization call.
    unsafe { ffi::EVP_PKEY_verify_recover_init_ex(ctx.as_mut_ptr(), params_ptr(params)) }
}

/// Wraps: EVP_PKEY_verify_recover_init_ex2
#[allow(non_snake_case)]
pub fn EVP_PKEY_verify_recover_init_ex2(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: Option<EvpSignatureRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    // SAFETY: all handles and the optional terminated list are live; OpenSSL
    // raises any algorithm reference retained by the context.
    unsafe {
        ffi::EVP_PKEY_verify_recover_init_ex2(
            ctx.as_mut_ptr(),
            signature_ptr(algorithm),
            params_ptr(params),
        )
    }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::evp::evp::EvpPkeyCtx;

    fn context() -> CBox<EvpPkeyCtx> {
        // SAFETY: null selects the default library context, both strings obey
        // their C contracts, and a non-null result is a fresh owned context.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"RSA".as_ptr(), ptr::null())
        };
        // SAFETY: the fresh non-null result transfers one context-free duty.
        unsafe { CBox::from_raw(raw) }.expect("EVP_PKEY_CTX_new_from_name")
    }

    #[test]
    fn initialization_variants_reject_a_context_without_a_key() {
        let mut context = context();
        assert!(EVP_PKEY_sign_init(&mut context.as_mut()) <= 0);
        assert!(EVP_PKEY_sign_init_ex(&mut context.as_mut(), None) <= 0);
        assert!(EVP_PKEY_sign_init_ex2(&mut context.as_mut(), None, None) <= 0);
        assert!(EVP_PKEY_verify_init(&mut context.as_mut()) <= 0);
        assert!(EVP_PKEY_verify_init_ex(&mut context.as_mut(), None) <= 0);
        assert!(EVP_PKEY_verify_init_ex2(&mut context.as_mut(), None, None) <= 0);
        assert!(EVP_PKEY_verify_recover_init(&mut context.as_mut()) <= 0);
        assert!(EVP_PKEY_verify_recover_init_ex(&mut context.as_mut(), None) <= 0);
        assert!(EVP_PKEY_verify_recover_init_ex2(&mut context.as_mut(), None, None) <= 0);
    }

    #[test]
    fn operation_wrappers_do_not_expose_raw_buffers() {
        let mut context = context();
        let mut output = [MaybeUninit::uninit(); 32];
        assert_eq!(
            EVP_PKEY_CTX_set_signature(&mut context.as_mut(), b"signature"),
            0,
        );
        assert!(EVP_PKEY_sign(&mut context.as_mut(), &mut output, b"message").is_err());
        assert_eq!(
            EVP_PKEY_verify(&mut context.as_mut(), b"signature", b"message"),
            -1,
        );
        assert!(EVP_PKEY_verify_recover(&mut context.as_mut(), &mut output, b"signature").is_err());
    }
}

/// Wraps: EVP_PKEY_CTX_set_signature
///
/// Copies a signature value into the active provider operation parameters.
#[allow(non_snake_case)]
pub fn EVP_PKEY_CTX_set_signature(ctx: &mut EvpPkeyCtxMut<'_>, signature: &[u8]) -> i32 {
    // SAFETY: the exclusive context is live and the readable signature run
    // remains valid for the synchronous parameter-setting operation.
    unsafe {
        ffi::EVP_PKEY_CTX_set_signature(ctx.as_mut_ptr(), signature.as_ptr(), signature.len())
    }
}

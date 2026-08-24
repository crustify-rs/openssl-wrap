//! Wrappers assigned from `crypto/evp/kem.c`.

#![allow(non_snake_case)]

use core::ptr;

use libcrypto_sys as ffi;

use crate::core::openssl_core::OsslParamArray;
use crate::evp::evp::{EvpPkeyCtxMut, EvpPkeyRef};

fn params_ptr(params: Option<&OsslParamArray<'_>>) -> *const ffi::ossl_param_st {
    params.map_or(ptr::null(), OsslParamArray::as_ptr)
}

/// Wraps: EVP_PKEY_auth_decapsulate_init
pub fn EVP_PKEY_auth_decapsulate_init(
    ctx: &mut EvpPkeyCtxMut<'_>,
    authentication_public_key: EvpPkeyRef<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    // SAFETY: all handles and the optional terminated parameter array are live
    // for the call. Provider initialization consumes no caller ownership.
    unsafe {
        ffi::EVP_PKEY_auth_decapsulate_init(
            ctx.as_mut_ptr(),
            authentication_public_key.as_ptr().cast_mut(),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_PKEY_auth_encapsulate_init
pub fn EVP_PKEY_auth_encapsulate_init(
    ctx: &mut EvpPkeyCtxMut<'_>,
    authentication_private_key: EvpPkeyRef<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    // SAFETY: as the authenticated decapsulation initializer.
    unsafe {
        ffi::EVP_PKEY_auth_encapsulate_init(
            ctx.as_mut_ptr(),
            authentication_private_key.as_ptr().cast_mut(),
            params_ptr(params),
        )
    }
}

/// Wraps: EVP_PKEY_decapsulate
/// Decapsulates into `secret`, or queries its required length when `None`.
#[must_use]
pub fn EVP_PKEY_decapsulate(
    ctx: &mut EvpPkeyCtxMut<'_>,
    secret: Option<&mut [u8]>,
    wrapped_key: &[u8],
) -> (i32, usize) {
    let (secret, mut secret_len) = secret.map_or((ptr::null_mut(), 0), |secret| {
        (secret.as_mut_ptr(), secret.len())
    });
    // SAFETY: the output is null or supplies `secret_len` writable bytes; the
    // wrapped key supplies exactly its readable slice length.
    let status = unsafe {
        ffi::EVP_PKEY_decapsulate(
            ctx.as_mut_ptr(),
            secret,
            &mut secret_len,
            wrapped_key.as_ptr(),
            wrapped_key.len(),
        )
    };
    (status, secret_len)
}

/// Wraps: EVP_PKEY_decapsulate_init
pub fn EVP_PKEY_decapsulate_init(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    // SAFETY: the exclusive context and optional terminated array are live.
    unsafe { ffi::EVP_PKEY_decapsulate_init(ctx.as_mut_ptr(), params_ptr(params)) }
}

/// Wraps: EVP_PKEY_encapsulate
/// Encapsulates into both buffers, or queries both lengths when `output` is `None`.
#[must_use]
pub fn EVP_PKEY_encapsulate(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: Option<(&mut [u8], &mut [u8])>,
) -> (i32, usize, usize) {
    let (wrapped, mut wrapped_len, secret, mut secret_len) = output.map_or(
        (ptr::null_mut(), 0, ptr::null_mut(), 0),
        |(wrapped, secret)| {
            (
                wrapped.as_mut_ptr(),
                wrapped.len(),
                secret.as_mut_ptr(),
                secret.len(),
            )
        },
    );
    // SAFETY: both outputs are simultaneously null for a size query or each
    // points to the writable capacity carried in its adjacent length.
    let status = unsafe {
        ffi::EVP_PKEY_encapsulate(
            ctx.as_mut_ptr(),
            wrapped,
            &mut wrapped_len,
            secret,
            &mut secret_len,
        )
    };
    (status, wrapped_len, secret_len)
}

/// Wraps: EVP_PKEY_encapsulate_init
pub fn EVP_PKEY_encapsulate_init(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    // SAFETY: the exclusive context and optional terminated array are live.
    unsafe { ffi::EVP_PKEY_encapsulate_init(ctx.as_mut_ptr(), params_ptr(params)) }
}

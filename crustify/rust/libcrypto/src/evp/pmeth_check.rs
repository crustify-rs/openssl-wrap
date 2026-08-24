//! Wrappers assigned from `crypto/evp/pmeth_check.c`.

use libcrypto_sys as ffi;

use crate::evp::evp::EvpPkeyCtxMut;

/// Wraps: EVP_PKEY_pairwise_check
#[allow(non_snake_case)]
pub fn EVP_PKEY_pairwise_check(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context handle covers provider export caches and
    // validation state touched synchronously by the check.
    unsafe { ffi::EVP_PKEY_pairwise_check(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_param_check
#[allow(non_snake_case)]
pub fn EVP_PKEY_param_check(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the context remains live and exclusively borrowed for validation.
    unsafe { ffi::EVP_PKEY_param_check(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_param_check_quick
#[allow(non_snake_case)]
pub fn EVP_PKEY_param_check_quick(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the context remains live and exclusively borrowed for validation.
    unsafe { ffi::EVP_PKEY_param_check_quick(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_private_check
#[allow(non_snake_case)]
pub fn EVP_PKEY_private_check(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the context remains live and exclusively borrowed for validation.
    unsafe { ffi::EVP_PKEY_private_check(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_public_check
#[allow(non_snake_case)]
pub fn EVP_PKEY_public_check(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the context remains live and exclusively borrowed for validation.
    unsafe { ffi::EVP_PKEY_public_check(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_public_check_quick
#[allow(non_snake_case)]
pub fn EVP_PKEY_public_check_quick(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the context remains live and exclusively borrowed for validation.
    unsafe { ffi::EVP_PKEY_public_check_quick(context.as_mut_ptr()) }
}

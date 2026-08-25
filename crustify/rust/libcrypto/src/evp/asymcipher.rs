//! Wrappers assigned from `crypto/evp/asymcipher.c`.

#![allow(non_snake_case)]

use core::ptr;

use libcrypto_sys as ffi;

use crate::core::openssl_core::OsslParamArray;
use crate::evp::evp::EvpPkeyCtxMut;

fn init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamArray<'_>>,
    call: unsafe extern "C" fn(*mut ffi::evp_pkey_ctx_st, *const ffi::ossl_param_st) -> i32,
) -> i32 {
    let params = params.map_or(ptr::null(), OsslParamArray::as_ptr);
    // SAFETY: `ctx` is exclusively borrowed for the call and `params` is null
    // or a terminated descriptor array whose referents remain live.
    unsafe { call(ctx.as_mut_ptr(), params) }
}

fn crypt(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: Option<&mut [u8]>,
    input: &[u8],
    call: unsafe extern "C" fn(
        *mut ffi::evp_pkey_ctx_st,
        *mut u8,
        *mut usize,
        *const u8,
        usize,
    ) -> i32,
) -> (i32, usize) {
    let (out, mut out_len) =
        output.map_or((ptr::null_mut(), 0), |out| (out.as_mut_ptr(), out.len()));
    // SAFETY: the exclusive context is live; `input` supplies `input.len()`
    // readable bytes, and a non-null output supplies `out_len` writable bytes.
    let status = unsafe {
        call(
            ctx.as_mut_ptr(),
            out,
            &mut out_len,
            input.as_ptr(),
            input.len(),
        )
    };
    (status, out_len)
}

/// Wraps: EVP_PKEY_decrypt
/// Decrypts into `output`, or queries the required length when it is `None`.
#[must_use]
pub fn EVP_PKEY_decrypt(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: Option<&mut [u8]>,
    input: &[u8],
) -> (i32, usize) {
    crypt(ctx, output, input, ffi::EVP_PKEY_decrypt)
}

/// Wraps: EVP_PKEY_decrypt_init
pub fn EVP_PKEY_decrypt_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle supplies a live operation context.
    unsafe { ffi::EVP_PKEY_decrypt_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_decrypt_init_ex
pub fn EVP_PKEY_decrypt_init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    init_ex(ctx, params, ffi::EVP_PKEY_decrypt_init_ex)
}

/// Wraps: EVP_PKEY_encrypt
/// Encrypts into `output`, or queries the required length when it is `None`.
#[must_use]
pub fn EVP_PKEY_encrypt(
    ctx: &mut EvpPkeyCtxMut<'_>,
    output: Option<&mut [u8]>,
    input: &[u8],
) -> (i32, usize) {
    crypt(ctx, output, input, ffi::EVP_PKEY_encrypt)
}

/// Wraps: EVP_PKEY_encrypt_init
pub fn EVP_PKEY_encrypt_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle supplies a live operation context.
    unsafe { ffi::EVP_PKEY_encrypt_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_encrypt_init_ex
pub fn EVP_PKEY_encrypt_init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    init_ex(ctx, params, ffi::EVP_PKEY_encrypt_init_ex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pmeth_lib::EVP_PKEY_CTX_new_from_name;

    #[test]
    fn rsa_context_accepts_safe_encrypt_initialization() {
        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"RSA", None).expect("RSA context");
        assert!(EVP_PKEY_encrypt_init(&mut ctx.as_mut()) <= 0);
    }
}

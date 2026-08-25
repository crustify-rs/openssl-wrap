//! Wrappers assigned from `crypto/rsa/rsa_lib.c`.

#![allow(non_snake_case)]

use core::ptr::{self, NonNull};

use ffibox::{CSlice, CVec};
use libcrypto_sys as ffi;

use crate::evp::evp::{EvpMdRef, EvpPkeyCtxMut};
use crate::evp::pmeth_lib::{Set0BufferError, set0_buffer};
use crate::mem::CryptoFree;

/// Wraps: EVP_PKEY_CTX_get0_rsa_oaep_label
pub fn EVP_PKEY_CTX_get0_rsa_oaep_label<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> Result<CSlice<'a, u8>, i32> {
    let mut label = ptr::null_mut();
    // SAFETY: the context is exclusively borrowed and the pointer output is writable.
    let len = unsafe { ffi::EVP_PKEY_CTX_get0_rsa_oaep_label(ctx.as_mut_ptr(), &mut label) };
    if len < 0 {
        return Err(len);
    }
    let len = len as usize;
    let Some(label) = NonNull::new(label).or_else(|| (len == 0).then(NonNull::dangling)) else {
        return Err(-1);
    };
    // SAFETY: OpenSSL reported `len` initialized bytes retained by the context;
    // the exclusive borrow prevents a conflicting label replacement.
    Ok(unsafe { CSlice::from_raw_parts(label, len) })
}

/// Wraps: EVP_PKEY_CTX_get_rsa_mgf1_md
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_mgf1_md<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> (i32, Option<EvpMdRef<'a>>) {
    let mut md = ptr::null();
    // SAFETY: the context is exclusive and the pointer output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_mgf1_md(ctx.as_mut_ptr(), &mut md) };
    // SAFETY: a non-null digest is retained by the context/provider state.
    let md = unsafe { EvpMdRef::from_ptr(md.cast_mut()) };
    (status, (status > 0).then_some(md).flatten())
}

/// Wraps: EVP_PKEY_CTX_get_rsa_mgf1_md_name
pub fn EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: &mut EvpPkeyCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the context is exclusive and `output` supplies its exact writable capacity.
    unsafe {
        ffi::EVP_PKEY_CTX_get_rsa_mgf1_md_name(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    }
}

/// Wraps: EVP_PKEY_CTX_get_rsa_oaep_md
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_oaep_md<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> (i32, Option<EvpMdRef<'a>>) {
    let mut md = ptr::null();
    // SAFETY: the context is exclusive and the pointer output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_oaep_md(ctx.as_mut_ptr(), &mut md) };
    // SAFETY: a non-null digest is retained by the context/provider state.
    let md = unsafe { EvpMdRef::from_ptr(md.cast_mut()) };
    (status, (status > 0).then_some(md).flatten())
}

/// Wraps: EVP_PKEY_CTX_get_rsa_oaep_md_name
pub fn EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: &mut EvpPkeyCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the context is exclusive and `output` supplies its exact writable capacity.
    unsafe {
        ffi::EVP_PKEY_CTX_get_rsa_oaep_md_name(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    }
}

/// Wraps: EVP_PKEY_CTX_get_rsa_padding
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_padding(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<i32>) {
    let mut padding = 0;
    // SAFETY: the context is exclusive and the local scalar output is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_padding(ctx.as_mut_ptr(), &mut padding) };
    (status, (status == 1).then_some(padding))
}

/// Wraps: EVP_PKEY_CTX_get_rsa_pss_saltlen
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<i32>) {
    let mut salt_len = 0;
    // SAFETY: the context is exclusive and the local scalar output is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx.as_mut_ptr(), &mut salt_len) };
    (status, (status == 1).then_some(salt_len))
}

/// Wraps: EVP_PKEY_CTX_set0_rsa_oaep_label
pub fn EVP_PKEY_CTX_set0_rsa_oaep_label(
    ctx: &mut EvpPkeyCtxMut<'_>,
    label: CVec<u8, CryptoFree>,
) -> Result<(), Set0BufferError> {
    set0_buffer(label, |raw, len| {
        // SAFETY: `set0_buffer` surrendered an OpenSSL allocation of exactly
        // `len` bytes. This C function consumes and frees it only on status 1.
        unsafe { ffi::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_mut_ptr(), raw.cast(), len) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pmeth_lib::EVP_PKEY_CTX_new_from_name;

    #[test]
    fn rsa_outputs_are_initialized_only_on_success() {
        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"RSA", None).expect("RSA context");
        let mut handle = ctx.as_mut();
        let (status, padding) = EVP_PKEY_CTX_get_rsa_padding(&mut handle);
        assert_eq!(padding.is_some(), status == 1);
        let (status, salt_len) = EVP_PKEY_CTX_get_rsa_pss_saltlen(&mut handle);
        assert_eq!(salt_len.is_some(), status == 1);
        let mut name = [0_u8; 80];
        assert!(EVP_PKEY_CTX_get_rsa_oaep_md_name(&mut handle, &mut name) <= 1);
    }
}

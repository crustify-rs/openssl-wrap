//! Wrappers assigned from `crypto/evp/dh_ctrl.c`.

#![allow(non_snake_case)]

use core::ptr;
#[cfg(feature = "deprecated-3-0")]
use core::ptr::NonNull;

#[cfg(feature = "deprecated-3-0")]
use ffibox::CSlice;
use ffibox::CVec;
use libcrypto_sys as ffi;

use crate::evp::evp::{EvpMdRef, EvpPkeyCtxMut};
use crate::evp::pmeth_lib::{Set0BufferError, set0_buffer};
use crate::mem::CryptoFree;

/// Wraps: EVP_PKEY_CTX_get0_dh_kdf_ukm
#[cfg(feature = "deprecated-3-0")]
#[must_use]
pub fn EVP_PKEY_CTX_get0_dh_kdf_ukm<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> Result<CSlice<'a, u8>, i32> {
    let mut ukm = ptr::null_mut();
    // SAFETY: the context is exclusively borrowed and the local pointer slot is writable.
    let len = unsafe { ffi::EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx.as_mut_ptr(), &mut ukm) };
    if len < 0 {
        return Err(len);
    }
    let len = len as usize;
    let Some(ukm) = NonNull::new(ukm).or_else(|| (len == 0).then(NonNull::dangling)) else {
        return Err(-1);
    };
    // SAFETY: OpenSSL reported `len` initialized UKM bytes retained by the
    // context; the exclusive context borrow keeps them live and unmodified.
    Ok(unsafe { CSlice::from_raw_parts(ukm, len) })
}

/// Wraps: EVP_PKEY_CTX_get_dh_kdf_md
#[must_use]
pub fn EVP_PKEY_CTX_get_dh_kdf_md<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> (i32, Option<EvpMdRef<'a>>) {
    let mut md = ptr::null();
    // SAFETY: the context is exclusive and the pointer output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_dh_kdf_md(ctx.as_mut_ptr(), &mut md) };
    // SAFETY: a non-null digest is retained by the live context/provider state.
    let md = unsafe { EvpMdRef::from_ptr(md.cast_mut()) };
    (status, (status > 0).then_some(md).flatten())
}

/// Wraps: EVP_PKEY_CTX_get_dh_kdf_outlen
#[must_use]
pub fn EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<i32>) {
    let mut len = 0;
    // SAFETY: the context is exclusive and the scalar output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_dh_kdf_outlen(ctx.as_mut_ptr(), &mut len) };
    (status, (status == 1).then_some(len))
}

/// Wraps: EVP_PKEY_CTX_get_dh_kdf_type
#[must_use]
pub fn EVP_PKEY_CTX_get_dh_kdf_type(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context remains live for the scalar control query.
    unsafe { ffi::EVP_PKEY_CTX_get_dh_kdf_type(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_set0_dh_kdf_ukm
pub fn EVP_PKEY_CTX_set0_dh_kdf_ukm(
    ctx: &mut EvpPkeyCtxMut<'_>,
    ukm: CVec<u8, CryptoFree>,
) -> Result<(), Set0BufferError> {
    set0_buffer(ukm, |raw, len| {
        // SAFETY: `set0_buffer` surrendered an OpenSSL-allocated run of exactly
        // `len` bytes. This C function consumes it only when returning 1.
        unsafe { ffi::EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx.as_mut_ptr(), raw, len) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::pmeth_lib::EVP_PKEY_CTX_new_from_name;

    #[test]
    fn getters_preserve_unsupported_statuses() {
        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"DH", None).expect("DH context");
        let mut handle = ctx.as_mut();
        let status = EVP_PKEY_CTX_get_dh_kdf_type(&mut handle);
        assert!(status <= 1);
        let (status, len) = EVP_PKEY_CTX_get_dh_kdf_outlen(&mut handle);
        assert_eq!(len.is_some(), status == 1);
    }
}

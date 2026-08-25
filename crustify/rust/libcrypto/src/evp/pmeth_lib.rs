//! Wrappers assigned from `crypto/evp/pmeth_lib.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr::NonNull;

use ffibox::CSlice;
use libcrypto_sys as ffi;

use crate::core::openssl_core::{OsslParam, terminated_param_len};
use crate::evp::evp::{EvpMdRef, EvpPkeyCtxMut, EvpPkeyCtxRef};

/// Wraps: EVP_PKEY_CTX_set_scrypt_N
pub fn EVP_PKEY_CTX_set_scrypt_N(ctx: &mut EvpPkeyCtxMut<'_>, n: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context; the scalar is
    // copied into provider or legacy operation state before the call returns.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_N(ctx.as_mut_ptr(), n) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_maxmem_bytes
pub fn EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx: &mut EvpPkeyCtxMut<'_>, maxmem_bytes: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context and OpenSSL copies
    // the scalar value synchronously.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_maxmem_bytes(ctx.as_mut_ptr(), maxmem_bytes) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_p
pub fn EVP_PKEY_CTX_set_scrypt_p(ctx: &mut EvpPkeyCtxMut<'_>, p: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context and OpenSSL copies
    // the scalar value synchronously.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_p(ctx.as_mut_ptr(), p) }
}

/// Wraps: EVP_PKEY_CTX_set_scrypt_r
pub fn EVP_PKEY_CTX_set_scrypt_r(ctx: &mut EvpPkeyCtxMut<'_>, r: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context and OpenSSL copies
    // the scalar value synchronously.
    unsafe { ffi::EVP_PKEY_CTX_set_scrypt_r(ctx.as_mut_ptr(), r) }
}

fn md_ptr(md: Option<EvpMdRef<'static>>) -> *const ffi::evp_md_st {
    md.map_or(core::ptr::null(), |md| md.as_ptr())
}

/// Wraps: EVP_PKEY_CTX_set_signature_md
///
/// A legacy operation may retain the digest pointer without raising its
/// reference count, so the safe surface accepts only an immortal digest
/// implementation. `None` selects OpenSSL's documented empty digest value.
pub fn EVP_PKEY_CTX_set_signature_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    md: Option<EvpMdRef<'static>>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and a non-null digest is
    // live for the rest of the process, covering both provider copying and a
    // legacy method retaining the pointer.
    unsafe { ffi::EVP_PKEY_CTX_set_signature_md(ctx.as_mut_ptr(), md_ptr(md)) }
}

/// Wraps: EVP_PKEY_CTX_set_tls1_prf_md
///
/// A legacy operation may retain the digest pointer without raising its
/// reference count, so the safe surface accepts only an immortal digest
/// implementation. `None` selects OpenSSL's documented empty digest value.
pub fn EVP_PKEY_CTX_set_tls1_prf_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    md: Option<EvpMdRef<'static>>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and a non-null digest is
    // immortal, satisfying either a synchronous provider copy or a retained
    // legacy pointer.
    unsafe { ffi::EVP_PKEY_CTX_set_tls1_prf_md(ctx.as_mut_ptr(), md_ptr(md)) }
}

/// Wraps: EVP_PKEY_CTX_settable_params
///
/// Borrows the provider's null-key-terminated table of accepted descriptors.
#[must_use]
pub fn EVP_PKEY_CTX_settable_params<'a>(
    ctx: EvpPkeyCtxRef<'a>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the shared context handle is live; OpenSSL returns null or a
    // provider-owned terminated descriptor table retained by context state.
    let raw = unsafe { ffi::EVP_PKEY_CTX_settable_params(ctx.as_ptr()) };
    let start = NonNull::new(raw.cast_mut().cast::<OsslParam<'a>>())?;
    // SAFETY: the public return contract promises a reachable null-key
    // terminator on every non-null result.
    let len = unsafe { terminated_param_len(raw) }?;
    // SAFETY: the scan established exactly `len` initialized descriptors, and
    // their provider storage remains live for the context handle's lifetime.
    unsafe { Some(CSlice::from_raw_parts(start, len)) }
}

/// Wraps: EVP_PKEY_CTX_str2ctrl
pub fn EVP_PKEY_CTX_str2ctrl(ctx: &mut EvpPkeyCtxMut<'_>, command: i32, value: &CStr) -> i32 {
    // SAFETY: the exclusive context and NUL-terminated string remain live for
    // the synchronous legacy control operation.
    unsafe { ffi::EVP_PKEY_CTX_str2ctrl(ctx.as_mut_ptr(), command, value.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::evp::evp::EvpPkeyCtx;

    fn context(name: &CStr) -> CBox<EvpPkeyCtx> {
        // SAFETY: null selects the process-wide library context and property
        // query, while `name` is a live NUL-terminated algorithm name.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), name.as_ptr(), core::ptr::null())
        };
        // SAFETY: a non-null result transfers one complete context allocation.
        unsafe { CBox::from_raw(raw) }.expect("EVP_PKEY_CTX_new_from_name")
    }

    #[test]
    fn scrypt_scalars_use_an_exclusive_context() {
        let mut ctx = context(c"SCRYPT");
        // SAFETY: the context is live and exclusively borrowed; derive-init
        // initializes its provider operation state before the setters run.
        assert_eq!(
            unsafe { ffi::EVP_PKEY_derive_init(ctx.as_mut().as_mut_ptr()) },
            1
        );
        let mut ctx = ctx.as_mut();
        assert_eq!(EVP_PKEY_CTX_set_scrypt_N(&mut ctx, 1024), 1);
        assert_eq!(EVP_PKEY_CTX_set_scrypt_r(&mut ctx, 8), 1);
        assert_eq!(EVP_PKEY_CTX_set_scrypt_p(&mut ctx, 1), 1);
        assert_eq!(
            EVP_PKEY_CTX_set_scrypt_maxmem_bytes(&mut ctx, 1024 * 1024),
            1
        );
        assert!(EVP_PKEY_CTX_settable_params(ctx.as_ref()).is_some());
    }

    #[test]
    fn nullable_digest_and_string_control_are_typed() {
        let mut ctx = context(c"RSA");
        let mut ctx = ctx.as_mut();
        assert!(EVP_PKEY_CTX_set_signature_md(&mut ctx, None) <= 0);
        assert!(EVP_PKEY_CTX_set_tls1_prf_md(&mut ctx, None) <= 0);
        assert!(EVP_PKEY_CTX_str2ctrl(&mut ctx, 0, c"value") <= 0);
    }
}

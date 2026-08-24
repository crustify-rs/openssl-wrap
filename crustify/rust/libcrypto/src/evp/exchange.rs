//! Wrappers assigned from `crypto/evp/exchange.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr;

use libcrypto_sys as ffi;

use crate::core::openssl_core::OsslParamArray;
use crate::evp::evp::{EvpPkeyCtxMut, EvpPkeyRef, SharedEvpSkey};
use crate::evp::evp_local::EvpSkeymgmtRef;

/// Wraps: EVP_PKEY_derive
/// Derives into `key`, or queries the maximum result length when it is `None`.
#[must_use]
pub fn EVP_PKEY_derive(ctx: &mut EvpPkeyCtxMut<'_>, key: Option<&mut [u8]>) -> (i32, usize) {
    let (key, mut len) = key.map_or((ptr::null_mut(), 0), |key| (key.as_mut_ptr(), key.len()));
    // SAFETY: the context is exclusively borrowed and a non-null output points
    // to `len` writable bytes; null requests only the size.
    let status = unsafe { ffi::EVP_PKEY_derive(ctx.as_mut_ptr(), key, &mut len) };
    (status, len)
}

/// Wraps: EVP_PKEY_derive_SKEY
/// Derives a freshly owned provider secret-key object.
#[must_use]
pub fn EVP_PKEY_derive_SKEY<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
    management: Option<EvpSkeymgmtRef<'_>>,
    key_type: Option<&CStr>,
    property_query: Option<&CStr>,
    key_len: usize,
    params: Option<&OsslParamArray<'_>>,
) -> Option<SharedEvpSkey<'a>> {
    let management =
        management.map_or(ptr::null_mut(), |management| management.as_ptr().cast_mut());
    let key_type = key_type.map_or(ptr::null(), CStr::as_ptr);
    let property_query = property_query.map_or(ptr::null(), CStr::as_ptr);
    let params = params.map_or(ptr::null(), OsslParamArray::as_ptr);
    // SAFETY: every optional pointer is null or backed by its safe borrowed
    // value; the exclusive context remains live for the returned dependency.
    let raw = unsafe {
        ffi::EVP_PKEY_derive_SKEY(
            ctx.as_mut_ptr(),
            management,
            key_type,
            property_query,
            key_len,
            params,
        )
    };
    // SAFETY: a non-null result transfers one `EVP_SKEY_free` obligation and
    // is conservatively tied to the operation context borrow.
    unsafe { SharedEvpSkey::from_raw(raw) }
}

/// Wraps: EVP_PKEY_derive_init
pub fn EVP_PKEY_derive_init(ctx: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle supplies a live operation context.
    unsafe { ffi::EVP_PKEY_derive_init(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_derive_init_ex
pub fn EVP_PKEY_derive_init_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    params: Option<&OsslParamArray<'_>>,
) -> i32 {
    let params = params.map_or(ptr::null(), OsslParamArray::as_ptr);
    // SAFETY: `params` is null or a live terminated descriptor array, and the
    // context is exclusively borrowed for initialization.
    unsafe { ffi::EVP_PKEY_derive_init_ex(ctx.as_mut_ptr(), params) }
}

/// Wraps: EVP_PKEY_derive_set_peer
pub fn EVP_PKEY_derive_set_peer(ctx: &mut EvpPkeyCtxMut<'_>, peer: EvpPkeyRef<'_>) -> i32 {
    // SAFETY: both handles are live. OpenSSL raises its own peer reference on
    // success, so no Rust borrow is stored without a matching C keepalive.
    unsafe { ffi::EVP_PKEY_derive_set_peer(ctx.as_mut_ptr(), peer.as_ptr().cast_mut()) }
}

/// Wraps: EVP_PKEY_derive_set_peer_ex
pub fn EVP_PKEY_derive_set_peer_ex(
    ctx: &mut EvpPkeyCtxMut<'_>,
    peer: EvpPkeyRef<'_>,
    validate_peer: bool,
) -> i32 {
    // SAFETY: as `EVP_PKEY_derive_set_peer`; the boolean is represented by the
    // documented C integer convention.
    unsafe {
        ffi::EVP_PKEY_derive_set_peer_ex(
            ctx.as_mut_ptr(),
            peer.as_ptr().cast_mut(),
            i32::from(validate_peer),
        )
    }
}

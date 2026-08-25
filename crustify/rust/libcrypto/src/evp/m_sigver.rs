//! Wrappers assigned from `crypto/evp/m_sigver.c`.

use core::ffi::CStr;
use core::ptr;

use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::OsslParamListRef;
use crate::evp::evp::{EvpMdRef, EvpPkeyCtxRef, EvpPkeyRef};
use crate::evp::evp_local::EvpMdCtxMut;

fn optional_cstr(value: Option<&CStr>) -> *const core::ffi::c_char {
    value.map_or(ptr::null(), CStr::as_ptr)
}

fn pkey_ptr(key: Option<EvpPkeyRef<'_>>) -> *mut ffi::evp_pkey_st {
    key.map_or(ptr::null_mut(), |key| key.as_ptr().cast_mut())
}

fn digest_ptr(digest: Option<EvpMdRef<'_>>) -> *const ffi::evp_md_st {
    digest.map_or(ptr::null(), |digest| digest.as_ptr())
}

fn params_ptr(params: Option<&OsslParamListRef<'_, '_>>) -> *const ffi::ossl_param_st {
    params.map_or(ptr::null(), OsslParamListRef::as_ptr)
}

/// Wraps: EVP_DigestSign
#[allow(non_snake_case)]
pub fn EVP_DigestSign(
    ctx: &mut EvpMdCtxMut<'_>,
    output: &mut [u8],
    message: &[u8],
) -> Result<usize, i32> {
    let mut len = output.len();
    // SAFETY: the exclusive context is live, both slices carry their exact
    // extents, and `len` supplies the output capacity on entry.
    let status = unsafe {
        ffi::EVP_DigestSign(
            ctx.as_mut_ptr(),
            output.as_mut_ptr(),
            &mut len,
            message.as_ptr(),
            message.len(),
        )
    };
    if status == 1 && len <= output.len() {
        Ok(len)
    } else {
        Err(status)
    }
}

/// Wraps: EVP_DigestSign
/// Queries the signature buffer size without finalizing the context.
#[allow(non_snake_case)]
pub fn EVP_DigestSign_size(ctx: &mut EvpMdCtxMut<'_>, message: &[u8]) -> Result<usize, i32> {
    let mut len = 0usize;
    // SAFETY: null output selects the documented size query, the message is a
    // live readable slice, and `len` is writable.
    let status = unsafe {
        ffi::EVP_DigestSign(
            ctx.as_mut_ptr(),
            ptr::null_mut(),
            &mut len,
            message.as_ptr(),
            message.len(),
        )
    };
    (status == 1).then_some(len).ok_or(status)
}

/// Wraps: EVP_DigestSignFinal
#[allow(non_snake_case)]
pub fn EVP_DigestSignFinal(ctx: &mut EvpMdCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    let mut len = output.len();
    // SAFETY: the exclusive context and output are live, and `len` contains
    // the slice capacity on entry.
    let status =
        unsafe { ffi::EVP_DigestSignFinal(ctx.as_mut_ptr(), output.as_mut_ptr(), &mut len) };
    if status == 1 && len <= output.len() {
        Ok(len)
    } else {
        Err(status)
    }
}

/// Wraps: EVP_DigestSignFinal
/// Queries the final signature size without finalizing the context.
#[allow(non_snake_case)]
pub fn EVP_DigestSignFinal_size(ctx: &mut EvpMdCtxMut<'_>) -> Result<usize, i32> {
    let mut len = 0usize;
    // SAFETY: null output selects the documented size query and `len` is a
    // live writable slot.
    let status = unsafe { ffi::EVP_DigestSignFinal(ctx.as_mut_ptr(), ptr::null_mut(), &mut len) };
    (status == 1).then_some(len).ok_or(status)
}

/// Wraps: EVP_DigestSignInit
#[allow(non_snake_case)]
pub fn EVP_DigestSignInit<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest: Option<EvpMdRef<'_>>,
    key: Option<EvpPkeyRef<'_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    let mut pctx = ptr::null_mut();
    // SAFETY: all typed handles are live, null is the only supported ENGINE
    // value, and the output pointer slot is writable.
    let status = unsafe {
        ffi::EVP_DigestSignInit(
            ctx.as_mut_ptr(),
            &mut pctx,
            digest_ptr(digest),
            ptr::null_mut(),
            pkey_ptr(key),
        )
    };
    // SAFETY: a non-null result points into state retained by `ctx`; `'a`
    // prevents the returned shared handle from outliving or aliasing mutation
    // through that context borrow.
    (status, unsafe { EvpPkeyCtxRef::from_ptr(pctx) })
}

/// Wraps: EVP_DigestSignInit_ex
/// Initializes signing in the process-wide default library context.
#[allow(non_snake_case)]
pub fn EVP_DigestSignInit_ex<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest_name: Option<&CStr>,
    properties: Option<&CStr>,
    key: Option<EvpPkeyRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    // SAFETY: a null library context is process-wide and cannot be outlived.
    unsafe { EVP_DigestSignInit_ex_with_libctx(ctx, digest_name, None, properties, key, params) }
}

/// Wraps: EVP_DigestSignInit_ex
/// Initializes signing with an explicit library context.
///
/// # Safety
///
/// `libctx` must outlive the underlying digest context, including after the
/// returned mutable borrow ends, because OpenSSL may retain it in `ctx->pctx`.
#[allow(non_snake_case)]
pub unsafe fn EVP_DigestSignInit_ex_with_libctx<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest_name: Option<&CStr>,
    libctx: Option<OsslLibCtxRef<'_>>,
    properties: Option<&CStr>,
    key: Option<EvpPkeyRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    let mut pctx = ptr::null_mut();
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the caller establishes the retained library-context lifetime;
    // all other typed inputs and the output slot are live for the call.
    let status = unsafe {
        ffi::EVP_DigestSignInit_ex(
            ctx.as_mut_ptr(),
            &mut pctx,
            optional_cstr(digest_name),
            libctx,
            optional_cstr(properties),
            pkey_ptr(key),
            params_ptr(params),
        )
    };
    // SAFETY: a non-null operation context is retained by `ctx` and bounded by
    // the returned borrow.
    (status, unsafe { EvpPkeyCtxRef::from_ptr(pctx) })
}

/// Wraps: EVP_DigestSignUpdate
#[allow(non_snake_case)]
pub fn EVP_DigestSignUpdate(ctx: &mut EvpMdCtxMut<'_>, data: &[u8]) -> i32 {
    // SAFETY: the context is exclusively borrowed and the slice supplies the
    // exact readable byte count.
    unsafe { ffi::EVP_DigestSignUpdate(ctx.as_mut_ptr(), data.as_ptr().cast(), data.len()) }
}

/// Wraps: EVP_DigestVerify
#[allow(non_snake_case)]
pub fn EVP_DigestVerify(ctx: &mut EvpMdCtxMut<'_>, signature: &[u8], message: &[u8]) -> i32 {
    // SAFETY: both input slices and the exclusive context are live for the
    // complete synchronous verification.
    unsafe {
        ffi::EVP_DigestVerify(
            ctx.as_mut_ptr(),
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
        )
    }
}

/// Wraps: EVP_DigestVerifyFinal
#[allow(non_snake_case)]
pub fn EVP_DigestVerifyFinal(ctx: &mut EvpMdCtxMut<'_>, signature: &[u8]) -> i32 {
    // SAFETY: the exclusive context and exact signature extent are live.
    unsafe { ffi::EVP_DigestVerifyFinal(ctx.as_mut_ptr(), signature.as_ptr(), signature.len()) }
}

/// Wraps: EVP_DigestVerifyInit
#[allow(non_snake_case)]
pub fn EVP_DigestVerifyInit<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest: Option<EvpMdRef<'_>>,
    key: Option<EvpPkeyRef<'_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    let mut pctx = ptr::null_mut();
    // SAFETY: all typed handles are live, null is the only supported ENGINE
    // value, and the output slot is writable.
    let status = unsafe {
        ffi::EVP_DigestVerifyInit(
            ctx.as_mut_ptr(),
            &mut pctx,
            digest_ptr(digest),
            ptr::null_mut(),
            pkey_ptr(key),
        )
    };
    // SAFETY: a non-null pkey context is retained by and borrowed from `ctx`.
    (status, unsafe { EvpPkeyCtxRef::from_ptr(pctx) })
}

/// Wraps: EVP_DigestVerifyInit_ex
/// Initializes verification in the process-wide default library context.
#[allow(non_snake_case)]
pub fn EVP_DigestVerifyInit_ex<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest_name: Option<&CStr>,
    properties: Option<&CStr>,
    key: Option<EvpPkeyRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    // SAFETY: a null library context is process-wide and cannot be outlived.
    unsafe { EVP_DigestVerifyInit_ex_with_libctx(ctx, digest_name, None, properties, key, params) }
}

/// Wraps: EVP_DigestVerifyInit_ex
/// Initializes verification with an explicit library context.
///
/// # Safety
///
/// `libctx` must outlive the underlying digest context because OpenSSL may
/// retain it in `ctx->pctx` beyond this mutable borrow.
#[allow(non_snake_case)]
pub unsafe fn EVP_DigestVerifyInit_ex_with_libctx<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest_name: Option<&CStr>,
    libctx: Option<OsslLibCtxRef<'_>>,
    properties: Option<&CStr>,
    key: Option<EvpPkeyRef<'_>>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    let mut pctx = ptr::null_mut();
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the caller establishes the retained context lifetime and all
    // typed inputs/output storage are live for the call.
    let status = unsafe {
        ffi::EVP_DigestVerifyInit_ex(
            ctx.as_mut_ptr(),
            &mut pctx,
            optional_cstr(digest_name),
            libctx,
            optional_cstr(properties),
            pkey_ptr(key),
            params_ptr(params),
        )
    };
    // SAFETY: a non-null pkey context is retained by and borrowed from `ctx`.
    (status, unsafe { EvpPkeyCtxRef::from_ptr(pctx) })
}

/// Wraps: EVP_DigestVerifyUpdate
#[allow(non_snake_case)]
pub fn EVP_DigestVerifyUpdate(ctx: &mut EvpMdCtxMut<'_>, data: &[u8]) -> i32 {
    // SAFETY: the exclusive context and exact readable extent are live.
    unsafe { ffi::EVP_DigestVerifyUpdate(ctx.as_mut_ptr(), data.as_ptr().cast(), data.len()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::digest::{EVP_DigestInit_ex, EVP_MD_CTX_new, EVP_MD_fetch};

    #[test]
    fn update_variants_fall_back_to_plain_digest_updates() {
        let digest = EVP_MD_fetch(None, c"SHA2-256", None).expect("fetch");
        let mut ctx = EVP_MD_CTX_new().expect("context");
        assert_eq!(
            EVP_DigestInit_ex(&mut ctx.as_mut(), Some(digest.as_ref())),
            1
        );
        assert_eq!(EVP_DigestSignUpdate(&mut ctx.as_mut(), b"a"), 1);

        assert_eq!(
            EVP_DigestInit_ex(&mut ctx.as_mut(), Some(digest.as_ref())),
            1
        );
        assert_eq!(EVP_DigestVerifyUpdate(&mut ctx.as_mut(), b"b"), 1);
    }
}

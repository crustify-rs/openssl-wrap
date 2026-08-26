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

/// Which half of `do_sigver_init` a shared seam drives.
#[derive(Clone, Copy)]
enum SigverOp {
    Sign,
    Verify,
}

/// The single FFI seam behind the four `EVP_Digest{Sign,Verify}Init` wrappers.
///
/// # Safety
///
/// A non-null `digest` is stored in `ctx->reqdigest` without a reference count
/// and must outlive the digest context; see [`EVP_DigestSignInit_with_md`].
unsafe fn sigver_init<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest: *const ffi::evp_md_st,
    key: Option<EvpPkeyRef<'_>>,
    op: SigverOp,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    let mut pctx = ptr::null_mut();
    let ctx = ctx.as_mut_ptr();
    let key = pkey_ptr(key);
    // SAFETY: the context and key handles are live, null is the only supported
    // ENGINE value, the output slot is writable, and the caller establishes
    // the retained-digest obligation.
    let status = unsafe {
        match op {
            SigverOp::Sign => ffi::EVP_DigestSignInit(ctx, &mut pctx, digest, ptr::null_mut(), key),
            SigverOp::Verify => {
                ffi::EVP_DigestVerifyInit(ctx, &mut pctx, digest, ptr::null_mut(), key)
            }
        }
    };
    // SAFETY: a non-null operation context is retained by the digest context;
    // `'a` prevents the returned shared handle from outliving or aliasing
    // mutation through that context borrow.
    (status, unsafe { EvpPkeyCtxRef::from_ptr(pctx) })
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
/// Initializes signing with the digest the key's algorithm selects by default.
///
/// No caller-held digest record is handed to C, so the context fetches the
/// digest itself into `ctx->fetched_digest` and settles that reference on
/// reset. Use [`EVP_DigestSignInit_with_md`] to install a digest the caller
/// holds, or [`EVP_DigestSignInit_ex`] to name one.
#[allow(non_snake_case)]
pub fn EVP_DigestSignInit<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    key: Option<EvpPkeyRef<'_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    // SAFETY: a null digest leaves `ctx->reqdigest` pointing at a record the
    // context fetched and owns, so the retained-borrow obligation of
    // `EVP_DigestSignInit_with_md` is discharged here.
    unsafe { sigver_init(ctx, ptr::null(), key, SigverOp::Sign) }
}

/// Wraps: EVP_DigestSignInit
/// Initializes signing with a digest implementation the caller holds.
///
/// # Safety
///
/// `digest` must remain live until this digest context is reset,
/// reinitialized or freed, and until every context copied or duplicated from
/// it is, because the copy carries the same unowned pointer.
///
/// Unlike `EVP_DigestInit_ex2`, which adopts one reference into
/// `ctx->fetched_digest`, `do_sigver_init` only records `ctx->reqdigest =
/// type` and never raises the digest's reference count. Every later read of
/// that field dereferences the caller's record —
/// [`EVP_MD_CTX_get0_md`](crate::evp::evp_lib::EVP_MD_CTX_get0_md),
/// [`EVP_MD_CTX_get1_md`](crate::evp::evp_lib::EVP_MD_CTX_get1_md), which also
/// up-references it, [`EVP_MD_CTX_get_size_ex`](crate::evp::evp_lib::EVP_MD_CTX_get_size_ex)
/// and [`EVP_MD_CTX_copy_ex`](crate::evp::digest::EVP_MD_CTX_copy_ex), which
/// copies the same unowned pointer into its destination.
///
/// Holding an owning [`SharedEvpMd`](crate::evp::evp::SharedEvpMd) is not
/// enough on its own: dropping it runs `EVP_MD_free`, which releases a record
/// carrying `EVP_MD_FLAG_NO_STORE`, and releases every fetched record in an
/// `OPENSSL_NO_CACHED_FETCH` build.
#[allow(non_snake_case)]
pub unsafe fn EVP_DigestSignInit_with_md<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest: EvpMdRef<'_>,
    key: Option<EvpPkeyRef<'_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    // SAFETY: the caller establishes that the stored, unreferenced digest
    // outlives the context.
    unsafe { sigver_init(ctx, digest.as_ptr(), key, SigverOp::Sign) }
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
/// Initializes verification with the key's default digest.
///
/// As with [`EVP_DigestSignInit`], omitting the digest leaves the fetched
/// record owned by the context.
#[allow(non_snake_case)]
pub fn EVP_DigestVerifyInit<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    key: Option<EvpPkeyRef<'_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    // SAFETY: a null digest leaves the context owning whatever it fetches.
    unsafe { sigver_init(ctx, ptr::null(), key, SigverOp::Verify) }
}

/// Wraps: EVP_DigestVerifyInit
/// Initializes verification with a digest implementation the caller holds.
///
/// # Safety
///
/// `digest` must remain live until this digest context, and every context
/// copied or duplicated from it, is reset, reinitialized or freed, for the
/// reason spelled out on [`EVP_DigestSignInit_with_md`]: `do_sigver_init`
/// stores it in `ctx->reqdigest` without raising its reference count.
#[allow(non_snake_case)]
pub unsafe fn EVP_DigestVerifyInit_with_md<'a>(
    ctx: &'a mut EvpMdCtxMut<'_>,
    digest: EvpMdRef<'_>,
    key: Option<EvpPkeyRef<'_>>,
) -> (i32, Option<EvpPkeyCtxRef<'a>>) {
    // SAFETY: the caller establishes that the stored, unreferenced digest
    // outlives the context.
    unsafe { sigver_init(ctx, digest.as_ptr(), key, SigverOp::Verify) }
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
    use crate::evp::evp_lib::{EVP_MD_CTX_get0_md, EVP_PKEY_Q_keygen, QuickKeygen};

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

    /// The safe initializers name no digest, so the whole sign/verify round
    /// trip runs without a caller-held `EVP_MD` for the context to borrow.
    #[test]
    fn default_digest_round_trip_needs_no_caller_held_digest() {
        let key = EVP_PKEY_Q_keygen(None, None, QuickKeygen::Ed25519).expect("ED25519 key");

        let mut ctx = EVP_MD_CTX_new().expect("context");
        let mut signer = ctx.as_mut();
        let (status, _) = EVP_DigestSignInit(&mut signer, Some(key.as_ref()));
        assert_eq!(status, 1);
        let len = EVP_DigestSign_size(&mut signer, b"message").expect("signature size");
        let mut signature = vec![0_u8; len];
        assert_eq!(
            EVP_DigestSign(&mut signer, &mut signature, b"message"),
            Ok(len)
        );

        let mut ctx = EVP_MD_CTX_new().expect("context");
        let mut verifier = ctx.as_mut();
        let (status, _) = EVP_DigestVerifyInit(&mut verifier, Some(key.as_ref()));
        assert_eq!(status, 1);
        assert_eq!(EVP_DigestVerify(&mut verifier, &signature, b"message"), 1);
        assert_ne!(EVP_DigestVerify(&mut verifier, &signature, b"other"), 1);
    }

    /// `do_sigver_init` records an explicitly supplied digest as
    /// `ctx->reqdigest` and raises no reference count, so the context hands
    /// back the caller's own record. That identity is the reason
    /// [`EVP_DigestSignInit_with_md`] is `unsafe`.
    #[test]
    fn an_explicit_digest_is_stored_by_pointer_not_by_reference() {
        let key = EVP_PKEY_Q_keygen(None, None, QuickKeygen::Rsa { bits: 2048 }).expect("RSA key");
        let digest = EVP_MD_fetch(None, c"SHA2-256", None).expect("fetch");
        let supplied = digest.as_ref().as_ptr();

        let mut ctx = EVP_MD_CTX_new().expect("context");
        let mut signer = ctx.as_mut();
        // SAFETY: `digest` outlives `ctx` in this scope, which is exactly the
        // obligation the wrapper states.
        let (status, _) =
            unsafe { EVP_DigestSignInit_with_md(&mut signer, digest.as_ref(), Some(key.as_ref())) };
        assert_eq!(status, 1);

        let stored = EVP_MD_CTX_get0_md(ctx.as_ref()).expect("digest recorded");
        assert_eq!(stored.as_ptr(), supplied);
    }
}

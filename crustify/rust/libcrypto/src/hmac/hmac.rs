//! Wrappers assigned from `crypto/hmac/hmac.c`.

#![allow(non_snake_case)]

use core::ptr;

use ffibox::{CBox, impl_dropped};
use libcrypto_sys as ffi;

use crate::evp::evp::EvpMdRef;
use crate::hmac::hmac_local::{HmacCtx, HmacCtxMut, HmacCtxRef};

/// Wraps: HMAC_CTX_copy
/// Copies the complete logical HMAC state into an existing destination.
///
/// # Safety
///
/// The digest borrowed by `source` must remain live for every later use of
/// `destination`, because OpenSSL copies that digest pointer without raising a
/// reference count.
pub unsafe fn HMAC_CTX_copy(destination: &mut HmacCtxMut<'_>, source: HmacCtxRef<'_>) -> i32 {
    // SAFETY: the caller establishes the retained digest lifetime; the typed
    // handles supply live exclusive destination and shared source pointers.
    unsafe { ffi::HMAC_CTX_copy(destination.as_mut_ptr(), source.as_ptr().cast_mut()) }
}

// `HMAC_CTX_free` resets and releases all three owned digest contexts before
// freeing the HMAC allocation. The macro binds that operation to `CBox` drop.
impl_dropped!(HmacCtx, ffi::hmac_ctx_st, ffi::HMAC_CTX_free);

/// Wraps: HMAC_CTX_free
/// Owning HMAC context whose drop invokes the matching C destructor.
pub type HmacCtxOwner = CBox<HmacCtx>;

/// Wraps: HMAC_CTX_get_md
/// Returns the digest borrowed by a context, if one has been selected.
#[must_use]
pub fn HMAC_CTX_get_md(ctx: HmacCtxRef<'_>) -> Option<EvpMdRef<'_>> {
    // SAFETY: the context handle is live, and OpenSSL returns its borrowed
    // digest pointer without changing ownership. The result is bounded by it.
    let raw = unsafe { ffi::HMAC_CTX_get_md(ctx.as_ptr()) };
    // SAFETY: a non-null result remains live for the context borrow.
    unsafe { EvpMdRef::from_ptr(raw.cast_mut()) }
}

/// Wraps: HMAC_CTX_new
/// Allocates a fully initialized legacy HMAC context.
#[must_use]
pub fn HMAC_CTX_new() -> Option<HmacCtxOwner> {
    // SAFETY: OpenSSL returns null or a fresh initialized allocation.
    let raw = unsafe { ffi::HMAC_CTX_new() };
    // SAFETY: a non-null result transfers one `HMAC_CTX_free` obligation.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: HMAC_CTX_reset
/// Clears the selected digest and resets all digest subcontexts.
pub fn HMAC_CTX_reset(ctx: &mut HmacCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive handle supplies a live context for the mutation.
    unsafe { ffi::HMAC_CTX_reset(ctx.as_mut_ptr()) }
}

/// Wraps: HMAC_CTX_set_flags
/// Applies digest-context flags to all three internal digest contexts.
pub fn HMAC_CTX_set_flags(ctx: &mut HmacCtxMut<'_>, flags: core::ffi::c_ulong) {
    // SAFETY: the exclusive handle supplies a live context for the mutation.
    unsafe { ffi::HMAC_CTX_set_flags(ctx.as_mut_ptr(), flags) }
}

/// Wraps: HMAC_Final
/// Finalizes into a buffer after checking it against the selected digest size.
pub fn HMAC_Final(ctx: &mut HmacCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: the shared reborrow is live and the query retains nothing.
    let required = unsafe { ffi::HMAC_size(ctx.as_ref().as_ptr()) };
    if required == 0 || output.len() < required {
        return Err(0);
    }
    let mut written = 0u32;
    // SAFETY: `output` has at least the selected digest size and the exclusive
    // handle prevents another Rust operation changing it during finalization.
    let status = unsafe { ffi::HMAC_Final(ctx.as_mut_ptr(), output.as_mut_ptr(), &mut written) };
    if status == 1 {
        Ok(written as usize)
    } else {
        Err(status)
    }
}

#[cfg(feature = "deprecated-1-1-0")]
/// Wraps: HMAC_Init
/// Invokes the compatibility initializer.
///
/// # Safety
///
/// A non-null `digest` is retained without a reference increment and must
/// outlive every later use of `ctx` (or a reset that clears it).
pub unsafe fn HMAC_Init(
    ctx: &mut HmacCtxMut<'_>,
    key: Option<&[u8]>,
    digest: Option<EvpMdRef<'_>>,
) -> i32 {
    let Some(len) = key.map_or(Some(0), |key| i32::try_from(key.len()).ok()) else {
        return 0;
    };
    let key = key.map_or(ptr::null(), |key| key.as_ptr().cast());
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: the caller establishes the retained digest lifetime and the key
    // is readable for its checked length during this synchronous call.
    unsafe { ffi::HMAC_Init(ctx.as_mut_ptr(), key, len, digest) }
}

/// Wraps: HMAC_Init_ex
/// Selects a digest and optionally installs a copied HMAC key.
///
/// # Safety
///
/// A non-null `digest` is retained without a reference increment and must
/// outlive every later use of `ctx` (or a reset that clears it).
pub unsafe fn HMAC_Init_ex(
    ctx: &mut HmacCtxMut<'_>,
    key: Option<&[u8]>,
    digest: Option<EvpMdRef<'_>>,
) -> i32 {
    let Some(len) = key.map_or(Some(0), |key| i32::try_from(key.len()).ok()) else {
        return 0;
    };
    let key = key.map_or(ptr::null(), |key| key.as_ptr().cast());
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: the caller establishes the retained digest lifetime; the key is
    // readable for its checked length, and null ENGINE is the only supported form.
    unsafe { ffi::HMAC_Init_ex(ctx.as_mut_ptr(), key, len, digest, ptr::null_mut()) }
}

/// Wraps: HMAC_Update
/// Supplies the next byte run to an initialized HMAC context.
pub fn HMAC_Update(ctx: &mut HmacCtxMut<'_>, data: &[u8]) -> i32 {
    // SAFETY: the context is exclusively borrowed and `data` covers `len` bytes.
    unsafe { ffi::HMAC_Update(ctx.as_mut_ptr(), data.as_ptr(), data.len()) }
}

/// Wraps: HMAC_size
/// Returns the selected digest output size, or zero when none is available.
#[must_use]
pub fn HMAC_size(ctx: HmacCtxRef<'_>) -> usize {
    // SAFETY: the shared handle is live and the query retains nothing.
    unsafe { ffi::HMAC_size(ctx.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use crate::evp::evp::SharedEvpMd;

    use super::*;

    #[test]
    fn new_reset_and_uninitialized_size_are_safe() {
        let mut ctx = HMAC_CTX_new().expect("HMAC context");
        assert_eq!(HMAC_size(ctx.as_ref()), 0);
        assert_eq!(HMAC_CTX_reset(&mut ctx.as_mut()), 1);
        assert_eq!(HMAC_Update(&mut ctx.as_mut(), b"not initialized"), 0);
    }

    #[test]
    fn initialized_context_copies_and_finalizes_into_checked_buffers() {
        // SAFETY: null selects the process-wide context and default properties.
        let raw = unsafe { ffi::EVP_MD_fetch(ptr::null_mut(), c"SHA2-256".as_ptr(), ptr::null()) };
        // SAFETY: a successful fetch transfers one public digest reference.
        let digest: SharedEvpMd<'static> = unsafe { SharedEvpMd::from_raw(raw) }.expect("SHA2-256");
        let mut source = HMAC_CTX_new().expect("source");
        let mut copy = HMAC_CTX_new().expect("copy");

        // SAFETY: `digest` remains alive until both contexts have finalized and
        // the copied context inherits the same live dependency.
        assert_eq!(
            unsafe {
                HMAC_Init_ex(
                    &mut source.as_mut(),
                    Some(b"a sufficiently long test key"),
                    Some(digest.as_ref()),
                )
            },
            1
        );
        assert!(HMAC_CTX_get_md(source.as_ref()).is_some());
        HMAC_CTX_set_flags(&mut source.as_mut(), 0);
        assert_eq!(HMAC_Update(&mut source.as_mut(), b"message"), 1);
        // SAFETY: `digest` also remains alive for every use of `copy`.
        assert_eq!(
            unsafe { HMAC_CTX_copy(&mut copy.as_mut(), source.as_ref()) },
            1
        );

        let mut first = [0_u8; 64];
        let mut second = [0_u8; 64];
        let first_len = HMAC_Final(&mut source.as_mut(), &mut first).expect("final");
        let second_len = HMAC_Final(&mut copy.as_mut(), &mut second).expect("copied final");
        assert_eq!(first_len, 32);
        assert_eq!(&first[..first_len], &second[..second_len]);
    }
}

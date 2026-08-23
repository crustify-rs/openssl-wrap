//! Wrappers assigned from `crypto/bio/bss_core.c`.

use core::ptr::NonNull;

use libcrypto_sys as ffi;

use super::internal_bio::{BioMethodRef, static_bio_method};

use super::bio_lib::BorrowedBio;
use super::context::OsslLibCtxRef;

/// Wraps: BIO_new_from_core_bio
/// Wraps a core BIO after acquiring an additional core reference.
///
/// An absent `context` selects the default library context, as it does for
/// [`BIO_new_ex`](crate::bio::bio_lib::BIO_new_ex): C resolves the argument
/// through `ossl_lib_ctx_get_concrete`, which maps null to that context.
///
/// # Safety
///
/// `core_bio` must identify a live core BIO compatible with the dispatch table
/// installed in `context`. This temporary raw seam remains until the opaque
/// `OSSL_CORE_BIO` dependency receives its own wrapper.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn BIO_new_from_core_bio<'a>(
    context: Option<OsslLibCtxRef<'a>>,
    core_bio: NonNull<ffi::OSSL_CORE_BIO>,
) -> Option<BorrowedBio<'a>> {
    let context = context.map_or(core::ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the caller establishes core-BIO compatibility; a supplied context
    // is live for `'a`, and OpenSSL up-refs the core BIO before returning.
    unsafe { BorrowedBio::from_raw(ffi::BIO_new_from_core_bio(context, core_bio.as_ptr())) }
}

/// Wraps: BIO_s_core
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_core() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // null or the address of a `static const` table, which is the
    // process-lifetime borrow `static_bio_method` requires.
    unsafe { static_bio_method(ffi::BIO_s_core()) }
}

//! Wrappers assigned from `crypto/bio/bss_core.c`.

use core::ptr::NonNull;

use libcrypto_sys as ffi;

use super::bio_lib::BorrowedBio;
use super::context::OsslLibCtxRef;

/// Wraps: BIO_new_from_core_bio
/// Wraps a core BIO after acquiring an additional core reference.
///
/// # Safety
///
/// `core_bio` must identify a live core BIO compatible with the dispatch table
/// installed in `context`. This temporary raw seam remains until the opaque
/// `OSSL_CORE_BIO` dependency receives its own wrapper.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn BIO_new_from_core_bio<'a>(
    context: OsslLibCtxRef<'a>,
    core_bio: NonNull<ffi::OSSL_CORE_BIO>,
) -> Option<BorrowedBio<'a>> {
    // SAFETY: the caller establishes core-BIO compatibility; the context is
    // live for `'a`, and OpenSSL up-refs the core BIO before returning.
    unsafe {
        BorrowedBio::from_raw(ffi::BIO_new_from_core_bio(
            context.as_ptr().cast_mut(),
            core_bio.as_ptr(),
        ))
    }
}

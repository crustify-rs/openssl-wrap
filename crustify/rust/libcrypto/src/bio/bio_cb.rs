//! Wrappers assigned from `crypto/bio/bio_cb.c`.

use libcrypto_sys as ffi;

use super::bio_bio_local::BioMut;

/// Wraps: BIO_debug_callback_ex
///
/// # Safety
/// `argp`, `len`, `argi`, `processed`, and `operation` must describe the
/// operation-specific callback payload expected by OpenSSL. The BIO callback
/// argument must be null or point to a live BIO suitable for debug output.
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn BIO_debug_callback_ex(
    bio: &mut BioMut<'_>,
    operation: i32,
    argp: *const core::ffi::c_char,
    len: usize,
    argi: i32,
    argl: core::ffi::c_long,
    result: i32,
    processed: Option<&mut usize>,
) -> core::ffi::c_long {
    let processed = processed.map_or(core::ptr::null_mut(), core::ptr::from_mut);
    // SAFETY: the caller establishes the operation-dependent payload contract;
    // the exclusive BIO handle and optional processed slot are live.
    unsafe {
        ffi::BIO_debug_callback_ex(
            bio.as_mut_ptr(),
            operation,
            argp,
            len,
            argi,
            argl,
            result,
            processed,
        )
    }
}

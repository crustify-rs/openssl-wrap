//! Wrappers assigned from `crypto/asn1/bio_asn1.c`.

use libcrypto_sys as ffi;

use crate::bio::bio_bio_local::BioMut;
use crate::bio::openssl_bio::{Asn1PsCallbacks, Asn1PsCleanupFunc, Asn1PsSetupFunc};

fn get_callbacks(
    bio: &mut BioMut<'_>,
    getter: unsafe extern "C" fn(
        *mut ffi::BIO,
        *mut ffi::asn1_ps_func,
        *mut ffi::asn1_ps_func,
    ) -> i32,
) -> Option<Asn1PsCallbacks> {
    let mut setup = None;
    let mut cleanup = None;
    // SAFETY: the exclusive BIO handle and both initialized output slots are
    // live for this synchronous getter call.
    let ok = unsafe { getter(bio.as_mut_ptr(), &mut setup, &mut cleanup) };
    if ok <= 0 {
        return None;
    }
    // SAFETY: callback pointers stored in a valid ASN.1 BIO obey their setup
    // and cleanup slot contracts.
    let (setup, cleanup) = unsafe {
        (
            Asn1PsSetupFunc::from_raw(setup),
            Asn1PsCleanupFunc::from_raw(cleanup),
        )
    };
    Some(Asn1PsCallbacks::from_valid_slots(setup, cleanup))
}

/// Wraps: BIO_asn1_get_prefix
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_asn1_get_prefix(bio: &mut BioMut<'_>) -> Option<Asn1PsCallbacks> {
    get_callbacks(bio, ffi::BIO_asn1_get_prefix)
}

/// Wraps: BIO_asn1_get_suffix
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_asn1_get_suffix(bio: &mut BioMut<'_>) -> Option<Asn1PsCallbacks> {
    get_callbacks(bio, ffi::BIO_asn1_get_suffix)
}

/// Wraps: BIO_asn1_set_prefix
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_asn1_set_prefix(bio: &mut BioMut<'_>, callbacks: Asn1PsCallbacks) -> bool {
    // SAFETY: the exclusive handle is live and callback wrappers carry static
    // code pointers satisfying the stored ASN.1 BIO contracts.
    unsafe {
        ffi::BIO_asn1_set_prefix(
            bio.as_mut_ptr(),
            callbacks.setup_raw(),
            callbacks.cleanup_raw(),
        ) > 0
    }
}

/// Wraps: BIO_asn1_set_suffix
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_asn1_set_suffix(bio: &mut BioMut<'_>, callbacks: Asn1PsCallbacks) -> bool {
    // SAFETY: as `BIO_asn1_set_prefix`, for the suffix slots.
    unsafe {
        ffi::BIO_asn1_set_suffix(
            bio.as_mut_ptr(),
            callbacks.setup_raw(),
            callbacks.cleanup_raw(),
        ) > 0
    }
}

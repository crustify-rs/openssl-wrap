//! Wrappers assigned from `crypto/bio/bss_dgram.c`.

use libcrypto_sys as ffi;

use ffibox::CBox;

use super::bio_bio_local::Bio;
use super::bio_sock2::BioSocket;

/// Wraps: BIO_dgram_non_fatal_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_dgram_non_fatal_error(error: i32) -> bool {
    // SAFETY: the classifier takes only a by-value error code.
    unsafe { ffi::BIO_dgram_non_fatal_error(error) != 0 }
}

/// Wraps: BIO_new_dgram
/// Transfers an owned datagram socket into a new BIO.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_dgram(socket: BioSocket) -> Option<CBox<Bio>> {
    let descriptor = socket.as_raw_socket();
    // SAFETY: the socket remains owned by `socket` until construction succeeds;
    // BIO_CLOSE makes the resulting BIO responsible for closing it.
    let raw = unsafe { ffi::BIO_new_dgram(descriptor, ffi::BIO_CLOSE as i32) };
    // SAFETY: a non-null constructor result transfers one BIO reference.
    let bio = unsafe { CBox::from_raw(raw) };
    if bio.is_some() {
        let _ = socket.into_raw_socket();
    }
    bio
}

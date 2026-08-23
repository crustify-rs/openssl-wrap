//! Wrappers assigned from `crypto/bio/bss_dgram.c`.

use libcrypto_sys as ffi;

use super::internal_bio::{BioMethodRef, static_bio_method};

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

/// Wraps: BIO_s_datagram
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_datagram() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // null or the address of a `static const` table, which is the
    // process-lifetime borrow `static_bio_method` requires.
    unsafe { static_bio_method(ffi::BIO_s_datagram()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux errno values: `EAGAIN`/`EWOULDBLOCK` is one of the codes the
    /// classifier accepts, `EBADF` is not.
    const EAGAIN: i32 = 11;
    const EBADF: i32 = 9;

    #[test]
    fn only_the_recoverable_datagram_errnos_are_non_fatal() {
        assert!(BIO_dgram_non_fatal_error(EAGAIN));
        assert!(!BIO_dgram_non_fatal_error(EBADF));
        assert!(!BIO_dgram_non_fatal_error(0));
    }
}

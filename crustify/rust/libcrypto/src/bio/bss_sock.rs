//! Wrappers assigned from `crypto/bio/bss_sock.c`.

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::bio_bio_local::Bio;
use super::bio_sock2::BioSocket;
use super::internal_bio::{BioMethodRef, static_bio_method};

/// Wraps: BIO_sock_non_fatal_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_non_fatal_error(error: i32) -> bool {
    // SAFETY: the classifier takes only a by-value socket error.
    unsafe { ffi::BIO_sock_non_fatal_error(error) != 0 }
}

/// Wraps: BIO_sock_should_retry
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_should_retry(result: i32) -> bool {
    // SAFETY: the classifier takes only a by-value operation result.
    unsafe { ffi::BIO_sock_should_retry(result) != 0 }
}

/// Wraps: BIO_new_socket
/// Transfers an owned socket to a newly allocated BIO.
#[allow(non_snake_case)]
pub fn BIO_new_socket(socket: BioSocket) -> Result<CBox<Bio>, BioSocket> {
    let fd = socket.into_raw_socket();
    // SAFETY: `fd` is a live uniquely owned socket. BIO_CLOSE transfers its
    // close responsibility to a successfully created BIO.
    let raw = unsafe { ffi::BIO_new_socket(fd, ffi::BIO_CLOSE as i32) };
    // SAFETY: a non-null result transfers one fully constructed BIO reference.
    match unsafe { CBox::from_raw(raw) } {
        Some(bio) => Ok(bio),
        None => Err(BioSocket::from_result(fd).expect("live socket descriptor")),
    }
}

/// Wraps: BIO_s_socket
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_socket() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // null or the address of a `static const` table, which is the
    // process-lifetime borrow `static_bio_method` requires.
    unsafe { static_bio_method(ffi::BIO_s_socket()) }
}

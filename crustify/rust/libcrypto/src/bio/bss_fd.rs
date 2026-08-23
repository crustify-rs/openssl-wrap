//! Wrappers assigned from `crypto/bio/bss_fd.c`.

use libcrypto_sys as ffi;

use super::internal_bio::{BioMethodRef, static_bio_method};

use ffibox::CBox;
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};

use super::bio_bio_local::Bio;

/// Wraps: BIO_fd_non_fatal_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_fd_non_fatal_error(error: i32) -> bool {
    // SAFETY: the classifier takes only a by-value error code.
    unsafe { ffi::BIO_fd_non_fatal_error(error) != 0 }
}

/// Wraps: BIO_fd_should_retry
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_fd_should_retry(result: i32) -> bool {
    // SAFETY: the classifier takes only a by-value operation result.
    unsafe { ffi::BIO_fd_should_retry(result) != 0 }
}

/// Wraps: BIO_new_fd
/// Transfers an owned file descriptor into a new BIO.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_fd(descriptor: OwnedFd) -> Option<CBox<Bio>> {
    let raw_fd = descriptor.as_raw_fd();
    // SAFETY: `descriptor` remains owned until success; BIO_CLOSE transfers
    // its close obligation to the returned BIO.
    let raw = unsafe { ffi::BIO_new_fd(raw_fd, ffi::BIO_CLOSE as i32) };
    // SAFETY: a non-null constructor result transfers one BIO reference.
    let bio = unsafe { CBox::from_raw(raw) };
    if bio.is_some() {
        let _ = descriptor.into_raw_fd();
    }
    bio
}

/// Wraps: BIO_s_fd
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_s_fd() -> Option<BioMethodRef<'static>> {
    // SAFETY: the selector has no caller-side memory obligations and returns
    // null or the address of a `static const` table, which is the
    // process-lifetime borrow `static_bio_method` requires.
    unsafe { static_bio_method(ffi::BIO_s_fd()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux errno values: `EAGAIN`/`EWOULDBLOCK` is one of the codes the
    /// classifier accepts, `EBADF` is not.
    const EAGAIN: i32 = 11;
    const EBADF: i32 = 9;

    #[test]
    fn only_the_recoverable_descriptor_errnos_are_non_fatal() {
        assert!(BIO_fd_non_fatal_error(EAGAIN));
        assert!(!BIO_fd_non_fatal_error(EBADF));
        assert!(!BIO_fd_non_fatal_error(0));
    }

    #[test]
    fn a_successful_result_never_asks_for_a_retry() {
        // Only 0 and -1 consult errno; any other result is a completed operation.
        assert!(!BIO_fd_should_retry(1));
        assert!(!BIO_fd_should_retry(42));
    }
}

//! Wrappers assigned from `crypto/bio/bio_sock2.c`.

use core::mem::ManuallyDrop;

use libcrypto_sys as ffi;

use super::internal_bio_addr::{BioAddrMut, BioAddrRef};

/// An owned socket returned by OpenSSL's BIO socket helpers.
#[derive(Debug)]
pub struct BioSocket {
    fd: i32,
}

impl BioSocket {
    pub(crate) fn from_result(fd: i32) -> Option<Self> {
        (fd >= 0).then_some(Self { fd })
    }

    /// Returns the socket number without transferring ownership.
    #[must_use]
    pub const fn as_raw_socket(&self) -> i32 {
        self.fd
    }

    /// Transfers responsibility for closing the socket to the caller.
    #[must_use]
    pub fn into_raw_socket(self) -> i32 {
        let this = ManuallyDrop::new(self);
        this.fd
    }
}

impl Drop for BioSocket {
    fn drop(&mut self) {
        // SAFETY: this owner holds the socket exactly once and Drop cannot run again.
        unsafe { ffi::BIO_closesocket(self.fd) };
    }
}

/// Wraps: BIO_closesocket
/// Consumes and closes an OpenSSL socket immediately, reporting whether the
/// close succeeded. The descriptor is surrendered either way.
#[allow(non_snake_case)]
pub fn BIO_closesocket(socket: BioSocket) -> bool {
    let fd = socket.into_raw_socket();
    // SAFETY: ownership of the live descriptor was consumed above.
    unsafe { ffi::BIO_closesocket(fd) == 1 }
}

/// Wraps: BIO_socket
/// Creates an owned socket, returning `None` when OpenSSL reports failure.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_socket(domain: i32, socket_type: i32, protocol: i32, options: i32) -> Option<BioSocket> {
    // SAFETY: all arguments are by-value socket configuration scalars.
    let fd = unsafe { ffi::BIO_socket(domain, socket_type, protocol, options) };
    BioSocket::from_result(fd)
}

/// Wraps: BIO_accept_ex
/// Accepts one connection and returns ownership of the accepted socket.
#[allow(non_snake_case)]
pub fn BIO_accept_ex(
    listener: &BioSocket,
    peer_address: Option<&mut BioAddrMut<'_>>,
    options: i32,
) -> Option<BioSocket> {
    let address = peer_address.map_or(core::ptr::null_mut(), |address| address.as_mut_ptr());
    // SAFETY: the listener stays owned and open for the call. The optional
    // exclusive address handle supplies writable output storage.
    let accepted = unsafe { ffi::BIO_accept_ex(listener.as_raw_socket(), address, options) };
    BioSocket::from_result(accepted)
}

/// Wraps: BIO_bind
#[allow(non_snake_case)]
pub fn BIO_bind(socket: &BioSocket, address: &BioAddrRef<'_>, options: i32) -> bool {
    // SAFETY: the socket remains open and the shared address stays live for the call.
    unsafe { ffi::BIO_bind(socket.as_raw_socket(), address.as_ptr(), options) != 0 }
}

/// Wraps: BIO_connect
#[allow(non_snake_case)]
pub fn BIO_connect(socket: &BioSocket, address: &BioAddrRef<'_>, options: i32) -> bool {
    // SAFETY: the socket remains open and the shared address stays live for the call.
    unsafe { ffi::BIO_connect(socket.as_raw_socket(), address.as_ptr(), options) != 0 }
}

/// Wraps: BIO_listen
/// Configures an owned socket to listen at `address`.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_listen(socket: &BioSocket, address: BioAddrRef<'_>, options: i32) -> bool {
    // SAFETY: both borrowed operands remain live for the synchronous call.
    unsafe { ffi::BIO_listen(socket.as_raw_socket(), address.as_ptr(), options) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux `<sys/socket.h>` values; `BIO_socket` forwards them to `socket(2)`.
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;

    #[test]
    fn a_created_socket_is_owned_and_closes_exactly_once() {
        let socket = BIO_socket(AF_INET, SOCK_STREAM, 0, 0).expect("TCP socket");
        assert!(socket.as_raw_socket() >= 0);
        assert!(BIO_closesocket(socket));
    }

    #[test]
    fn an_unsupported_domain_yields_no_owner() {
        assert!(BIO_socket(-1, SOCK_STREAM, 0, 0).is_none());
    }

    #[test]
    fn surrendering_the_descriptor_disarms_the_owner() {
        let socket = BIO_socket(AF_INET, SOCK_STREAM, 0, 0).expect("TCP socket");
        let fd = socket.into_raw_socket();
        assert!(fd >= 0);
        // SAFETY: `into_raw_socket` transferred the close obligation here, so
        // this is the descriptor's single close.
        assert_eq!(unsafe { ffi::BIO_closesocket(fd) }, 1);
    }
}

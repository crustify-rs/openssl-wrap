//! Wrappers assigned from `crypto/bio/bio_sock.c`.

use core::ffi::c_long;

use libcrypto_sys as ffi;

use super::bio_sock2::BioSocket;
use super::internal_bio_addr::BioAddrMut;
use super::openssl_bio::{BioSockInfo, BioSockInfoType};

/// Wraps: BIO_set_tcp_ndelay
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_set_tcp_ndelay(socket: &BioSocket, enabled: bool) -> bool {
    // SAFETY: the borrowed owner keeps the socket open for the duration of the call.
    unsafe { ffi::BIO_set_tcp_ndelay(socket.as_raw_socket(), i32::from(enabled)) == 1 }
}

/// Wraps: BIO_sock_error
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_error(socket: &BioSocket) -> i32 {
    // SAFETY: the borrowed owner keeps the socket open for the duration of the call.
    unsafe { ffi::BIO_sock_error(socket.as_raw_socket()) }
}

/// Wraps: BIO_sock_init
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_init() -> bool {
    // SAFETY: initialization has no caller-side memory obligations.
    unsafe { ffi::BIO_sock_init() == 1 }
}

/// Wraps: BIO_socket_ioctl
/// Invokes a socket-control request with a typed in/out value.
///
/// # Safety
///
/// `request` must designate an operation whose argument is a live `T`, with
/// the exact size, alignment, initialization, and access mode supplied here.
#[allow(non_snake_case)]
pub unsafe fn BIO_socket_ioctl<T>(socket: &BioSocket, request: c_long, argument: &mut T) -> i32 {
    // SAFETY: the caller establishes the request-to-`T` contract; the socket
    // owner and mutable reference keep both operands live for this call.
    unsafe {
        ffi::BIO_socket_ioctl(
            socket.as_raw_socket(),
            request,
            core::ptr::from_mut(argument).cast(),
        )
    }
}

/// Wraps: BIO_socket_nbio
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_socket_nbio(socket: &BioSocket, enabled: bool) -> bool {
    // SAFETY: the borrowed owner keeps the socket open for the duration of the call.
    unsafe { ffi::BIO_socket_nbio(socket.as_raw_socket(), i32::from(enabled)) == 1 }
}

/// Wraps: BIO_socket_wait
/// Waits until `deadline`, an absolute `time_t`. A `0` deadline means "do not
/// wait" and reports readiness immediately; a deadline already in the past
/// reports `0`.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_socket_wait(socket: &BioSocket, for_read: bool, deadline: ffi::time_t) -> i32 {
    // SAFETY: the borrowed owner keeps the socket open; the remaining values are scalars.
    unsafe { ffi::BIO_socket_wait(socket.as_raw_socket(), i32::from(for_read), deadline) }
}

/// Wraps: BIO_sock_info
/// Queries the socket's bound address into initialized BIO address storage.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_info(socket: &BioSocket, address: &mut BioAddrMut<'_>) -> bool {
    let mut info = BioSockInfo::for_address(address);
    let mut handle = info.as_mut();
    // SAFETY: the socket remains owned and open; the union handle supplies the
    // live writable address arm `BIO_SOCK_INFO_ADDRESS` fills, and OpenSSL
    // neither retains nor frees the address beyond this synchronous call.
    unsafe {
        ffi::BIO_sock_info(
            socket.as_raw_socket(),
            BioSockInfoType::ADDRESS.as_raw(),
            handle.as_mut_ptr(),
        ) == 1
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::os::fd::IntoRawFd;

    use super::*;
    use crate::bio::bio_addr::{BIO_ADDR_family, BIO_ADDR_new, BIO_ADDR_rawport};

    /// Linux `FIONBIO` from `<asm-generic/ioctls.h>`; the request
    /// `BIO_socket_nbio` itself forwards to `BIO_socket_ioctl`.
    const FIONBIO: c_long = 0x5421;

    fn loopback_listener() -> BioSocket {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        BioSocket::from_result(listener.into_raw_fd()).expect("owned listening socket")
    }

    #[test]
    fn socket_options_apply_to_a_live_listener() {
        assert!(BIO_sock_init());
        let socket = loopback_listener();
        assert_eq!(BIO_sock_error(&socket), 0);
        assert!(BIO_socket_nbio(&socket, true));
        assert!(BIO_set_tcp_ndelay(&socket, true));
        assert!(BIO_socket_nbio(&socket, false));
    }

    #[test]
    fn ioctl_passes_a_typed_in_out_argument() {
        let socket = loopback_listener();
        let mut enable: i32 = 1;
        // SAFETY: `FIONBIO` takes a live writable `int`, which is exactly what
        // this argument supplies for the duration of the call.
        let enabled = unsafe { BIO_socket_ioctl(&socket, FIONBIO, &mut enable) };
        assert_eq!(enabled, 0);
        let mut disable: i32 = 0;
        // SAFETY: as above.
        let disabled = unsafe { BIO_socket_ioctl(&socket, FIONBIO, &mut disable) };
        assert_eq!(disabled, 0);
    }

    #[test]
    fn socket_info_writes_the_bound_address_through_the_union() {
        assert!(BIO_sock_init());
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
        let expected = listener.local_addr().expect("bound address");
        let socket = BioSocket::from_result(listener.into_raw_fd()).expect("owned socket");

        let mut storage = BIO_ADDR_new().expect("BIO_ADDR_new");
        let mut address = storage.as_mut();
        assert!(BIO_sock_info(&socket, &mut address));

        // The union that reborrowed the address is gone with the call, so the
        // address storage reads back through its own handles again.
        assert_eq!(
            BIO_ADDR_family(&storage.as_ref()),
            i32::try_from(ffi::AF_INET).expect("AF_INET fits in a C int")
        );
        assert_eq!(
            u16::from_be(BIO_ADDR_rawport(&storage.as_ref())),
            expected.port()
        );
    }

    #[test]
    fn wait_separates_an_absent_deadline_from_an_expired_one() {
        let socket = loopback_listener();
        assert_eq!(BIO_socket_wait(&socket, true, 0), 1);
        assert_eq!(BIO_socket_wait(&socket, true, 1), 0);
    }
}

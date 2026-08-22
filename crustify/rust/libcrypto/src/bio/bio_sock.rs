//! Wrappers assigned from `crypto/bio/bio_sock.c`.

use libcrypto_sys as ffi;

use super::bio_sock2::BioSocket;
use super::internal_bio_addr::BioAddrMut;

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
pub unsafe fn BIO_socket_ioctl<T>(socket: &BioSocket, request: i64, argument: &mut T) -> i32 {
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
/// Waits until `deadline` (an absolute Unix `time_t` value).
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_socket_wait(socket: &BioSocket, for_read: bool, deadline: i64) -> i32 {
    // SAFETY: the borrowed owner keeps the socket open; the remaining values are scalars.
    unsafe { ffi::BIO_socket_wait(socket.as_raw_socket(), i32::from(for_read), deadline) }
}

/// Wraps: BIO_sock_info
/// Queries the socket's bound address into initialized BIO address storage.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sock_info(socket: &BioSocket, address: &mut BioAddrMut<'_>) -> bool {
    let mut info = ffi::BIO_sock_info_u {
        addr: address.as_mut_ptr(),
    };
    // SAFETY: the socket remains owned and open; the exclusive address handle
    // supplies the union's live writable address arm for this synchronous call.
    unsafe {
        ffi::BIO_sock_info(
            socket.as_raw_socket(),
            ffi::BIO_sock_info_type_BIO_SOCK_INFO_ADDRESS,
            &mut info,
        ) == 1
    }
}

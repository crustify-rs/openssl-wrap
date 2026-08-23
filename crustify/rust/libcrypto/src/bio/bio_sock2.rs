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
    use ffibox::CBox;

    use super::*;
    use crate::bio::bio_addr::{
        BIO_ADDR_family, BIO_ADDR_free, BIO_ADDR_new, BIO_ADDR_rawaddress, BIO_ADDR_rawmake,
        BIO_ADDR_rawport,
    };
    use crate::bio::bio_sock::BIO_sock_info;
    use crate::bio::internal_bio_addr::BioAddr;

    /// Linux `<sys/socket.h>` values; `BIO_socket` forwards them to `socket(2)`.
    const AF_INET: i32 = 2;
    const SOCK_STREAM: i32 = 1;

    /// A loopback address carrying `port` in network byte order, as
    /// `BIO_ADDR_rawmake` stores it.
    fn loopback(port: u16) -> CBox<BioAddr> {
        let mut address = BIO_ADDR_new().expect("BIO_ADDR_new");
        assert!(BIO_ADDR_rawmake(
            &mut address.as_mut(),
            AF_INET,
            &[127, 0, 0, 1],
            port,
        ));
        address
    }

    fn tcp_socket() -> BioSocket {
        BIO_socket(AF_INET, SOCK_STREAM, 0, 0).expect("TCP socket")
    }

    /// The address the kernel actually assigned to `socket`.
    fn local_address(socket: &BioSocket) -> CBox<BioAddr> {
        let mut address = BIO_ADDR_new().expect("BIO_ADDR_new");
        assert!(BIO_sock_info(socket, &mut address.as_mut()));
        address
    }

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

    #[test]
    fn binding_to_port_zero_assigns_a_loopback_address() {
        let socket = tcp_socket();
        let requested = loopback(0);
        assert!(BIO_bind(&socket, &requested.as_ref(), 0));

        let assigned = local_address(&socket);
        assert_eq!(BIO_ADDR_family(&assigned.as_ref()), AF_INET);
        assert_ne!(
            BIO_ADDR_rawport(&assigned.as_ref()),
            0,
            "bind(2) picks an ephemeral port for port 0"
        );
        let mut octets = [0_u8; 4];
        assert_eq!(
            BIO_ADDR_rawaddress(&assigned.as_ref(), &mut octets),
            Ok(octets.len())
        );
        assert_eq!(octets, [127, 0, 0, 1]);

        BIO_ADDR_free(assigned);
        BIO_ADDR_free(requested);
        assert!(BIO_closesocket(socket));
    }

    #[test]
    fn binding_an_already_bound_socket_fails_without_taking_the_address() {
        let socket = tcp_socket();
        let first = loopback(0);
        assert!(BIO_bind(&socket, &first.as_ref(), 0));
        // A second bind on the same descriptor is rejected by the kernel; the
        // borrowed address is untouched and still the caller's to release.
        assert!(!BIO_bind(&socket, &first.as_ref(), 0));
        assert_eq!(BIO_ADDR_family(&first.as_ref()), AF_INET);

        BIO_ADDR_free(first);
        assert!(BIO_closesocket(socket));
    }

    #[test]
    fn a_loopback_connection_is_accepted_with_its_peer_address() {
        let listener = tcp_socket();
        let wildcard = loopback(0);
        assert!(BIO_listen(&listener, wildcard.as_ref(), 0));
        let bound = local_address(&listener);

        let client = tcp_socket();
        let target = loopback(BIO_ADDR_rawport(&bound.as_ref()));
        assert!(BIO_connect(&client, &target.as_ref(), 0));

        let mut peer = BIO_ADDR_new().expect("BIO_ADDR_new");
        let accepted = BIO_accept_ex(&listener, Some(&mut peer.as_mut()), 0).expect("accepted");
        assert_ne!(accepted.as_raw_socket(), listener.as_raw_socket());
        assert_ne!(accepted.as_raw_socket(), client.as_raw_socket());

        // `accept(2)` filled the optional output address with the peer.
        assert_eq!(BIO_ADDR_family(&peer.as_ref()), AF_INET);
        assert_ne!(BIO_ADDR_rawport(&peer.as_ref()), 0);
        let client_address = local_address(&client);
        assert_eq!(
            BIO_ADDR_rawport(&peer.as_ref()),
            BIO_ADDR_rawport(&client_address.as_ref())
        );

        BIO_ADDR_free(client_address);
        BIO_ADDR_free(peer);
        BIO_ADDR_free(target);
        BIO_ADDR_free(bound);
        BIO_ADDR_free(wildcard);
        assert!(BIO_closesocket(accepted));
        assert!(BIO_closesocket(client));
        assert!(BIO_closesocket(listener));
    }

    #[test]
    fn accepting_without_a_peer_slot_still_yields_the_socket() {
        let listener = tcp_socket();
        let wildcard = loopback(0);
        assert!(BIO_listen(&listener, wildcard.as_ref(), 0));
        let bound = local_address(&listener);

        let client = tcp_socket();
        assert!(BIO_connect(
            &client,
            &loopback(BIO_ADDR_rawport(&bound.as_ref())).as_ref(),
            0
        ));

        let accepted = BIO_accept_ex(&listener, None, 0).expect("accepted");
        assert!(accepted.as_raw_socket() >= 0);

        BIO_ADDR_free(bound);
        BIO_ADDR_free(wildcard);
        assert!(BIO_closesocket(accepted));
        assert!(BIO_closesocket(client));
        assert!(BIO_closesocket(listener));
    }

    #[test]
    fn connecting_to_a_closed_loopback_port_fails() {
        // Bind and immediately release a port, then connect to it: nothing is
        // listening, so the kernel refuses the connection.
        let probe = tcp_socket();
        let wildcard = loopback(0);
        assert!(BIO_bind(&probe, &wildcard.as_ref(), 0));
        let bound = local_address(&probe);
        let port = BIO_ADDR_rawport(&bound.as_ref());
        assert!(BIO_closesocket(probe));

        let client = tcp_socket();
        let target = loopback(port);
        assert!(!BIO_connect(&client, &target.as_ref(), 0));

        BIO_ADDR_free(target);
        BIO_ADDR_free(bound);
        BIO_ADDR_free(wildcard);
        assert!(BIO_closesocket(client));
    }
}

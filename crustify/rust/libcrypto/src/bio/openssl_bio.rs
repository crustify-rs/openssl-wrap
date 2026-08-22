//! Wrappers assigned from `include/openssl/bio.h`.

#[cfg(feature = "deprecated-1-1-0")]
use core::ffi::CStr;
use core::marker::PhantomData;
#[cfg(feature = "deprecated-1-1-0")]
use core::ptr;
use core::ptr::{NonNull, addr_of};

use ffibox::{CCell, CPtr, CType, CVal, CValued};
use libcrypto_sys as ffi;

#[cfg(feature = "deprecated-1-1-0")]
use super::bio_sock2::BioSocket;
use super::internal_bio_addr::{BioAddr, BioAddrMut, BioAddrRef};
#[cfg(feature = "deprecated-1-1-0")]
use crate::mem::CryptoString;

/// Wraps: BIO_hostserv_priorities
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct BioHostservPriorities(ffi::BIO_hostserv_priorities);

impl BioHostservPriorities {
    /// Treat an unqualified input as a host name.
    pub const HOST: Self = Self(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST);

    /// Treat an unqualified input as a service name.
    pub const SERVICE: Self = Self(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV);

    /// Validates and wraps a raw OpenSSL priority value.
    pub const fn from_raw(raw: ffi::BIO_hostserv_priorities) -> Option<Self> {
        match raw {
            ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST
            | ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV => Some(Self(raw)),
            _ => None,
        }
    }

    /// Returns the raw value expected by OpenSSL.
    pub const fn as_raw(self) -> ffi::BIO_hostserv_priorities {
        self.0
    }
}

/// Wraps: BIO_lookup_type
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct BioLookupType(ffi::BIO_lookup_type);

impl BioLookupType {
    /// Request addresses suitable for connecting a client.
    pub const CLIENT: Self = Self(ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT);

    /// Request addresses suitable for accepting server connections.
    pub const SERVER: Self = Self(ffi::BIO_lookup_type_BIO_LOOKUP_SERVER);

    /// Validates and wraps a raw OpenSSL lookup type.
    pub const fn from_raw(raw: ffi::BIO_lookup_type) -> Option<Self> {
        match raw {
            ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT | ffi::BIO_lookup_type_BIO_LOOKUP_SERVER => {
                Some(Self(raw))
            }
            _ => None,
        }
    }

    /// Returns the raw value expected by OpenSSL.
    pub const fn as_raw(self) -> ffi::BIO_lookup_type {
        self.0
    }
}

/// Wraps: BIO_sock_info_type
///
/// A checked, layout-compatible value for the socket-information selector.
/// Keeping the bindgen integer private prevents safe Rust from inventing a C
/// enum value that OpenSSL's switch does not handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BioSockInfoType(ffi::BIO_sock_info_type);

impl BioSockInfoType {
    /// Request the socket's local address.
    pub const ADDRESS: Self = Self(ffi::BIO_sock_info_type_BIO_SOCK_INFO_ADDRESS);

    /// Convert a raw C enum value after validating its discriminant.
    #[must_use]
    pub const fn from_raw(raw: ffi::BIO_sock_info_type) -> Option<Self> {
        if raw == ffi::BIO_sock_info_type_BIO_SOCK_INFO_ADDRESS {
            Some(Self::ADDRESS)
        } else {
            None
        }
    }

    /// Return the ABI value used by OpenSSL.
    #[must_use]
    pub const fn as_raw(self) -> ffi::BIO_sock_info_type {
        self.0
    }
}

/// Wraps: BIO_sock_info_u
///
/// Layout-compatible storage for the socket-information argument union. The
/// lifetime parameter records the mutable `BIO_ADDR` borrow stored in its sole
/// published variant; OpenSSL writes that address but does not retain it.
#[repr(transparent)]
pub struct BioSockInfo<'addr> {
    inner: CType<ffi::BIO_sock_info_u>,
    address: PhantomData<&'addr mut BioAddr>,
}

/// Shared borrowed handle to a socket-information union.
#[repr(transparent)]
pub struct BioSockInfoRef<'view, 'addr>(CPtr<'view, BioSockInfo<'addr>>);

impl Clone for BioSockInfoRef<'_, '_> {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for BioSockInfoRef<'_, '_> {}

/// Exclusive borrowed handle to a socket-information union.
#[repr(transparent)]
pub struct BioSockInfoMut<'view, 'addr>(BioSockInfoRef<'view, 'addr>);

// SAFETY: `BioSockInfo` is transparent over `CType<BIO_sock_info_u>`; its
// lifetime marker is zero-sized. Both handles are transparent over a `CPtr`,
// and the shared handle exposes no operation that writes through its pointer.
unsafe impl<'addr> CCell for BioSockInfo<'addr> {
    type C = ffi::BIO_sock_info_u;
    type Ref<'view>
        = BioSockInfoRef<'view, 'addr>
    where
        'addr: 'view;
    type Mut<'view>
        = BioSockInfoMut<'view, 'addr>
    where
        'addr: 'view;

    unsafe fn ref_from_raw<'view>(ptr: NonNull<Self>) -> Self::Ref<'view>
    where
        'addr: 'view,
    {
        // SAFETY: the caller guarantees that the union is live for `'view`.
        BioSockInfoRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'view>(ptr: NonNull<Self>) -> Self::Mut<'view>
    where
        'addr: 'view,
    {
        // SAFETY: the caller additionally guarantees exclusive access.
        BioSockInfoMut(BioSockInfoRef(unsafe { CPtr::new(ptr) }))
    }
}

impl<'addr> BioSockInfo<'addr> {
    /// Creates inline union storage borrowing an address for OpenSSL to fill.
    #[must_use]
    pub fn for_address(mut address: BioAddrMut<'addr>) -> CVal<Self> {
        let address = address.as_mut_ptr();
        CVal::new(Self {
            inner: CType::new(ffi::BIO_sock_info_u { addr: address }),
            address: PhantomData,
        })
    }
}

// SAFETY: the union only borrows its address. Disposing the inline union has
// no resource to release and deliberately leaves the borrowed address alone.
unsafe impl CValued for BioSockInfo<'_> {
    unsafe fn c_dispose(_this: NonNull<Self>) {}
}

impl<'view, 'addr> BioSockInfoRef<'view, 'addr> {
    /// Borrows raw union storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// A non-null pointer must address a live `BIO_sock_info_u` for `'view`.
    /// Its `addr`, when non-null, must remain a live shared `BIO_ADDR` for that
    /// lifetime and must originate from mutable storage borrowed for `'addr`.
    pub unsafe fn from_ptr(ptr: *mut ffi::BIO_sock_info_u) -> Option<Self> {
        NonNull::new(ptr.cast::<BioSockInfo<'addr>>()).map(|ptr| {
            // SAFETY: the caller supplies the required liveness and invariants.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer for the raw FFI seam.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::BIO_sock_info_u {
        self.0.as_non_null().as_ptr().cast()
    }

    /// Wraps: BIO_sock_info_u.addr
    #[must_use]
    pub fn address(&self) -> Option<BioAddrRef<'view>> {
        // SAFETY: the handle carries a live shared borrow; raw-place projection
        // copies the union field without forming a reference to its storage.
        let address = unsafe { addr_of!((*self.as_ptr()).addr).read() };
        // SAFETY: the constructor contract requires a non-null field to remain
        // a live shared BIO_ADDR for the returned handle's lifetime.
        unsafe { BioAddrRef::from_ptr(address) }
    }
}

impl<'view, 'addr> BioSockInfoMut<'view, 'addr> {
    /// Exclusively borrows raw union storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// As [`BioSockInfoRef::from_ptr`], except the stored address must be
    /// exclusively borrowed and no competing union handle may be used.
    pub unsafe fn from_ptr(ptr: *mut ffi::BIO_sock_info_u) -> Option<Self> {
        NonNull::new(ptr.cast::<BioSockInfo<'addr>>()).map(|ptr| {
            // SAFETY: the caller supplies liveness, invariants and exclusivity.
            Self(BioSockInfoRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer for a `BIO_sock_info` call.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::BIO_sock_info_u {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrows this exclusive handle without write access.
    #[must_use]
    pub fn as_ref(&self) -> BioSockInfoRef<'_, 'addr> {
        self.0
    }

    /// Exclusively reborrows the address stored in the active union variant.
    #[must_use]
    pub fn address_mut(&mut self) -> Option<BioAddrMut<'_>> {
        // SAFETY: the exclusive union handle guarantees that its borrowed
        // address has no competing handle during this reborrow.
        let address = unsafe { addr_of!((*self.as_mut_ptr()).addr).read() };
        // SAFETY: the constructor contract supplies liveness and exclusivity.
        unsafe { BioAddrMut::from_ptr(address) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_info_union_preserves_layout() {
        assert_eq!(
            core::mem::size_of::<BioSockInfo<'static>>(),
            core::mem::size_of::<ffi::BIO_sock_info_u>()
        );
        assert_eq!(
            core::mem::align_of::<BioSockInfo<'static>>(),
            core::mem::align_of::<ffi::BIO_sock_info_u>()
        );
        assert_eq!(
            core::mem::size_of::<BioSockInfoRef<'static, 'static>>(),
            core::mem::size_of::<*mut ffi::BIO_sock_info_u>()
        );
    }

    #[test]
    fn socket_info_union_binds_and_reborrows_address() {
        let mut storage = BioAddr::zeroed();
        let raw = core::ptr::addr_of_mut!(storage).cast::<ffi::bio_addr_st>();
        // SAFETY: `storage` is initialized layout-compatible address storage
        // and is exclusively available for the union's lifetime.
        let address = unsafe { BioAddrMut::from_ptr(raw) }.expect("live BIO_ADDR");
        let mut info = BioSockInfo::for_address(address);

        assert_eq!(
            info.as_ref().address().expect("address variant").as_ptr(),
            raw.cast_const()
        );
        let mut info_mut = info.as_mut();
        assert_eq!(info_mut.as_mut_ptr(), info_mut.as_ref().as_ptr().cast_mut());
        assert_eq!(
            info_mut
                .address_mut()
                .expect("address variant")
                .as_mut_ptr(),
            raw
        );
    }

    #[test]
    fn hostserv_priorities_validate_raw_values() {
        assert_eq!(
            BioHostservPriorities::from_raw(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST,),
            Some(BioHostservPriorities::HOST)
        );
        assert_eq!(
            BioHostservPriorities::from_raw(ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV,),
            Some(BioHostservPriorities::SERVICE)
        );
        assert_eq!(BioHostservPriorities::from_raw(u32::MAX), None);
    }

    #[test]
    fn lookup_types_validate_raw_values() {
        assert_eq!(
            BioLookupType::from_raw(ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT),
            Some(BioLookupType::CLIENT)
        );
        assert_eq!(
            BioLookupType::from_raw(ffi::BIO_lookup_type_BIO_LOOKUP_SERVER),
            Some(BioLookupType::SERVER)
        );
        assert_eq!(BioLookupType::from_raw(u32::MAX), None);
    }

    #[test]
    fn socket_info_selector_is_checked_and_layout_compatible() {
        assert_eq!(
            core::mem::size_of::<BioSockInfoType>(),
            core::mem::size_of::<ffi::BIO_sock_info_type>()
        );
        assert_eq!(
            core::mem::align_of::<BioSockInfoType>(),
            core::mem::align_of::<ffi::BIO_sock_info_type>()
        );
        assert_eq!(
            BioSockInfoType::from_raw(BioSockInfoType::ADDRESS.as_raw()),
            Some(BioSockInfoType::ADDRESS)
        );
        assert_eq!(BioSockInfoType::from_raw(1), None);
    }

    #[test]
    fn wrappers_preserve_the_raw_enum_layout() {
        assert_eq!(
            core::mem::size_of::<BioHostservPriorities>(),
            core::mem::size_of::<ffi::BIO_hostserv_priorities>()
        );
        assert_eq!(
            core::mem::align_of::<BioLookupType>(),
            core::mem::align_of::<ffi::BIO_lookup_type>()
        );
    }
}

#[cfg(feature = "deprecated-1-1-0")]
/// The three outcomes distinguished by legacy `BIO_accept`.
#[derive(Debug)]
pub enum BioAcceptResult {
    /// A connected socket and, when requested, its allocated host/service text.
    Accepted {
        socket: BioSocket,
        peer: Option<CryptoString>,
    },
    /// The listening socket is nonblocking and the operation should be retried.
    Retry,
    /// OpenSSL reported an error.
    Error,
}

#[cfg(feature = "deprecated-1-1-0")]
/// Wraps: BIO_accept
#[allow(non_snake_case)]
pub fn BIO_accept(listener: &BioSocket, include_peer: bool) -> BioAcceptResult {
    let mut peer = ptr::null_mut();
    let peer_out = include_peer
        .then_some(&mut peer)
        .map_or(ptr::null_mut(), ptr::from_mut);
    // SAFETY: the listening socket remains open and `peer_out`, when non-null,
    // is a live output slot. OpenSSL transfers any allocated string to it.
    let result = unsafe { ffi::BIO_accept(listener.as_raw_socket(), peer_out) };
    if result == -2 {
        return BioAcceptResult::Retry;
    }
    let Some(socket) = BioSocket::from_result(result) else {
        return BioAcceptResult::Error;
    };
    // SAFETY: a non-null value written on success is a fresh NUL-terminated
    // allocation whose ownership OpenSSL transfers to the caller.
    let peer = unsafe { CryptoString::from_raw(peer) };
    BioAcceptResult::Accepted { socket, peer }
}

#[cfg(feature = "deprecated-1-1-0")]
/// Wraps: BIO_get_accept_socket
#[allow(non_snake_case)]
pub fn BIO_get_accept_socket(host_service: &CStr, reuse_address: bool) -> Option<BioSocket> {
    // SAFETY: the legacy API does not mutate the live input C string despite
    // its non-const declaration; the other argument is a scalar.
    let result = unsafe {
        ffi::BIO_get_accept_socket(host_service.as_ptr().cast_mut(), i32::from(reuse_address))
    };
    BioSocket::from_result(result)
}

#[cfg(feature = "deprecated-1-1-0")]
/// Wraps: BIO_get_host_ip
#[allow(non_snake_case)]
pub fn BIO_get_host_ip(host: &CStr) -> Option<[u8; 4]> {
    let mut address = [0_u8; 4];
    // SAFETY: `host` is a live C string and `address` supplies the four writable
    // bytes required for an IPv4 result.
    let ok = unsafe { ffi::BIO_get_host_ip(host.as_ptr(), address.as_mut_ptr()) };
    (ok == 1).then_some(address)
}

#[cfg(feature = "deprecated-1-1-0")]
/// Wraps: BIO_get_port
#[allow(non_snake_case)]
pub fn BIO_get_port(service: &CStr) -> Option<u16> {
    let mut port = 0_u16;
    // SAFETY: `service` is a live C string and `port` is a live output slot.
    let ok = unsafe { ffi::BIO_get_port(service.as_ptr(), &mut port) };
    (ok == 1).then_some(port)
}

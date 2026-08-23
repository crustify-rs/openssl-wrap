//! Wrappers assigned from `include/openssl/bio.h`.

#[cfg(feature = "deprecated-1-1-0")]
use core::ffi::CStr;
use core::ffi::{c_int, c_void};
use core::marker::PhantomData;
use core::ptr;
use core::ptr::{NonNull, addr_of, addr_of_mut};
#[cfg(feature = "deprecated-1-1-0")]
use std::sync::{Mutex, MutexGuard};

use ffibox::{CCell, CPtr, CSlice, CSliceMut, CType, CVal, CValued};
use libcrypto_sys as ffi;

use super::bio_bio_local::BioMut;
#[cfg(feature = "deprecated-3-0")]
use super::bio_bio_local::BioRef;
#[cfg(feature = "deprecated-3-5")]
use super::bio_meth::{
    BioMethodCallbackCtrl, BioMethodCreateCallback, BioMethodCtrlCallback,
    BioMethodDestroyCallback, BioMethodGetsCallback, BioMethodPutsCallback, BioMethodReadCallback,
    BioMethodReadExCallback, BioMethodWriteCallback, BioMethodWriteExCallback,
};

#[cfg(feature = "deprecated-1-1-0")]
use super::bio_sock2::BioSocket;
use super::internal_bio::BioMethodRef;
use super::internal_bio_addr::{BioAddr, BioAddrMut, BioAddrRef};
#[cfg(feature = "deprecated-1-1-0")]
use crate::mem::CryptoString;
#[cfg(feature = "deprecated-1-1-0")]
use libc::netdb::HostEntRef;

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
    #[must_use]
    pub const fn from_raw(raw: ffi::BIO_hostserv_priorities) -> Option<Self> {
        match raw {
            ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_HOST
            | ffi::BIO_hostserv_priorities_BIO_PARSE_PRIO_SERV => Some(Self(raw)),
            _ => None,
        }
    }

    /// Returns the raw value expected by OpenSSL.
    #[must_use]
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
    #[must_use]
    pub const fn from_raw(raw: ffi::BIO_lookup_type) -> Option<Self> {
        match raw {
            ffi::BIO_lookup_type_BIO_LOOKUP_CLIENT | ffi::BIO_lookup_type_BIO_LOOKUP_SERVER => {
                Some(Self(raw))
            }
            _ => None,
        }
    }

    /// Returns the raw value expected by OpenSSL.
    #[must_use]
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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
    use crate::bio::internal_bio_addr::BioAddr;

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

    unsafe extern "C" fn echo_extended_callback(
        _bio: *mut ffi::BIO,
        _operation: i32,
        _argp: *const core::ffi::c_char,
        _len: usize,
        _argi: i32,
        _argl: core::ffi::c_long,
        result: i32,
        _processed: *mut usize,
    ) -> core::ffi::c_long {
        core::ffi::c_long::from(result)
    }

    #[test]
    fn extended_callback_handle_is_callable() {
        // SAFETY: this callback ignores pointer payloads, is thread-safe, and
        // never unwinds.
        let callback = unsafe { BioCallbackFnEx::from_raw(Some(echo_extended_callback)) }
            .expect("non-null callback");
        // SAFETY: both constructors have no caller-side pointer inputs.
        let raw = unsafe { ffi::BIO_new(ffi::BIO_s_null()) };
        // SAFETY: a non-null result transfers one owned BIO reference.
        let mut bio: ffibox::CBox<super::super::bio_bio_local::Bio> =
            unsafe { ffibox::CBox::from_raw(raw) }.expect("BIO_new");
        let mut processed = 0_usize;
        // SAFETY: the test callback ignores every operation-specific payload,
        // so the null pointer and zero-valued metadata satisfy its contract.
        let result = unsafe {
            callback.call(
                &mut bio.as_mut(),
                0,
                core::ptr::null(),
                0,
                0,
                0,
                7,
                Some(&mut processed),
            )
        };
        assert_eq!(result, 7);
        assert_eq!(processed, 0);
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

    #[test]
    fn bio_msg_layout_and_borrowed_fields_are_preserved() {
        assert_eq!(
            core::mem::size_of::<BioMsg<'_>>(),
            core::mem::size_of::<ffi::bio_msg_st>()
        );
        assert_eq!(
            core::mem::align_of::<BioMsg<'_>>(),
            core::mem::align_of::<ffi::bio_msg_st>()
        );

        let mut bytes = [1_u8, 2, 3, 4];
        let mut peer = BioAddr::zeroed();
        let peer_raw = core::ptr::addr_of_mut!(peer).cast::<ffi::bio_addr_st>();

        // Safe end to end: the descriptor records the buffer borrow in `'buf`.
        let mut message = BioMsg::for_slice(&mut bytes);
        assert_eq!(message.as_ref().data_len(), 4);

        {
            let mut message_mut = message.as_mut();
            message_mut.set_flags(0x55);

            // SAFETY: `peer` is live zero-initialized `BIO_ADDR` storage that
            // outlives the descriptor and is reached only through it until the
            // handle is taken back below.
            let peer_view = unsafe { BioAddrMut::from_ptr(peer_raw) }.expect("non-null BIO_ADDR");
            assert!(message_mut.set_peer(Some(peer_view)).is_none());

            assert_eq!(message_mut.as_ref().flags(), 0x55);
            assert_eq!(message_mut.peer_mut().unwrap().as_mut_ptr(), peer_raw);
            assert!(message_mut.truncate_data(3));
            assert!(!message_mut.truncate_data(4));
            assert!(message_mut.data_mut().unwrap().set_elem(1, 9));

            // Replacing a stored borrow hands the previous one back.
            let mut reclaimed = message_mut.take_peer().expect("the stored peer");
            assert_eq!(reclaimed.as_mut_ptr(), peer_raw);
            assert!(message_mut.take_peer().is_none());
        }

        {
            let message_ref = message.as_ref();
            let data = message_ref.data().expect("the stored run");
            assert_eq!(data.len(), 3);
            assert_eq!(data.elems().collect::<Vec<_>>(), vec![1, 9, 3]);
            assert!(message_ref.peer().is_none());
            assert!(message_ref.local().is_none());
        }

        // The truncated run comes back, and the descriptor is left empty.
        let reclaimed = message.as_mut().take_data().expect("the stored run");
        assert_eq!(reclaimed.len(), 3);
        assert!(message.as_ref().data().is_none());
        assert_eq!(message.as_ref().data_len(), 0);
    }

    #[test]
    fn poll_descriptor_validates_and_tags_union_arms() {
        assert_eq!(
            core::mem::size_of::<BioPollDescriptor>(),
            core::mem::size_of::<ffi::bio_poll_descriptor_st>()
        );
        assert_eq!(
            core::mem::align_of::<BioPollDescriptor>(),
            core::mem::align_of::<ffi::bio_poll_descriptor_st>()
        );

        let mut descriptor = BioPollDescriptor::zeroed();
        let raw = core::ptr::addr_of_mut!(descriptor).cast::<ffi::bio_poll_descriptor_st>();
        {
            // SAFETY: `raw` addresses initialized descriptor storage and this
            // is its only active handle.
            let mut descriptor_mut = unsafe { BioPollDescriptorMut::from_ptr(raw) }.unwrap();
            descriptor_mut.set_socket_fd(17);
            assert_eq!(
                descriptor_mut.as_ref().value(),
                Some(BioPollDescriptorValue::SocketFd(17))
            );

            let custom_type = ffi::BIO_POLL_DESCRIPTOR_CUSTOM_START + 7;
            assert!(descriptor_mut.set_custom_integer(custom_type, 0x1234));
            assert_eq!(
                descriptor_mut.as_ref().value(),
                Some(BioPollDescriptorValue::Custom {
                    type_id: custom_type,
                    value: BioPollCustomValue {
                        bits: 0x1234,
                        _borrow: PhantomData,
                    },
                })
            );
            assert!(!descriptor_mut.set_custom_integer(3, 0));
            descriptor_mut.set_none();
            assert_eq!(
                descriptor_mut.as_ref().value(),
                Some(BioPollDescriptorValue::None)
            );
        }

        // SAFETY: the raw-place write only installs an invalid scalar tag for
        // validating that the safe view rejects reserved discriminants.
        unsafe { core::ptr::addr_of_mut!((*raw).type_).write(3) };
        // SAFETY: the descriptor storage is still live and no mutable handle is
        // in use. Invalid tags are explicitly represented by `None`.
        let descriptor_ref = unsafe { BioPollDescriptorRef::from_ptr(raw) }.unwrap();
        assert_eq!(descriptor_ref.kind(), None);
        assert_eq!(descriptor_ref.value(), None);
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

/// Wraps: bio_msg_st
///
/// Layout-compatible storage for one datagram descriptor. `BIO_MSG` owns
/// nothing: it names a caller-supplied byte buffer and two optional
/// caller-supplied `BIO_ADDR`s. OpenSSL reads and writes *through* those
/// pointers — `dgram_recvmmsg` fills the buffer and the addresses and shortens
/// `data_len` — but no libcrypto path ever replaces a pointer field, so the
/// descriptor's fields hold exactly the borrows Rust stored in them. The
/// lifetime parameter records those borrows, which is what lets the setters be
/// safe: a `BioMsg<'buf>` cannot be used past `'buf`.
#[repr(transparent)]
pub struct BioMsg<'buf> {
    inner: CType<ffi::bio_msg_st>,
    borrows: PhantomData<(&'buf mut [u8], &'buf mut BioAddr)>,
}

/// Shared borrowed handle to a datagram descriptor.
#[repr(transparent)]
pub struct BioMsgRef<'view, 'buf>(CPtr<'view, BioMsg<'buf>>);

impl Clone for BioMsgRef<'_, '_> {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for BioMsgRef<'_, '_> {}

/// Exclusive borrowed handle to a datagram descriptor.
#[repr(transparent)]
pub struct BioMsgMut<'view, 'buf>(BioMsgRef<'view, 'buf>);

// SAFETY: `BioMsg` is transparent over `CType<bio_msg_st>`; its borrow marker
// is zero-sized. Both handles are transparent over a `CPtr`, and the shared
// handle exposes no operation that writes through its pointer.
unsafe impl<'buf> CCell for BioMsg<'buf> {
    type C = ffi::bio_msg_st;
    type Ref<'view>
        = BioMsgRef<'view, 'buf>
    where
        'buf: 'view;
    type Mut<'view>
        = BioMsgMut<'view, 'buf>
    where
        'buf: 'view;

    unsafe fn ref_from_raw<'view>(ptr: NonNull<Self>) -> Self::Ref<'view>
    where
        'buf: 'view,
    {
        // SAFETY: the caller guarantees the descriptor is live for `'view`.
        BioMsgRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'view>(ptr: NonNull<Self>) -> Self::Mut<'view>
    where
        'buf: 'view,
    {
        // SAFETY: the caller additionally guarantees exclusive access.
        BioMsgMut(BioMsgRef(unsafe { CPtr::new(ptr) }))
    }
}

// SAFETY: the descriptor only borrows its buffer and addresses. Disposing the
// inline value has no resource to release and deliberately leaves the borrowed
// storage alone.
unsafe impl CValued for BioMsg<'_> {
    unsafe fn c_dispose(_this: NonNull<Self>) {}
}

impl<'buf> BioMsg<'buf> {
    /// Creates empty inline descriptor storage: no buffer, no addresses and no
    /// flags. Fill it through [`CVal::as_mut`].
    #[must_use]
    pub fn empty() -> CVal<Self> {
        CVal::new(Self {
            inner: CType::new(ffi::bio_msg_st {
                data: ptr::null_mut(),
                data_len: 0,
                peer: ptr::null_mut(),
                local: ptr::null_mut(),
                flags: 0,
            }),
            borrows: PhantomData,
        })
    }

    /// Creates inline descriptor storage naming a byte buffer for OpenSSL to
    /// send from or receive into. `data_len` starts at the buffer's length,
    /// which is the byte count on send and the capacity on receive.
    #[must_use]
    pub fn for_buffer(data: CSliceMut<'buf, u8>) -> CVal<Self> {
        let mut message = Self::empty();
        message.as_mut().set_data(Some(data));
        message
    }

    /// Creates inline descriptor storage over Rust-owned bytes. The exclusive
    /// borrow is what the descriptor stores, so the buffer stays unreachable
    /// from Rust until the descriptor's `'buf` ends or the run is taken back
    /// with [`BioMsgMut::take_data`].
    #[must_use]
    pub fn for_slice(data: &'buf mut [u8]) -> CVal<Self> {
        let len = data.len();
        // SAFETY: an exclusive slice borrow addresses `len` initialized bytes
        // live for `'buf`, and it is consumed here, so the raw run this
        // derives is the only remaining path to them.
        let data =
            unsafe { CSliceMut::from_raw_parts(NonNull::new_unchecked(data.as_mut_ptr()), len) };
        Self::for_buffer(data)
    }
}

impl<'view, 'buf> BioMsgRef<'view, 'buf> {
    /// Borrows raw descriptor storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// A non-null pointer must address a live, initialized `BIO_MSG` for
    /// `'view`. Each non-null pointer field must name storage that stays live
    /// for `'buf` — `data` for at least `data_len` bytes — and must not be
    /// written through any path other than this descriptor while `'buf` lasts.
    pub unsafe fn from_ptr(ptr: *mut ffi::bio_msg_st) -> Option<Self> {
        NonNull::new(ptr.cast::<BioMsg<'buf>>()).map(|ptr| {
            // SAFETY: the caller supplies the required liveness and invariants.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer for the raw FFI seam.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::bio_msg_st {
        self.0.as_non_null().as_ptr().cast()
    }

    /// Wraps: bio_msg_st.data
    ///
    /// Returns the borrowed byte buffer together with the capacity or received
    /// length currently held in `data_len`. The view is bound to this shared
    /// borrow, not to `'buf`, so a later exclusive handle can replace it.
    #[must_use]
    pub fn data(&self) -> Option<CSlice<'view, u8>> {
        // SAFETY: both fields are copied through raw-place projections; the
        // handle's construction contract keeps `data` live for `data_len`
        // bytes throughout `'buf`, which outlives `'view`.
        unsafe {
            let data = addr_of!((*self.as_ptr()).data).read().cast::<u8>();
            let len = addr_of!((*self.as_ptr()).data_len).read();
            NonNull::new(data).map(|data| CSlice::from_raw_parts(data, len))
        }
    }

    /// Wraps: bio_msg_st.flags
    #[must_use]
    pub fn flags(&self) -> u64 {
        // SAFETY: `self` guarantees a live initialized descriptor and this is
        // a copy of its scalar field through a raw-place projection.
        unsafe { addr_of!((*self.as_ptr()).flags).read() }
    }

    /// Wraps: bio_msg_st.peer
    #[must_use]
    pub fn peer(&self) -> Option<BioAddrRef<'view>> {
        // SAFETY: a non-null peer is caller-supplied initialized BIO_ADDR
        // storage live for `'buf`, which outlives `'view`.
        unsafe {
            let peer = addr_of!((*self.as_ptr()).peer).read();
            BioAddrRef::from_ptr(peer)
        }
    }

    /// Wraps: bio_msg_st.local
    #[must_use]
    pub fn local(&self) -> Option<BioAddrRef<'view>> {
        // SAFETY: a non-null local address obeys the same borrowed-storage
        // contract as `peer`.
        unsafe {
            let local = addr_of!((*self.as_ptr()).local).read();
            BioAddrRef::from_ptr(local)
        }
    }

    /// Wraps: bio_msg_st.data_len
    #[must_use]
    pub fn data_len(&self) -> usize {
        // SAFETY: `self` guarantees a live initialized descriptor and this is
        // a copy of its scalar field through a raw-place projection.
        unsafe { addr_of!((*self.as_ptr()).data_len).read() }
    }
}

impl<'view, 'buf> BioMsgMut<'view, 'buf> {
    /// Exclusively borrows raw descriptor storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// As [`BioMsgRef::from_ptr`], plus: the buffer and addresses named by its
    /// pointer fields must be *exclusively* borrowed for `'buf`, and no
    /// competing descriptor handle may be used while the result lives.
    pub unsafe fn from_ptr(ptr: *mut ffi::bio_msg_st) -> Option<Self> {
        NonNull::new(ptr.cast::<BioMsg<'buf>>()).map(|ptr| {
            // SAFETY: the caller supplies liveness, exclusivity and lifetimes.
            Self(BioMsgRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer for the raw FFI seam.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::bio_msg_st {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrows shared, for reaching the getters.
    #[must_use]
    pub fn as_ref(&self) -> BioMsgRef<'_, 'buf> {
        self.0
    }

    /// Exclusively views the byte buffer currently named by this descriptor,
    /// without giving up the descriptor's hold on it.
    #[must_use]
    pub fn data_mut(&mut self) -> Option<CSliceMut<'_, u8>> {
        // SAFETY: the exclusive descriptor handle is the only path to the
        // buffer while the returned view is live, and the handle's contract
        // guarantees `data` is valid for `data_len` bytes.
        unsafe {
            let data = addr_of!((*self.as_mut_ptr()).data).read().cast::<u8>();
            let len = addr_of!((*self.as_mut_ptr()).data_len).read();
            NonNull::new(data).map(|data| CSliceMut::from_raw_parts(data, len))
        }
    }

    /// Exclusively views the optional peer address.
    #[must_use]
    pub fn peer_mut(&mut self) -> Option<BioAddrMut<'_>> {
        // SAFETY: the field's non-null value is initialized BIO_ADDR storage
        // exclusively borrowed by this descriptor, and the result is
        // restricted to this exclusive reborrow.
        unsafe {
            let peer = addr_of!((*self.as_mut_ptr()).peer).read();
            BioAddrMut::from_ptr(peer)
        }
    }

    /// Exclusively views the optional local address.
    #[must_use]
    pub fn local_mut(&mut self) -> Option<BioAddrMut<'_>> {
        // SAFETY: as `peer_mut`, for the local-address field.
        unsafe {
            let local = addr_of!((*self.as_mut_ptr()).local).read();
            BioAddrMut::from_ptr(local)
        }
    }

    /// Replaces the message flags.
    pub fn set_flags(&mut self, flags: u64) {
        // SAFETY: the exclusive handle supplies writable provenance for this
        // scalar field and no reference to the C object is formed.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).flags).write(flags) }
    }

    /// Shrinks the visible data run without permitting it to exceed the
    /// existing buffer bound — the operation a receive path performs when it
    /// reports how many of the offered bytes arrived.
    pub fn truncate_data(&mut self, new_len: usize) -> bool {
        if new_len > self.as_ref().data_len() {
            return false;
        }
        // SAFETY: the exclusive handle supplies writable provenance and the
        // check preserves the current buffer bound.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).data_len).write(new_len) };
        true
    }

    /// Stores a byte run for OpenSSL to send from or receive into, returning
    /// the run this descriptor held before. `None` clears the field and
    /// reclaims the previous borrow.
    ///
    /// Safe because `'buf` outlives every use of the descriptor: the stored
    /// pointer cannot dangle, and taking the run by value leaves this
    /// descriptor its only Rust-visible writer.
    pub fn set_data(&mut self, data: Option<CSliceMut<'buf, u8>>) -> Option<CSliceMut<'buf, u8>> {
        let (data, len) = data.map_or((ptr::null_mut(), 0), |mut data| {
            (data.as_mut_elem_ptr().cast::<c_void>(), data.len())
        });
        // SAFETY: the exclusive handle permits both raw-place writes; the
        // previous field value was, by this handle's contract, a run of
        // `data_len` bytes exclusively borrowed for `'buf`, and clearing the
        // field makes it unreachable through the descriptor.
        unsafe {
            let previous = addr_of!((*self.as_mut_ptr()).data).read().cast::<u8>();
            let previous_len = addr_of!((*self.as_mut_ptr()).data_len).read();
            addr_of_mut!((*self.as_mut_ptr()).data).write(data);
            addr_of_mut!((*self.as_mut_ptr()).data_len).write(len);
            NonNull::new(previous).map(|previous| CSliceMut::from_raw_parts(previous, previous_len))
        }
    }

    /// Reclaims the stored byte run and clears the field.
    pub fn take_data(&mut self) -> Option<CSliceMut<'buf, u8>> {
        self.set_data(None)
    }

    /// Stores the peer address OpenSSL sends to or reports the sender in,
    /// returning the address this descriptor held before. `None` clears the
    /// field and reclaims the previous borrow.
    ///
    /// Safe for the same reason as [`set_data`](Self::set_data).
    pub fn set_peer(&mut self, peer: Option<BioAddrMut<'buf>>) -> Option<BioAddrMut<'buf>> {
        let peer = peer.map_or(ptr::null_mut(), |mut peer| peer.as_mut_ptr());
        // SAFETY: the exclusive handle permits the raw-place write, and the
        // previous field value was an initialized BIO_ADDR exclusively
        // borrowed for `'buf` that the write makes unreachable here.
        unsafe {
            let previous = addr_of!((*self.as_mut_ptr()).peer).read();
            addr_of_mut!((*self.as_mut_ptr()).peer).write(peer);
            BioAddrMut::from_ptr(previous)
        }
    }

    /// Reclaims the stored peer address and clears the field.
    pub fn take_peer(&mut self) -> Option<BioAddrMut<'buf>> {
        self.set_peer(None)
    }

    /// Stores the local address OpenSSL sends from or reports the receiving
    /// interface in, returning the address this descriptor held before.
    ///
    /// Safe for the same reason as [`set_data`](Self::set_data).
    pub fn set_local(&mut self, local: Option<BioAddrMut<'buf>>) -> Option<BioAddrMut<'buf>> {
        let local = local.map_or(ptr::null_mut(), |mut local| local.as_mut_ptr());
        // SAFETY: as `set_peer`, for the local-address field.
        unsafe {
            let previous = addr_of!((*self.as_mut_ptr()).local).read();
            addr_of_mut!((*self.as_mut_ptr()).local).write(local);
            BioAddrMut::from_ptr(previous)
        }
    }

    /// Reclaims the stored local address and clears the field.
    pub fn take_local(&mut self) -> Option<BioAddrMut<'buf>> {
        self.set_local(None)
    }
}

ffibox::define_ctype!(
    /// Wraps: bio_poll_descriptor_st
    ///
    /// Layout-compatible storage for OpenSSL's tagged poll-descriptor union.
    BioPollDescriptor,
    BioPollDescriptorRef,
    BioPollDescriptorMut,
    ffi::bio_poll_descriptor_st
);

/// Wraps: bio_poll_descriptor_st.type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BioPollDescriptorType {
    /// No descriptor.
    None,
    /// A socket file descriptor.
    SocketFd,
    /// A borrowed SSL object.
    Ssl,
    /// An application-defined descriptor kind.
    Custom(u32),
}

impl BioPollDescriptorType {
    /// Validates a raw OpenSSL poll-descriptor tag.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            ffi::BIO_POLL_DESCRIPTOR_TYPE_NONE => Some(Self::None),
            ffi::BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD => Some(Self::SocketFd),
            ffi::BIO_POLL_DESCRIPTOR_TYPE_SSL => Some(Self::Ssl),
            ffi::BIO_POLL_DESCRIPTOR_CUSTOM_START.. => Some(Self::Custom(raw)),
            _ => None,
        }
    }

    /// Returns the ABI tag used by OpenSSL.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        match self {
            Self::None => ffi::BIO_POLL_DESCRIPTOR_TYPE_NONE,
            Self::SocketFd => ffi::BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD,
            Self::Ssl => ffi::BIO_POLL_DESCRIPTOR_TYPE_SSL,
            Self::Custom(raw) => raw,
        }
    }
}

/// Opaque borrowed token for the libssl-owned arm of a poll descriptor.
///
/// `ssl_st` is intentionally not re-wrapped in libcrypto: libssl is a
/// higher-layer library. The token preserves identity and lifetime without
/// publishing that unavailable dependency as a raw pointer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BioPollSslRef<'a> {
    ptr: NonNull<ffi::SSL>,
    _borrow: PhantomData<&'a ffi::SSL>,
}

impl BioPollSslRef<'_> {
    /// Tests whether two tokens identify the same SSL object.
    #[must_use]
    pub fn same_object(self, other: Self) -> bool {
        self == other
    }
}

/// Wraps: bio_poll_descriptor_st.value.custom
///
/// The custom pointer and integer union arms occupy the same bits. A custom
/// tag does not say which interpretation its owner chose, so the safe common
/// view exposes those bits as an integer and never dereferences them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BioPollCustomValue<'a> {
    bits: usize,
    _borrow: PhantomData<&'a c_void>,
}

impl BioPollCustomValue<'_> {
    /// Wraps: bio_poll_descriptor_st.value.custom_ui
    #[must_use]
    pub const fn as_integer(self) -> usize {
        self.bits
    }

    /// Reports whether the shared pointer/integer bits are zero.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.bits == 0
    }
}

/// Wraps: bio_poll_descriptor_st.value
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BioPollDescriptorValue<'a> {
    /// The union has no active value.
    None,
    /// Wraps: bio_poll_descriptor_st.value.fd
    SocketFd(i32),
    /// Wraps: bio_poll_descriptor_st.value.ssl
    Ssl(Option<BioPollSslRef<'a>>),
    /// An application-defined value and its custom tag.
    Custom {
        /// Custom tag, always at least `BIO_POLL_DESCRIPTOR_CUSTOM_START`.
        type_id: u32,
        /// The common pointer/integer representation.
        value: BioPollCustomValue<'a>,
    },
}

impl<'a> BioPollDescriptorRef<'a> {
    /// Returns the validated union discriminator.
    #[must_use]
    pub fn kind(&self) -> Option<BioPollDescriptorType> {
        // SAFETY: the scalar tag is copied through a raw-place projection.
        let raw = unsafe { core::ptr::addr_of!((*self.as_ptr()).type_).read() };
        BioPollDescriptorType::from_raw(raw)
    }

    /// Returns a tagged safe view of the active union arm.
    #[must_use]
    pub fn value(&self) -> Option<BioPollDescriptorValue<'a>> {
        match self.kind()? {
            BioPollDescriptorType::None => Some(BioPollDescriptorValue::None),
            BioPollDescriptorType::SocketFd => {
                // SAFETY: the validated tag selects the `fd` union arm; the
                // scalar is copied through a raw-place projection.
                let fd = unsafe { core::ptr::addr_of!((*self.as_ptr()).value.fd).read() };
                Some(BioPollDescriptorValue::SocketFd(fd))
            }
            BioPollDescriptorType::Ssl => {
                // SAFETY: the validated tag selects the `ssl` union arm. A
                // non-null pointer is a borrowed SSL object by the C contract.
                let ssl = unsafe { core::ptr::addr_of!((*self.as_ptr()).value.ssl).read() };
                Some(BioPollDescriptorValue::Ssl(NonNull::new(ssl).map(|ptr| {
                    BioPollSslRef {
                        ptr,
                        _borrow: PhantomData,
                    }
                })))
            }
            BioPollDescriptorType::Custom(type_id) => {
                // SAFETY: all custom union arms share these bits and every bit
                // pattern is valid for `usize`; no pointer is dereferenced.
                let bits = unsafe { core::ptr::addr_of!((*self.as_ptr()).value.custom_ui).read() };
                Some(BioPollDescriptorValue::Custom {
                    type_id,
                    value: BioPollCustomValue {
                        bits,
                        _borrow: PhantomData,
                    },
                })
            }
        }
    }
}

impl<'a> BioPollDescriptorMut<'a> {
    /// Selects the empty descriptor value.
    pub fn set_none(&mut self) {
        // SAFETY: this exclusive handle permits both writes. Zeroing the union
        // before publishing the NONE tag leaves a valid descriptor.
        unsafe {
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).value.custom_ui).write(0);
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).type_)
                .write(ffi::BIO_POLL_DESCRIPTOR_TYPE_NONE);
        }
    }

    /// Selects a socket file descriptor.
    pub fn set_socket_fd(&mut self, fd: i32) {
        // SAFETY: this exclusive handle permits both writes; publishing the tag
        // after its union payload keeps the final descriptor well formed.
        unsafe {
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).value.fd).write(fd);
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).type_)
                .write(ffi::BIO_POLL_DESCRIPTOR_TYPE_SOCK_FD);
        }
    }

    /// Selects an integer-valued custom descriptor.
    ///
    /// Returns `false` without modifying the descriptor for a reserved tag.
    pub fn set_custom_integer(&mut self, type_id: u32, value: usize) -> bool {
        if type_id < ffi::BIO_POLL_DESCRIPTOR_CUSTOM_START {
            return false;
        }
        // SAFETY: this exclusive handle permits both writes and `type_id` is a
        // validated custom discriminator.
        unsafe {
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).value.custom_ui).write(value);
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).type_).write(type_id);
        }
        true
    }

    /// Selects a pointer-valued custom descriptor.
    ///
    /// # Safety
    ///
    /// A non-null value must remain live, with whatever access discipline the
    /// custom descriptor implementation requires, until this descriptor is no
    /// longer usable or is replaced. The custom tag must denote that `T`.
    pub unsafe fn set_custom_pointer<T>(&mut self, type_id: u32, value: Option<&'a mut T>) -> bool {
        if type_id < ffi::BIO_POLL_DESCRIPTOR_CUSTOM_START {
            return false;
        }
        let value = value.map_or(core::ptr::null_mut(), |value| {
            core::ptr::from_mut(value).cast::<c_void>()
        });
        // SAFETY: the caller upholds the stored-borrow and tag contract; this
        // exclusive handle permits both writes.
        unsafe {
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).value.custom).write(value);
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).type_).write(type_id);
        }
        true
    }

    /// Copies an existing borrowed SSL token into this descriptor.
    pub fn set_ssl(&mut self, ssl: Option<BioPollSslRef<'a>>) {
        let ssl = ssl.map_or(core::ptr::null_mut(), |ssl| ssl.ptr.as_ptr());
        // SAFETY: the token carries the stored SSL borrow and this exclusive
        // descriptor handle permits both writes.
        unsafe {
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).value.ssl).write(ssl);
            core::ptr::addr_of_mut!((*self.as_mut_ptr()).type_)
                .write(ffi::BIO_POLL_DESCRIPTOR_TYPE_SSL);
        }
    }
}

/// Wraps: BIO_callback_fn_ex
/// A nullable-checked handle to OpenSSL's extended BIO callback ABI.
#[derive(Clone, Copy)]
pub struct BioCallbackFnEx(ffi::BIO_callback_fn_ex);

impl BioCallbackFnEx {
    /// Wrap a raw callback, returning `None` for the null function pointer.
    ///
    /// # Safety
    /// A non-null callback must accept every operation-specific payload that
    /// OpenSSL may supply, obey its thread-safety rules, and never unwind.
    #[must_use]
    pub unsafe fn from_raw(raw: ffi::BIO_callback_fn_ex) -> Option<Self> {
        raw.map(|callback| Self(Some(callback)))
    }

    /// Return the callback representation used by OpenSSL.
    #[must_use]
    pub const fn as_raw(self) -> ffi::BIO_callback_fn_ex {
        self.0
    }

    /// Invoke the callback with an operation-specific payload.
    ///
    /// # Safety
    /// `argp`, `len`, `argi`, `processed`, and `operation` must satisfy the
    /// selected callback's operation-specific contract. Any pointed-to storage
    /// must remain live for the synchronous invocation.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn call(
        self,
        bio: &mut BioMut<'_>,
        operation: i32,
        argp: *const core::ffi::c_char,
        len: usize,
        argi: i32,
        argl: core::ffi::c_long,
        result: i32,
        processed: Option<&mut usize>,
    ) -> core::ffi::c_long {
        let callback = self.0.expect("BioCallbackFnEx is non-null");
        let processed = processed.map_or(core::ptr::null_mut(), core::ptr::from_mut);
        // SAFETY: the caller establishes the operation-specific callback
        // payload contract; the BIO and optional output slot are live.
        unsafe {
            callback(
                bio.as_mut_ptr(),
                operation,
                argp,
                len,
                argi,
                argl,
                result,
                processed,
            )
        }
    }
}

#[cfg(feature = "deprecated-3-0")]
/// A nullable-checked handle to OpenSSL's legacy BIO callback ABI.
#[derive(Clone, Copy)]
pub struct BioCallbackFn(ffi::BIO_callback_fn);

#[cfg(feature = "deprecated-3-0")]
impl BioCallbackFn {
    #[must_use]
    pub fn from_raw(raw: ffi::BIO_callback_fn) -> Option<Self> {
        raw.map(|callback| Self(Some(callback)))
    }

    #[must_use]
    pub const fn as_raw(self) -> ffi::BIO_callback_fn {
        self.0
    }

    /// # Safety
    /// The operation and payload must satisfy the selected callback's legacy
    /// operation-specific contract for the synchronous invocation.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn call(
        self,
        bio: &mut BioMut<'_>,
        operation: i32,
        argp: *const core::ffi::c_char,
        argi: i32,
        argl: core::ffi::c_long,
        result: core::ffi::c_long,
    ) -> core::ffi::c_long {
        let callback = self.0.expect("BioCallbackFn is non-null");
        // SAFETY: delegated to the caller as documented above.
        unsafe { callback(bio.as_mut_ptr(), operation, argp, argi, argl, result) }
    }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: BIO_debug_callback
///
/// # Safety
/// `argp`, `argi`, and `operation` must describe a valid operation-specific
/// callback payload. The BIO's callback argument must be null or a live BIO.
#[allow(non_snake_case)]
#[allow(clippy::too_many_arguments)]
pub unsafe fn BIO_debug_callback(
    bio: &mut BioMut<'_>,
    operation: i32,
    argp: *const core::ffi::c_char,
    argi: i32,
    argl: core::ffi::c_long,
    result: core::ffi::c_long,
) -> core::ffi::c_long {
    // SAFETY: the caller establishes the operation-specific payload and
    // callback-argument invariants; the exclusive BIO handle is live.
    unsafe { ffi::BIO_debug_callback(bio.as_mut_ptr(), operation, argp, argi, argl, result) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: BIO_get_callback
#[allow(non_snake_case)]
pub fn BIO_get_callback(bio: &BioRef<'_>) -> Option<BioCallbackFn> {
    // SAFETY: the shared handle supplies one live BIO for the field getter.
    let raw = unsafe { ffi::BIO_get_callback(bio.as_ptr()) };
    BioCallbackFn::from_raw(raw)
}

type RawBioInfoCallback = unsafe extern "C" fn(*mut ffi::BIO, c_int, c_int) -> c_int;

/// Wraps: BIO_info_cb
/// Callable handle for the legacy three-argument BIO information callback.
#[derive(Clone, Copy)]
pub struct BioInfoCallback(RawBioInfoCallback);

impl BioInfoCallback {
    /// Adopt a raw callback obeying the `BIO_info_cb` contract.
    ///
    /// # Safety
    ///
    /// The callback must accept every live BIO and scalar command/value pair
    /// OpenSSL may supply, must not unwind, and must obey C thread-safety rules.
    #[must_use]
    pub unsafe fn from_raw(callback: RawBioInfoCallback) -> Self {
        Self(callback)
    }

    pub(crate) fn as_raw(self) -> ffi::BIO_info_cb {
        Some(self.0)
    }

    /// Invoke the callback with a live BIO.
    pub fn call(self, mut bio: BioMut<'_>, command: i32, value: i32) -> i32 {
        // SAFETY: construction establishes the callback contract and the
        // exclusive handle supplies a live BIO for the synchronous call.
        unsafe { (self.0)(bio.as_mut_ptr(), command, value) }
    }
}

#[cfg(feature = "deprecated-1-1-0")]
static HOST_LOOKUP_LOCK: Mutex<()> = Mutex::new(());

/// A locked view of resolver-owned host data.
#[cfg(feature = "deprecated-1-1-0")]
pub struct BioHostEntGuard {
    raw: NonNull<ffi::hostent>,
    lock: MutexGuard<'static, ()>,
}

#[cfg(feature = "deprecated-1-1-0")]
impl BioHostEntGuard {
    /// Borrow the host entry while preventing another wrapper lookup from
    /// replacing the resolver's static storage.
    #[must_use]
    pub fn as_ref(&self) -> HostEntRef<'_> {
        let _keep_locked = &self.lock;
        // SAFETY: the guard serializes calls that replace the resolver-owned
        // static entry, and its borrow bounds the returned typed view. The
        // entry the resolver stored is well formed in the sense `HostEnt`
        // requires: NUL-terminated name, NULL-terminated alias and address
        // vectors, and `h_length` readable bytes per address.
        unsafe { HostEntRef::from_ptr(self.raw.as_ptr().cast()) }
            .expect("BIO_gethostbyname returned a stored non-null pointer")
    }
}

#[cfg(feature = "deprecated-1-1-0")]
/// Wraps: BIO_gethostbyname
/// Performs a serialized legacy host lookup.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_gethostbyname(name: &CStr) -> Option<BioHostEntGuard> {
    let lock = HOST_LOOKUP_LOCK.lock().ok()?;
    // SAFETY: `name` remains live and NUL-terminated; the mutex prevents a
    // competing safe wrapper call from replacing the returned static entry.
    let raw = unsafe { ffi::BIO_gethostbyname(name.as_ptr()) };
    NonNull::new(raw).map(|raw| BioHostEntGuard { raw, lock })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_callback_ctrl
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_callback_ctrl(method: BioMethodRef<'_>) -> Option<BioMethodCallbackCtrl> {
    // SAFETY: the method handle is live; a returned function pointer is static
    // method code obeying the callback-control contract.
    unsafe { ffi::BIO_meth_get_callback_ctrl(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodCallbackCtrl::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_create
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_create(method: BioMethodRef<'_>) -> Option<BioMethodCreateCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_create(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodCreateCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_ctrl
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_ctrl(method: BioMethodRef<'_>) -> Option<BioMethodCtrlCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_ctrl(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodCtrlCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_destroy
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_destroy(method: BioMethodRef<'_>) -> Option<BioMethodDestroyCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_destroy(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodDestroyCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_gets
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_gets(method: BioMethodRef<'_>) -> Option<BioMethodGetsCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_gets(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodGetsCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_puts
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_puts(method: BioMethodRef<'_>) -> Option<BioMethodPutsCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_puts(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodPutsCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_read
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_read(method: BioMethodRef<'_>) -> Option<BioMethodReadCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_read(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodReadCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_read_ex
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_read_ex(method: BioMethodRef<'_>) -> Option<BioMethodReadExCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_read_ex(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodReadExCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_write
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_write(method: BioMethodRef<'_>) -> Option<BioMethodWriteCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_write(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodWriteCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-5")]
/// Wraps: BIO_meth_get_write_ex
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_write_ex(method: BioMethodRef<'_>) -> Option<BioMethodWriteExCallback> {
    // SAFETY: the method handle is live and the returned code pointer is static.
    unsafe { ffi::BIO_meth_get_write_ex(method.as_ptr()) }
        .map(|raw| unsafe { BioMethodWriteExCallback::from_raw(raw) })
}

#[cfg(feature = "deprecated-3-0")]
/// A validated legacy BIO callback pointer.
#[derive(Clone, Copy)]
pub struct BioCallback(ffi::crustify_BIO_callback_fn);

#[cfg(feature = "deprecated-3-0")]
impl BioCallback {
    /// Wraps a raw legacy callback.
    ///
    /// # Safety
    /// The function must uphold OpenSSL's callback ABI for every operation and
    /// may not unwind across the C boundary.
    pub const unsafe fn from_raw(callback: ffi::crustify_BIO_callback_fn) -> Self {
        Self(callback)
    }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: BIO_set_callback
#[allow(non_snake_case)]
pub fn BIO_set_callback(bio: &mut super::bio_bio_local::BioMut<'_>, callback: Option<BioCallback>) {
    // SAFETY: `bio` is exclusive and `BioCallback` can only be constructed by
    // a caller accepting the legacy callback ABI obligations.
    unsafe {
        ffi::BIO_set_callback(
            bio.as_mut_ptr(),
            callback.map_or(None, |callback| callback.0),
        )
    }
}
/// Opaque in/out state passed between an ASN.1 prefix/suffix setup callback
/// and its paired cleanup callback.
pub struct Asn1PsBuffer {
    buffer: *mut u8,
    length: i32,
    argument: *mut c_void,
}

impl Asn1PsBuffer {
    /// Creates the null state expected before a setup callback runs.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            buffer: core::ptr::null_mut(),
            length: 0,
            argument: core::ptr::null_mut(),
        }
    }

    /// Returns the current non-negative byte count.
    #[must_use]
    pub fn len(&self) -> Option<usize> {
        usize::try_from(self.length).ok()
    }

    /// Reports whether the current callback buffer length is zero.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

fn call_asn1_ps(
    callback: ffi::asn1_ps_func,
    bio: &mut BioMut<'_>,
    state: &mut Asn1PsBuffer,
) -> i32 {
    let callback = callback.expect("constructor rejects null callbacks");
    // SAFETY: the callback wrapper's constructor establishes the setup or
    // cleanup contract. All three in/out slots and the exclusive BIO handle
    // remain live for this synchronous invocation.
    unsafe {
        callback(
            bio.as_mut_ptr(),
            &mut state.buffer,
            &mut state.length,
            core::ptr::from_mut(&mut state.argument).cast(),
        )
    }
}

/// Wraps: asn1_ps_func
/// Setup variant: produces a prefix/suffix buffer owned by the ASN.1 BIO until
/// its paired cleanup callback runs.
#[derive(Clone, Copy)]
pub struct Asn1PsSetupFunc(ffi::asn1_ps_func);

impl Asn1PsSetupFunc {
    /// Validates a raw callback as the setup variant.
    ///
    /// # Safety
    ///
    /// The callback must accept a live exclusive BIO, initialize a coherent
    /// buffer/length pair on success, use the argument as a `void **` context
    /// slot, retain nothing beyond that state, accept every state passed to
    /// [`Self::call`] (including [`Asn1PsBuffer::empty`]), and must not unwind.
    pub unsafe fn from_raw(raw: ffi::asn1_ps_func) -> Option<Self> {
        raw.map(|function| Self(Some(function)))
    }

    pub(crate) const fn as_raw(self) -> ffi::asn1_ps_func {
        self.0
    }

    /// Invokes this setup callback with its opaque state slots.
    pub fn call(&self, bio: &mut BioMut<'_>, state: &mut Asn1PsBuffer) -> i32 {
        call_asn1_ps(self.0, bio, state)
    }
}

/// Wraps: asn1_ps_func
/// Cleanup variant paired with an [`Asn1PsSetupFunc`].
#[derive(Clone, Copy)]
pub struct Asn1PsCleanupFunc(ffi::asn1_ps_func);

impl Asn1PsCleanupFunc {
    /// Validates a raw callback as the cleanup variant.
    ///
    /// # Safety
    ///
    /// The callback must accept state produced by its paired setup callback,
    /// release the owned buffer/context resources it consumes, leave the slots
    /// coherent for any later cleanup, safely accept empty/already-cleaned
    /// state, and must not unwind.
    pub unsafe fn from_raw(raw: ffi::asn1_ps_func) -> Option<Self> {
        raw.map(|function| Self(Some(function)))
    }

    pub(crate) const fn as_raw(self) -> ffi::asn1_ps_func {
        self.0
    }

    /// Invokes this cleanup callback with its opaque state slots.
    pub fn call(&self, bio: &mut BioMut<'_>, state: &mut Asn1PsBuffer) -> i32 {
        call_asn1_ps(self.0, bio, state)
    }
}

/// A setup/cleanup pair that may safely share one ASN.1 BIO state slot.
#[derive(Clone, Copy)]
pub struct Asn1PsCallbacks {
    setup: Option<Asn1PsSetupFunc>,
    cleanup: Option<Asn1PsCleanupFunc>,
}

impl Asn1PsCallbacks {
    /// Creates a pair with both callbacks disabled.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            setup: None,
            cleanup: None,
        }
    }

    /// Couples independently validated callback handles.
    ///
    /// # Safety
    /// `cleanup`, when present, must accept every successful state produced by
    /// `setup`, when present. Their ownership protocol must release each state
    /// exactly once without retaining any stack slots or unwinding.
    #[must_use]
    pub unsafe fn new(setup: Option<Asn1PsSetupFunc>, cleanup: Option<Asn1PsCleanupFunc>) -> Self {
        Self { setup, cleanup }
    }

    pub(crate) const fn setup_raw(self) -> ffi::asn1_ps_func {
        match self.setup {
            Some(setup) => setup.as_raw(),
            None => None,
        }
    }

    pub(crate) const fn cleanup_raw(self) -> ffi::asn1_ps_func {
        match self.cleanup {
            Some(cleanup) => cleanup.as_raw(),
            None => None,
        }
    }

    pub(crate) const fn from_valid_slots(
        setup: Option<Asn1PsSetupFunc>,
        cleanup: Option<Asn1PsCleanupFunc>,
    ) -> Self {
        Self { setup, cleanup }
    }

    /// Returns the optional setup callback.
    #[must_use]
    pub const fn setup(self) -> Option<Asn1PsSetupFunc> {
        self.setup
    }

    /// Returns the optional cleanup callback.
    #[must_use]
    pub const fn cleanup(self) -> Option<Asn1PsCleanupFunc> {
        self.cleanup
    }
}

#[cfg(test)]
mod asn1_ps_tests {
    use ffibox::CBox;

    use super::*;
    use crate::bio::bio_bio_local::Bio;

    unsafe extern "C" fn empty_setup(
        bio: *mut ffi::BIO,
        buffer: *mut *mut u8,
        length: *mut i32,
        argument: *mut c_void,
    ) -> i32 {
        assert!(!bio.is_null());
        assert!(!buffer.is_null());
        assert!(!length.is_null());
        assert!(!argument.is_null());
        // SAFETY: the wrapper supplies live writable output slots.
        unsafe {
            buffer.write(core::ptr::null_mut());
            length.write(0);
        }
        1
    }

    #[test]
    fn setup_callback_receives_opaque_in_out_state() {
        // SAFETY: `BIO_s_null` is a process-lifetime method and a successful
        // `BIO_new` transfers one complete BIO reference.
        let raw = unsafe { ffi::BIO_new(ffi::BIO_s_null()) };
        // SAFETY: the returned reference is uniquely adopted by its matching
        // `BIO_free` owner.
        let mut bio = unsafe { CBox::<Bio>::from_raw(raw) }.expect("BIO_new");
        // SAFETY: `empty_setup` accepts the wrapper's slots and never retains
        // them or unwinds.
        let callback = unsafe { Asn1PsSetupFunc::from_raw(Some(empty_setup)) }.unwrap();
        let mut state = Asn1PsBuffer::empty();

        assert_eq!(callback.call(&mut bio.as_mut(), &mut state), 1);
        assert!(state.is_empty());
        assert_eq!(state.len(), Some(0));
    }
}

/// Wraps: BIO_meth_get_recvmmsg
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_recvmmsg(
    method: BioMethodRef<'_>,
) -> Option<super::bio_meth::BioMethodMmsgCallback> {
    // SAFETY: the borrowed handle guarantees a live shared BIO_METHOD for the
    // duration of this synchronous getter call.
    let raw = unsafe { ffi::crustify_BIO_meth_get_recvmmsg(method.as_ptr()) };
    // SAFETY: any callback installed in a valid BIO_METHOD obeys that method
    // slot's static C contract.
    unsafe { super::bio_meth::BioMethodMmsgCallback::from_raw(raw) }
}

/// Wraps: BIO_meth_get_sendmmsg
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_get_sendmmsg(
    method: BioMethodRef<'_>,
) -> Option<super::bio_meth::BioMethodMmsgCallback> {
    // SAFETY: as `BIO_meth_get_recvmmsg`, for the send slot.
    let raw = unsafe { ffi::crustify_BIO_meth_get_sendmmsg(method.as_ptr()) };
    // SAFETY: valid method tables contain callbacks obeying the slot contract.
    unsafe { super::bio_meth::BioMethodMmsgCallback::from_raw(raw) }
}

#[cfg(test)]
mod mmsg_method_getter_tests {
    use super::*;
    use crate::bio::bio_lib::BIO_new;
    use crate::bio::bio_meth::{
        BIO_meth_new, BIO_meth_set_recvmmsg, BIO_meth_set_sendmmsg, BioMethodMmsgCallback,
    };

    unsafe extern "C" fn process_one(
        _bio: *mut ffi::BIO,
        _messages: *mut ffi::BIO_MSG,
        _stride: usize,
        count: usize,
        _flags: u64,
        processed: *mut usize,
    ) -> c_int {
        if count == 0 || processed.is_null() {
            return 0;
        }
        // SAFETY: the BIO method callback contract supplies one live output
        // slot, and this branch has rejected a null pointer.
        unsafe { processed.write(1) };
        1
    }

    #[test]
    fn getters_return_callable_installed_callbacks() {
        let mut method = BIO_meth_new(75, c"mmsg getters").expect("BIO_meth_new");
        // SAFETY: `process_one` accepts every well-formed message run, writes
        // at most one processed entry, is thread-safe, and never unwinds.
        let callback = unsafe { BioMethodMmsgCallback::from_raw(Some(process_one)) }.unwrap();
        assert!(BIO_meth_set_recvmmsg(method.as_mut(), Some(callback)));
        assert!(BIO_meth_set_sendmmsg(method.as_mut(), Some(callback)));

        let receive = BIO_meth_get_recvmmsg(method.as_ref()).expect("receive callback");
        let send = BIO_meth_get_sendmmsg(method.as_ref()).expect("send callback");
        let mut bio = BIO_new(method.as_ref()).expect("BIO_new");
        let mut message = BioMsg::empty();
        // SAFETY: `CVal` is transparent over its inline descriptor, which is
        // live and initialized for the rest of this scope; the one-element
        // view is the only handle to it, and no reference to the C object is
        // formed on the way.
        let mut messages = unsafe {
            CSliceMut::from_raw_parts(
                NonNull::new_unchecked(addr_of_mut!(message).cast::<BioMsg<'_>>()),
                1,
            )
        };

        assert_eq!(receive.call(&mut bio.as_mut(), &mut messages, 0), Some(1));
        assert_eq!(send.call(&mut bio.as_mut(), &mut messages, 0), Some(1));
    }
}

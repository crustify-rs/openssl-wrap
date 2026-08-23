//! Wrappers assigned from `crypto/bio/bio_addr.c`.

use core::ffi::CStr;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CBoxWith, CCell, CCloned, CDropped, CDropper};
use libc::netdb::{AddrInfo, AddrInfoRef};
use libcrypto_sys as ffi;

use super::internal_bio_addr::{BioAddr, BioAddrMut, BioAddrRef};
use super::openssl_bio::{BioHostservPriorities, BioLookupType};
use crate::mem::CryptoString;

/// Teardown policy for the address-info lists returned by OpenSSL.
#[derive(Clone, Copy, Debug, Default)]
pub struct BioAddrInfoFree;

/// An owned OpenSSL address-info list.
pub type BioAddrInfo = CBoxWith<AddrInfo, BioAddrInfoFree>;

// SAFETY: OpenSSL's `BIO_ADDRINFO_free` accepts exactly the list heads returned
// by its lookup APIs and releases the complete list, including AF_UNIX nodes.
unsafe impl CDropper<AddrInfo> for BioAddrInfoFree {
    unsafe fn c_drop(&self, address_info: NonNull<AddrInfo>) {
        // SAFETY: the strategy contract transfers a uniquely owned OpenSSL
        // address-info list head. The two bindgen views name the same C layout.
        unsafe { ffi::BIO_ADDRINFO_free(address_info.as_ptr().cast()) }
    }
}

/// Wraps: BIO_ADDRINFO_address
#[allow(non_snake_case)]
pub fn BIO_ADDRINFO_address<'a>(address_info: &AddrInfoRef<'a>) -> Option<BioAddrRef<'a>> {
    // SAFETY: the address-info handle keeps the node and its child address live.
    let raw = unsafe { ffi::BIO_ADDRINFO_address(address_info.as_ptr().cast()) };
    // SAFETY: a non-null result is the node's borrowed address and remains live
    // for no longer than the input handle's lifetime.
    unsafe { BioAddrRef::from_ptr(raw.cast_mut()) }
}

/// Wraps: BIO_ADDRINFO_family
#[allow(non_snake_case)]
pub fn BIO_ADDRINFO_family(address_info: &AddrInfoRef<'_>) -> i32 {
    // SAFETY: the handle supplies a live address-info node for the call.
    unsafe { ffi::BIO_ADDRINFO_family(address_info.as_ptr().cast()) }
}

/// Wraps: BIO_ADDRINFO_free
#[allow(non_snake_case)]
pub fn BIO_ADDRINFO_free(address_info: BioAddrInfo) {
    drop(address_info);
}

/// Wraps: BIO_ADDRINFO_next
#[allow(non_snake_case)]
pub fn BIO_ADDRINFO_next<'a>(address_info: &AddrInfoRef<'a>) -> Option<AddrInfoRef<'a>> {
    // SAFETY: the input handle keeps its complete owning list live.
    let raw = unsafe { ffi::BIO_ADDRINFO_next(address_info.as_ptr().cast()) };
    // SAFETY: a non-null next node belongs to the same list and is therefore
    // live for no longer than the input handle.
    unsafe { AddrInfoRef::from_ptr(raw.cast_mut().cast()) }
}

/// Wraps: BIO_ADDRINFO_protocol
#[allow(non_snake_case)]
pub fn BIO_ADDRINFO_protocol(address_info: &AddrInfoRef<'_>) -> i32 {
    // SAFETY: the handle supplies a live address-info node for the call.
    unsafe { ffi::BIO_ADDRINFO_protocol(address_info.as_ptr().cast()) }
}

/// Wraps: BIO_ADDRINFO_socktype
#[allow(non_snake_case)]
pub fn BIO_ADDRINFO_socktype(address_info: &AddrInfoRef<'_>) -> i32 {
    // SAFETY: the handle supplies a live address-info node for the call.
    unsafe { ffi::BIO_ADDRINFO_socktype(address_info.as_ptr().cast()) }
}

/// Wraps: BIO_ADDR_clear
#[allow(non_snake_case)]
pub fn BIO_ADDR_clear(address: &mut BioAddrMut<'_>) {
    // SAFETY: the exclusive handle supplies writable layout-compatible storage.
    unsafe { ffi::BIO_ADDR_clear(address.as_mut_ptr()) }
}

/// Wraps: BIO_ADDR_copy
#[allow(non_snake_case)]
pub fn BIO_ADDR_copy(destination: &mut BioAddrMut<'_>, source: &BioAddrRef<'_>) -> bool {
    // SAFETY: the exclusive destination and shared source are live and cannot
    // alias incompatibly through their safe handle types.
    unsafe { ffi::BIO_ADDR_copy(destination.as_mut_ptr(), source.as_ptr()) != 0 }
}

/// Wraps: BIO_ADDR_dup
#[allow(non_snake_case)]
pub fn BIO_ADDR_dup(address: &BioAddrRef<'_>) -> Option<CBox<BioAddr>> {
    // SAFETY: the shared handle supplies one live source address.
    let raw = unsafe { ffi::BIO_ADDR_dup(address.as_ptr()) };
    // SAFETY: a non-null result is a fresh allocation transferred by OpenSSL.
    unsafe { CBox::from_raw(raw) }
}

// SAFETY: `BIO_ADDR_dup` makes a fresh deep copy and `CDropped` below releases
// exactly that allocation.
unsafe impl CCloned for BioAddr {
    unsafe fn c_clone(address: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract supplies a live source address.
        let raw = unsafe { ffi::BIO_ADDR_dup(address.as_ptr().cast()) };
        NonNull::new(raw.cast())
    }
}

/// Wraps: BIO_ADDR_family
#[allow(non_snake_case)]
pub fn BIO_ADDR_family(address: &BioAddrRef<'_>) -> i32 {
    // SAFETY: the shared handle supplies one live address.
    unsafe { ffi::BIO_ADDR_family(address.as_ptr()) }
}

/// Wraps: BIO_ADDR_free
#[allow(non_snake_case)]
pub fn BIO_ADDR_free(address: CBox<BioAddr>) {
    drop(address);
}

// SAFETY: `BIO_ADDR_free` is the allocator-matched destructor for every fully
// constructed address produced by `BIO_ADDR_new` or `BIO_ADDR_dup`.
unsafe impl CDropped for BioAddr {
    unsafe fn c_drop(address: NonNull<Self>) {
        // SAFETY: the trait contract transfers one owned address allocation.
        unsafe { ffi::BIO_ADDR_free(address.as_ptr().cast()) }
    }
}

/// Wraps: BIO_ADDR_hostname_string
#[allow(non_snake_case)]
pub fn BIO_ADDR_hostname_string(address: &BioAddrRef<'_>, numeric: bool) -> Option<CryptoString> {
    // SAFETY: the address remains live and OpenSSL returns a fresh string or null.
    let raw = unsafe { ffi::BIO_ADDR_hostname_string(address.as_ptr(), i32::from(numeric)) };
    // SAFETY: a non-null result is a fresh NUL-terminated OpenSSL allocation.
    unsafe { CryptoString::from_raw(raw) }
}

/// Wraps: BIO_ADDR_new
#[allow(non_snake_case)]
pub fn BIO_ADDR_new() -> Option<CBox<BioAddr>> {
    // SAFETY: the constructor has no caller-side pointer obligations.
    let raw = unsafe { ffi::BIO_ADDR_new() };
    // SAFETY: a non-null result is a fresh, fully initialized address.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: BIO_ADDR_path_string
#[allow(non_snake_case)]
pub fn BIO_ADDR_path_string(address: &BioAddrRef<'_>) -> Option<CryptoString> {
    // SAFETY: the address remains live and OpenSSL returns a fresh string or null.
    let raw = unsafe { ffi::BIO_ADDR_path_string(address.as_ptr()) };
    // SAFETY: a non-null result is a fresh NUL-terminated OpenSSL allocation.
    unsafe { CryptoString::from_raw(raw) }
}

/// Failure to copy the family-specific bytes from a socket address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BioAddrRawAddressError {
    /// The address family has no raw byte representation.
    Unavailable,
    /// The destination is smaller than the required byte count.
    TooSmall { required: usize },
}

/// Wraps: BIO_ADDR_rawaddress
#[allow(non_snake_case)]
pub fn BIO_ADDR_rawaddress(
    address: &BioAddrRef<'_>,
    destination: &mut [u8],
) -> Result<usize, BioAddrRawAddressError> {
    let mut required = 0_usize;
    // SAFETY: querying with a null output buffer writes only the live length slot.
    let available =
        unsafe { ffi::BIO_ADDR_rawaddress(address.as_ptr(), ptr::null_mut(), &mut required) } != 0;
    if !available {
        return Err(BioAddrRawAddressError::Unavailable);
    }
    if destination.len() < required {
        return Err(BioAddrRawAddressError::TooSmall { required });
    }
    let mut written = 0_usize;
    // SAFETY: the prior query established the number of bytes OpenSSL copies,
    // and the length check proves the destination has at least that capacity.
    let copied = unsafe {
        ffi::BIO_ADDR_rawaddress(
            address.as_ptr(),
            destination.as_mut_ptr().cast(),
            &mut written,
        )
    } != 0;
    if copied {
        Ok(written)
    } else {
        Err(BioAddrRawAddressError::Unavailable)
    }
}

/// Wraps: BIO_ADDR_rawmake
///
/// `where_bytes` is copied into aligned, NUL-padded temporary storage. This
/// makes the API safe for both fixed-width Internet addresses and Unix paths.
#[allow(non_snake_case)]
pub fn BIO_ADDR_rawmake(
    address: &mut BioAddrMut<'_>,
    family: i32,
    where_bytes: &[u8],
    port: u16,
) -> bool {
    let words = where_bytes
        .len()
        .saturating_add(1)
        .div_ceil(core::mem::size_of::<usize>());
    let mut aligned = vec![0_usize; words.max(1)];
    // SAFETY: `aligned` owns at least `where_bytes.len() + 1` writable bytes;
    // the initialized source cannot overlap it. The retained zero byte makes a
    // Unix path NUL-terminated, while native address structs get proper alignment.
    unsafe {
        ptr::copy_nonoverlapping(
            where_bytes.as_ptr(),
            aligned.as_mut_ptr().cast::<u8>(),
            where_bytes.len(),
        )
    };
    // SAFETY: the exclusive address is writable and the aligned temporary has
    // `where_bytes.len()` readable bytes plus a terminator for the whole call.
    unsafe {
        ffi::BIO_ADDR_rawmake(
            address.as_mut_ptr(),
            family,
            aligned.as_ptr().cast(),
            where_bytes.len(),
            port,
        ) != 0
    }
}

/// Wraps: BIO_ADDR_rawport
#[allow(non_snake_case)]
pub fn BIO_ADDR_rawport(address: &BioAddrRef<'_>) -> u16 {
    // SAFETY: the shared handle supplies one live address.
    unsafe { ffi::BIO_ADDR_rawport(address.as_ptr()) }
}

/// Wraps: BIO_ADDR_service_string
#[allow(non_snake_case)]
pub fn BIO_ADDR_service_string(address: &BioAddrRef<'_>, numeric: bool) -> Option<CryptoString> {
    // SAFETY: the address remains live and OpenSSL returns a fresh string or null.
    let raw = unsafe { ffi::BIO_ADDR_service_string(address.as_ptr(), i32::from(numeric)) };
    // SAFETY: a non-null result is a fresh NUL-terminated OpenSSL allocation.
    unsafe { CryptoString::from_raw(raw) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_owner_copies_and_clears() {
        let source = BIO_ADDR_new().expect("BIO_ADDR_new");
        let mut copy = BIO_ADDR_dup(&source.as_ref()).expect("BIO_ADDR_dup");
        assert_eq!(
            BIO_ADDR_family(&source.as_ref()),
            BIO_ADDR_family(&copy.as_ref())
        );
        BIO_ADDR_clear(&mut copy.as_mut());
        let clone = copy.try_clone().expect("CCloned BIO_ADDR_dup");
        assert_eq!(BIO_ADDR_rawport(&clone.as_ref()), 0);
    }

    #[test]
    fn a_unix_lookup_without_a_host_never_reaches_c() {
        let family = i32::try_from(ffi::AF_UNIX).expect("AF_UNIX fits an int");
        assert!(BIO_lookup(None, None, BioLookupType::CLIENT, family, 0).is_none());
        assert!(BIO_lookup_ex(None, None, BioLookupType::CLIENT, family, 0, 0).is_none());
    }

    #[test]
    fn a_unix_lookup_with_a_host_resolves_that_path() {
        let family = i32::try_from(ffi::AF_UNIX).expect("AF_UNIX fits an int");
        let path = Some(c"/tmp/crustify.sock");
        let list = BIO_lookup(path, None, BioLookupType::CLIENT, family, 0)
            .expect("AF_UNIX lookups wrap the path without touching the filesystem");
        assert_eq!(BIO_ADDRINFO_family(&list.as_ref()), family);
    }

    #[test]
    fn an_internet_lookup_still_accepts_an_absent_host() {
        let family = i32::try_from(ffi::AF_INET).expect("AF_INET fits an int");
        assert!(BIO_lookup(None, Some(c"80"), BioLookupType::SERVER, family, 0).is_some());
    }

    #[test]
    fn invalid_family_has_no_raw_address() {
        let address = BIO_ADDR_new().expect("BIO_ADDR_new");
        let mut output = [0_u8; 16];
        assert_eq!(
            BIO_ADDR_rawaddress(&address.as_ref(), &mut output),
            Err(BioAddrRawAddressError::Unavailable)
        );
    }
}

fn input_ptr(value: Option<&CStr>) -> *const core::ffi::c_char {
    value.map_or(ptr::null(), CStr::as_ptr)
}

/// Reports whether OpenSSL's lookup path for `family` dereferences `host`
/// without checking it.
///
/// Every family but `AF_UNIX` reaches `getaddrinfo`, which documents a null
/// node name. The `AF_UNIX` branch of `BIO_lookup_ex` instead calls
/// `strlen(host)` before it inspects anything, so an absent host would be a
/// null dereference inside C.
fn family_requires_host(family: i32) -> bool {
    u32::try_from(family) == Ok(ffi::AF_UNIX)
}

unsafe fn adopt_result(raw: *mut ffi::BIO_ADDRINFO) -> Option<BioAddrInfo> {
    let raw = raw.cast::<<AddrInfo as CCell>::C>();
    // SAFETY: the caller passes the unique head returned by a successful
    // BIO_lookup operation and selects its matching list destructor.
    unsafe { CBoxWith::from_raw(raw, BioAddrInfoFree) }
}

/// Wraps: BIO_lookup
/// Resolves an optional host/service pair into an owned address list.
///
/// Returns `None` without calling C for an `AF_UNIX` lookup with no host, the
/// one combination whose C path dereferences `host` unconditionally.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_lookup(
    host: Option<&CStr>,
    service: Option<&CStr>,
    lookup_type: BioLookupType,
    family: i32,
    socket_type: i32,
) -> Option<BioAddrInfo> {
    if host.is_none() && family_requires_host(family) {
        return None;
    }
    let mut result = ptr::null_mut();
    // SAFETY: input strings remain live and the check above supplies the host
    // the `AF_UNIX` path dereferences; `result` is a writable output slot.
    let ok = unsafe {
        ffi::BIO_lookup(
            input_ptr(host),
            input_ptr(service),
            lookup_type.as_raw(),
            family,
            socket_type,
            &mut result,
        )
    };
    if ok != 1 {
        return None;
    }
    // SAFETY: success transfers the unique list head to the caller.
    unsafe { adopt_result(result) }
}

/// Wraps: BIO_lookup_ex
/// Resolves an optional host/service pair with an explicit protocol.
///
/// Returns `None` without calling C for an `AF_UNIX` lookup with no host, the
/// one combination whose C path dereferences `host` unconditionally.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_lookup_ex(
    host: Option<&CStr>,
    service: Option<&CStr>,
    lookup_type: BioLookupType,
    family: i32,
    socket_type: i32,
    protocol: i32,
) -> Option<BioAddrInfo> {
    if host.is_none() && family_requires_host(family) {
        return None;
    }
    let mut result = ptr::null_mut();
    let Ok(lookup_type) = i32::try_from(lookup_type.as_raw()) else {
        return None;
    };
    // SAFETY: input strings remain live and the check above supplies the host
    // the `AF_UNIX` path dereferences; `result` is a writable output slot.
    let ok = unsafe {
        ffi::BIO_lookup_ex(
            input_ptr(host),
            input_ptr(service),
            lookup_type,
            family,
            socket_type,
            protocol,
            &mut result,
        )
    };
    if ok != 1 {
        return None;
    }
    // SAFETY: success transfers the unique list head to the caller.
    unsafe { adopt_result(result) }
}

/// Host and service components allocated by `BIO_parse_hostserv`.
#[derive(Debug)]
pub struct ParsedHostService {
    /// Parsed host name, absent for an empty or wildcard host.
    pub host: Option<CryptoString>,
    /// Parsed service name, absent for an empty or wildcard service.
    pub service: Option<CryptoString>,
}

/// Wraps: BIO_parse_hostserv
#[allow(non_snake_case)]
pub fn BIO_parse_hostserv(
    input: &CStr,
    priority: BioHostservPriorities,
) -> Option<ParsedHostService> {
    let mut host = ptr::null_mut();
    let mut service = ptr::null_mut();
    // SAFETY: `input` is a live C string and both output slots are live.
    // Success transfers any non-null strings to the caller.
    let ok = unsafe {
        ffi::BIO_parse_hostserv(input.as_ptr(), &mut host, &mut service, priority.as_raw())
    };
    if ok == 0 {
        return None;
    }
    // SAFETY: successful non-null outputs are fresh NUL-terminated allocations
    // released by `CRYPTO_free`.
    let host = unsafe { CryptoString::from_raw(host) };
    // SAFETY: as above for the independent service output.
    let service = unsafe { CryptoString::from_raw(service) };
    Some(ParsedHostService { host, service })
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;

    #[test]
    fn parses_host_and_service_into_owned_strings() {
        let parsed = BIO_parse_hostserv(c"localhost:443", BioHostservPriorities::HOST)
            .expect("valid host/service");
        assert_eq!(
            parsed.host.as_ref().map(|s| s.as_c_str()),
            Some(c"localhost")
        );
        assert_eq!(parsed.service.as_ref().map(|s| s.as_c_str()), Some(c"443"));
    }
}

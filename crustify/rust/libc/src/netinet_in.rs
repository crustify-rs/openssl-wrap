//! Wrappers assigned from `/usr/include/netinet/in.h`.

use core::ptr;

use libc_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: in_addr
    ///
    /// Layout-compatible storage for a C IPv4 address. The `s_addr` value is
    /// kept in network byte order, matching `struct in_addr`.
    ///
    /// A handle may be formed over storage that does not carry the struct's
    /// four-byte alignment. OpenSSL reads this type straight out of
    /// caller-supplied byte buffers — `BIO_ADDR_rawmake`'s `const void *where`
    /// reaches `*(struct in_addr *)where` at `crypto/bio/bio_addr.c:148`, and
    /// on the `BIO_lookup_ex` fallback path that argument is a
    /// `hostent::h_addr_list` element, whose alignment the resolver does not
    /// promise. The accessors below therefore use unaligned loads and stores,
    /// and `from_ptr` requires only a live, initialized four-byte address.
    InAddr,
    InAddrRef,
    InAddrMut,
    ffi::in_addr
);

impl InAddrRef<'_> {
    /// Returns the address bits in network byte order.
    #[must_use]
    pub fn s_addr(&self) -> u32 {
        // SAFETY: the handle contract guarantees a live, initialized `in_addr`
        // and `s_addr` covers all of it, so every bit pattern is valid. The
        // read is unaligned because a wrapped address need not be four-byte
        // aligned (see `InAddr`), and raw projection forms no reference to the
        // C object.
        unsafe { ptr::addr_of!((*self.as_ptr()).s_addr).read_unaligned() }
    }
}

impl InAddrMut<'_> {
    /// Sets the address bits in network byte order.
    pub fn set_s_addr(&mut self, value: u32) {
        // SAFETY: the exclusive handle contract guarantees live, writable
        // `in_addr` storage; the unaligned store writes the whole field, whose
        // every bit pattern is valid, without forming a reference.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).s_addr).write_unaligned(value) }
    }
}

ffibox::define_ctype!(
    /// Wraps: in6_addr
    ///
    /// Layout-compatible storage for a C IPv6 address. Octets preserve network
    /// byte order; the 16- and 32-bit views use the host's native byte order,
    /// exactly like the corresponding C union members.
    ///
    /// As for [`InAddr`], a handle may be formed over unaligned storage:
    /// `BIO_ADDR_rawmake` reads `*(struct in6_addr *)where` from the same
    /// untyped buffers. The byte view needs no alignment, and the word views
    /// use unaligned loads and stores so that all three agree on which
    /// pointers they accept.
    In6Addr,
    In6AddrRef,
    In6AddrMut,
    ffi::in6_addr
);

impl In6AddrRef<'_> {
    /// Copy the address as sixteen network-order octets (`s6_addr`).
    #[must_use]
    pub fn octets(&self) -> [u8; 16] {
        // SAFETY: the handle guarantees a live, initialized `in6_addr`. The
        // byte member spans the whole union, every bit pattern is valid for
        // `[u8; 16]`, and its alignment is one, so any wrapped address is
        // readable. Raw projection forms no reference to C storage.
        unsafe { ptr::addr_of!((*self.as_ptr()).__in6_u.__u6_addr8).read() }
    }

    /// Copy the address as eight native-endian 16-bit words (`s6_addr16`).
    #[must_use]
    pub fn native_u16s(&self) -> [u16; 8] {
        // SAFETY: as `octets`, and every bit pattern is valid for `[u16; 8]`.
        // The load is unaligned because a wrapped address need not carry the
        // union's alignment (see `In6Addr`).
        unsafe { ptr::addr_of!((*self.as_ptr()).__in6_u.__u6_addr16).read_unaligned() }
    }

    /// Copy the address as four native-endian 32-bit words (`s6_addr32`).
    #[must_use]
    pub fn native_u32s(&self) -> [u32; 4] {
        // SAFETY: as `octets`, and every bit pattern is valid for `[u32; 4]`.
        // The load is unaligned for the same reason as `native_u16s`.
        unsafe { ptr::addr_of!((*self.as_ptr()).__in6_u.__u6_addr32).read_unaligned() }
    }
}

impl In6AddrMut<'_> {
    /// Replace the address from sixteen network-order octets (`s6_addr`).
    pub fn set_octets(&mut self, octets: [u8; 16]) {
        // SAFETY: the exclusive handle guarantees live, writable union
        // storage; writing the complete byte member initializes all 16 bytes,
        // and that member's alignment is one.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).__in6_u.__u6_addr8).write(octets) }
    }

    /// Replace the address from eight native-endian 16-bit words.
    pub fn set_native_u16s(&mut self, words: [u16; 8]) {
        // SAFETY: as `set_octets`; the complete member is 16 bytes wide, and
        // the store is unaligned because the storage need not carry the
        // union's alignment.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).__in6_u.__u6_addr16).write_unaligned(words)
        }
    }

    /// Replace the address from four native-endian 32-bit words.
    pub fn set_native_u32s(&mut self, words: [u32; 4]) {
        // SAFETY: as `set_native_u16s`.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).__in6_u.__u6_addr32).write_unaligned(words)
        }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    /// Byte storage whose payload is guaranteed to start one byte past a
    /// four-byte boundary, so it can never satisfy the alignment of
    /// `in_addr` or `in6_addr`.
    #[repr(C, align(4))]
    struct MisalignedStorage {
        _pad: u8,
        bytes: [u8; 16],
    }

    impl MisalignedStorage {
        const fn new() -> Self {
            Self {
                _pad: 0,
                bytes: [0; 16],
            }
        }
    }

    #[test]
    fn layout_matches_raw_in_addr() {
        assert_eq!(size_of::<InAddr>(), size_of::<ffi::in_addr>());
        assert_eq!(align_of::<InAddr>(), align_of::<ffi::in_addr>());
    }

    #[test]
    fn borrowed_handles_read_and_write_address_bits() {
        let mut storage = InAddr::zeroed();
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::in_addr>();

        {
            // SAFETY: `raw` points to live, layout-compatible storage that is
            // exclusively used through this mutable handle for this scope.
            let mut address = unsafe { InAddrMut::from_ptr(raw) }.expect("non-null in_addr");
            address.set_s_addr(0x0102_0304);
            assert_eq!(address.as_ref().s_addr(), 0x0102_0304);
        }

        // SAFETY: `raw` still points to the live storage above, and the prior
        // exclusive handle is no longer used.
        let address = unsafe { InAddrRef::from_ptr(raw) }.expect("non-null in_addr");
        assert_eq!(address.s_addr(), 0x0102_0304);
        assert_eq!(address.as_ptr(), raw.cast_const());
    }

    #[test]
    fn in_addr_handles_accept_unaligned_storage() {
        let mut storage = MisalignedStorage::new();
        let raw = ptr::addr_of_mut!(storage.bytes).cast::<ffi::in_addr>();
        assert_ne!(raw as usize % align_of::<ffi::in_addr>(), 0);

        {
            // SAFETY: the four bytes at `raw` are live and initialized, every
            // bit pattern is a valid `in_addr`, and only this handle reaches
            // them for the scope.
            let mut address = unsafe { InAddrMut::from_ptr(raw) }.expect("non-null in_addr");
            address.set_s_addr(u32::from_ne_bytes([9, 8, 7, 6]));
        }

        assert_eq!(storage.bytes[..4], [9, 8, 7, 6]);

        // SAFETY: as above; the previous exclusive handle is gone.
        let address = unsafe { InAddrRef::from_ptr(raw) }.expect("non-null in_addr");
        assert_eq!(address.s_addr(), u32::from_ne_bytes([9, 8, 7, 6]));
    }

    #[test]
    fn layout_matches_raw_in6_addr() {
        assert_eq!(size_of::<In6Addr>(), size_of::<ffi::in6_addr>());
        assert_eq!(align_of::<In6Addr>(), align_of::<ffi::in6_addr>());
    }

    #[test]
    fn borrowed_handles_copy_and_replace_all_union_views() {
        let mut storage = In6Addr::zeroed();
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::in6_addr>();
        // SAFETY: `raw` points to live layout-compatible storage used only
        // through this exclusive handle for its lifetime.
        let mut address = unsafe { In6AddrMut::from_ptr(raw) }.expect("in6_addr");

        let octets = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        address.set_octets(octets);
        assert_eq!(address.as_ref().octets(), octets);

        let words16 = [1_u16, 2, 3, 4, 5, 6, 7, 8];
        address.set_native_u16s(words16);
        assert_eq!(address.as_ref().native_u16s(), words16);

        let words32 = [1_u32, 2, 3, 4];
        address.set_native_u32s(words32);
        assert_eq!(address.as_ref().native_u32s(), words32);
    }

    #[test]
    fn in6_addr_views_reinterpret_the_same_sixteen_bytes() {
        let mut storage = In6Addr::zeroed();
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::in6_addr>();
        // SAFETY: `raw` points to live layout-compatible storage reached only
        // through this exclusive handle.
        let mut address = unsafe { In6AddrMut::from_ptr(raw) }.expect("in6_addr");

        let octets = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        address.set_octets(octets);

        // The word views are the same bytes read in host order, which is what
        // `s6_addr16` and `s6_addr32` are in C.
        let expected16 = [
            u16::from_ne_bytes([0x20, 0x01]),
            u16::from_ne_bytes([0x0d, 0xb8]),
            0,
            0,
            0,
            0,
            0,
            u16::from_ne_bytes([0, 0x01]),
        ];
        assert_eq!(address.as_ref().native_u16s(), expected16);
        assert_eq!(
            address.as_ref().native_u32s()[0],
            u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8])
        );
    }

    #[test]
    fn in6_addr_handles_accept_unaligned_storage() {
        let mut storage = MisalignedStorage::new();
        let raw = ptr::addr_of_mut!(storage.bytes).cast::<ffi::in6_addr>();
        assert_ne!(raw as usize % align_of::<ffi::in6_addr>(), 0);

        let octets = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42];
        {
            // SAFETY: the sixteen bytes at `raw` are live and initialized,
            // every bit pattern is a valid `in6_addr`, and only this handle
            // reaches them for the scope.
            let mut address = unsafe { In6AddrMut::from_ptr(raw) }.expect("in6_addr");
            address.set_octets(octets);
            assert_eq!(address.as_ref().octets(), octets);
            assert_eq!(
                address.as_ref().native_u32s()[0],
                u32::from_ne_bytes([0xfe, 0x80, 0, 0])
            );
            address.set_native_u32s([7, 6, 5, 4]);
            assert_eq!(address.as_ref().native_u32s(), [7, 6, 5, 4]);
            address.set_native_u16s([1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(address.as_ref().native_u16s(), [1, 2, 3, 4, 5, 6, 7, 8]);
        }

        assert_eq!(storage.bytes[..2], 1_u16.to_ne_bytes());
    }
}

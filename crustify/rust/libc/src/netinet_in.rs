//! Wrappers assigned from `/usr/include/netinet/in.h`.

use core::ptr;

use libc_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: in_addr
    ///
    /// Layout-compatible storage for a C IPv4 address. The `s_addr` value is
    /// kept in network byte order, matching `struct in_addr`.
    InAddr,
    InAddrRef,
    InAddrMut,
    ffi::in_addr
);

impl InAddrRef<'_> {
    /// Returns the address bits in network byte order.
    pub fn s_addr(&self) -> u32 {
        // SAFETY: the handle contract guarantees a live, aligned `in_addr`;
        // `s_addr` is an initialized `u32` and is read without forming a
        // reference to the C object.
        unsafe { ptr::addr_of!((*self.as_ptr()).s_addr).read() }
    }
}

impl InAddrMut<'_> {
    /// Sets the address bits in network byte order.
    pub fn set_s_addr(&mut self, value: u32) {
        // SAFETY: the exclusive handle contract guarantees writable, aligned
        // `in_addr` storage; writing a `u32` preserves the field's validity.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).s_addr).write(value) }
    }
}

ffibox::define_ctype!(
    /// Wraps: in6_addr
    ///
    /// Layout-compatible storage for a C IPv6 address. Octets preserve network
    /// byte order; the 16- and 32-bit views use the host's native byte order,
    /// exactly like the corresponding C union members.
    In6Addr,
    In6AddrRef,
    In6AddrMut,
    ffi::in6_addr
);

impl In6AddrRef<'_> {
    /// Copy the address as sixteen network-order octets (`s6_addr`).
    #[must_use]
    pub fn octets(&self) -> [u8; 16] {
        // SAFETY: the handle guarantees a live, initialized `in6_addr`. Every
        // bit pattern is valid for the byte-array union member, and raw
        // projection forms no reference to C storage.
        unsafe { ptr::addr_of!((*self.as_ptr()).__in6_u.__u6_addr8).read() }
    }

    /// Copy the address as eight native-endian 16-bit words (`s6_addr16`).
    #[must_use]
    pub fn native_u16s(&self) -> [u16; 8] {
        // SAFETY: as `octets`; every bit pattern is valid for `[u16; 8]`, and
        // the C union guarantees this member's alignment.
        unsafe { ptr::addr_of!((*self.as_ptr()).__in6_u.__u6_addr16).read() }
    }

    /// Copy the address as four native-endian 32-bit words (`s6_addr32`).
    #[must_use]
    pub fn native_u32s(&self) -> [u32; 4] {
        // SAFETY: as `octets`; every bit pattern is valid for `[u32; 4]`, and
        // the C union guarantees this member's alignment.
        unsafe { ptr::addr_of!((*self.as_ptr()).__in6_u.__u6_addr32).read() }
    }
}

impl In6AddrMut<'_> {
    /// Replace the address from sixteen network-order octets (`s6_addr`).
    pub fn set_octets(&mut self, octets: [u8; 16]) {
        // SAFETY: the exclusive handle guarantees writable, aligned union
        // storage; writing the complete byte member initializes all 16 bytes.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).__in6_u.__u6_addr8).write(octets) }
    }

    /// Replace the address from eight native-endian 16-bit words.
    pub fn set_native_u16s(&mut self, words: [u16; 8]) {
        // SAFETY: the exclusive handle guarantees writable, aligned union
        // storage; writing this complete member initializes all 16 bytes.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).__in6_u.__u6_addr16).write(words) }
    }

    /// Replace the address from four native-endian 32-bit words.
    pub fn set_native_u32s(&mut self, words: [u32; 4]) {
        // SAFETY: the exclusive handle guarantees writable, aligned union
        // storage; writing this complete member initializes all 16 bytes.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).__in6_u.__u6_addr32).write(words) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

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
}

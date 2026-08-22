//! Wrappers assigned from `/usr/include/netinet/in.h`.

use core::ptr::{addr_of, addr_of_mut};

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
        unsafe { addr_of!((*self.as_ptr()).s_addr).read() }
    }
}

impl InAddrMut<'_> {
    /// Sets the address bits in network byte order.
    pub fn set_s_addr(&mut self, value: u32) {
        // SAFETY: the exclusive handle contract guarantees writable, aligned
        // `in_addr` storage; writing a `u32` preserves the field's validity.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).s_addr).write(value) }
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
        let raw = addr_of_mut!(storage).cast::<ffi::in_addr>();

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
}

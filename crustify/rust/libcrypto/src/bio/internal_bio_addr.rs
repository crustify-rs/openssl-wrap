//! Wrappers assigned from `include/internal/bio_addr.h`.

use libcrypto_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: bio_addr_st
    ///
    /// Layout-compatible storage for OpenSSL's socket-address union. Every
    /// variant (`sockaddr`, `sockaddr_in`, `sockaddr_in6`, `sockaddr_un`) is a
    /// plain by-value struct, so the union owns no field storage: it needs no
    /// field disposer, and `BIO_ADDR_clear` only resets it in place. Heap
    /// ownership is the `CDropped` / `CCloned` pair over `BIO_ADDR_free` and
    /// `BIO_ADDR_dup` in [`super::bio_addr`]; embedded and stack storage uses
    /// [`BioAddr::zeroed`], which matches what `BIO_ADDR_clear` produces
    /// because `AF_UNSPEC` is zero.
    ///
    /// The variants stay opaque to safe Rust: the public API declares the union
    /// only as a tag, so access is mediated by the `BIO_ADDR_*` operations.
    BioAddr,
    BioAddrRef,
    BioAddrMut,
    ffi::bio_addr_st
);

#[cfg(test)]
mod tests {
    use core::mem::{offset_of, size_of};
    use core::ptr::addr_of_mut;

    use super::*;
    use crate::bio::bio_addr::{
        BIO_ADDR_clear, BIO_ADDR_family, BIO_ADDR_path_string, BIO_ADDR_rawaddress,
        BIO_ADDR_rawmake, BIO_ADDR_rawport,
    };

    /// Guard word written immediately after the address storage.
    const GUARD: u64 = 0x5555_5555_5555_5555;

    /// A `BioAddr` followed by a guard word. The generated union is only useful
    /// as embedded or stack storage if the linked libcrypto was compiled with
    /// the same variants bindgen saw; a smaller Rust-side layout is a buffer
    /// overflow, and this makes one observable instead of silent.
    #[repr(C)]
    struct GuardedAddress {
        address: BioAddr,
        guard: u64,
    }

    impl GuardedAddress {
        fn new() -> Self {
            Self {
                address: BioAddr::zeroed(),
                guard: GUARD,
            }
        }

        fn as_mut(&mut self) -> BioAddrMut<'_> {
            let raw = addr_of_mut!(self.address).cast::<ffi::bio_addr_st>();
            // SAFETY: `raw` addresses this value's live, zero-initialized
            // address storage, which is a valid `AF_UNSPEC` `BIO_ADDR`. The
            // exclusive borrow of `self` keeps every other handle out of use
            // for as long as the returned one lives.
            unsafe { BioAddrMut::from_ptr(raw) }.expect("non-null BIO_ADDR pointer")
        }
    }

    fn family(value: u32) -> i32 {
        i32::try_from(value).expect("an address family fits in a C int")
    }

    #[test]
    fn c_library_agrees_on_the_size_of_the_address_union() {
        // The guard has to sit immediately after the address for an overrun to
        // reach it; `#[repr(C)]` would otherwise be free to pad the two apart.
        assert_eq!(offset_of!(GuardedAddress, guard), size_of::<BioAddr>());

        let mut guarded = GuardedAddress::new();
        {
            let mut handle = guarded.as_mut();
            let bytes = handle.as_mut_ptr().cast::<u8>();
            // SAFETY: the exclusive handle borrows exactly `size_of::<BioAddr>()`
            // writable bytes, and every bit pattern is a valid union member.
            unsafe { bytes.write_bytes(0xFF, size_of::<BioAddr>()) };

            // `BIO_ADDR_clear` memsets `sizeof(BIO_ADDR)` as the *linked*
            // library compiled it, without reading the poisoned family first.
            BIO_ADDR_clear(&mut handle);

            for offset in 0..size_of::<BioAddr>() {
                // SAFETY: `offset` stays inside the address storage the handle
                // borrows, and every bit pattern is a valid `u8`.
                let byte = unsafe { bytes.add(offset).read() };
                assert_eq!(
                    byte, 0,
                    "libcrypto's BIO_ADDR is smaller than the generated union: \
                     byte {offset} survived the clear"
                );
            }
        }

        assert_eq!(
            guarded.guard, GUARD,
            "libcrypto's BIO_ADDR is larger than the generated union"
        );
    }

    #[test]
    fn c_library_agrees_on_every_generated_union_variant() {
        // The longest path `sockaddr_un::sun_path` holds with its terminator.
        // This variant is what fixes the union's size, so it is also the one
        // that overruns the guard word if the two layouts disagree.
        let path = [b'u'; 107];
        let mut guarded = GuardedAddress::new();
        assert!(
            BIO_ADDR_rawmake(&mut guarded.as_mut(), family(ffi::AF_UNIX), &path, 0),
            "libcrypto rejects AF_UNIX although the generated union has `s_un`"
        );
        assert_eq!(guarded.guard, GUARD, "the AF_UNIX variant overran its slot");
        let handle = guarded.as_mut();
        assert_eq!(
            BIO_ADDR_path_string(&handle.as_ref())
                .expect("AF_UNIX path")
                .as_bytes(),
            &path,
        );

        let ipv4 = [127_u8, 0, 0, 1];
        let mut guarded = GuardedAddress::new();
        assert!(
            BIO_ADDR_rawmake(
                &mut guarded.as_mut(),
                family(ffi::AF_INET),
                &ipv4,
                443_u16.to_be(),
            ),
            "libcrypto rejects AF_INET although the generated union has `s_in`"
        );
        assert_eq!(guarded.guard, GUARD, "the AF_INET variant overran its slot");
        let handle = guarded.as_mut();
        let mut readback = [0_u8; 16];
        assert_eq!(BIO_ADDR_rawaddress(&handle.as_ref(), &mut readback), Ok(4));
        assert_eq!(&readback[..4], &ipv4);
        assert_eq!(BIO_ADDR_rawport(&handle.as_ref()), 443_u16.to_be());

        // 2001:db8::1, from the documentation range.
        let mut ipv6 = [0_u8; 16];
        ipv6[..2].copy_from_slice(&[0x20, 0x01]);
        ipv6[2..4].copy_from_slice(&[0x0d, 0xb8]);
        ipv6[15] = 1;
        let mut guarded = GuardedAddress::new();
        assert!(
            BIO_ADDR_rawmake(
                &mut guarded.as_mut(),
                family(ffi::AF_INET6),
                &ipv6,
                443_u16.to_be(),
            ),
            "libcrypto rejects AF_INET6 although the generated union has `s_in6`"
        );
        assert_eq!(
            guarded.guard, GUARD,
            "the AF_INET6 variant overran its slot"
        );
        let handle = guarded.as_mut();
        let mut readback = [0_u8; 16];
        assert_eq!(BIO_ADDR_rawaddress(&handle.as_ref(), &mut readback), Ok(16));
        assert_eq!(readback, ipv6);
    }

    #[test]
    fn zeroed_storage_is_the_cleared_address() {
        let mut zeroed = GuardedAddress::new();
        let mut cleared = GuardedAddress::new();
        BIO_ADDR_clear(&mut cleared.as_mut());

        // `BIO_ADDR_new` and `BIO_ADDR_clear` both leave `AF_UNSPEC`, which is
        // zero, so inline storage needs no C constructor to become valid.
        let zeroed_handle = zeroed.as_mut();
        let cleared_handle = cleared.as_mut();
        assert_eq!(
            BIO_ADDR_family(&zeroed_handle.as_ref()),
            BIO_ADDR_family(&cleared_handle.as_ref()),
        );
        assert_eq!(BIO_ADDR_rawport(&zeroed_handle.as_ref()), 0);
    }

    #[test]
    fn borrowed_handles_preserve_the_raw_pointer() {
        let mut storage = BioAddr::zeroed();
        let raw = addr_of_mut!(storage).cast::<ffi::bio_addr_st>();

        // SAFETY: `storage` is initialized layout-compatible storage and stays
        // live for the duration of this shared handle.
        let shared = unsafe { BioAddrRef::from_ptr(raw) }.expect("non-null BIO_ADDR pointer");
        assert_eq!(shared.as_ptr(), raw.cast_const());

        // The shared handle is not used after this point, leaving the storage
        // exclusively borrowed for the mutable handle's lifetime.
        // SAFETY: `raw` still points to live storage and no competing handle is
        // used while the exclusive handle is live.
        let mut exclusive =
            unsafe { BioAddrMut::from_ptr(raw) }.expect("non-null BIO_ADDR pointer");
        assert_eq!(exclusive.as_mut_ptr(), raw);
        assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());
    }
}

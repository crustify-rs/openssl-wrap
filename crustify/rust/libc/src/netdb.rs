//! Wrappers assigned from `/usr/include/netdb.h`.

use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use libc_sys as ffi;

ffibox::define_ctype!(
    /// Wraps: addrinfo
    AddrInfo,
    AddrInfoRef,
    AddrInfoMut,
    ffi::addrinfo
);

ffibox::define_ctype!(
    /// Wraps: hostent
    ///
    /// Layout-compatible storage for a C host database entry. The resolver or
    /// the caller owns the strings and address buffers referenced by the
    /// entry, so this type has borrowed handles but no owning pointer form.
    HostEnt,
    HostEntRef,
    HostEntMut,
    ffi::hostent
);

/// A borrowed, NUL-terminated string referenced by a [`HostEnt`].
///
/// Bytes are copied out individually so no Rust reference covers storage that
/// remains under C ownership.
#[derive(Clone, Copy)]
pub struct HostEntStringRef<'a> {
    ptr: NonNull<core::ffi::c_char>,
    _borrow: PhantomData<&'a HostEnt>,
}

impl HostEntStringRef<'_> {
    /// Number of bytes before the terminating NUL.
    #[must_use]
    pub fn len(&self) -> usize {
        let mut len = 0;
        // SAFETY: construction is restricted to a non-null, NUL-terminated
        // string borrowed by a live `HostEnt`; each byte before the terminator
        // is initialized and is copied without forming a reference.
        unsafe {
            while self.ptr.as_ptr().add(len).read() != 0 {
                len += 1;
            }
        }
        len
    }

    /// Whether the string has no bytes before its terminating NUL.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        // SAFETY: construction guarantees that the first byte is initialized
        // and belongs to a NUL-terminated string.
        unsafe { self.ptr.as_ptr().read() == 0 }
    }

    /// Copy byte `index`, or return `None` at and beyond the terminator.
    #[must_use]
    pub fn byte(&self, index: usize) -> Option<u8> {
        if index >= self.len() {
            return None;
        }
        // SAFETY: the length check proves `index` precedes the terminator and
        // therefore addresses an initialized byte in the borrowed string.
        Some(unsafe { self.ptr.as_ptr().cast::<u8>().add(index).read() })
    }

    /// Copy the bytes before the NUL into an exactly sized destination.
    ///
    /// Returns `false` without copying when the lengths differ.
    #[must_use]
    pub fn copy_to_slice(&self, destination: &mut [u8]) -> bool {
        let len = self.len();
        if destination.len() != len {
            return false;
        }
        // SAFETY: `len` initialized bytes precede the terminator. The Rust
        // destination cannot overlap the C-owned host-entry storage.
        unsafe {
            ptr::copy_nonoverlapping(
                self.ptr.as_ptr().cast::<u8>(),
                destination.as_mut_ptr(),
                len,
            )
        };
        true
    }
}

/// A borrowed, NUL-terminated list of alias strings from a [`HostEnt`].
#[derive(Clone, Copy)]
pub struct HostEntAliasesRef<'a> {
    ptr: NonNull<*mut core::ffi::c_char>,
    _borrow: PhantomData<&'a HostEnt>,
}

impl<'a> HostEntAliasesRef<'a> {
    /// Alias at `index`, or `None` when the list terminator is reached.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<HostEntStringRef<'a>> {
        for offset in 0..=index {
            // SAFETY: a `hostent` alias vector is a NUL-terminated array of
            // initialized pointers; iteration stops at its first terminator.
            let alias = unsafe { self.ptr.as_ptr().add(offset).read() };
            let alias = NonNull::new(alias)?;
            if offset == index {
                return Some(HostEntStringRef {
                    ptr: alias,
                    _borrow: PhantomData,
                });
            }
        }
        None
    }

    /// Iterate over the aliases in list order.
    pub fn iter(&self) -> impl Iterator<Item = HostEntStringRef<'a>> + use<'a> {
        let mut next = self.ptr.as_ptr();
        core::iter::from_fn(move || {
            // SAFETY: `next` advances only within the initialized,
            // NUL-terminated pointer vector and is not read after its first
            // null element.
            let alias = unsafe { next.read() };
            let alias = NonNull::new(alias)?;
            // SAFETY: a non-null element is not the terminator, so the next
            // pointer slot belongs to the same vector.
            next = unsafe { next.add(1) };
            Some(HostEntStringRef {
                ptr: alias,
                _borrow: PhantomData,
            })
        })
    }
}

/// One borrowed address buffer referenced by a [`HostEnt`].
#[derive(Clone, Copy)]
pub struct HostEntAddressRef<'a> {
    ptr: NonNull<u8>,
    len: usize,
    _borrow: PhantomData<&'a HostEnt>,
}

impl HostEntAddressRef<'_> {
    /// Number of bytes in this address.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the address contains no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy byte `index`, or return `None` when it is out of bounds.
    #[must_use]
    pub fn byte(&self, index: usize) -> Option<u8> {
        if index >= self.len {
            return None;
        }
        // SAFETY: construction proves `len` initialized bytes start at `ptr`,
        // and the bounds check keeps this raw copy within that buffer.
        Some(unsafe { self.ptr.as_ptr().add(index).read() })
    }

    /// Copy the address into an exactly sized destination.
    ///
    /// Returns `false` without copying when the lengths differ.
    #[must_use]
    pub fn copy_to_slice(&self, destination: &mut [u8]) -> bool {
        if destination.len() != self.len {
            return false;
        }
        // SAFETY: construction guarantees `len` initialized bytes at `ptr`.
        // The Rust destination cannot overlap C-owned host-entry storage.
        unsafe { ptr::copy_nonoverlapping(self.ptr.as_ptr(), destination.as_mut_ptr(), self.len) };
        true
    }
}

/// A borrowed, NUL-terminated list of fixed-length host addresses.
#[derive(Clone, Copy)]
pub struct HostEntAddressesRef<'a> {
    ptr: NonNull<*mut core::ffi::c_char>,
    address_len: usize,
    _borrow: PhantomData<&'a HostEnt>,
}

impl<'a> HostEntAddressesRef<'a> {
    /// Address at `index`, or `None` when the list terminator is reached.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<HostEntAddressRef<'a>> {
        for offset in 0..=index {
            // SAFETY: a `hostent` address vector is a NUL-terminated array of
            // initialized pointers; iteration stops at its first terminator.
            let address = unsafe { self.ptr.as_ptr().add(offset).read() };
            let address = NonNull::new(address.cast::<u8>())?;
            if offset == index {
                return Some(HostEntAddressRef {
                    ptr: address,
                    len: self.address_len,
                    _borrow: PhantomData,
                });
            }
        }
        None
    }

    /// Iterate over addresses in list order.
    pub fn iter(&self) -> impl Iterator<Item = HostEntAddressRef<'a>> + use<'a> {
        let mut next = self.ptr.as_ptr();
        let len = self.address_len;
        core::iter::from_fn(move || {
            // SAFETY: `next` advances only within the initialized,
            // NUL-terminated pointer vector and is not read after its first
            // null element.
            let address = unsafe { next.read() };
            let address = NonNull::new(address.cast::<u8>())?;
            // SAFETY: a non-null element is not the terminator, so the next
            // slot belongs to the same vector.
            next = unsafe { next.add(1) };
            Some(HostEntAddressRef {
                ptr: address,
                len,
                _borrow: PhantomData,
            })
        })
    }
}

impl<'a> HostEntRef<'a> {
    /// Borrow the optional official host name.
    #[must_use]
    pub fn official_name(&self) -> Option<HostEntStringRef<'a>> {
        // SAFETY: the handle proves the `hostent` header is live for `'a`;
        // raw projection copies its initialized borrowed pointer.
        let name = unsafe { ptr::addr_of!((*self.as_ptr()).h_name).read() };
        NonNull::new(name).map(|ptr| HostEntStringRef {
            ptr,
            _borrow: PhantomData,
        })
    }

    /// Borrow the optional NUL-terminated alias list.
    #[must_use]
    pub fn aliases(&self) -> Option<HostEntAliasesRef<'a>> {
        // SAFETY: raw projection copies the initialized borrowed list pointer
        // from the live header without forming a reference.
        let aliases = unsafe { ptr::addr_of!((*self.as_ptr()).h_aliases).read() };
        NonNull::new(aliases).map(|ptr| HostEntAliasesRef {
            ptr,
            _borrow: PhantomData,
        })
    }

    /// Address family recorded for every entry in the address list.
    #[must_use]
    pub fn address_type(&self) -> core::ffi::c_int {
        // SAFETY: raw projection copies an initialized scalar field from the
        // live header and forms no reference to C storage.
        unsafe { ptr::addr_of!((*self.as_ptr()).h_addrtype).read() }
    }

    /// Number of bytes in each address, or `None` for an invalid negative C
    /// value.
    #[must_use]
    pub fn address_len(&self) -> Option<usize> {
        // SAFETY: raw projection copies the initialized scalar field.
        let length = unsafe { ptr::addr_of!((*self.as_ptr()).h_length).read() };
        usize::try_from(length).ok()
    }

    /// Borrow the optional NUL-terminated address list.
    ///
    /// Returns `None` when the list is null or its per-address length is
    /// negative.
    #[must_use]
    pub fn addresses(&self) -> Option<HostEntAddressesRef<'a>> {
        let address_len = self.address_len()?;
        // SAFETY: raw projection copies the initialized borrowed list pointer
        // from the live header without forming a reference.
        let addresses = unsafe { ptr::addr_of!((*self.as_ptr()).h_addr_list).read() };
        NonNull::new(addresses).map(|ptr| HostEntAddressesRef {
            ptr,
            address_len,
            _borrow: PhantomData,
        })
    }
}

impl HostEntMut<'_> {
    /// Set the address family recorded for the address list.
    pub fn set_address_type(&mut self, address_type: core::ffi::c_int) {
        // SAFETY: the exclusive handle guarantees writable header storage;
        // raw projection writes the scalar without forming a reference.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).h_addrtype).write(address_type) }
    }

    /// Set the number of bytes in each address.
    ///
    /// Values larger than C's signed integer range are rejected.
    pub fn set_address_len(&mut self, length: usize) -> Result<(), HostEntLengthOverflow> {
        let length = core::ffi::c_int::try_from(length).map_err(|_| HostEntLengthOverflow)?;
        // SAFETY: the exclusive handle guarantees writable header storage;
        // raw projection writes a valid C integer without forming a reference.
        unsafe { ptr::addr_of_mut!((*self.as_mut_ptr()).h_length).write(length) }
        Ok(())
    }
}

/// An address length cannot be represented by C's `int` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostEntLengthOverflow;

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn addrinfo_wrapper_preserves_layout_and_supports_borrowed_handles() {
        assert_eq!(size_of::<AddrInfo>(), size_of::<ffi::addrinfo>());
        assert_eq!(align_of::<AddrInfo>(), align_of::<ffi::addrinfo>());

        let mut value = AddrInfo::zeroed();
        let raw = ptr::addr_of_mut!(value).cast::<ffi::addrinfo>();
        // SAFETY: `raw` points to a live layout-compatible value and remains
        // exclusively borrowed for the lifetime of the returned handle.
        let view = unsafe { AddrInfoMut::from_ptr(raw) }.expect("stack addrinfo");
        assert_eq!(view.as_ref().as_ptr(), raw.cast_const());
    }

    #[test]
    fn layout_matches_raw_hostent() {
        assert_eq!(size_of::<HostEnt>(), size_of::<ffi::hostent>());
        assert_eq!(align_of::<HostEnt>(), align_of::<ffi::hostent>());
    }

    #[test]
    fn borrowed_fields_are_copied_without_rust_references_to_c_storage() {
        let mut official_name = *b"example\0";
        let mut alias = *b"alias\0";
        let mut aliases = [
            alias.as_mut_ptr().cast::<core::ffi::c_char>(),
            ptr::null_mut(),
        ];
        let mut address = [127_u8, 0, 0, 1];
        let mut addresses = [
            address.as_mut_ptr().cast::<core::ffi::c_char>(),
            ptr::null_mut(),
        ];
        let mut raw = ffi::hostent {
            h_name: official_name.as_mut_ptr().cast(),
            h_aliases: aliases.as_mut_ptr(),
            h_addrtype: 2,
            h_length: 4,
            h_addr_list: addresses.as_mut_ptr(),
        };

        // SAFETY: `raw` and every pointer it contains remain live and
        // unchanged while this shared handle and its derived views are used.
        let host = unsafe { HostEntRef::from_ptr(ptr::addr_of_mut!(raw)) }.expect("hostent");

        let name = host.official_name().expect("official name");
        let mut name_copy = [0_u8; 7];
        assert!(name.copy_to_slice(&mut name_copy));
        assert_eq!(&name_copy, b"example");

        let first_alias = host.aliases().expect("aliases").get(0).expect("alias");
        let mut alias_copy = [0_u8; 5];
        assert!(first_alias.copy_to_slice(&mut alias_copy));
        assert_eq!(&alias_copy, b"alias");

        let first_address = host
            .addresses()
            .expect("addresses")
            .get(0)
            .expect("address");
        let mut address_copy = [0_u8; 4];
        assert!(first_address.copy_to_slice(&mut address_copy));
        assert_eq!(address_copy, [127, 0, 0, 1]);
        assert_eq!(host.address_type(), 2);
        assert_eq!(host.address_len(), Some(4));
    }

    #[test]
    fn mutable_handle_updates_scalar_metadata() {
        let mut storage = HostEnt::zeroed();
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::hostent>();
        // SAFETY: `raw` points to live layout-compatible storage used only by
        // this exclusive handle for the duration of the test.
        let mut host = unsafe { HostEntMut::from_ptr(raw) }.expect("hostent");
        host.set_address_type(10);
        assert_eq!(host.set_address_len(16), Ok(()));
        assert_eq!(host.as_ref().address_type(), 10);
        assert_eq!(host.as_ref().address_len(), Some(16));
    }
}

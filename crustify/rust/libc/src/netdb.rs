//! Wrappers assigned from `/usr/include/netdb.h`.

use ffibox::define_ctype;

use libc_sys as ffi;

define_ctype!(
    /// Wraps: addrinfo
    AddrInfo,
    AddrInfoRef,
    AddrInfoMut,
    ffi::addrinfo
);

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use core::ptr;

    use super::*;

    #[test]
    fn wrapper_preserves_layout_and_supports_borrowed_handles() {
        assert_eq!(size_of::<AddrInfo>(), size_of::<ffi::addrinfo>());
        assert_eq!(align_of::<AddrInfo>(), align_of::<ffi::addrinfo>());

        let mut value = AddrInfo::zeroed();
        let raw = ptr::addr_of_mut!(value).cast::<ffi::addrinfo>();
        // SAFETY: `raw` points to a live layout-compatible value and remains
        // exclusively borrowed for the lifetime of the returned handle.
        let view = unsafe { AddrInfoMut::from_ptr(raw) }.expect("stack addrinfo");
        assert_eq!(view.as_ref().as_ptr(), raw.cast_const());
    }
}

//! Ownership strategies for C runtime allocations.

use core::ptr::NonNull;

use ffibox::{CCloned, CDropped, CLenDropped, CrustifyStr};

use libc_sys as ffi;

/// Wraps: free
/// Stateless lifecycle strategy for storage allocated by the C runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct LibcFree;

/// An owned NUL-terminated string allocated by the C runtime.
pub type LibcString = CrustifyStr<LibcFree>;

// SAFETY: `c_drop` delegates to the matching C allocator's release primitive.
unsafe impl CDropped for LibcFree {
    unsafe fn c_drop(obj: NonNull<Self>) {
        // SAFETY: the trait contract requires `obj` to denote uniquely owned
        // storage allocated by the C runtime.
        unsafe { ffi::free(obj.as_ptr().cast()) }
    }
}

// SAFETY: C `free` releases buffers without needing their length.
unsafe impl CLenDropped for LibcFree {
    unsafe fn c_drop_len(ptr: *mut u8, _byte_len: usize) {
        // SAFETY: the trait contract requires `ptr` to denote uniquely owned
        // storage allocated by the C runtime.
        unsafe { ffi::free(ptr.cast()) }
    }
}

/// Wraps: strdup
// SAFETY: `strdup` returns an independent malloc-family string allocation,
// which the `LibcFree` supertrait strategy releases with `free`.
unsafe impl CCloned for LibcFree {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: the trait contract guarantees that `obj` points to a live,
        // NUL-terminated string; `strdup` reads it without taking ownership.
        NonNull::new(unsafe { ffi::strdup(obj.as_ptr().cast()) }.cast())
    }
}

#[cfg(test)]
mod tests {
    use ffibox::CVoidBox;

    use super::*;

    #[test]
    fn libc_owner_releases_malloc_storage() {
        // SAFETY: `malloc` returns a uniquely owned allocation or null.
        let ptr = unsafe { ffi::malloc(16) };
        // SAFETY: `ptr` came from `malloc`, whose matching releaser is
        // represented by `LibcFree`; ownership is transferred to the handle.
        let owned = unsafe { CVoidBox::<LibcFree>::from_raw(ptr) };
        assert!(owned.is_some());
    }

    #[test]
    fn libc_string_clone_is_independent() {
        // SAFETY: the C literal is NUL-terminated and `strdup` returns a fresh
        // malloc-family allocation or null.
        let raw = unsafe { ffi::strdup(c"libc string".as_ptr()) };
        // SAFETY: ownership of the fresh NUL-terminated allocation transfers
        // to the matching `free` strategy.
        let original = unsafe { LibcString::from_raw(raw) }.expect("strdup allocation");
        let copy = original.try_clone().expect("strdup clone");

        assert_eq!(original.as_c_str(), c"libc string");
        assert_eq!(copy.as_c_str(), c"libc string");
        assert_ne!(original.as_ptr(), copy.as_ptr());
    }
}

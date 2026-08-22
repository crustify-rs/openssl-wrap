//! Ownership strategies for C runtime allocations.

use core::ptr::NonNull;

use ffibox::{CDropped, CLenDropped};

use libc_sys as ffi;

/// Wraps: free
/// Stateless lifecycle strategy for storage allocated by the C runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct LibcFree;

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
}

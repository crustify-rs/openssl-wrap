//! Ownership strategies for C runtime allocations.

use core::ptr::NonNull;

use ffibox::{CCloned, CDropped, CLenDropped, CrustifyStr};

use libc_sys as ffi;

/// Wraps: free
/// Stateless lifecycle strategy for storage allocated by the C runtime.
#[derive(Debug, Clone, Copy, Default)]
pub struct LibcFree;

/// An owned NUL-terminated string allocated by the C runtime.
///
/// Dropping releases it with `free`; cloning duplicates it with `strdup`.
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
//
// This impl carries a precondition the `CCloned` contract does not state on
// its own: `strdup` copies up to the first NUL, so `obj` must denote a
// NUL-terminated allocation, not an arbitrary malloc buffer. That holds for
// every reachable caller: `LibcFree` is a deleter strategy rather than a
// `CCell`, so the only consumer of its `CCloned` impl is
// `CrustifyStr<LibcFree>`, whose type invariant is exactly a live
// NUL-terminated string; `CVoidBox` and `CVec` expose no clone.
//
// SAFETY: `strdup` leaves its source untouched and returns an independent
// malloc-family allocation, so the copy owes exactly one `free`, the
// `CDropped` supertrait's `c_drop`; null means the copy failed.
unsafe impl CCloned for LibcFree {
    unsafe fn c_clone(obj: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: `obj` denotes a live, uniquely owned, NUL-terminated
        // malloc-family string; `strdup` reads it without taking ownership.
        NonNull::new(unsafe { ffi::strdup(obj.as_ptr().cast()) }.cast())
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::{CVec, CVoidBox};

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
    fn libc_owner_releases_counted_storage() {
        let source = [9_u8, 8, 7, 6];

        // SAFETY: `malloc` returns a uniquely owned allocation of the
        // requested four bytes, or null.
        let raw = unsafe { ffi::malloc(4) }.cast::<u8>();
        assert!(!raw.is_null());
        // SAFETY: the fresh allocation holds the four writable bytes being
        // written and cannot overlap the stack array being read.
        unsafe { ptr::copy_nonoverlapping(source.as_ptr(), raw, source.len()) };
        // SAFETY: `raw` owns `source.len()` initialized bytes from the C
        // runtime allocator, whose length-aware releaser is `LibcFree`; `free`
        // ignores the byte count handed back to it.
        let buffer = unsafe { CVec::<u8, LibcFree>::from_raw_parts(raw, source.len()) }
            .expect("malloc allocation");

        assert_eq!(buffer.as_slice(), source);
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

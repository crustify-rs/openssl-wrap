//! Wrappers assigned from `include/openssl/lhash.h`.

use core::marker::PhantomData;
use core::ptr::NonNull;

use ffibox::{CCell, CDropped, CPtr, CType};
use libcrypto_sys as ffi;

/// Wraps: DEFINE_LHASH_OF_EX
///
/// Generic layout wrapper for the homogeneous family of `LHASH_OF(T)` types.
/// OpenSSL implements every generated type by casting it to the same
/// `OPENSSL_LHASH`; the marker retains the element type without changing that
/// layout. The table owns its nodes, but not the element pointers stored in
/// them.
#[repr(transparent)]
pub struct LHash<T> {
    inner: CType<ffi::OPENSSL_LHASH>,
    element: PhantomData<*mut T>,
}

/// Shared borrowed handle to a typed OpenSSL hash table.
#[repr(transparent)]
pub struct LHashRef<'a, T>(CPtr<'a, LHash<T>>);

impl<T> Clone for LHashRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for LHashRef<'_, T> {}

/// Exclusive borrowed handle to a typed OpenSSL hash table.
#[repr(transparent)]
pub struct LHashMut<'a, T>(LHashRef<'a, T>);

// SAFETY: `LHash<T>` is transparent over `CType<OPENSSL_LHASH>` and its other
// field is zero-sized. Both handles are transparent over `CPtr<LHash<T>>`;
// the shared handle exposes no operation that can write through its pointer.
unsafe impl<T> CCell for LHash<T> {
    type C = ffi::OPENSSL_LHASH;
    type Ref<'a>
        = LHashRef<'a, T>
    where
        T: 'a;
    type Mut<'a>
        = LHashMut<'a, T>
    where
        T: 'a;

    unsafe fn ref_from_raw<'a>(ptr: NonNull<Self>) -> Self::Ref<'a>
    where
        T: 'a,
    {
        // SAFETY: the caller guarantees that `ptr` is live for `'a`.
        LHashRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'a>(ptr: NonNull<Self>) -> Self::Mut<'a>
    where
        T: 'a,
    {
        // SAFETY: the caller additionally guarantees exclusive access for `'a`.
        LHashMut(LHashRef(unsafe { CPtr::new(ptr) }))
    }
}

impl<'a, T> LHashRef<'a, T> {
    /// Borrow a generated `LHASH_OF(T) *` after it has been erased to its
    /// common `OPENSSL_LHASH *` representation.
    ///
    /// # Safety
    ///
    /// `ptr` must be null or point to a live OpenSSL hash table whose generated
    /// element type is `T`, and a non-null table must outlive `'a`.
    pub unsafe fn from_ptr(ptr: *mut ffi::OPENSSL_LHASH) -> Option<Self> {
        NonNull::new(ptr.cast::<LHash<T>>()).map(|ptr| {
            // SAFETY: the caller supplies the required type, liveness and lifetime.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer to the common OpenSSL table representation.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::OPENSSL_LHASH {
        self.0.as_non_null().as_ptr().cast()
    }
}

impl<'a, T> LHashMut<'a, T> {
    /// Exclusively borrow an erased generated hash-table pointer.
    ///
    /// # Safety
    ///
    /// As [`LHashRef::from_ptr`], and no other handle to this table may be used
    /// while the result lives.
    pub unsafe fn from_ptr(ptr: *mut ffi::OPENSSL_LHASH) -> Option<Self> {
        NonNull::new(ptr.cast::<LHash<T>>()).map(|ptr| {
            // SAFETY: the caller supplies the required type, liveness, lifetime,
            // and exclusivity.
            Self(LHashRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer to the common OpenSSL table representation.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::OPENSSL_LHASH {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrow the table without write access.
    #[must_use]
    pub fn as_ref(&self) -> LHashRef<'_, T> {
        self.0
    }
}

// SAFETY: `OPENSSL_LH_free` releases exactly the table nodes and table storage
// once. It deliberately does not release the typed element pointers.
unsafe impl<T> CDropped for LHash<T> {
    unsafe fn c_drop(object: NonNull<Self>) {
        // SAFETY: `CDropped::c_drop` supplies one live, uniquely owned table and
        // the `LHash` representation has the same address as `OPENSSL_LHASH`.
        unsafe { ffi::OPENSSL_LH_free(object.as_ptr().cast()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    enum FirstElement {}
    enum SecondElement {}

    #[test]
    fn generic_instances_keep_the_erased_c_layout() {
        assert_eq!(
            core::mem::size_of::<LHash<FirstElement>>(),
            core::mem::size_of::<ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            core::mem::align_of::<LHash<FirstElement>>(),
            core::mem::align_of::<ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            core::mem::size_of::<LHash<FirstElement>>(),
            core::mem::size_of::<LHash<SecondElement>>()
        );
        assert_eq!(
            core::mem::size_of::<LHashRef<'static, FirstElement>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_LHASH>()
        );
        assert_eq!(
            core::mem::size_of::<LHashMut<'static, SecondElement>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_LHASH>()
        );
    }
}

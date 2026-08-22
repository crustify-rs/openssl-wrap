//! Wrappers assigned from `include/openssl/stack.h`.

use core::marker::PhantomData;
use core::ptr::NonNull;

use libcrypto_sys as ffi;

/// Wraps: OPENSSL_sk_compfunc
/// A C comparator associated with concrete Rust-side argument types.
#[derive(Clone, Copy)]
pub struct OpenSslSkCompFunc<A, B = A> {
    raw: ffi::OPENSSL_sk_compfunc,
    marker: PhantomData<fn(&A, &B)>,
}

impl<A, B> OpenSslSkCompFunc<A, B> {
    /// Associates an erased C comparator with its actual argument types.
    ///
    /// # Safety
    ///
    /// On every invocation, `raw` must only read the two live values supplied,
    /// must accept pointers to `A` and `B`, and must not unwind across the C ABI.
    pub unsafe fn from_raw(raw: ffi::OPENSSL_sk_compfunc) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }

    /// Calls the comparator with live typed values.
    #[must_use]
    pub fn compare(&self, left: &A, right: &B) -> i32 {
        let function = self.raw.expect("constructor rejects null callbacks");
        // SAFETY: the constructor bound this callback to `A` and `B`; both
        // shared borrows remain live and immutable for the call.
        unsafe {
            function(
                core::ptr::from_ref(left).cast(),
                core::ptr::from_ref(right).cast(),
            )
        }
    }

    pub(crate) const fn as_raw(&self) -> ffi::OPENSSL_sk_compfunc {
        self.raw
    }
}

/// Wraps: OPENSSL_sk_copyfunc
/// A deep-copy callback associated with one concrete element type.
#[derive(Clone, Copy)]
pub struct OpenSslSkCopyFunc<T> {
    raw: ffi::OPENSSL_sk_copyfunc,
    marker: PhantomData<fn(&T) -> T>,
}

impl<T> OpenSslSkCopyFunc<T> {
    /// Associates an erased copy callback with `T`.
    ///
    /// # Safety
    ///
    /// The callback must accept a shared pointer to a live `T` and return null
    /// or a fresh allocation suitable for the paired `free` callback.
    pub unsafe fn from_raw(raw: ffi::OPENSSL_sk_copyfunc) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }

    /// Deep-copies `source` into an owner carrying its matching destructor.
    pub fn copy_owned(&self, source: &T, free: OpenSslSkFreeFunc<T>) -> Option<OpenSslSkOwned<T>> {
        let function = self.raw.expect("constructor rejects null callbacks");
        // SAFETY: the constructor establishes the callback's type and ownership
        // contract; `source` is shared and live throughout the invocation.
        let raw = unsafe { function(core::ptr::from_ref(source).cast()) };
        NonNull::new(raw.cast()).map(|ptr| OpenSslSkOwned { ptr, free })
    }
}

/// Wraps: OPENSSL_sk_freefunc
/// A destructor callback associated with one concrete element type.
#[derive(Clone, Copy)]
pub struct OpenSslSkFreeFunc<T> {
    raw: ffi::OPENSSL_sk_freefunc,
    marker: PhantomData<fn(T)>,
}

impl<T> OpenSslSkFreeFunc<T> {
    /// Associates an erased destructor with allocations of `T`.
    ///
    /// # Safety
    ///
    /// The callback must consume exactly one allocation produced for `T`, must
    /// accept null if the C implementation can pass it, and must not unwind.
    pub unsafe fn from_raw(raw: ffi::OPENSSL_sk_freefunc) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }
}

/// An erased stack element paired with the runtime destructor that owns it.
pub struct OpenSslSkOwned<T> {
    ptr: NonNull<T>,
    free: OpenSslSkFreeFunc<T>,
}

impl<T> OpenSslSkOwned<T> {
    /// Returns the address without transferring ownership.
    #[must_use]
    pub const fn as_non_null(&self) -> NonNull<T> {
        self.ptr
    }
}

impl<T> Drop for OpenSslSkOwned<T> {
    fn drop(&mut self) {
        let function = self.free.raw.expect("constructor rejects null callbacks");
        // SAFETY: this owner contains the unique allocation returned by the
        // paired copy callback and invokes its registered destructor once.
        unsafe { function(self.ptr.as_ptr().cast()) }
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    static FREED: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn copy_i32(source: *const c_void) -> *mut c_void {
        // SAFETY: the callback is associated only with a live shared `i32`.
        let value = unsafe { *source.cast::<i32>() };
        Box::into_raw(Box::new(value)).cast()
    }

    unsafe extern "C" fn free_i32(value: *mut c_void) {
        if !value.is_null() {
            // SAFETY: `copy_i32` produced this unique `Box<i32>` allocation.
            drop(unsafe { Box::from_raw(value.cast::<i32>()) });
            FREED.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn copy_callback_carries_its_runtime_destructor() {
        FREED.store(0, Ordering::Relaxed);
        // SAFETY: the callbacks above obey the documented `i32` copy/free contracts.
        let copy = unsafe { OpenSslSkCopyFunc::from_raw(Some(copy_i32)) }.unwrap();
        // SAFETY: the callbacks above obey the documented `i32` copy/free contracts.
        let free = unsafe { OpenSslSkFreeFunc::from_raw(Some(free_i32)) }.unwrap();
        let owned = copy.copy_owned(&7, free).unwrap();
        drop(owned);
        assert_eq!(FREED.load(Ordering::Relaxed), 1);
    }
}

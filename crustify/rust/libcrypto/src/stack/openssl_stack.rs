//! Wrappers assigned from `include/openssl/stack.h`.

use core::marker::PhantomData;
use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use libcrypto_sys as ffi;

/// Wraps: OPENSSL_sk_compfunc
/// A C comparator associated with concrete Rust-side argument types.
pub struct OpenSslSkCompFunc<A, B = A> {
    raw: ffi::OPENSSL_sk_compfunc,
    marker: PhantomData<fn(&A, &B)>,
}

impl<A, B> Clone for OpenSslSkCompFunc<A, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A, B> Copy for OpenSslSkCompFunc<A, B> {}

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

/// Wraps: OPENSSL_sk_compfunc
/// Stack-specific comparator whose erased arguments point at two element
/// pointer slots rather than directly at the elements.
pub struct OpenSslSkStackCompFunc<T> {
    raw: ffi::OPENSSL_sk_compfunc,
    marker: PhantomData<fn(T)>,
}

impl<T> Clone for OpenSslSkStackCompFunc<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpenSslSkStackCompFunc<T> {}

impl<T> OpenSslSkStackCompFunc<T> {
    /// Associates an erased C stack comparator with its element type.
    ///
    /// # Safety
    ///
    /// On every invocation, `raw` must interpret both arguments as pointers to
    /// `T` pointer slots, read only live non-null elements when it dereferences
    /// them, retain nothing, and must not unwind.
    pub unsafe fn from_raw(raw: ffi::OPENSSL_sk_compfunc) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }

    pub(crate) const fn as_raw(&self) -> ffi::OPENSSL_sk_compfunc {
        self.raw
    }
}

/// Wraps: OPENSSL_sk_copyfunc
/// A deep-copy callback associated with one concrete element type.
pub struct OpenSslSkCopyFunc<T> {
    raw: ffi::OPENSSL_sk_copyfunc,
    marker: PhantomData<fn(&T) -> T>,
}

impl<T> Clone for OpenSslSkCopyFunc<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpenSslSkCopyFunc<T> {}

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

    pub(crate) const fn as_raw(&self) -> ffi::OPENSSL_sk_copyfunc {
        self.raw
    }
}

/// Wraps: OPENSSL_sk_freefunc
/// A destructor callback associated with one concrete element type.
pub struct OpenSslSkFreeFunc<T> {
    raw: ffi::OPENSSL_sk_freefunc,
    marker: PhantomData<fn(T)>,
}

impl<T> Clone for OpenSslSkFreeFunc<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpenSslSkFreeFunc<T> {}

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

    pub(crate) const fn as_raw(&self) -> ffi::OPENSSL_sk_freefunc {
        self.raw
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

    fn into_parts(self) -> (NonNull<T>, OpenSslSkFreeFunc<T>) {
        let this = ManuallyDrop::new(self);
        (this.ptr, this.free)
    }
}

/// Wraps: OPENSSL_sk_copyfunc_thunk
/// A C adapter that invokes an erased copy callback for a concrete element.
pub struct OpenSslSkCopyFuncThunk<T> {
    raw: ffi::OPENSSL_sk_copyfunc_thunk,
    marker: PhantomData<fn(&T) -> T>,
}

impl<T> Clone for OpenSslSkCopyFuncThunk<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpenSslSkCopyFuncThunk<T> {}

impl<T> OpenSslSkCopyFuncThunk<T> {
    /// Associates a C copy thunk with the element type it adapts.
    ///
    /// # Safety
    ///
    /// `raw` must invoke its callback with the supplied live `T`, return only
    /// a fresh compatible allocation or null, and must not unwind.
    pub unsafe fn from_raw(raw: ffi::OPENSSL_sk_copyfunc_thunk) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }

    /// Copies one element through the thunk and binds the result to its
    /// matching destructor.
    pub fn copy_owned(
        &self,
        copy: OpenSslSkCopyFunc<T>,
        source: &T,
        free: OpenSslSkFreeFunc<T>,
    ) -> Option<OpenSslSkOwned<T>> {
        let thunk = self.raw.expect("constructor rejects null callbacks");
        // SAFETY: both callback wrappers and this thunk's constructor establish
        // the concrete `T` contract; `source` is live for the synchronous call.
        let raw = unsafe { thunk(copy.as_raw(), core::ptr::from_ref(source).cast()) };
        NonNull::new(raw.cast()).map(|ptr| OpenSslSkOwned { ptr, free })
    }
}

/// Wraps: OPENSSL_sk_freefunc_thunk
/// A C adapter that consumes an element through its erased destructor.
pub struct OpenSslSkFreeFuncThunk<T> {
    raw: ffi::OPENSSL_sk_freefunc_thunk,
    marker: PhantomData<fn(T)>,
}

impl<T> Clone for OpenSslSkFreeFuncThunk<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpenSslSkFreeFuncThunk<T> {}

impl<T> OpenSslSkFreeFuncThunk<T> {
    /// Associates a C free thunk with the element type it adapts.
    ///
    /// # Safety
    ///
    /// `raw` must invoke the supplied destructor exactly once for `value` and
    /// must not retain the pointer or unwind.
    pub unsafe fn from_raw(raw: ffi::OPENSSL_sk_freefunc_thunk) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }

    /// Consumes an owned element through the thunk.
    pub fn free_owned(&self, value: OpenSslSkOwned<T>) {
        let thunk = self.raw.expect("constructor rejects null callbacks");
        let (ptr, free) = value.into_parts();
        // SAFETY: ownership of `ptr` was removed from `value`; the thunk's
        // contract invokes its matching destructor exactly once.
        unsafe { thunk(free.as_raw(), ptr.as_ptr().cast()) }
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

    unsafe extern "C" fn copy_thunk(
        copy: ffi::OPENSSL_sk_copyfunc,
        source: *const c_void,
    ) -> *mut c_void {
        // SAFETY: the test passes a non-null `copy_i32` and its live source.
        unsafe { copy.expect("copy callback")(source) }
    }

    unsafe extern "C" fn free_thunk(free: ffi::OPENSSL_sk_freefunc, value: *mut c_void) {
        // SAFETY: the test passes a non-null `free_i32` and its owned value.
        unsafe { free.expect("free callback")(value) }
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

    #[test]
    fn thunk_callbacks_preserve_typed_copy_ownership() {
        FREED.store(0, Ordering::Relaxed);
        // SAFETY: all four callbacks obey their documented `i32` contracts.
        let copy = unsafe { OpenSslSkCopyFunc::from_raw(Some(copy_i32)) }.unwrap();
        // SAFETY: all four callbacks obey their documented `i32` contracts.
        let free = unsafe { OpenSslSkFreeFunc::from_raw(Some(free_i32)) }.unwrap();
        // SAFETY: `copy_thunk` faithfully invokes the supplied typed copier.
        let copy_thunk = unsafe { OpenSslSkCopyFuncThunk::from_raw(Some(copy_thunk)) }.unwrap();
        // SAFETY: `free_thunk` faithfully invokes the supplied typed destructor.
        let free_thunk = unsafe { OpenSslSkFreeFuncThunk::from_raw(Some(free_thunk)) }.unwrap();

        let owned = copy_thunk.copy_owned(copy, &11, free).unwrap();
        free_thunk.free_owned(owned);
        assert_eq!(FREED.load(Ordering::Relaxed), 1);
    }
}

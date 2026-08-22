//! Wrappers assigned from `crypto/stack/stack.c`.

use core::marker::PhantomData;
use core::ptr::NonNull;

use ffibox::{CCell, CCloned, CDropped, CPtr, CType};
use libcrypto_sys as ffi;

/// Wraps: stack_st
///
/// Generic layout wrapper for the homogeneous family of `STACK_OF(T)` types.
/// OpenSSL implements every generated stack by erasing it to the common
/// `OPENSSL_STACK` representation. The marker retains the element type without
/// changing that representation. A plain stack owns its pointer array, but not
/// the elements stored in that array.
#[repr(transparent)]
pub struct Stack<T> {
    inner: CType<ffi::OPENSSL_STACK>,
    element: PhantomData<*mut T>,
}

/// Shared borrowed handle to a typed OpenSSL stack.
#[repr(transparent)]
pub struct StackRef<'a, T>(CPtr<'a, Stack<T>>);

impl<T> Clone for StackRef<'_, T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for StackRef<'_, T> {}

/// Exclusive borrowed handle to a typed OpenSSL stack.
#[repr(transparent)]
pub struct StackMut<'a, T>(StackRef<'a, T>);

// SAFETY: `Stack<T>` is transparent over `CType<OPENSSL_STACK>` and its other
// field is zero-sized. Both handles are transparent over `CPtr<Stack<T>>`; the
// shared handle exposes no operation that can write through its pointer.
unsafe impl<T> CCell for Stack<T> {
    type C = ffi::OPENSSL_STACK;
    type Ref<'a>
        = StackRef<'a, T>
    where
        T: 'a;
    type Mut<'a>
        = StackMut<'a, T>
    where
        T: 'a;

    unsafe fn ref_from_raw<'a>(ptr: NonNull<Self>) -> Self::Ref<'a>
    where
        T: 'a,
    {
        // SAFETY: the caller guarantees that `ptr` is live for `'a`.
        StackRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'a>(ptr: NonNull<Self>) -> Self::Mut<'a>
    where
        T: 'a,
    {
        // SAFETY: the caller additionally guarantees exclusive access for `'a`.
        StackMut(StackRef(unsafe { CPtr::new(ptr) }))
    }
}

impl<'a, T> StackRef<'a, T> {
    /// Borrow a generated `STACK_OF(T) *` after it has been erased to its
    /// common `OPENSSL_STACK *` representation.
    ///
    /// # Safety
    ///
    /// `ptr` must be null or point to a live OpenSSL stack whose generated
    /// element type is `T`, and a non-null stack must outlive `'a`.
    pub unsafe fn from_ptr(ptr: *mut ffi::OPENSSL_STACK) -> Option<Self> {
        NonNull::new(ptr.cast::<Stack<T>>()).map(|ptr| {
            // SAFETY: the caller supplies the required type, liveness and lifetime.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer to the common OpenSSL stack representation.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::OPENSSL_STACK {
        self.0.as_non_null().as_ptr().cast()
    }
}

impl<'a, T> StackMut<'a, T> {
    /// Exclusively borrow an erased generated stack pointer.
    ///
    /// # Safety
    ///
    /// As [`StackRef::from_ptr`], and no other handle to this stack may be used
    /// while the result lives.
    pub unsafe fn from_ptr(ptr: *mut ffi::OPENSSL_STACK) -> Option<Self> {
        NonNull::new(ptr.cast::<Stack<T>>()).map(|ptr| {
            // SAFETY: the caller supplies the required type, liveness, lifetime,
            // and exclusivity.
            Self(StackRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer to the common OpenSSL stack representation.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::OPENSSL_STACK {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrow the stack without write access.
    #[must_use]
    pub fn as_ref(&self) -> StackRef<'_, T> {
        self.0
    }
}

// SAFETY: `OPENSSL_sk_free` releases exactly the stack's pointer array and the
// stack allocation once. It deliberately does not release the typed elements.
unsafe impl<T> CDropped for Stack<T> {
    unsafe fn c_drop(object: NonNull<Self>) {
        // SAFETY: `CDropped::c_drop` supplies one live, uniquely owned stack and
        // `Stack<T>` has the same address representation as `OPENSSL_STACK`.
        unsafe { ffi::OPENSSL_sk_free(object.as_ptr().cast()) }
    }
}

// SAFETY: `OPENSSL_sk_dup` creates an independent stack allocation and pointer
// array while preserving the element pointers, which the plain stack does not
// own. The duplicate therefore owes one independent `OPENSSL_sk_free`.
unsafe impl<T> CCloned for Stack<T> {
    unsafe fn c_clone(object: NonNull<Self>) -> Option<NonNull<Self>> {
        // SAFETY: `CCloned::c_clone` supplies a live stack. The C routine only
        // reads it and returns either a complete duplicate or null.
        NonNull::new(unsafe { ffi::OPENSSL_sk_dup(object.as_ptr().cast()) }.cast())
    }
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use ffibox::CBox;

    use super::*;

    enum FirstElement {}
    enum SecondElement {}

    #[test]
    fn generic_instances_keep_the_erased_c_layout() {
        assert_eq!(
            core::mem::size_of::<Stack<FirstElement>>(),
            core::mem::size_of::<ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::align_of::<Stack<FirstElement>>(),
            core::mem::align_of::<ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<Stack<FirstElement>>(),
            core::mem::size_of::<Stack<SecondElement>>()
        );
        assert_eq!(
            core::mem::size_of::<StackRef<'static, FirstElement>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<StackMut<'static, SecondElement>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn owners_produce_typed_borrows_and_clone_the_container() {
        // `OPENSSL_sk_dup(NULL)` constructs an empty stack in this OpenSSL
        // implementation. The resulting non-null allocation is owned here.
        // SAFETY: ownership of the returned allocation is transferred to the
        // `CBox`, whose `CDropped` implementation uses its matching releaser.
        let mut stack =
            unsafe { CBox::<Stack<FirstElement>>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
                .expect("allocate empty OpenSSL stack");
        let raw = stack.as_ptr();

        {
            let shared = stack.as_ref();
            assert_eq!(shared.as_ptr(), raw.cast_const());
        }
        {
            let mut exclusive = stack.as_mut();
            assert_eq!(exclusive.as_mut_ptr(), raw);
            assert_eq!(exclusive.as_ref().as_ptr(), raw.cast_const());
        }

        let duplicate = stack.try_clone().expect("duplicate OpenSSL stack");
        assert_ne!(duplicate.as_ptr(), raw);
    }
}

//! Wrappers assigned from `crypto/stack/stack.c`.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use ffibox::{CBox, CBoxWith, CCell, CCloned, CDropped, CDropper, CPtr, CType};
use libcrypto_sys as ffi;

use super::openssl_stack::{OpenSslSkCopyFunc, OpenSslSkFreeFunc, OpenSslSkStackCompFunc};

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
    use core::ffi::c_void;
    use core::ptr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ffibox::CBox;

    use super::*;

    enum FirstElement {}
    enum SecondElement {}

    static DEEP_FREES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn copy_i32(source: *const c_void) -> *mut c_void {
        // SAFETY: the test registers this callback only for live `i32` elements.
        let value = unsafe { source.cast::<i32>().read() };
        Box::into_raw(Box::new(value)).cast()
    }

    unsafe extern "C" fn free_i32(value: *mut c_void) {
        if !value.is_null() {
            // SAFETY: the deep-copy callback created one unique `Box<i32>`.
            drop(unsafe { Box::from_raw(value.cast::<i32>()) });
            DEEP_FREES.fetch_add(1, Ordering::Relaxed);
        }
    }

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

    #[test]
    fn wrappers_mutate_pointer_slots_without_exposing_elements() {
        assert_eq!(OPENSSL_sk_num::<i32>(None), None);
        assert!(OPENSSL_sk_is_sorted::<i32>(None));
        assert!(!OPENSSL_sk_reserve::<i32>(None, 1));
        assert!(OPENSSL_sk_value::<i32>(None, 0).is_none());

        let mut stack = OPENSSL_sk_new_null::<i32>().expect("new stack");
        assert!(OPENSSL_sk_reserve(Some(&mut stack.as_mut()), 2));

        let raw = Box::into_raw(Box::new(17_i32));
        // SAFETY: `raw` is a live `i32` until it is removed below.
        let element = unsafe { StackElement::from_raw(raw) }.unwrap();
        assert_eq!(
            // SAFETY: the Box remains live while its token is stored.
            unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) },
            Some(1)
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0)
                .unwrap()
                .as_non_null(),
            element.as_non_null()
        );
        let removed = OPENSSL_sk_pop(Some(&mut stack.as_mut())).unwrap();
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(0));

        // SAFETY: removal transferred the only stored token back, and the Box
        // allocation has not otherwise been consumed.
        drop(unsafe { Box::from_raw(removed.as_non_null().as_ptr()) });
    }

    #[test]
    fn deep_copy_owner_frees_copied_elements() {
        DEEP_FREES.store(0, Ordering::Relaxed);
        let mut source = OPENSSL_sk_new_null::<i32>().expect("new source stack");
        let original = Box::into_raw(Box::new(23_i32));
        // SAFETY: `original` stays live until removed after the copy.
        let token = unsafe { StackElement::from_raw(original) }.unwrap();
        // SAFETY: the Box remains live throughout its residence in `source`.
        unsafe { OPENSSL_sk_push(Some(&mut source.as_mut()), Some(token)) }.unwrap();

        // SAFETY: these callbacks copy and free precisely `i32` allocations.
        let copy = unsafe { OpenSslSkCopyFunc::from_raw(Some(copy_i32)) }.unwrap();
        // SAFETY: these callbacks copy and free precisely `i32` allocations.
        let free = unsafe { OpenSslSkFreeFunc::from_raw(Some(free_i32)) }.unwrap();
        let deep = OPENSSL_sk_deep_copy(Some(source.as_ref()), copy, free).expect("deep copy");
        assert_eq!(OPENSSL_sk_num(Some(deep.as_ref())), Some(1));
        drop(deep);
        assert_eq!(DEEP_FREES.load(Ordering::Relaxed), 1);

        let original = OPENSSL_sk_pop(Some(&mut source.as_mut())).unwrap();
        // SAFETY: the original stack did not own or free this Box.
        drop(unsafe { Box::from_raw(original.as_non_null().as_ptr()) });
    }
}

/// Opaque identity of one non-null pointer stored in an OpenSSL stack.
///
/// This token deliberately cannot be dereferenced: many concrete `STACK_OF`
/// element types are C layout wrappers for which forming a Rust reference is
/// unsound. `from_raw` is the explicit higher-layer conversion seam.
#[repr(transparent)]
pub struct StackElement<T> {
    ptr: NonNull<T>,
}

impl<T> Clone for StackElement<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for StackElement<T> {}

impl<T> StackElement<T> {
    /// Wraps a typed element address without taking ownership.
    ///
    /// # Safety
    ///
    /// `ptr` must have the concrete element type `T`. Whenever a stack
    /// comparator, copier, or destructor can access it, the pointed-to object
    /// must additionally be live and satisfy that callback's contract.
    pub unsafe fn from_raw(ptr: *mut T) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { ptr })
    }

    /// Returns the opaque address for an explicit lower-level FFI seam.
    #[must_use]
    pub const fn as_non_null(self) -> NonNull<T> {
        self.ptr
    }
}

fn element_ptr<T>(element: Option<StackElement<T>>) -> *const c_void {
    element.map_or(core::ptr::null(), |element| element.ptr.as_ptr().cast())
}

fn element_from_raw<T>(ptr: *mut c_void) -> Option<StackElement<T>> {
    NonNull::new(ptr.cast()).map(|ptr| StackElement { ptr })
}

fn stack_ref_ptr<T>(stack: Option<StackRef<'_, T>>) -> *const ffi::OPENSSL_STACK {
    stack.map_or(core::ptr::null(), |stack| stack.as_ptr())
}

fn stack_mut_ptr<T>(stack: Option<&mut StackMut<'_, T>>) -> *mut ffi::OPENSSL_STACK {
    stack.map_or(core::ptr::null_mut(), StackMut::as_mut_ptr)
}

fn comparator_raw<T>(comparator: Option<OpenSslSkStackCompFunc<T>>) -> ffi::OPENSSL_sk_compfunc {
    comparator.and_then(|comparator| comparator.as_raw())
}

/// Runtime teardown policy for a stack that owns all of its elements.
pub struct OpenSslSkPopFree<T> {
    free: OpenSslSkFreeFunc<T>,
}

// SAFETY: this policy is only constructed together with a stack whose element
// allocations are uniquely owned and match `free`; `OPENSSL_sk_pop_free`
// releases every non-null element and then the stack itself exactly once.
unsafe impl<T> CDropper<Stack<T>> for OpenSslSkPopFree<T> {
    unsafe fn c_drop(&self, stack: NonNull<Stack<T>>) {
        // SAFETY: the trait transfers unique ownership of the stack and the
        // policy records the matching destructor for each owned element.
        unsafe { ffi::OPENSSL_sk_pop_free(stack.as_ptr().cast(), self.free.as_raw()) }
    }
}

type RawCompThunk =
    unsafe extern "C" fn(ffi::OPENSSL_sk_compfunc, *const c_void, *const c_void) -> i32;

/// Typed handle for the optional adapter stored by
/// [`OPENSSL_sk_set_cmp_thunks`].
#[derive(Clone, Copy)]
pub struct OpenSslSkCompThunk<T> {
    raw: Option<RawCompThunk>,
    marker: PhantomData<fn(*const T)>,
}

impl<T> OpenSslSkCompThunk<T> {
    /// Associates a comparator thunk with the stack element type it adapts.
    ///
    /// # Safety
    ///
    /// `raw` must adapt every stored comparator and pointer-slot pair for `T`,
    /// must not retain its arguments, and must not unwind.
    pub unsafe fn from_raw(raw: Option<RawCompThunk>) -> Option<Self> {
        raw.map(|function| Self {
            raw: Some(function),
            marker: PhantomData,
        })
    }

    const fn as_raw(&self) -> Option<RawCompThunk> {
        self.raw
    }
}

/// Wraps: OPENSSL_sk_deep_copy
/// Deep-copies every non-null element and returns an owner that also releases
/// those copied elements.
#[allow(non_snake_case)]
pub fn OPENSSL_sk_deep_copy<T>(
    source: Option<StackRef<'_, T>>,
    copy: OpenSslSkCopyFunc<T>,
    free: OpenSslSkFreeFunc<T>,
) -> Option<CBoxWith<Stack<T>, OpenSslSkPopFree<T>>> {
    let source = source.map_or(core::ptr::null(), |source| source.as_ptr());
    // SAFETY: the source is null or live for the call; the callback wrappers
    // establish matching copy/free contracts. A successful result owns its
    // stack and copied elements under `OpenSslSkPopFree`.
    unsafe {
        CBoxWith::from_raw(
            ffi::OPENSSL_sk_deep_copy(source, copy.as_raw(), free.as_raw()),
            OpenSslSkPopFree { free },
        )
    }
}

/// Wraps: OPENSSL_sk_delete
#[allow(non_snake_case)]
pub fn OPENSSL_sk_delete<T>(
    stack: Option<&mut StackMut<'_, T>>,
    index: usize,
) -> Option<StackElement<T>> {
    let index = i32::try_from(index).ok()?;
    // SAFETY: the optional exclusive handle supplies null or a live stack; the C routine only
    // moves pointer slots and returns the removed opaque element address.
    element_from_raw(unsafe { ffi::OPENSSL_sk_delete(stack_mut_ptr(stack), index) })
}

/// Wraps: OPENSSL_sk_delete_ptr
#[allow(non_snake_case)]
pub fn OPENSSL_sk_delete_ptr<T>(
    stack: Option<&mut StackMut<'_, T>>,
    element: Option<StackElement<T>>,
) -> Option<StackElement<T>> {
    // SAFETY: the optional exclusive handle supplies null or a live stack; pointer identity is
    // compared without dereferencing `element`.
    element_from_raw(unsafe {
        ffi::OPENSSL_sk_delete_ptr(stack_mut_ptr(stack), element_ptr(element))
    })
}

/// Wraps: OPENSSL_sk_dup
#[allow(non_snake_case)]
pub fn OPENSSL_sk_dup<T>(source: Option<StackRef<'_, T>>) -> Option<CBox<Stack<T>>> {
    let source = source.map_or(core::ptr::null(), |source| source.as_ptr());
    // SAFETY: the source is null or live for the call. The returned allocation
    // owns only its pointer array and matches `Stack<T>`'s destructor.
    unsafe { CBox::from_raw(ffi::OPENSSL_sk_dup(source)) }
}

/// Wraps: OPENSSL_sk_find
///
/// # Safety
///
/// If the stack has a comparator, `element` and every stored non-null element
/// it examines must remain live and satisfy that comparator's type contract.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_find<T>(
    stack: Option<StackRef<'_, T>>,
    element: Option<StackElement<T>>,
) -> Option<usize> {
    // SAFETY: the caller establishes element/comparator validity; the optional
    // shared handle supplies null or remains live for the synchronous search.
    usize::try_from(unsafe { ffi::OPENSSL_sk_find(stack_ref_ptr(stack), element_ptr(element)) })
        .ok()
}

/// Wraps: OPENSSL_sk_find_all
/// Returns the first matching index and the total number of matches.
///
/// # Safety
///
/// The same element and comparator obligations as [`OPENSSL_sk_find`] apply.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_find_all<T>(
    stack: Option<StackRef<'_, T>>,
    element: Option<StackElement<T>>,
) -> Option<(usize, usize)> {
    let mut count = 0;
    // SAFETY: the caller establishes comparator validity; `count` is a live
    // output slot for the duration of the call.
    let index =
        unsafe { ffi::OPENSSL_sk_find_all(stack_ref_ptr(stack), element_ptr(element), &mut count) };
    Some((usize::try_from(index).ok()?, usize::try_from(count).ok()?))
}

/// Wraps: OPENSSL_sk_find_ex
///
/// # Safety
///
/// The same element and comparator obligations as [`OPENSSL_sk_find`] apply.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_find_ex<T>(
    stack: Option<StackRef<'_, T>>,
    element: Option<StackElement<T>>,
) -> Option<usize> {
    // SAFETY: the caller establishes the element/comparator validity.
    usize::try_from(unsafe { ffi::OPENSSL_sk_find_ex(stack_ref_ptr(stack), element_ptr(element)) })
        .ok()
}

/// Wraps: OPENSSL_sk_free
#[allow(non_snake_case)]
pub fn OPENSSL_sk_free<T>(stack: Option<CBox<Stack<T>>>) {
    drop(stack);
}

/// Wraps: OPENSSL_sk_insert
///
/// # Safety
///
/// A non-null `element` must remain live for as long as it is stored and for
/// every invocation of the stack's comparator.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_insert<T>(
    stack: Option<&mut StackMut<'_, T>>,
    element: Option<StackElement<T>>,
    index: usize,
) -> Option<usize> {
    let index = i32::try_from(index).ok()?;
    // SAFETY: the caller guarantees the retained element lifetime when a
    // stack is present; the optional exclusive handle supplies null or is live.
    let count =
        unsafe { ffi::OPENSSL_sk_insert(stack_mut_ptr(stack), element_ptr(element), index) };
    (count > 0).then(|| usize::try_from(count).expect("positive int fits usize"))
}

/// Wraps: OPENSSL_sk_is_sorted
#[must_use]
#[allow(non_snake_case)]
pub fn OPENSSL_sk_is_sorted<T>(stack: Option<StackRef<'_, T>>) -> bool {
    // SAFETY: the optional shared handle supplies null or a live stack and the routine only
    // reads its sorted flag.
    unsafe { ffi::OPENSSL_sk_is_sorted(stack_ref_ptr(stack)) != 0 }
}

/// Wraps: OPENSSL_sk_new
#[allow(non_snake_case)]
pub fn OPENSSL_sk_new<T>(comparator: Option<OpenSslSkStackCompFunc<T>>) -> Option<CBox<Stack<T>>> {
    // SAFETY: the callback wrapper has static code lifetime and the returned
    // complete stack transfers ownership to its matching CBox destructor.
    unsafe { CBox::from_raw(ffi::OPENSSL_sk_new(comparator_raw(comparator))) }
}

/// Wraps: OPENSSL_sk_new_null
#[allow(non_snake_case)]
pub fn OPENSSL_sk_new_null<T>() -> Option<CBox<Stack<T>>> {
    // SAFETY: a non-null result is a fresh complete stack allocation.
    unsafe { CBox::from_raw(ffi::OPENSSL_sk_new_null()) }
}

/// Wraps: OPENSSL_sk_new_reserve
#[allow(non_snake_case)]
pub fn OPENSSL_sk_new_reserve<T>(
    comparator: Option<OpenSslSkStackCompFunc<T>>,
    capacity: usize,
) -> Option<CBox<Stack<T>>> {
    let capacity = i32::try_from(capacity).ok()?;
    // SAFETY: as `OPENSSL_sk_new`; `capacity` is representable by C's API.
    unsafe {
        CBox::from_raw(ffi::OPENSSL_sk_new_reserve(
            comparator_raw(comparator),
            capacity,
        ))
    }
}

/// Wraps: OPENSSL_sk_num
#[must_use]
#[allow(non_snake_case)]
pub fn OPENSSL_sk_num<T>(stack: Option<StackRef<'_, T>>) -> Option<usize> {
    // SAFETY: the optional shared handle supplies null or a live stack.
    usize::try_from(unsafe { ffi::OPENSSL_sk_num(stack_ref_ptr(stack)) }).ok()
}

/// Wraps: OPENSSL_sk_pop
#[allow(non_snake_case)]
pub fn OPENSSL_sk_pop<T>(stack: Option<&mut StackMut<'_, T>>) -> Option<StackElement<T>> {
    // SAFETY: the optional exclusive handle supplies null or a live stack.
    element_from_raw(unsafe { ffi::OPENSSL_sk_pop(stack_mut_ptr(stack)) })
}

/// Wraps: OPENSSL_sk_pop_free
#[allow(non_snake_case)]
pub fn OPENSSL_sk_pop_free<T>(stack: Option<CBoxWith<Stack<T>, OpenSslSkPopFree<T>>>) {
    drop(stack);
}

/// Wraps: OPENSSL_sk_push
///
/// # Safety
///
/// A non-null `element` must remain live for as long as it is stored and for
/// every invocation of the stack's comparator.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_push<T>(
    stack: Option<&mut StackMut<'_, T>>,
    element: Option<StackElement<T>>,
) -> Option<usize> {
    // SAFETY: the caller guarantees the retained element lifetime when a
    // stack is present; OpenSSL explicitly accepts a null stack.
    let count = unsafe { ffi::OPENSSL_sk_push(stack_mut_ptr(stack), element_ptr(element)) };
    (count > 0).then(|| usize::try_from(count).expect("positive int fits usize"))
}

/// Wraps: OPENSSL_sk_reserve
#[allow(non_snake_case)]
pub fn OPENSSL_sk_reserve<T>(stack: Option<&mut StackMut<'_, T>>, additional: usize) -> bool {
    let Ok(additional) = i32::try_from(additional) else {
        return false;
    };
    // SAFETY: the optional exclusive handle supplies null or a live stack; the count is valid.
    unsafe { ffi::OPENSSL_sk_reserve(stack_mut_ptr(stack), additional) != 0 }
}

/// Wraps: OPENSSL_sk_set
///
/// # Safety
///
/// A non-null `element` must remain live for as long as it is stored and for
/// every invocation of the stack's comparator.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_set<T>(
    stack: Option<&mut StackMut<'_, T>>,
    index: usize,
    element: Option<StackElement<T>>,
) -> Option<StackElement<T>> {
    let index = i32::try_from(index).ok()?;
    // SAFETY: the caller guarantees the retained element lifetime when a
    // stack is present; OpenSSL explicitly accepts a null stack.
    element_from_raw(unsafe {
        ffi::OPENSSL_sk_set(stack_mut_ptr(stack), index, element_ptr(element))
    })
}

/// Wraps: OPENSSL_sk_set_cmp_func
#[allow(non_snake_case)]
pub fn OPENSSL_sk_set_cmp_func<T>(
    stack: &mut StackMut<'_, T>,
    comparator: Option<OpenSslSkStackCompFunc<T>>,
) -> Option<OpenSslSkStackCompFunc<T>> {
    // SAFETY: the exclusive handle supplies a live stack. Both the new and old
    // callbacks have the pointer-slot signature represented by this wrapper.
    let old =
        unsafe { ffi::OPENSSL_sk_set_cmp_func(stack.as_mut_ptr(), comparator_raw(comparator)) };
    // SAFETY: OpenSSL returns the previously stored comparator of this stack.
    unsafe { OpenSslSkStackCompFunc::from_raw(old) }
}

/// Wraps: OPENSSL_sk_set_cmp_thunks
#[allow(non_snake_case)]
pub fn OPENSSL_sk_set_cmp_thunks<T>(
    stack: Option<&mut StackMut<'_, T>>,
    thunk: Option<OpenSslSkCompThunk<T>>,
) {
    let raw = thunk.as_ref().and_then(OpenSslSkCompThunk::as_raw);
    // SAFETY: the optional exclusive handle supplies null or a live stack and the thunk wrapper
    // establishes a static adapter compatible with this element type.
    unsafe { ffi::OPENSSL_sk_set_cmp_thunks(stack_mut_ptr(stack), raw) };
}

/// Wraps: OPENSSL_sk_shift
#[allow(non_snake_case)]
pub fn OPENSSL_sk_shift<T>(stack: Option<&mut StackMut<'_, T>>) -> Option<StackElement<T>> {
    // SAFETY: the optional exclusive handle supplies null or a live stack.
    element_from_raw(unsafe { ffi::OPENSSL_sk_shift(stack_mut_ptr(stack)) })
}

/// Wraps: OPENSSL_sk_sort
#[allow(non_snake_case)]
pub fn OPENSSL_sk_sort<T>(stack: Option<&mut StackMut<'_, T>>) {
    // SAFETY: the optional exclusive handle supplies null or a valid stack
    // whose callback/element invariants were established earlier.
    unsafe { ffi::OPENSSL_sk_sort(stack_mut_ptr(stack)) }
}

/// Wraps: OPENSSL_sk_unshift
///
/// # Safety
///
/// A non-null `element` must remain live for as long as it is stored and for
/// every invocation of the stack's comparator.
#[allow(non_snake_case)]
pub unsafe fn OPENSSL_sk_unshift<T>(
    stack: Option<&mut StackMut<'_, T>>,
    element: Option<StackElement<T>>,
) -> Option<usize> {
    // SAFETY: the caller guarantees the retained element lifetime when a
    // stack is present; OpenSSL explicitly accepts a null stack.
    let count = unsafe { ffi::OPENSSL_sk_unshift(stack_mut_ptr(stack), element_ptr(element)) };
    (count > 0).then(|| usize::try_from(count).expect("positive int fits usize"))
}

/// Wraps: OPENSSL_sk_value
#[allow(non_snake_case)]
pub fn OPENSSL_sk_value<T>(
    stack: Option<StackRef<'_, T>>,
    index: usize,
) -> Option<StackElement<T>> {
    let index = i32::try_from(index).ok()?;
    // SAFETY: the optional shared handle supplies null or a live stack and the routine returns
    // only the opaque pointer value from the selected slot.
    element_from_raw(unsafe { ffi::OPENSSL_sk_value(stack_ref_ptr(stack), index) })
}

/// Wraps: OPENSSL_sk_zero
#[allow(non_snake_case)]
pub fn OPENSSL_sk_zero<T>(stack: Option<&mut StackMut<'_, T>>) {
    // SAFETY: the optional exclusive handle supplies null or a live stack; the routine clears
    // pointer slots without touching the pointed-to elements.
    unsafe { ffi::OPENSSL_sk_zero(stack_mut_ptr(stack)) }
}

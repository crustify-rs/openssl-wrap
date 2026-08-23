//! Wrappers assigned from `crypto/stack/stack.c`.

use core::ffi::c_void;
use core::marker::PhantomData;
use core::ptr::NonNull;

use ffibox::{CBox, CBoxWith, CCell, CCloned, CDropped, CDropper, CPtr, CType};
use libcrypto_sys as ffi;

use super::openssl_stack::{
    OpenSslSkCopyFunc, OpenSslSkCopyFuncThunk, OpenSslSkFreeFunc, OpenSslSkFreeFuncThunk,
    OpenSslSkStackCompFunc,
};

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

impl<T> Stack<T> {
    /// Promotes a stack that only owns its pointer array into one that also
    /// owns every stored element, releasing them with `free`.
    ///
    /// This is the second releaser OpenSSL publishes for a stack: the result
    /// is torn down by `OPENSSL_sk_pop_free` instead of `OPENSSL_sk_free`.
    ///
    /// # Safety
    ///
    /// Every non-null element stored in `stack`, now or later, must be a
    /// uniquely owned allocation that `free` releases exactly once, and no
    /// other owner may release it. In particular a stack duplicated by
    /// [`OPENSSL_sk_dup`] shares its element pointers with the original, so at
    /// most one of the two may be promoted here.
    pub unsafe fn into_pop_free(
        stack: CBox<Self>,
        free: OpenSslSkFreeFunc<T>,
    ) -> CBoxWith<Self, OpenSslSkPopFree<T>> {
        let raw = stack.into_raw();
        // SAFETY: `CBox::into_raw` surrenders a live, uniquely owned, non-null
        // stack, and the caller established the element ownership `free` needs.
        unsafe { CBoxWith::from_raw(raw, OpenSslSkPopFree { free }) }
            .expect("an owning CBox never holds a null stack")
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

    /// Stores a boxed value in `stack` and hands back its element token.
    ///
    /// # Safety
    ///
    /// The caller must reclaim or transfer every returned allocation exactly
    /// once, as each test below does.
    unsafe fn push_boxed(stack: &mut CBox<Stack<i32>>, value: i32) -> StackElement<i32> {
        let raw = Box::into_raw(Box::new(value));
        // SAFETY: `raw` is a live, uniquely owned `i32` allocation.
        let element = unsafe { StackElement::from_raw(raw) }.unwrap();
        // SAFETY: the caller keeps the allocation live for as long as it is
        // stored and for every comparator invocation.
        unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(element)) }.unwrap();
        element
    }

    /// Reads the `i32` an element token addresses.
    ///
    /// # Safety
    ///
    /// `element` must still address a live `i32`.
    unsafe fn read_element(element: StackElement<i32>) -> i32 {
        // SAFETY: the caller guarantees the allocation is still live.
        unsafe { element.as_non_null().as_ptr().read() }
    }

    /// Reclaims a `Box<i32>` the tests stored in a stack.
    ///
    /// # Safety
    ///
    /// `element` must be an allocation from [`push_boxed`] that nothing else
    /// has reclaimed.
    unsafe fn reclaim(element: StackElement<i32>) {
        // SAFETY: the caller transfers the unique `Box<i32>` back.
        drop(unsafe { Box::from_raw(element.as_non_null().as_ptr()) });
    }

    /// The comparator contract `OpenSslSkStackCompFunc` describes: both
    /// arguments address element *slots*, not the elements themselves.
    unsafe extern "C" fn compare_i32_slots(left: *const c_void, right: *const c_void) -> i32 {
        // SAFETY: every stack routine that reaches a comparator — `qsort` in
        // `OPENSSL_sk_sort`, `ossl_bsearch`, `internal_find`'s linear scan and
        // `OPENSSL_sk_insert`'s sortedness check — passes the addresses of two
        // slots holding live `i32` pointers.
        let (left, right) = unsafe {
            (
                left.cast::<*const i32>().read(),
                right.cast::<*const i32>().read(),
            )
        };
        // SAFETY: the tests keep every stored element live while it resides in
        // a stack carrying this comparator.
        let (left, right) = unsafe { (left.read(), right.read()) };
        match left.cmp(&right) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
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
            OPENSSL_sk_set_copy_thunks(&mut exclusive, None);
            OPENSSL_sk_set_thunks(&mut exclusive, None);
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
        static FREES: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn copy_i32(source: *const c_void) -> *mut c_void {
            // SAFETY: this callback is registered only for live `i32` elements.
            let value = unsafe { source.cast::<i32>().read() };
            Box::into_raw(Box::new(value)).cast()
        }

        unsafe extern "C" fn free_i32(value: *mut c_void) {
            if !value.is_null() {
                // SAFETY: `copy_i32` created one unique `Box<i32>`.
                drop(unsafe { Box::from_raw(value.cast::<i32>()) });
                FREES.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut source = OPENSSL_sk_new_null::<i32>().expect("new source stack");
        // SAFETY: the allocation is reclaimed once, below.
        let token = unsafe { push_boxed(&mut source, 23) };

        // SAFETY: these callbacks copy and free precisely `i32` allocations.
        let copy = unsafe { OpenSslSkCopyFunc::from_raw(Some(copy_i32)) }.unwrap();
        // SAFETY: these callbacks copy and free precisely `i32` allocations.
        let free = unsafe { OpenSslSkFreeFunc::from_raw(Some(free_i32)) }.unwrap();
        let deep = OPENSSL_sk_deep_copy(Some(source.as_ref()), copy, free).expect("deep copy");
        assert_eq!(OPENSSL_sk_num(Some(deep.as_ref())), Some(1));
        // The copy is independent: it holds a different allocation.
        let copied = OPENSSL_sk_value(Some(deep.as_ref()), 0).unwrap();
        assert_ne!(copied.as_non_null(), token.as_non_null());
        // SAFETY: both allocations are still live here.
        assert_eq!(unsafe { read_element(copied) }, 23);
        drop(deep);
        assert_eq!(FREES.load(Ordering::Relaxed), 1);

        let original = OPENSSL_sk_pop(Some(&mut source.as_mut())).unwrap();
        // SAFETY: the source stack did not own or free this Box.
        unsafe { reclaim(original) };
    }

    #[test]
    fn a_null_source_deep_copies_into_an_empty_owner() {
        unsafe extern "C" fn never_copies(_source: *const c_void) -> *mut c_void {
            unreachable!("an empty source has no element to copy")
        }

        unsafe extern "C" fn never_frees(_value: *mut c_void) {
            unreachable!("an empty copy has no element to release")
        }

        // SAFETY: neither callback can be reached from an empty source.
        let copy = unsafe { OpenSslSkCopyFunc::<i32>::from_raw(Some(never_copies)) }.unwrap();
        // SAFETY: as above.
        let free = unsafe { OpenSslSkFreeFunc::<i32>::from_raw(Some(never_frees)) }.unwrap();
        // Like `OPENSSL_sk_dup`, a null source produces a fresh empty stack.
        let deep = OPENSSL_sk_deep_copy(None, copy, free).expect("deep copy of a null source");
        assert_eq!(OPENSSL_sk_num(Some(deep.as_ref())), Some(0));
        OPENSSL_sk_pop_free(Some(deep));
    }

    #[test]
    fn promoted_owner_releases_every_transferred_element() {
        static FREES: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn free_i32(value: *mut c_void) {
            if !value.is_null() {
                // SAFETY: every element stored below is a unique `Box<i32>`.
                drop(unsafe { Box::from_raw(value.cast::<i32>()) });
                FREES.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mut stack = OPENSSL_sk_new_null::<i32>().expect("new stack");
        for value in [2_i32, 3, 5] {
            // SAFETY: ownership of the Box moves into the stack, which is
            // promoted below to an owner that frees it exactly once.
            unsafe { push_boxed(&mut stack, value) };
        }

        // SAFETY: `free_i32` releases exactly the `Box<i32>` allocations above.
        let free = unsafe { OpenSslSkFreeFunc::from_raw(Some(free_i32)) }.unwrap();
        // SAFETY: each stored element is a uniquely owned Box that `free_i32`
        // releases once, and no other owner holds one.
        let owning = unsafe { Stack::into_pop_free(stack, free) };
        assert_eq!(OPENSSL_sk_num(Some(owning.as_ref())), Some(3));

        OPENSSL_sk_pop_free(Some(owning));
        assert_eq!(FREES.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn constructors_reserve_capacity_and_duplicates_share_element_pointers() {
        let mut source = OPENSSL_sk_new_reserve::<i32>(None, 4).expect("reserved stack");
        assert_eq!(OPENSSL_sk_num(Some(source.as_ref())), Some(0));
        // Reserving does not populate the stack, so it is still sorted.
        assert!(OPENSSL_sk_is_sorted(Some(source.as_ref())));
        // SAFETY: the allocation is reclaimed once, below.
        let stored = unsafe { push_boxed(&mut source, 11) };

        let duplicate = OPENSSL_sk_dup(Some(source.as_ref())).expect("duplicate");
        assert_eq!(OPENSSL_sk_num(Some(duplicate.as_ref())), Some(1));
        // The duplicate holds the very same element pointer, which neither
        // stack owns.
        assert_eq!(
            OPENSSL_sk_value(Some(duplicate.as_ref()), 0)
                .unwrap()
                .as_non_null(),
            stored.as_non_null()
        );
        OPENSSL_sk_free(Some(duplicate));

        // A null source is not an error: it produces a fresh empty stack.
        let empty = OPENSSL_sk_dup::<i32>(None).expect("duplicate of a null source");
        assert_eq!(OPENSSL_sk_num(Some(empty.as_ref())), Some(0));
        OPENSSL_sk_free(Some(empty));

        // SAFETY: neither stack ever owned the element.
        unsafe { reclaim(stored) };
    }

    #[test]
    fn sorted_search_wrappers_report_matches_and_neighbours() {
        // SAFETY: `compare_i32_slots` obeys the element-slot comparator
        // contract for `i32` and never retains or unwinds.
        let comparator = unsafe { OpenSslSkStackCompFunc::from_raw(Some(compare_i32_slots)) };
        let mut stack = OPENSSL_sk_new(comparator).expect("new stack");
        let mut stored = Vec::new();
        for value in [5_i32, 1, 9, 3, 5] {
            // SAFETY: every allocation is reclaimed once, below.
            stored.push(unsafe { push_boxed(&mut stack, value) });
        }

        // Pushing out of order clears the flag the constructor set.
        assert!(!OPENSSL_sk_is_sorted(Some(stack.as_ref())));
        OPENSSL_sk_sort(Some(&mut stack.as_mut()));
        assert!(OPENSSL_sk_is_sorted(Some(stack.as_ref())));

        let order: Vec<i32> = (0..5)
            .map(|index| {
                let element = OPENSSL_sk_value(Some(stack.as_ref()), index).unwrap();
                // SAFETY: every element is still live and stored.
                unsafe { read_element(element) }
            })
            .collect();
        assert_eq!(order, [1, 3, 5, 5, 9]);

        let five = stored[0];
        // SAFETY: `five` and every stored element remain live for the search.
        let found = unsafe { OPENSSL_sk_find(Some(stack.as_ref()), Some(five)) };
        assert_eq!(found, Some(2));
        // SAFETY: as above; both equal elements are counted.
        let all = unsafe { OPENSSL_sk_find_all(Some(stack.as_ref()), Some(five)) };
        assert_eq!(all, Some((2, 2)));

        let absent = Box::into_raw(Box::new(4_i32));
        // SAFETY: `absent` is a live `i32` for the searches below.
        let absent = unsafe { StackElement::from_raw(absent) }.unwrap();
        // An exact search reports nothing...
        // SAFETY: every element the comparator sees is live.
        let exact = unsafe { OPENSSL_sk_find(Some(stack.as_ref()), Some(absent)) };
        assert_eq!(exact, None);
        // ...while the `_ex` form reports where the binary search stopped.
        // SAFETY: as above.
        let nearest = unsafe { OPENSSL_sk_find_ex(Some(stack.as_ref()), Some(absent)) };
        assert_eq!(nearest, Some(1));

        // A null stack has nothing to search, whichever form is used.
        // SAFETY: no comparator runs without a stack.
        unsafe {
            assert_eq!(OPENSSL_sk_find::<i32>(None, Some(absent)), None);
            assert_eq!(OPENSSL_sk_find_ex::<i32>(None, Some(absent)), None);
            assert_eq!(OPENSSL_sk_find_all::<i32>(None, Some(absent)), None);
        }

        // SAFETY: each allocation is reclaimed exactly once.
        unsafe { reclaim(absent) };
        for element in stored {
            // SAFETY: the stack never owned these allocations.
            unsafe { reclaim(element) };
        }
    }

    #[test]
    fn the_comparator_thunk_mediates_searches_but_not_sorting() {
        static THUNK_CALLS: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn counting_thunk(
            comparator: ffi::OPENSSL_sk_compfunc,
            left: *const c_void,
            right: *const c_void,
        ) -> i32 {
            THUNK_CALLS.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the stack passes its stored comparator together with the
            // two element-slot addresses it would otherwise hand it directly.
            unsafe { comparator.expect("stored comparator")(left, right) }
        }

        // SAFETY: `compare_i32_slots` obeys the element-slot comparator contract.
        let comparator = unsafe { OpenSslSkStackCompFunc::from_raw(Some(compare_i32_slots)) };
        let mut stack = OPENSSL_sk_new(comparator).expect("new stack");
        let mut stored = Vec::new();
        for value in [5_i32, 1, 9, 3] {
            // SAFETY: every allocation is reclaimed once, below.
            stored.push(unsafe { push_boxed(&mut stack, value) });
        }

        // SAFETY: `counting_thunk` forwards the stored comparator unchanged,
        // retains nothing and cannot unwind.
        let thunk = unsafe { OpenSslSkCompThunk::from_raw(Some(counting_thunk)) };
        OPENSSL_sk_set_cmp_thunks(Some(&mut stack.as_mut()), thunk);

        // `OPENSSL_sk_sort` hands the comparator straight to `qsort`, so the
        // adapter is bypassed — exactly what the wrapper documents.
        THUNK_CALLS.store(0, Ordering::Relaxed);
        OPENSSL_sk_sort(Some(&mut stack.as_mut()));
        assert_eq!(THUNK_CALLS.load(Ordering::Relaxed), 0);
        assert!(OPENSSL_sk_is_sorted(Some(stack.as_ref())));

        // Searching does go through it.
        THUNK_CALLS.store(0, Ordering::Relaxed);
        let five = stored[0];
        // SAFETY: `five` and every stored element remain live for the search.
        let through_thunk = unsafe { OPENSSL_sk_find(Some(stack.as_ref()), Some(five)) };
        assert_eq!(through_thunk, Some(2));
        assert!(THUNK_CALLS.load(Ordering::Relaxed) > 0);

        // Clearing the adapter restores the direct comparator call.
        OPENSSL_sk_set_cmp_thunks::<i32>(Some(&mut stack.as_mut()), None);
        THUNK_CALLS.store(0, Ordering::Relaxed);
        // SAFETY: as above.
        let direct = unsafe { OPENSSL_sk_find(Some(stack.as_ref()), Some(five)) };
        assert_eq!(direct, Some(2));
        assert_eq!(THUNK_CALLS.load(Ordering::Relaxed), 0);

        for element in stored {
            // SAFETY: the stack never owned these allocations.
            unsafe { reclaim(element) };
        }
    }

    #[test]
    fn replacing_the_comparator_hands_back_the_previous_one() {
        // SAFETY: `compare_i32_slots` obeys the element-slot comparator contract.
        let comparator = unsafe { OpenSslSkStackCompFunc::from_raw(Some(compare_i32_slots)) };
        let mut stack = OPENSSL_sk_new(comparator).expect("new stack");

        let previous = OPENSSL_sk_set_cmp_func(&mut stack.as_mut(), None);
        assert!(previous.is_some());
        // The slot now holds nothing, so putting the comparator back reports
        // no predecessor.
        assert!(OPENSSL_sk_set_cmp_func(&mut stack.as_mut(), previous).is_none());

        // The restored comparator is the one the stack consults: pushing a
        // smaller element after a larger one clears the sorted flag.
        let mut stored = Vec::new();
        for value in [7_i32, 2] {
            // SAFETY: every allocation is reclaimed once, below.
            stored.push(unsafe { push_boxed(&mut stack, value) });
        }
        assert!(!OPENSSL_sk_is_sorted(Some(stack.as_ref())));

        for element in stored {
            // SAFETY: the stack never owned these allocations.
            unsafe { reclaim(element) };
        }
    }

    #[test]
    fn insertion_and_removal_wrappers_only_move_pointer_slots() {
        let mut stack = OPENSSL_sk_new_null::<i32>().expect("new stack");
        // SAFETY: every allocation is reclaimed once, below.
        let (first, second) = unsafe { (push_boxed(&mut stack, 1), push_boxed(&mut stack, 2)) };

        let middle = Box::into_raw(Box::new(3_i32));
        // SAFETY: `middle` outlives its residence in the stack.
        let middle = unsafe { StackElement::from_raw(middle) }.unwrap();
        // SAFETY: as above.
        let length = unsafe { OPENSSL_sk_insert(Some(&mut stack.as_mut()), Some(middle), 1) };
        assert_eq!(length, Some(3));
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 1)
                .unwrap()
                .as_non_null(),
            middle.as_non_null()
        );

        let front = Box::into_raw(Box::new(4_i32));
        // SAFETY: `front` outlives its residence in the stack.
        let front = unsafe { StackElement::from_raw(front) }.unwrap();
        // SAFETY: as above.
        let length = unsafe { OPENSSL_sk_unshift(Some(&mut stack.as_mut()), Some(front)) };
        assert_eq!(length, Some(4));
        assert_eq!(
            OPENSSL_sk_shift(Some(&mut stack.as_mut()))
                .unwrap()
                .as_non_null(),
            front.as_non_null()
        );

        // Out-of-range removals report nothing and change nothing.
        assert!(OPENSSL_sk_delete(Some(&mut stack.as_mut()), 99).is_none());
        let absent = Box::into_raw(Box::new(5_i32));
        // SAFETY: `absent` is live and never stored; `delete_ptr` only
        // compares pointer identity.
        let absent = unsafe { StackElement::from_raw(absent) }.unwrap();
        assert!(OPENSSL_sk_delete_ptr(Some(&mut stack.as_mut()), Some(absent)).is_none());
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(3));

        assert_eq!(
            OPENSSL_sk_delete(Some(&mut stack.as_mut()), 1)
                .unwrap()
                .as_non_null(),
            middle.as_non_null()
        );
        assert_eq!(
            OPENSSL_sk_delete_ptr(Some(&mut stack.as_mut()), Some(second))
                .unwrap()
                .as_non_null(),
            second.as_non_null()
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));

        // Zeroing abandons the remaining slot without touching the element.
        OPENSSL_sk_zero(Some(&mut stack.as_mut()));
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(0));
        // SAFETY: each allocation is reclaimed exactly once, and the stack
        // released none of them.
        unsafe {
            reclaim(first);
            reclaim(second);
            reclaim(middle);
            reclaim(front);
            reclaim(absent);
        }
    }

    #[test]
    fn installed_thunks_mediate_deep_copy_and_pop_free() {
        static COPIES: AtomicUsize = AtomicUsize::new(0);
        static FREES: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "C" fn copy_i32(source: *const c_void) -> *mut c_void {
            // SAFETY: this callback is registered only for live `i32` elements.
            let value = unsafe { source.cast::<i32>().read() };
            Box::into_raw(Box::new(value)).cast()
        }

        unsafe extern "C" fn free_i32(value: *mut c_void) {
            if !value.is_null() {
                // SAFETY: `copy_i32` created one unique `Box<i32>`.
                drop(unsafe { Box::from_raw(value.cast::<i32>()) });
            }
        }

        unsafe extern "C" fn copy_thunk(
            copy: ffi::OPENSSL_sk_copyfunc,
            source: *const c_void,
        ) -> *mut c_void {
            COPIES.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the stack passes the copy callback it was given together
            // with one live source element.
            unsafe { copy.expect("copy callback")(source) }
        }

        unsafe extern "C" fn free_thunk(free: ffi::OPENSSL_sk_freefunc, value: *mut c_void) {
            FREES.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the stack passes the destructor it was given together
            // with one element allocation it is releasing.
            unsafe { free.expect("free callback")(value) }
        }

        let mut source = OPENSSL_sk_new_null::<i32>().expect("new source stack");
        // SAFETY: `copy_thunk` forwards the supplied copier for a live `i32`.
        let installed_copy = unsafe { OpenSslSkCopyFuncThunk::from_raw(Some(copy_thunk)) };
        OPENSSL_sk_set_copy_thunks(&mut source.as_mut(), installed_copy);
        // SAFETY: `free_thunk` forwards the supplied destructor exactly once.
        let installed_free = unsafe { OpenSslSkFreeFuncThunk::from_raw(Some(free_thunk)) };
        OPENSSL_sk_set_thunks(&mut source.as_mut(), installed_free);

        let mut stored = Vec::new();
        for value in [13_i32, 17] {
            // SAFETY: every allocation is reclaimed once, below.
            stored.push(unsafe { push_boxed(&mut source, value) });
        }

        // SAFETY: both callbacks handle precisely `i32` allocations.
        let copy = unsafe { OpenSslSkCopyFunc::from_raw(Some(copy_i32)) }.unwrap();
        // SAFETY: as above.
        let free = unsafe { OpenSslSkFreeFunc::from_raw(Some(free_i32)) }.unwrap();

        // `internal_copy` copies the source struct wholesale, so the deep copy
        // inherits both adapters and routes each element through them.
        let deep = OPENSSL_sk_deep_copy(Some(source.as_ref()), copy, free).expect("deep copy");
        assert_eq!(COPIES.load(Ordering::Relaxed), 2);
        assert_eq!(OPENSSL_sk_num(Some(deep.as_ref())), Some(2));

        OPENSSL_sk_pop_free(Some(deep));
        assert_eq!(FREES.load(Ordering::Relaxed), 2);

        for element in stored {
            // SAFETY: the source stack never owned these allocations.
            unsafe { reclaim(element) };
        }
    }

    #[test]
    fn set_echoes_the_stored_element_and_leaves_the_previous_one_to_the_caller() {
        let mut stack = OPENSSL_sk_new_null::<i32>().expect("new stack");
        let first = Box::into_raw(Box::new(41_i32));
        let second = Box::into_raw(Box::new(42_i32));
        // SAFETY: both allocations stay live until they are reclaimed below.
        let first = unsafe { StackElement::from_raw(first) }.unwrap();
        // SAFETY: both allocations stay live until they are reclaimed below.
        let second = unsafe { StackElement::from_raw(second) }.unwrap();
        // SAFETY: `first` outlives its residence in the stack.
        unsafe { OPENSSL_sk_push(Some(&mut stack.as_mut()), Some(first)) }.unwrap();

        // An out-of-range index stores nothing.
        // SAFETY: `second` outlives the call and is not stored by it.
        assert!(unsafe { OPENSSL_sk_set(Some(&mut stack.as_mut()), 1, Some(second)) }.is_none());

        // The displaced element is only recoverable before the write.
        let displaced = OPENSSL_sk_value(Some(stack.as_ref()), 0).unwrap();
        assert_eq!(displaced.as_non_null(), first.as_non_null());
        // SAFETY: `second` outlives its residence in the stack.
        let stored = unsafe { OPENSSL_sk_set(Some(&mut stack.as_mut()), 0, Some(second)) }.unwrap();
        assert_eq!(stored.as_non_null(), second.as_non_null());
        assert_eq!(
            OPENSSL_sk_value(Some(stack.as_ref()), 0)
                .unwrap()
                .as_non_null(),
            second.as_non_null()
        );
        assert_eq!(OPENSSL_sk_num(Some(stack.as_ref())), Some(1));

        // SAFETY: the stack owns neither Box; each is reclaimed exactly once.
        drop(unsafe { Box::from_raw(displaced.as_non_null().as_ptr()) });
        // SAFETY: as above, for the element still residing in the stack.
        drop(unsafe { Box::from_raw(second.as_non_null().as_ptr()) });
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
///
/// Reached through [`OPENSSL_sk_deep_copy`], which produces the copied
/// elements it releases, or through [`Stack::into_pop_free`] for a stack whose
/// elements were transferred to it by the caller.
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
///
/// Duplicates the stack allocation and its pointer array only: the duplicate
/// stores the very same element pointers, which neither stack owns. A null
/// source yields a new empty stack rather than `None`.
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
/// Unlike [`OPENSSL_sk_find`], a sorted stack with no exact match reports the
/// index of the nearest element instead of `None`.
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
/// Inserts at `index`, shifting the elements after it right and appending when
/// `index` is at or beyond the current length; returns the new length.
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
/// Appends `element` and returns the new length.
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
/// Returns the element that was just stored, echoing `element`, and `None`
/// when the stack is null, `index` is out of range, or `element` is `None`.
/// The element previously held at `index` is dropped from the stack without
/// being returned; read it with [`OPENSSL_sk_value`] first when it is owned,
/// otherwise it leaks. Storing also resets the sorted flag, which stays set
/// only while the stack holds at most one element.
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
///
/// Sorts only when a comparator is installed and the stack is not already
/// marked sorted. OpenSSL hands the comparator straight to `qsort` here, so
/// the adapter installed by [`OPENSSL_sk_set_cmp_thunks`] is bypassed; a thunk
/// that does more than cast its arguments makes this order disagree with
/// [`OPENSSL_sk_find`].
#[allow(non_snake_case)]
pub fn OPENSSL_sk_sort<T>(stack: Option<&mut StackMut<'_, T>>) {
    // SAFETY: the optional exclusive handle supplies null or a valid stack
    // whose callback/element invariants were established earlier.
    unsafe { ffi::OPENSSL_sk_sort(stack_mut_ptr(stack)) }
}

/// Wraps: OPENSSL_sk_unshift
///
/// Inserts `element` at the front and returns the new length.
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
///
/// Clears the pointer slots without touching the elements. On a stack owned
/// through [`OpenSslSkPopFree`] this abandons every stored element, so release
/// them first.
#[allow(non_snake_case)]
pub fn OPENSSL_sk_zero<T>(stack: Option<&mut StackMut<'_, T>>) {
    // SAFETY: the optional exclusive handle supplies null or a live stack; the routine clears
    // pointer slots without touching the pointed-to elements.
    unsafe { ffi::OPENSSL_sk_zero(stack_mut_ptr(stack)) }
}

/// Wraps: OPENSSL_sk_set_copy_thunks
#[allow(non_snake_case)]
pub fn OPENSSL_sk_set_copy_thunks<T>(
    stack: &mut StackMut<'_, T>,
    thunk: Option<OpenSslSkCopyFuncThunk<T>>,
) {
    let raw = thunk.and_then(OpenSslSkCopyFuncThunk::as_raw);
    // SAFETY: the exclusive typed stack handle permits replacing the slot and
    // the thunk wrapper binds its stored adapter to the same element type.
    unsafe { ffi::OPENSSL_sk_set_copy_thunks(stack.as_mut_ptr(), raw) };
}

/// Wraps: OPENSSL_sk_set_thunks
#[allow(non_snake_case)]
pub fn OPENSSL_sk_set_thunks<T>(
    stack: &mut StackMut<'_, T>,
    thunk: Option<OpenSslSkFreeFuncThunk<T>>,
) {
    let raw = thunk.and_then(OpenSslSkFreeFuncThunk::as_raw);
    // SAFETY: the exclusive typed stack handle permits replacing the slot and
    // the thunk wrapper binds its stored adapter to this stack's element type.
    unsafe { ffi::OPENSSL_sk_set_thunks(stack.as_mut_ptr(), raw) };
}

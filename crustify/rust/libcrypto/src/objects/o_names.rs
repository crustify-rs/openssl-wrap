//! Wrappers assigned from `crypto/objects/o_names.c`.

use core::ffi::{CStr, c_void};
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use super::openssl_objects::ObjNameRef;

type RawNameHash = unsafe extern "C" fn(*const core::ffi::c_char) -> core::ffi::c_ulong;
type RawNameCompare =
    unsafe extern "C" fn(*const core::ffi::c_char, *const core::ffi::c_char) -> core::ffi::c_int;
type RawNameFree =
    unsafe extern "C" fn(*const core::ffi::c_char, core::ffi::c_int, *const core::ffi::c_char);

/// Static hash callback installed for an OBJ_NAME class.
#[derive(Clone, Copy)]
pub struct ObjNameHashCallback(RawNameHash);

impl ObjNameHashCallback {
    /// # Safety
    /// The callback must accept every live NUL-terminated name supplied by
    /// OpenSSL, retain nothing, remain thread-safe, and never unwind.
    pub unsafe fn from_raw(raw: RawNameHash) -> Self {
        Self(raw)
    }
}

/// Static comparison callback installed for an OBJ_NAME class.
#[derive(Clone, Copy)]
pub struct ObjNameCompareCallback(RawNameCompare);

impl ObjNameCompareCallback {
    /// # Safety
    /// The callback must implement a total ordering for all live C strings
    /// supplied by OpenSSL, retain nothing, and never unwind.
    pub unsafe fn from_raw(raw: RawNameCompare) -> Self {
        Self(raw)
    }
}

/// Static disposal callback installed for an OBJ_NAME class.
#[derive(Clone, Copy)]
pub struct ObjNameFreeCallback(RawNameFree);

impl ObjNameFreeCallback {
    /// # Safety
    /// The callback must accept every stored name/data pair in this class,
    /// dispose only resources it owns, remain thread-safe, and never unwind.
    pub unsafe fn from_raw(raw: RawNameFree) -> Self {
        Self(raw)
    }
}

/// An opaque, registry-owned payload returned by `OBJ_NAME_get`.
pub struct ObjNameValue<'a> {
    ptr: NonNull<c_void>,
    marker: PhantomData<&'a ()>,
}

impl ObjNameValue<'_> {
    /// Reinterprets the erased payload after validating its registered type.
    ///
    /// # Safety
    ///
    /// The requested `T` must match `type_id`; the corresponding registry entry
    /// must remain installed and live for every subsequent use of the pointer.
    #[must_use]
    pub unsafe fn cast<T>(&self) -> NonNull<T> {
        self.ptr.cast()
    }
}

/// Wraps: OBJ_NAME_get
/// Looks up an opaque payload. The borrow prevents treating it as owned data.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_NAME_get(name: &CStr, type_id: i32) -> Option<ObjNameValue<'_>> {
    // SAFETY: `name` is a live immutable C string. The returned registry
    // pointer remains opaque and cannot be dereferenced through this safe API.
    let raw = unsafe { ffi::OBJ_NAME_get(name.as_ptr(), type_id) };
    NonNull::new(raw.cast_mut().cast()).map(|ptr| ObjNameValue {
        ptr,
        marker: PhantomData,
    })
}

/// Wraps: OBJ_NAME_init
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_NAME_init() -> bool {
    // SAFETY: initialization has no caller-side memory obligations.
    unsafe { ffi::OBJ_NAME_init() == 1 }
}

struct DoAllContext<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
}

unsafe extern "C" fn do_all_trampoline<F>(name: *const ffi::OBJ_NAME, context: *mut c_void)
where
    F: for<'a> FnMut(ObjNameRef<'a>),
{
    // SAFETY: the wrapper supplies this exact context type and keeps it
    // exclusively borrowed for the complete synchronous C traversal.
    let context = unsafe { &mut *context.cast::<DoAllContext<'_, F>>() };
    if context.panic.is_some() {
        return;
    }
    // SAFETY: OpenSSL invokes the callback with a live registry entry for only
    // this call; the generated handle does not form a reference to its bytes.
    let Some(name) = (unsafe { ObjNameRef::from_ptr(name.cast_mut()) }) else {
        return;
    };
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (context.callback)(name))) {
        context.panic = Some(panic);
    }
}

fn do_all<F>(type_id: i32, sorted: bool, callback: &mut F)
where
    F: for<'a> FnMut(ObjNameRef<'a>),
{
    let mut context = DoAllContext {
        callback,
        panic: None,
    };
    // SAFETY: the trampoline/context pair stays live and exclusively borrowed
    // for the synchronous traversal. The trampoline catches Rust panics.
    unsafe {
        if sorted {
            ffi::OBJ_NAME_do_all_sorted(
                type_id,
                Some(do_all_trampoline::<F>),
                core::ptr::from_mut(&mut context).cast(),
            );
        } else {
            ffi::OBJ_NAME_do_all(
                type_id,
                Some(do_all_trampoline::<F>),
                core::ptr::from_mut(&mut context).cast(),
            );
        }
    }
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
}

/// Wraps: OBJ_NAME_do_all
/// Visits registry entries of `type_id` in unspecified order.
///
/// # Safety
///
/// OpenSSL performs this traversal without taking `obj_lock`. No thread or
/// callback may add, replace, or remove object-name entries until it returns.
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_do_all<F>(type_id: i32, callback: &mut F)
where
    F: for<'a> FnMut(ObjNameRef<'a>),
{
    do_all(type_id, false, callback);
}

/// Wraps: OBJ_NAME_do_all_sorted
/// Visits registry entries of `type_id` ordered by name.
///
/// # Safety
///
/// As [`OBJ_NAME_do_all`], the global registry must not be mutated during the
/// traversal, including from `callback`.
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_do_all_sorted<F>(type_id: i32, callback: &mut F)
where
    F: for<'a> FnMut(ObjNameRef<'a>),
{
    do_all(type_id, true, callback);
}

/// Wraps: OBJ_NAME_add
///
/// # Safety
/// `name` and `data` are stored without copying. They must remain live and
/// immutable until this entry is removed or its class is cleaned up, and they
/// must satisfy the registered class disposal callback's ownership contract.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_add(name: &CStr, type_id: i32, data: &CStr) -> bool {
    // SAFETY: the caller supplies the otherwise-unexpressible stored lifetimes
    // and disposal contract for both strings.
    unsafe { ffi::OBJ_NAME_add(name.as_ptr(), type_id, data.as_ptr()) == 1 }
}

/// Wraps: OBJ_NAME_cleanup
///
/// # Safety
/// No C or Rust code may concurrently traverse or use entries in the selected
/// class. A negative class tears down the complete process-global registry.
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_cleanup(type_id: i32) {
    // SAFETY: the caller excludes all registry users invalidated by cleanup.
    unsafe { ffi::OBJ_NAME_cleanup(type_id) }
}

/// Wraps: OBJ_NAME_new_index
/// Allocates a new object-name class and installs optional static callbacks.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_NAME_new_index(
    hash: Option<ObjNameHashCallback>,
    compare: Option<ObjNameCompareCallback>,
    free: Option<ObjNameFreeCallback>,
) -> Option<i32> {
    // SAFETY: callback wrappers establish their stored static contracts.
    let index = unsafe {
        ffi::OBJ_NAME_new_index(
            hash.map(|callback| callback.0),
            compare.map(|callback| callback.0),
            free.map(|callback| callback.0),
        )
    };
    (index > 0).then_some(index)
}

/// Wraps: OBJ_NAME_remove
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_NAME_remove(name: &CStr, type_id: i32) -> bool {
    // SAFETY: the string is live for the lookup; OpenSSL synchronizes removal
    // and invokes any registered static disposer before returning.
    unsafe { ffi::OBJ_NAME_remove(name.as_ptr(), type_id) == 1 }
}

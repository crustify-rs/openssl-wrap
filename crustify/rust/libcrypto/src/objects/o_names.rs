//! Wrappers assigned from `crypto/objects/o_names.c`.

use core::ffi::{CStr, c_void};
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use super::openssl_objects::ObjNameRef;

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

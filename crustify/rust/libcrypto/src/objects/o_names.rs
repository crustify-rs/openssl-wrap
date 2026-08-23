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

/// An opaque, registry-owned payload: what `OBJ_NAME_get` returns, and what
/// the `data` slot of a non-alias [`ObjNameRef`] holds.
pub struct ObjNameValue<'a> {
    ptr: NonNull<c_void>,
    marker: PhantomData<&'a ()>,
}

impl<'a> ObjNameValue<'a> {
    /// Builds a payload view over a registry pointer.
    ///
    /// Crate-internal: `'a` is chosen by the caller, which must bind it to the
    /// borrow the pointer was read through — the registry lookup, or the
    /// [`ObjNameRef`] handle owning the field.
    pub(crate) fn from_ptr(ptr: NonNull<c_void>) -> Self {
        Self {
            ptr,
            marker: PhantomData,
        }
    }

    /// The erased pointer, for storing the payload back into an entry.
    pub(crate) fn as_non_null(&self) -> NonNull<c_void> {
        self.ptr
    }

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
/// Looks up an opaque payload. The borrow only prevents treating the result as
/// owned data; it does not track how long the registry entry stays installed,
/// which is the obligation [`ObjNameValue::cast`] states.
#[must_use]
#[allow(non_snake_case)]
pub fn OBJ_NAME_get(name: &CStr, type_id: i32) -> Option<ObjNameValue<'_>> {
    // SAFETY: `name` is a live immutable C string. The returned registry
    // pointer remains opaque and cannot be dereferenced through this safe API.
    let raw = unsafe { ffi::OBJ_NAME_get(name.as_ptr(), type_id) };
    NonNull::new(raw.cast_mut().cast()).map(ObjNameValue::from_ptr)
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
///
/// Replacing an existing entry invokes the class disposal callback, which
/// OpenSSL calls without a null check. When this call replaces an entry, the
/// class must therefore have been created with a disposal callback.
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
///
/// Cleanup removes every selected entry, and OpenSSL invokes each entry's
/// class disposal callback without a null check, so every class reached here
/// must have been created with one.
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_cleanup(type_id: i32) {
    // SAFETY: the caller excludes all registry users invalidated by cleanup.
    unsafe { ffi::OBJ_NAME_cleanup(type_id) }
}

/// Wraps: OBJ_NAME_new_index
/// Allocates a new object-name class and installs optional static callbacks.
///
/// Passing `free = None` leaves the class without a disposal callback. OpenSSL
/// calls that callback unconditionally when an entry of the class is replaced
/// or removed, so a class created this way must never reach
/// [`OBJ_NAME_add`]'s replacement path, [`OBJ_NAME_remove`], or
/// [`OBJ_NAME_cleanup`]. Creating any class also extends the callback table
/// over the built-in classes, which have no disposer either.
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
///
/// # Safety
/// When an entry is found, OpenSSL calls the class disposal callback without
/// checking it for null, so `type_id` must name a class created with one. The
/// built-in classes and any class created through [`OBJ_NAME_new_index`] with
/// `free = None` have no disposer, and removing an entry from those calls a
/// null function pointer.
///
/// The disposal callback also runs against the stored `name`/`data` pointers,
/// so it must own exactly what [`OBJ_NAME_add`] recorded for this entry.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_remove(name: &CStr, type_id: i32) -> bool {
    // SAFETY: the string is live for the lookup; the caller guarantees the
    // class has a disposal callback matching the entry's stored pointers.
    unsafe { ffi::OBJ_NAME_remove(name.as_ptr(), type_id) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_is_idempotent() {
        assert!(OBJ_NAME_init());
        assert!(OBJ_NAME_init());
    }

    #[test]
    fn lookups_return_the_registered_opaque_payload() {
        let class = OBJ_NAME_new_index(None, None, None).expect("object-name class");
        // SAFETY: both strings are `'static` literals, so they outlive the
        // entry. The test never replaces, removes or cleans up this entry, so
        // the class needs no disposal callback.
        assert!(unsafe { OBJ_NAME_add(c"crustify-review-name", class, c"crustify-review-data") });

        let value = OBJ_NAME_get(c"crustify-review-name", class).expect("registered payload");
        // SAFETY: the entry added above is still installed, and its payload is
        // the `c"crustify-review-data"` literal — a live NUL-terminated string.
        let payload = unsafe { CStr::from_ptr(value.cast::<core::ffi::c_char>().as_ptr()) };
        assert_eq!(payload, c"crustify-review-data");

        assert!(OBJ_NAME_get(c"crustify-review-absent", class).is_none());
    }
}

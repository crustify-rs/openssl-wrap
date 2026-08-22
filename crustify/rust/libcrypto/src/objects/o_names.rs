//! Wrappers assigned from `crypto/objects/o_names.c`.

use core::ffi::{CStr, c_void};
use core::marker::PhantomData;
use core::ptr::NonNull;

use libcrypto_sys as ffi;

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

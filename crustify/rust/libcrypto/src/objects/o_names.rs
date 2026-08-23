//! Wrappers assigned from `crypto/objects/o_names.c`.

use core::ffi::{CStr, c_char, c_void};
use core::marker::PhantomData;
use core::ptr::NonNull;
use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use super::openssl_objects::{ALIAS_FLAG, ObjNameData, ObjNameRef};

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

    /// Builds a payload view over a pointer that is about to be registered as
    /// an entry's [`ObjNameData::Value`].
    ///
    /// # Safety
    ///
    /// `'a` must not outlive the storage `ptr` addresses. The class the
    /// payload is registered under fixes its concrete type, so it must be the
    /// type every reader of that class casts it back to.
    #[must_use]
    pub unsafe fn from_raw(ptr: NonNull<c_void>) -> Self {
        Self::from_ptr(ptr)
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
/// Installs one entry, taking its `OBJ_NAME_ALIAS` discriminator from the
/// payload rather than from the class argument.
///
/// C spells both payload arms `const char *`, but only
/// [`ObjNameData::Alias`] is a string: a non-alias entry stores the class's
/// registered object, the way `EVP_add_cipher` stores a `const EVP_CIPHER *`.
/// Deriving the bit from `data` keeps the stored discriminator in step with
/// the slot it describes, exactly as
/// [`ObjNameMut::set_data`](super::openssl_objects::ObjNameMut::set_data)
/// does, so [`OBJ_NAME_get`] and [`ObjNameRef::data`] read it back the way it
/// was written. `type_id` therefore names only the class.
///
/// # Safety
/// `name` and the payload are stored without copying. They must remain live
/// and immutable until this entry is removed or its class is cleaned up, and
/// they must satisfy the registered class disposal callback's ownership
/// contract.
///
/// Replacing an existing entry invokes the class disposal callback, which
/// OpenSSL calls without a null check. When this call replaces an entry, the
/// class must therefore have been created with a disposal callback.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn OBJ_NAME_add(name: &CStr, type_id: i32, data: ObjNameData<'_>) -> bool {
    let (type_id, data): (i32, *const c_char) = match data {
        ObjNameData::Alias(target) => (type_id | ALIAS_FLAG, target.as_ptr()),
        ObjNameData::Value(payload) => (
            type_id & !ALIAS_FLAG,
            payload.as_non_null().as_ptr().cast_const().cast(),
        ),
    };
    // SAFETY: the caller supplies the otherwise-unexpressible stored lifetimes
    // and disposal contract for the name and the payload.
    unsafe { ffi::OBJ_NAME_add(name.as_ptr(), type_id, data) == 1 }
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
    use std::ffi::CString;
    use std::sync::{Mutex, PoisonError};

    use super::*;

    /// `OBJ_NAME_add` takes `obj_lock` but `OBJ_NAME_do_all` does not, so the
    /// tests that touch the process-global registry serialize against each
    /// other rather than relying on the harness thread schedule.
    static REGISTRY: Mutex<()> = Mutex::new(());

    /// A non-alias payload over a `'static` string, so the tests can read it
    /// back as one while it is still stored as an erased pointer.
    fn payload(value: &'static CStr) -> ObjNameData<'static> {
        // SAFETY: `value` is `'static` and the tests cast the payload back to
        // the `c_char` run it was registered from.
        ObjNameData::Value(unsafe {
            ObjNameValue::from_raw(NonNull::new(value.as_ptr().cast_mut().cast()).unwrap())
        })
    }

    #[test]
    fn initialization_is_idempotent() {
        assert!(OBJ_NAME_init());
        assert!(OBJ_NAME_init());
    }

    #[test]
    fn traversals_visit_one_class_and_the_sorted_form_orders_by_name() {
        let _registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let class = OBJ_NAME_new_index(None, None, None).expect("object-name class");
        for (name, data) in [
            (c"crustify-review-do-all-c", c"3"),
            (c"crustify-review-do-all-a", c"1"),
            (c"crustify-review-do-all-b", c"2"),
        ] {
            // SAFETY: both strings are `'static` literals, so they outlive the
            // entry. Nothing replaces, removes or cleans up these entries, so
            // the class needs no disposal callback.
            assert!(unsafe { OBJ_NAME_add(name, class, payload(data)) });
        }

        let mut visited = Vec::new();
        {
            let mut collect = |entry: ObjNameRef<'_>| {
                // The traversal filters by class before it reaches us.
                assert_eq!(entry.r#type(), class);
                visited.push(entry.name().expect("registered name").to_owned());
            };
            // SAFETY: the registry guard excludes every other mutator, and the
            // callback only reads the entries it is handed.
            unsafe { OBJ_NAME_do_all(class, &mut collect) };
        }
        assert_eq!(visited.len(), 3);

        let mut ordered = Vec::new();
        {
            let mut collect = |entry: ObjNameRef<'_>| {
                ordered.push(entry.name().expect("registered name").to_owned());
            };
            // SAFETY: as above.
            unsafe { OBJ_NAME_do_all_sorted(class, &mut collect) };
        }
        assert_eq!(
            ordered,
            [
                CString::from(c"crustify-review-do-all-a"),
                CString::from(c"crustify-review-do-all-b"),
                CString::from(c"crustify-review-do-all-c"),
            ]
        );

        // The unsorted form visits the same set in an unspecified order.
        visited.sort();
        assert_eq!(visited, ordered);
    }

    #[test]
    fn a_traversal_of_an_unpopulated_class_visits_nothing() {
        let _registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let class = OBJ_NAME_new_index(None, None, None).expect("object-name class");
        let mut visited = 0_usize;
        {
            let mut count = |_: ObjNameRef<'_>| visited += 1;
            // SAFETY: the registry guard excludes every other mutator.
            unsafe {
                OBJ_NAME_do_all(class, &mut count);
                OBJ_NAME_do_all_sorted(class, &mut count);
            }
        }
        assert_eq!(visited, 0);
    }

    #[test]
    fn lookups_return_the_registered_opaque_payload() {
        let _registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let class = OBJ_NAME_new_index(None, None, None).expect("object-name class");
        // SAFETY: both strings are `'static` literals, so they outlive the
        // entry. The test never replaces, removes or cleans up this entry, so
        // the class needs no disposal callback.
        assert!(unsafe {
            OBJ_NAME_add(
                c"crustify-review-name",
                class,
                payload(c"crustify-review-data"),
            )
        });

        let value = OBJ_NAME_get(c"crustify-review-name", class).expect("registered payload");
        // SAFETY: the entry added above is still installed, and its payload is
        // the `c"crustify-review-data"` literal — a live NUL-terminated string.
        let stored = unsafe { CStr::from_ptr(value.cast::<core::ffi::c_char>().as_ptr()) };
        assert_eq!(stored, c"crustify-review-data");

        assert!(OBJ_NAME_get(c"crustify-review-absent", class).is_none());
    }

    #[test]
    fn an_alias_entry_resolves_to_the_payload_it_names() {
        let _registry = REGISTRY.lock().unwrap_or_else(PoisonError::into_inner);
        let class = OBJ_NAME_new_index(None, None, None).expect("object-name class");
        // A payload that is not a C string at all: reading it as one would run
        // past its end. This is the shape `EVP_add_cipher` registers.
        static METHOD: [u8; 8] = [0xff; 8];
        let method = NonNull::from(&METHOD).cast::<c_void>();

        // SAFETY: `METHOD` is `'static`, so it outlives the entry, and nothing
        // replaces, removes or cleans up these entries.
        let stored = unsafe {
            let value = ObjNameValue::from_raw(method);
            OBJ_NAME_add(c"crustify-review-method", class, ObjNameData::Value(value))
                && OBJ_NAME_add(
                    c"crustify-review-method-alias",
                    class,
                    ObjNameData::Alias(c"crustify-review-method"),
                )
        };
        assert!(stored);

        // A lookup of the alias follows it to the aliased entry's payload, so
        // both names report the same erased pointer.
        for name in [c"crustify-review-method", c"crustify-review-method-alias"] {
            let value = OBJ_NAME_get(name, class).expect("registered payload");
            // SAFETY: the entries above are still installed and `METHOD` is
            // the byte array both of them resolve to.
            assert_eq!(unsafe { value.cast::<u8>() }, method.cast());
        }

        // The alias arm is only reachable through the discriminator: asking
        // for the alias entry itself hands back its target name instead.
        let raw =
            OBJ_NAME_get(c"crustify-review-method-alias", class | ALIAS_FLAG).expect("alias entry");
        // SAFETY: an alias entry's payload is the name literal stored above.
        let target = unsafe { CStr::from_ptr(raw.cast::<core::ffi::c_char>().as_ptr()) };
        assert_eq!(target, c"crustify-review-method");
    }
}

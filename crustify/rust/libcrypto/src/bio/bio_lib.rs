//! Wrappers assigned from `crypto/bio/bio_lib.c`.

use core::ffi::{c_long, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::CBox;
use libcrypto_sys as ffi;

use super::bio_bio_local::{Bio, BioMut};

/// Wraps: BIO_err_is_non_fatal
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_err_is_non_fatal(error_code: u32) -> bool {
    // SAFETY: the classifier takes only a by-value packed error code.
    unsafe { ffi::BIO_err_is_non_fatal(error_code) != 0 }
}

/// A shared, type-erased pointer whose lifetime is tied to a BIO handle.
#[derive(Clone, Copy, Debug)]
pub struct BioOpaqueRef<'a> {
    pointer: NonNull<c_void>,
    _borrow: PhantomData<&'a ()>,
}

impl BioOpaqueRef<'_> {
    /// Return the opaque pointer without changing its ownership.
    #[must_use]
    pub const fn as_ptr(self) -> *const c_void {
        self.pointer.as_ptr().cast_const()
    }
}

/// An exclusive, type-erased pointer whose lifetime is tied to a BIO handle.
#[derive(Debug)]
pub struct BioOpaqueMut<'a> {
    pointer: NonNull<c_void>,
    _borrow: PhantomData<&'a mut ()>,
}

impl BioOpaqueMut<'_> {
    /// Return the opaque writable pointer without changing its ownership.
    #[must_use]
    pub const fn as_mut_ptr(&mut self) -> *mut c_void {
        self.pointer.as_ptr()
    }

    /// Reborrow this pointer as a shared opaque view.
    #[must_use]
    pub const fn as_ref(&self) -> BioOpaqueRef<'_> {
        BioOpaqueRef {
            pointer: self.pointer,
            _borrow: PhantomData,
        }
    }
}

/// Wraps: BIO_clear_flags
#[allow(non_snake_case)]
pub fn BIO_clear_flags(bio: &mut BioMut<'_>, flags: i32) {
    // SAFETY: the exclusive handle supplies one live writable BIO.
    unsafe { ffi::BIO_clear_flags(bio.as_mut_ptr(), flags) }
}

/// Wraps: BIO_copy_next_retry
///
/// Returns `false` instead of calling C when the BIO has no next node.
#[allow(non_snake_case)]
pub fn BIO_copy_next_retry(bio: &mut BioMut<'_>) -> bool {
    // SAFETY: the exclusive handle supplies a live BIO for the link getter.
    let next = unsafe { ffi::BIO_next(bio.as_mut_ptr()) };
    if next.is_null() {
        return false;
    }
    // SAFETY: the exclusive handle is live and the check above establishes the
    // non-null next-node precondition required by BIO_copy_next_retry.
    unsafe { ffi::BIO_copy_next_retry(bio.as_mut_ptr()) }
    true
}

/// Wraps: BIO_ctrl
///
/// # Safety
/// `command`, `large_argument`, and `pointer_argument` must satisfy the
/// selected BIO method's command-specific pointer type, alignment, extent,
/// initialization, mutability, and lifetime contract.
#[allow(non_snake_case)]
pub unsafe fn BIO_ctrl(
    bio: Option<&mut BioMut<'_>>,
    command: i32,
    large_argument: c_long,
    pointer_argument: *mut c_void,
) -> c_long {
    let bio = bio.map_or(ptr::null_mut(), |bio| bio.as_mut_ptr());
    // SAFETY: the caller establishes the selected command's untyped payload
    // contract; the optional typed BIO handle is live for the call.
    unsafe { ffi::BIO_ctrl(bio, command, large_argument, pointer_argument) }
}

/// Wraps: BIO_ctrl_pending
#[allow(non_snake_case)]
pub fn BIO_ctrl_pending(bio: &mut BioMut<'_>) -> usize {
    // SAFETY: the exclusive handle supplies one live BIO for the control call.
    unsafe { ffi::BIO_ctrl_pending(bio.as_mut_ptr()) }
}

/// Wraps: BIO_ctrl_wpending
#[allow(non_snake_case)]
pub fn BIO_ctrl_wpending(bio: &mut BioMut<'_>) -> usize {
    // SAFETY: the exclusive handle supplies one live BIO for the control call.
    unsafe { ffi::BIO_ctrl_wpending(bio.as_mut_ptr()) }
}

/// Wraps: BIO_do_connect_retry
#[allow(non_snake_case)]
pub fn BIO_do_connect_retry(bio: &mut BioMut<'_>, timeout: i32, nap_milliseconds: i32) -> i32 {
    // SAFETY: the exclusive handle supplies one live BIO for the retry loop.
    unsafe { ffi::BIO_do_connect_retry(bio.as_mut_ptr(), timeout, nap_milliseconds) }
}

/// Wraps: BIO_eof
#[allow(non_snake_case)]
pub fn BIO_eof(bio: &mut BioMut<'_>) -> bool {
    // SAFETY: the exclusive handle supplies one live BIO for the control call.
    unsafe { ffi::BIO_eof(bio.as_mut_ptr()) != 0 }
}

/// Wraps: BIO_find_type
#[allow(non_snake_case)]
pub fn BIO_find_type<'a>(bio: &'a mut BioMut<'_>, bio_type: i32) -> Option<BioMut<'a>> {
    // SAFETY: the exclusive reborrow keeps the complete chain live and prevents
    // use of the originating handle while a returned node handle is live.
    let found = unsafe { ffi::BIO_find_type(bio.as_mut_ptr(), bio_type) };
    // SAFETY: a non-null result is a node of the exclusively borrowed input
    // chain and is therefore live and exclusive for `'a`.
    unsafe { BioMut::from_ptr(found) }
}

/// Wraps: BIO_free
#[allow(non_snake_case)]
pub fn BIO_free(bio: CBox<Bio>) -> bool {
    let raw = bio.into_raw();
    // SAFETY: consuming the owner transfers exactly one BIO reference to C.
    unsafe { ffi::BIO_free(raw) != 0 }
}

/// Wraps: BIO_free_all
#[allow(non_snake_case)]
pub fn BIO_free_all(bio: CBox<Bio>) {
    let raw = bio.into_raw();
    // SAFETY: ownership of the chain head is transferred; OpenSSL consumes its
    // successive owned links until a shared reference stops the traversal.
    unsafe { ffi::BIO_free_all(raw) }
}

/// Wraps: BIO_get_callback_arg
#[allow(non_snake_case)]
pub fn BIO_get_callback_arg<'a>(bio: &'a mut BioMut<'_>) -> Option<BioOpaqueMut<'a>> {
    // SAFETY: the exclusive handle supplies one live BIO and prevents another
    // safe accessor from reaching its mutable application cookie concurrently.
    let pointer = unsafe { ffi::BIO_get_callback_arg(bio.as_mut_ptr()) };
    NonNull::new(pointer.cast()).map(|pointer| BioOpaqueMut {
        pointer,
        _borrow: PhantomData,
    })
}

/// Wraps: BIO_get_data
#[allow(non_snake_case)]
pub fn BIO_get_data<'a>(bio: &'a mut BioMut<'_>) -> Option<BioOpaqueMut<'a>> {
    // SAFETY: the exclusive handle supplies one live BIO and prevents another
    // safe accessor from reaching its type-erased method data concurrently.
    let pointer = unsafe { ffi::BIO_get_data(bio.as_mut_ptr()) };
    NonNull::new(pointer).map(|pointer| BioOpaqueMut {
        pointer,
        _borrow: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_null_bio() -> CBox<Bio> {
        // SAFETY: both constructors have no caller-side pointer obligations.
        let raw = unsafe { ffi::BIO_new(ffi::BIO_s_null()) };
        // SAFETY: a non-null result transfers one owned BIO reference.
        unsafe { CBox::from_raw(raw) }.expect("BIO_new")
    }

    #[test]
    fn flag_and_control_wrappers_use_exclusive_borrows() {
        let mut bio = new_null_bio();
        let mut view = bio.as_mut();
        BIO_clear_flags(&mut view, i32::MAX);
        assert!(BIO_eof(&mut view));
        assert_eq!(BIO_ctrl_pending(&mut view), 0);
        assert_eq!(BIO_ctrl_wpending(&mut view), 0);
        assert!(!BIO_copy_next_retry(&mut view));
        assert!(BIO_get_data(&mut view).is_none());
    }

    #[test]
    fn explicit_free_consumes_the_owner() {
        assert!(BIO_free(new_null_bio()));
    }
}

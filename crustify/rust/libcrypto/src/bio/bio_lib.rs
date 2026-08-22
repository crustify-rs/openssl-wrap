//! Wrappers assigned from `crypto/bio/bio_lib.c`.

use core::ffi::{CStr, c_long, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CType};
use libcrypto_sys as ffi;

use super::bio_bio_local::{Bio, BioMut, BioRef};
use super::context::OsslLibCtxRef;
use super::internal_bio::BioMethodRef;

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

/// A BIO owner whose method or context is borrowed for `'a`.
#[must_use = "dropping the owner releases its BIO reference"]
pub struct BorrowedBio<'a> {
    inner: CBox<Bio>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BorrowedBio<'_> {
    pub(crate) unsafe fn from_raw(raw: *mut ffi::BIO) -> Option<Self> {
        // SAFETY: the caller transfers one newly constructed BIO reference.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the BIO without write access.
    #[must_use]
    pub fn as_ref(&self) -> BioRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the BIO.
    #[must_use]
    pub fn as_mut(&mut self) -> BioMut<'_> {
        self.inner.as_mut()
    }
}

/// An opaque application-data pointer stored in a BIO.
#[derive(Clone, Copy)]
pub struct BioExData<'a> {
    ptr: NonNull<c_void>,
    borrow: PhantomData<&'a Bio>,
}

impl BioExData<'_> {
    /// Reinterpret the opaque application pointer.
    ///
    /// # Safety
    ///
    /// The stored value must point to a live, properly aligned `T` for the
    /// returned pointer's use. OpenSSL does not validate application data.
    #[must_use]
    pub unsafe fn cast<T>(self) -> NonNull<T> {
        self.ptr.cast()
    }
}

/// Wraps: BIO_get_ex_data
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_ex_data(bio: BioRef<'_>, index: i32) -> Option<BioExData<'_>> {
    // SAFETY: the shared handle keeps the BIO header live for this lookup.
    let raw = unsafe { ffi::BIO_get_ex_data(bio.as_ptr(), index) };
    NonNull::new(raw).map(|ptr| BioExData {
        ptr,
        borrow: PhantomData,
    })
}

/// Wraps: BIO_get_init
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_init(bio: BioRef<'_>) -> i32 {
    // SAFETY: the handle identifies a live BIO; this operation only reads its flag.
    unsafe { ffi::BIO_get_init(bio.as_ptr().cast_mut()) }
}

/// Wraps: BIO_get_line
/// Reads at most `buffer.len() - 1` bytes and writes a trailing NUL.
#[allow(non_snake_case)]
pub fn BIO_get_line(mut bio: BioMut<'_>, buffer: &mut [u8]) -> i32 {
    let Ok(size) = i32::try_from(buffer.len()) else {
        return -1;
    };
    // SAFETY: the exclusive BIO handle and mutable slice remain live for the
    // call; `size` is exactly the writable buffer length.
    unsafe { ffi::BIO_get_line(bio.as_mut_ptr(), buffer.as_mut_ptr().cast(), size) }
}

/// Wraps: BIO_get_retry_BIO
/// Returns the last retrying BIO in the chain and its retry reason.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_retry_BIO<'a>(bio: BioRef<'a>) -> (BioRef<'a>, i32) {
    let mut reason = 0;
    // SAFETY: this function only walks and reads the live chain rooted at
    // `bio`; the result is one of those nodes and remains borrowed from it.
    let raw = unsafe { ffi::BIO_get_retry_BIO(bio.as_ptr().cast_mut(), &mut reason) };
    // SAFETY: a non-null input makes the implementation return at least that
    // input node, all of which stay live for the input borrow.
    let retry = unsafe { BioRef::from_ptr(raw) }.expect("BIO_get_retry_BIO returned null");
    (retry, reason)
}

/// Wraps: BIO_get_retry_reason
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_retry_reason(bio: BioRef<'_>) -> i32 {
    // SAFETY: the live handle permits the implementation's scalar field read.
    unsafe { ffi::BIO_get_retry_reason(bio.as_ptr().cast_mut()) }
}

/// Wraps: BIO_get_shutdown
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_shutdown(bio: BioRef<'_>) -> i32 {
    // SAFETY: the handle identifies a live BIO; this operation only reads its flag.
    unsafe { ffi::BIO_get_shutdown(bio.as_ptr().cast_mut()) }
}

/// Wraps: BIO_gets
/// Reads a method-defined line or record into `buffer`.
#[allow(non_snake_case)]
pub fn BIO_gets(mut bio: BioMut<'_>, buffer: &mut [u8]) -> i32 {
    let Ok(size) = i32::try_from(buffer.len()) else {
        return -1;
    };
    // SAFETY: the exclusive BIO handle and mutable slice remain live for the
    // synchronous call; `size` is exactly the writable buffer length.
    unsafe { ffi::BIO_gets(bio.as_mut_ptr(), buffer.as_mut_ptr().cast(), size) }
}

/// Wraps: BIO_indent
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_indent(mut bio: BioMut<'_>, indent: i32, maximum: i32) -> bool {
    // SAFETY: the exclusive handle keeps the output BIO live while OpenSSL writes spaces.
    unsafe { ffi::BIO_indent(bio.as_mut_ptr(), indent, maximum) == 1 }
}

/// Wraps: BIO_int_ctrl
///
/// # Safety
///
/// `command` must be one whose BIO method interprets the control pointer as a
/// live `int`; choosing a command with a different pointer contract can make
/// the C method access the temporary integer with the wrong type or extent.
#[allow(non_snake_case)]
pub unsafe fn BIO_int_ctrl(mut bio: BioMut<'_>, command: i32, long_arg: i64, int_arg: i32) -> i64 {
    // SAFETY: OpenSSL creates the command's temporary integer argument itself;
    // the wrapper passes no untyped caller memory.
    unsafe { ffi::BIO_int_ctrl(bio.as_mut_ptr(), command, long_arg, int_arg) }
}

/// Wraps: BIO_method_name
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_method_name(bio: BioRef<'_>) -> &CStr {
    // SAFETY: a live BIO always has a live method whose immutable name is
    // NUL-terminated and remains valid for the BIO borrow.
    unsafe { CStr::from_ptr(ffi::BIO_method_name(bio.as_ptr())) }
}

/// Wraps: BIO_method_type
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_method_type(bio: BioRef<'_>) -> i32 {
    // SAFETY: the shared handle keeps the BIO and method table live.
    unsafe { ffi::BIO_method_type(bio.as_ptr()) }
}

/// Wraps: BIO_new
/// Constructs a BIO borrowing its method table for the owner's lifetime.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new<'a>(method: BioMethodRef<'a>) -> Option<BorrowedBio<'a>> {
    // SAFETY: the method handle is live and the returned owner is lifetime-tied
    // to it; the constructor returns one new BIO reference or null.
    unsafe { BorrowedBio::from_raw(ffi::BIO_new(method.as_ptr())) }
}

/// Wraps: BIO_new_ex
/// Constructs a BIO borrowing both its method and optional library context.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_new_ex<'a>(
    context: Option<OsslLibCtxRef<'a>>,
    method: BioMethodRef<'a>,
) -> Option<BorrowedBio<'a>> {
    let context = context.map_or(core::ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: non-null arguments are protected by `'a`; the returned owner
    // retains that lifetime and adopts the constructor's fresh reference.
    unsafe { BorrowedBio::from_raw(ffi::BIO_new_ex(context, method.as_ptr())) }
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
    #[test]
    fn scalar_queries_and_retry_view_use_borrowed_handles() {
        let bio = new_null_bio();
        assert_eq!(BIO_get_init(bio.as_ref()), 1);
        assert_eq!(BIO_get_shutdown(bio.as_ref()), 1);
        assert!(!BIO_method_name(bio.as_ref()).is_empty());

        let (retry, reason) = BIO_get_retry_BIO(bio.as_ref());
        assert_eq!(retry.as_ptr(), bio.as_ptr().cast_const());
        assert_eq!(reason, BIO_get_retry_reason(bio.as_ref()));
    }

    #[test]
    fn writable_operations_accept_bounded_slices() {
        let mut bio = new_null_bio();
        let mut line = [0_u8; 16];
        assert!(BIO_get_line(bio.as_mut(), &mut line) <= 0);
        assert!(BIO_gets(bio.as_mut(), &mut line) <= 0);
        assert!(BIO_indent(bio.as_mut(), 4, 2));
    }
}

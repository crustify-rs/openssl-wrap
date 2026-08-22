//! Wrappers assigned from `crypto/bio/bio_lib.c`.

use core::ffi::{CStr, c_long, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use ffibox::{CBox, CBoxWith, CDropper, CSliceMut, CType};
use libcrypto_sys as ffi;

use super::bio_bio_local::{Bio, BioMut, BioRef};
use super::context::OsslLibCtxRef;
use super::internal_bio::BioMethodRef;
use super::openssl_bio::{BioCallbackFnEx, BioInfoCallback, BioMsg, BioPollDescriptorMut};

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

/// Wraps: BIO_next
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_next<'a>(bio: &BioRef<'a>) -> Option<BioRef<'a>> {
    // SAFETY: `bio` is live for `'a`; OpenSSL returns either its linked
    // successor (which the chain keeps live) or null.
    let next = unsafe { ffi::BIO_next(bio.as_ptr().cast_mut()) };
    // SAFETY: the chain relationship ties a non-null successor to `bio`.
    unsafe { BioRef::from_ptr(next) }
}

/// Wraps: BIO_number_read
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_number_read(bio: &BioRef<'_>) -> u64 {
    // SAFETY: `bio` supplies a live BIO for a read-only counter query.
    unsafe { ffi::BIO_number_read(bio.as_ptr().cast_mut()) }
}

/// Wraps: BIO_number_written
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_number_written(bio: &BioRef<'_>) -> u64 {
    // SAFETY: `bio` supplies a live BIO for a read-only counter query.
    unsafe { ffi::BIO_number_written(bio.as_ptr().cast_mut()) }
}

/// Wraps: BIO_pop
///
/// # Safety
/// The caller must own or otherwise keep the returned remainder of the chain
/// alive for the lifetime of the returned handle.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn BIO_pop<'a>(bio: &'a mut BioMut<'_>) -> Option<BioMut<'a>> {
    // SAFETY: `bio` is exclusive and the caller upholds ownership of the
    // detached remainder.
    let next = unsafe { ffi::BIO_pop(bio.as_mut_ptr()) };
    // SAFETY: a non-null result is the live detached successor and the caller
    // guarantees its lifetime.
    unsafe { BioMut::from_ptr(next) }
}

/// Wraps: BIO_ptr_ctrl
///
/// # Safety
/// `T`, the command, and the requested lifetime must match the pointer-valued
/// control operation implemented by this BIO. The pointee must remain live and
/// suitably aligned while the result is used.
#[must_use]
#[allow(non_snake_case)]
pub unsafe fn BIO_ptr_ctrl<T>(
    bio: &mut BioMut<'_>,
    command: i32,
    argument: core::ffi::c_long,
) -> Option<NonNull<T>> {
    // SAFETY: `bio` is exclusive; the caller supplies the command-specific
    // type and validity contract.
    NonNull::new(unsafe { ffi::BIO_ptr_ctrl(bio.as_mut_ptr(), command, argument) }.cast())
}

/// Wraps: BIO_push
///
/// # Safety
/// `append` must remain live until it is detached from `head`, and the caller
/// must prevent either linked BIO from being independently freed meanwhile.
#[allow(non_snake_case)]
pub unsafe fn BIO_push(head: &mut BioMut<'_>, append: &mut BioMut<'_>) -> bool {
    // SAFETY: both handles are exclusive and the caller guarantees the stored
    // cross-object lifetime and chain ownership rules.
    !unsafe { ffi::BIO_push(head.as_mut_ptr(), append.as_mut_ptr()) }.is_null()
}

/// Wraps: BIO_puts
#[allow(non_snake_case)]
pub fn BIO_puts(bio: &mut BioMut<'_>, text: &CStr) -> i32 {
    // SAFETY: `bio` is exclusive and `text` is a live NUL-terminated input.
    unsafe { ffi::BIO_puts(bio.as_mut_ptr(), text.as_ptr()) }
}

/// Wraps: BIO_read
#[allow(non_snake_case)]
pub fn BIO_read(bio: &mut BioMut<'_>, output: &mut [u8]) -> i32 {
    let len = output.len().min(i32::MAX as usize) as i32;
    // SAFETY: `bio` is exclusive and `output` provides `len` writable bytes.
    unsafe { ffi::BIO_read(bio.as_mut_ptr(), output.as_mut_ptr().cast(), len) }
}

/// Wraps: BIO_read_ex
#[allow(non_snake_case)]
pub fn BIO_read_ex(bio: &mut BioMut<'_>, output: &mut [u8]) -> Option<usize> {
    let mut read = 0;
    // SAFETY: `bio` is exclusive, `output` supplies its declared writable
    // length, and `read` is a live scalar output slot.
    let ok = unsafe {
        ffi::BIO_read_ex(
            bio.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
            &mut read,
        )
    };
    (ok != 0).then_some(read)
}

/// Wraps: BIO_set_callback_arg
///
/// # Safety
/// `argument` is stored without ownership. A non-null pointee must remain live
/// until the callback argument is replaced or the BIO is freed.
#[allow(non_snake_case)]
pub unsafe fn BIO_set_callback_arg<T>(bio: &mut BioMut<'_>, argument: Option<NonNull<T>>) {
    // SAFETY: `bio` is exclusive and the caller guarantees the stored
    // argument's lifetime.
    unsafe {
        ffi::BIO_set_callback_arg(
            bio.as_mut_ptr(),
            argument.map_or(core::ptr::null_mut(), |p| p.as_ptr().cast()),
        )
    }
}

/// Wraps: BIO_set_data
///
/// # Safety
/// `data` is stored without ownership. A non-null pointee must satisfy the
/// selected BIO method's type, lifetime, and teardown contract.
#[allow(non_snake_case)]
pub unsafe fn BIO_set_data<T>(bio: &mut BioMut<'_>, data: Option<NonNull<T>>) {
    // SAFETY: `bio` is exclusive and the caller upholds the method-specific
    // stored-data contract.
    unsafe {
        ffi::BIO_set_data(
            bio.as_mut_ptr(),
            data.map_or(core::ptr::null_mut(), |p| p.as_ptr().cast()),
        )
    }
}

/// Wraps: BIO_set_ex_data
///
/// # Safety
/// OpenSSL stores `data` without a Rust lifetime. Its type, lifetime, and any
/// registered ex-data cleanup callback must agree for `index`.
#[allow(non_snake_case)]
pub unsafe fn BIO_set_ex_data<T>(
    bio: &mut BioMut<'_>,
    index: i32,
    data: Option<NonNull<T>>,
) -> bool {
    // SAFETY: `bio` is exclusive and the caller upholds the indexed ex-data
    // contract.
    unsafe {
        ffi::BIO_set_ex_data(
            bio.as_mut_ptr(),
            index,
            data.map_or(core::ptr::null_mut(), |p| p.as_ptr().cast::<c_void>()),
        ) != 0
    }
}

/// Wraps: BIO_set_flags
#[allow(non_snake_case)]
pub fn BIO_set_flags(bio: &mut BioMut<'_>, flags: i32) {
    // SAFETY: `bio` is exclusive and flags are a by-value bit mask.
    unsafe { ffi::BIO_set_flags(bio.as_mut_ptr(), flags) }
}

/// Wraps: BIO_set_init
#[allow(non_snake_case)]
pub fn BIO_set_init(bio: &mut BioMut<'_>, initialized: bool) {
    // SAFETY: `bio` is exclusive and the state is a scalar.
    unsafe { ffi::BIO_set_init(bio.as_mut_ptr(), i32::from(initialized)) }
}

/// Wraps: BIO_set_next
///
/// # Safety
/// A non-null `next` is stored without increasing its reference count. It must
/// remain live until replaced or detached, and linked BIOs must not be freed
/// independently.
#[allow(non_snake_case)]
pub unsafe fn BIO_set_next(bio: &mut BioMut<'_>, next: Option<&mut BioMut<'_>>) {
    // SAFETY: `bio` is exclusive and the caller guarantees the stored link's
    // lifetime and ownership discipline.
    unsafe {
        ffi::BIO_set_next(
            bio.as_mut_ptr(),
            next.map_or(core::ptr::null_mut(), BioMut::as_mut_ptr),
        )
    }
}

/// Wraps: BIO_set_retry_reason
#[allow(non_snake_case)]
pub fn BIO_set_retry_reason(bio: &mut BioMut<'_>, reason: i32) {
    // SAFETY: `bio` is exclusive and `reason` is a scalar.
    unsafe { ffi::BIO_set_retry_reason(bio.as_mut_ptr(), reason) }
}

/// Wraps: BIO_set_send_flags
#[allow(non_snake_case)]
pub fn BIO_set_send_flags(bio: &mut BioMut<'_>, flags: i32) -> core::ffi::c_long {
    // SAFETY: `bio` is exclusive and flags are a by-value bit mask.
    unsafe { ffi::BIO_set_send_flags(bio.as_mut_ptr(), flags) }
}

/// Wraps: BIO_set_shutdown
#[allow(non_snake_case)]
pub fn BIO_set_shutdown(bio: &mut BioMut<'_>, shutdown: bool) {
    // SAFETY: `bio` is exclusive and the state is a scalar.
    unsafe { ffi::BIO_set_shutdown(bio.as_mut_ptr(), i32::from(shutdown)) }
}

/// Wraps: BIO_test_flags
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_test_flags(bio: &BioRef<'_>, flags: i32) -> i32 {
    // SAFETY: `bio` is live and the operation only reads its flags.
    unsafe { ffi::BIO_test_flags(bio.as_ptr(), flags) }
}

/// Wraps: BIO_up_ref
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_up_ref(bio: &BioRef<'_>) -> Option<CBox<Bio>> {
    // SAFETY: `bio` is a live reference; success creates one independently
    // owned count settled by `CBox<Bio>`'s destructor.
    if unsafe { ffi::BIO_up_ref(bio.as_ptr().cast_mut()) } == 0 {
        None
    } else {
        // SAFETY: the successful increment transferred one BIO reference.
        unsafe { CBox::from_raw(bio.as_ptr().cast_mut()) }
    }
}

/// Wraps: BIO_vfree
#[allow(non_snake_case)]
pub fn BIO_vfree(bio: Option<CBox<Bio>>) {
    drop(bio);
}

/// Wraps: BIO_wait
#[allow(non_snake_case)]
pub fn BIO_wait(bio: &mut BioMut<'_>, max_time: ffi::time_t, nap_milliseconds: u32) -> i32 {
    // SAFETY: `bio` is exclusive and the remaining arguments are scalars.
    unsafe { ffi::BIO_wait(bio.as_mut_ptr(), max_time, nap_milliseconds) }
}

/// Wraps: BIO_write
#[allow(non_snake_case)]
pub fn BIO_write(bio: &mut BioMut<'_>, input: &[u8]) -> i32 {
    let len = input.len().min(i32::MAX as usize) as i32;
    // SAFETY: `bio` is exclusive and `input` supplies `len` readable bytes.
    unsafe { ffi::BIO_write(bio.as_mut_ptr(), input.as_ptr().cast(), len) }
}

/// Wraps: BIO_write_ex
#[allow(non_snake_case)]
pub fn BIO_write_ex(bio: &mut BioMut<'_>, input: &[u8]) -> Option<usize> {
    let mut written = 0;
    // SAFETY: `bio` is exclusive, `input` supplies its declared readable
    // length, and `written` is a live scalar output slot.
    let ok = unsafe {
        ffi::BIO_write_ex(
            bio.as_mut_ptr(),
            input.as_ptr().cast(),
            input.len(),
            &mut written,
        )
    };
    (ok != 0).then_some(written)
}

#[cfg(test)]
mod scheduled_tests {
    use super::*;
    use crate::bio::bss_null::BIO_s_null;

    fn null_bio() -> CBox<Bio> {
        let method = BIO_s_null().expect("null method");
        // SAFETY: `method` is a process-lifetime method table and BIO_new
        // returns a fresh fully constructed BIO or null.
        let raw = unsafe { ffi::BIO_new(method.as_ptr()) };
        // SAFETY: ownership of the fresh reference transfers to CBox.
        unsafe { CBox::from_raw(raw) }.expect("null BIO")
    }

    #[test]
    fn writes_update_counters_and_flags_round_trip() {
        let mut bio = null_bio();
        assert_eq!(BIO_write(&mut bio.as_mut(), b"hello"), 5);
        assert_eq!(BIO_number_written(&bio.as_ref()), 5);

        BIO_set_flags(&mut bio.as_mut(), 0x40);
        assert_eq!(BIO_test_flags(&bio.as_ref(), 0x40), 0x40);
    }

    #[test]
    fn up_ref_returns_an_independently_owned_count() {
        let bio = null_bio();
        let mut extra = BIO_up_ref(&bio.as_ref()).expect("reference increment");
        BIO_vfree(Some(bio));
        assert_eq!(BIO_write(&mut extra.as_mut(), b"x"), 1);
    }

    #[test]
    fn extended_callback_slot_round_trips_absence() {
        let mut bio = null_bio();
        BIO_set_callback_ex(&mut bio.as_mut(), None);
        assert!(BIO_get_callback_ex(bio.as_ref()).is_none());
    }
}

/// Wraps: BIO_callback_ctrl
/// Installs a legacy information callback through the method control hook.
#[allow(non_snake_case)]
pub fn BIO_callback_ctrl(bio: &mut BioMut<'_>, callback: Option<BioInfoCallback>) -> c_long {
    // SAFETY: the BIO is exclusively borrowed and the only supported command
    // is selected here. Callback handles carry static compatible code pointers.
    unsafe {
        ffi::BIO_callback_ctrl(
            bio.as_mut_ptr(),
            ffi::BIO_CTRL_SET_CALLBACK as i32,
            callback.and_then(BioInfoCallback::as_raw),
        )
    }
}

/// Wraps: BIO_get_callback_ex
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_callback_ex(bio: BioRef<'_>) -> Option<BioCallbackFnEx> {
    // SAFETY: callbacks stored in a valid BIO obey OpenSSL's extended callback
    // contract; the shared handle is live for this field getter.
    unsafe { BioCallbackFnEx::from_raw(ffi::BIO_get_callback_ex(bio.as_ptr())) }
}

/// Wraps: BIO_get_rpoll_descriptor
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_rpoll_descriptor(
    bio: &mut BioMut<'_>,
    descriptor: &mut BioPollDescriptorMut<'_>,
) -> bool {
    // SAFETY: both exclusive handles supply initialized writable storage for
    // the synchronous control operation.
    unsafe { ffi::BIO_get_rpoll_descriptor(bio.as_mut_ptr(), descriptor.as_mut_ptr()) > 0 }
}

/// Wraps: BIO_get_wpoll_descriptor
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_wpoll_descriptor(
    bio: &mut BioMut<'_>,
    descriptor: &mut BioPollDescriptorMut<'_>,
) -> bool {
    // SAFETY: as `BIO_get_rpoll_descriptor`, for the write descriptor.
    unsafe { ffi::BIO_get_wpoll_descriptor(bio.as_mut_ptr(), descriptor.as_mut_ptr()) > 0 }
}

/// Wraps: BIO_recvmmsg
/// Receives into a tightly packed run of initialized message descriptors.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_recvmmsg(
    bio: &mut BioMut<'_>,
    messages: &mut CSliceMut<'_, BioMsg>,
    flags: u64,
) -> Option<usize> {
    let mut processed = 0;
    // SAFETY: the BIO and message run are exclusive, the exact descriptor
    // stride and count describe the contiguous run, and the output slot lives.
    let ok = unsafe {
        ffi::BIO_recvmmsg(
            bio.as_mut_ptr(),
            messages.as_ptr(),
            core::mem::size_of::<ffi::BIO_MSG>(),
            messages.len(),
            flags,
            &mut processed,
        )
    };
    (ok > 0).then_some(processed)
}

/// Wraps: BIO_sendmmsg
/// Sends a tightly packed run of initialized message descriptors.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_sendmmsg(
    bio: &mut BioMut<'_>,
    messages: &mut CSliceMut<'_, BioMsg>,
    flags: u64,
) -> Option<usize> {
    let mut processed = 0;
    // SAFETY: as `BIO_recvmmsg`; the send method receives the same in/out
    // descriptor layout and live processed-count slot.
    let ok = unsafe {
        ffi::BIO_sendmmsg(
            bio.as_mut_ptr(),
            messages.as_ptr(),
            core::mem::size_of::<ffi::BIO_MSG>(),
            messages.len(),
            flags,
            &mut processed,
        )
    };
    (ok > 0).then_some(processed)
}

/// Wraps: BIO_set_callback_ex
#[allow(non_snake_case)]
pub fn BIO_set_callback_ex(bio: &mut BioMut<'_>, callback: Option<BioCallbackFnEx>) {
    // SAFETY: the BIO is exclusively borrowed and callback handles carry
    // static code pointers satisfying OpenSSL's extended callback ABI.
    unsafe {
        ffi::BIO_set_callback_ex(bio.as_mut_ptr(), callback.and_then(BioCallbackFnEx::as_raw))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct BioFreeAll;

// SAFETY: `BIO_free_all` accepts a uniquely owned chain head and releases each
// successive owned link, stopping when a shared reference retains a node.
unsafe impl CDropper<Bio> for BioFreeAll {
    unsafe fn c_drop(&self, chain: NonNull<Bio>) {
        // SAFETY: the strategy contract transfers the complete uniquely owned
        // chain represented by this head to OpenSSL's chain destructor.
        unsafe { ffi::BIO_free_all(chain.as_ptr().cast()) }
    }
}

/// An owned BIO chain whose duplicated state may borrow from another chain.
#[must_use = "dropping the owner releases the complete BIO chain"]
pub struct BioChain<'a> {
    inner: CBoxWith<Bio, BioFreeAll>,
    borrow: PhantomData<&'a CType<c_void>>,
}

impl BioChain<'_> {
    unsafe fn from_raw(raw: *mut ffi::BIO) -> Option<Self> {
        // SAFETY: the caller transfers the head of one newly constructed chain
        // whose links must collectively be released with `BIO_free_all`.
        unsafe { CBoxWith::from_raw(raw, BioFreeAll) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the chain head without write access.
    #[must_use]
    pub fn as_ref(&self) -> BioRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the chain head.
    #[must_use]
    pub fn as_mut(&mut self) -> BioMut<'_> {
        self.inner.as_mut()
    }
}

/// Wraps: BIO_dup_chain
///
/// Deep-copies every node. The returned owner remains lifetime-bound to the
/// input because BIO methods, callback arguments, and application data may
/// retain shared state even after their duplication callbacks run.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_dup_chain<'a>(input: Option<&mut BioMut<'a>>) -> Option<BioChain<'a>> {
    let input = input.map_or(ptr::null_mut(), |input| input.as_mut_ptr());
    // SAFETY: a non-null input is exclusively borrowed for the operation. The
    // returned chain adopts OpenSSL's fresh ownership and cannot outlive state
    // reachable through the input chain.
    let duplicate = unsafe { ffi::BIO_dup_chain(input) };
    // SAFETY: a non-null result is a newly allocated, fully constructed chain
    // transferred to the caller and requiring `BIO_free_all` for teardown.
    unsafe { BioChain::from_raw(duplicate) }
}

#[cfg(test)]
mod dup_chain_tests {
    use super::*;

    fn new_null_bio() -> CBox<Bio> {
        let method = super::super::bss_null::BIO_s_null().expect("null method");
        // SAFETY: the process-lifetime method descriptor is live and the
        // constructor returns one fresh BIO reference or null.
        let raw = unsafe { ffi::BIO_new(method.as_ptr()) };
        // SAFETY: ownership of the fresh BIO reference transfers to this owner.
        unsafe { CBox::from_raw(raw) }.expect("BIO_new")
    }

    fn new_two_node_chain() -> BioChain<'static> {
        let head = new_null_bio();
        let tail = new_null_bio();
        let tail = tail.into_raw();
        // SAFETY: both BIOs are uniquely owned and live; ownership of `tail`
        // becomes part of the chain rooted at `head`.
        let linked = unsafe { ffi::BIO_push(head.as_ptr(), tail) };
        assert_eq!(linked, head.as_ptr());
        let head = head.into_raw();
        // SAFETY: the complete linked chain is now transferred to one owner.
        unsafe { BioChain::from_raw(head) }.expect("non-null chain")
    }

    #[test]
    fn duplicates_and_owns_the_complete_chain() {
        assert!(BIO_dup_chain(None).is_none());

        let mut source = new_two_node_chain();
        let source_head = source.as_ref().as_ptr();
        let source_tail = BIO_next(&source.as_ref()).expect("source tail").as_ptr();

        let mut source_handle = source.as_mut();
        let duplicate = BIO_dup_chain(Some(&mut source_handle)).expect("BIO_dup_chain");
        let duplicate_head = duplicate.as_ref();
        let duplicate_tail = BIO_next(&duplicate_head).expect("duplicate tail");

        assert_ne!(duplicate_head.as_ptr(), source_head);
        assert_ne!(duplicate_tail.as_ptr(), source_tail);
        assert!(BIO_next(&duplicate_tail).is_none());
    }
}

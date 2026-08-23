//! Wrappers assigned from `crypto/bio/bio_meth.c`.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;

use ffibox::{CBox, CSliceMut};
use libcrypto_sys as ffi;

use super::bio_bio_local::BioMut;
use super::internal_bio::{BioMethod, BioMethodMut};
use super::openssl_bio::{BioInfoCallback, BioMsg};

type RawWrite = unsafe extern "C" fn(*mut ffi::BIO, *const c_char, c_int) -> c_int;
type RawWriteEx = unsafe extern "C" fn(*mut ffi::BIO, *const c_char, usize, *mut usize) -> c_int;
type RawRead = unsafe extern "C" fn(*mut ffi::BIO, *mut c_char, c_int) -> c_int;
type RawReadEx = unsafe extern "C" fn(*mut ffi::BIO, *mut c_char, usize, *mut usize) -> c_int;
type RawPuts = unsafe extern "C" fn(*mut ffi::BIO, *const c_char) -> c_int;
type RawGets = unsafe extern "C" fn(*mut ffi::BIO, *mut c_char, c_int) -> c_int;
type RawCtrl = unsafe extern "C" fn(*mut ffi::BIO, c_int, c_long, *mut c_void) -> c_long;
type RawCreate = unsafe extern "C" fn(*mut ffi::BIO) -> c_int;
type RawDestroy = unsafe extern "C" fn(*mut ffi::BIO) -> c_int;
type RawCallbackCtrl = unsafe extern "C" fn(*mut ffi::BIO, c_int, ffi::BIO_info_cb) -> c_long;
type RawMmsg =
    unsafe extern "C" fn(*mut ffi::BIO, *mut ffi::BIO_MSG, usize, usize, u64, *mut usize) -> c_int;

macro_rules! callback_handle {
    ($name:ident, $raw:ty) => {
        #[derive(Clone, Copy)]
        pub struct $name($raw);

        impl $name {
            /// Adopts a raw callback that obeys the corresponding BIO method contract.
            ///
            /// # Safety
            ///
            /// The callback must obey OpenSSL's argument, buffer, return-value,
            /// unwinding, and thread-safety requirements whenever C invokes it.
            #[must_use]
            pub unsafe fn from_raw(callback: $raw) -> Self {
                Self(callback)
            }

            pub(crate) const fn raw(self) -> $raw {
                self.0
            }
        }
    };
}

callback_handle!(BioMethodWriteCallback, RawWrite);
callback_handle!(BioMethodWriteExCallback, RawWriteEx);
callback_handle!(BioMethodReadCallback, RawRead);
callback_handle!(BioMethodReadExCallback, RawReadEx);
callback_handle!(BioMethodPutsCallback, RawPuts);
callback_handle!(BioMethodGetsCallback, RawGets);
callback_handle!(BioMethodCtrlCallback, RawCtrl);
callback_handle!(BioMethodCreateCallback, RawCreate);
callback_handle!(BioMethodDestroyCallback, RawDestroy);
callback_handle!(BioMethodCallbackCtrl, RawCallbackCtrl);

/// Callable handle for the sendmmsg/recvmmsg BIO method slots.
#[derive(Clone, Copy)]
pub struct BioMethodMmsgCallback(RawMmsg);

impl BioMethodMmsgCallback {
    /// Adopts a callback obeying the BIO multi-message method contract.
    ///
    /// # Safety
    /// The callback must accept every well-formed BIO/message run supplied to
    /// this method slot, initialize `msgs_processed`, and must not unwind.
    #[must_use]
    pub unsafe fn from_raw(raw: Option<RawMmsg>) -> Option<Self> {
        raw.map(Self)
    }

    const fn raw(self) -> RawMmsg {
        self.0
    }

    /// Calls the method on a tightly packed run of message descriptors.
    #[must_use]
    pub fn call(
        self,
        bio: &mut BioMut<'_>,
        messages: &mut CSliceMut<'_, BioMsg<'_>>,
        flags: u64,
    ) -> Option<usize> {
        let mut processed = 0;
        // SAFETY: the callback contract, exclusive BIO, contiguous initialized
        // message run, exact stride, and live output slot satisfy the raw ABI.
        let ok = unsafe {
            (self.0)(
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
}

impl BioMethodWriteCallback {
    /// Invoke the method callback with a readable byte buffer.
    pub fn call(self, mut bio: BioMut<'_>, data: &[u8]) -> i32 {
        let Ok(length) = i32::try_from(data.len()) else {
            return -1;
        };
        // SAFETY: this handle's construction contract and the typed operands
        // establish the raw callback's BIO and buffer requirements.
        unsafe { (self.0)(bio.as_mut_ptr(), data.as_ptr().cast(), length) }
    }
}

impl BioMethodWriteExCallback {
    /// Invoke the extended write callback, returning status and byte count.
    pub fn call(self, mut bio: BioMut<'_>, data: &[u8]) -> (i32, usize) {
        let mut written = 0;
        // SAFETY: the callback contract, live BIO, readable slice, and output
        // slot satisfy the C signature for this synchronous invocation.
        let status = unsafe {
            (self.0)(
                bio.as_mut_ptr(),
                data.as_ptr().cast(),
                data.len(),
                &mut written,
            )
        };
        (status, written)
    }
}

impl BioMethodReadCallback {
    /// Invoke the method callback with a writable initialized buffer.
    pub fn call(self, mut bio: BioMut<'_>, buffer: &mut [u8]) -> i32 {
        let Ok(length) = i32::try_from(buffer.len()) else {
            return -1;
        };
        // SAFETY: the callback contract, live BIO, and writable slice satisfy
        // the raw signature for the synchronous call.
        unsafe { (self.0)(bio.as_mut_ptr(), buffer.as_mut_ptr().cast(), length) }
    }
}

impl BioMethodReadExCallback {
    /// Invoke the extended read callback, returning status and byte count.
    pub fn call(self, mut bio: BioMut<'_>, buffer: &mut [u8]) -> (i32, usize) {
        let mut read = 0;
        // SAFETY: the callback contract, live BIO, writable slice, and output
        // slot satisfy the C signature for this synchronous invocation.
        let status = unsafe {
            (self.0)(
                bio.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut read,
            )
        };
        (status, read)
    }
}

impl BioMethodPutsCallback {
    /// Invoke the callback with a NUL-terminated string.
    pub fn call(self, mut bio: BioMut<'_>, string: &CStr) -> i32 {
        // SAFETY: the callback contract and both live typed operands satisfy its signature.
        unsafe { (self.0)(bio.as_mut_ptr(), string.as_ptr()) }
    }
}

impl BioMethodGetsCallback {
    /// Invoke the line-input callback with a writable buffer.
    pub fn call(self, mut bio: BioMut<'_>, buffer: &mut [u8]) -> i32 {
        let Ok(length) = i32::try_from(buffer.len()) else {
            return -1;
        };
        // SAFETY: the callback contract and typed live operands satisfy its signature.
        unsafe { (self.0)(bio.as_mut_ptr(), buffer.as_mut_ptr().cast(), length) }
    }
}

impl BioMethodCtrlCallback {
    /// Invoke a command with an optional typed in/out argument.
    ///
    /// # Safety
    ///
    /// `command` must designate an operation whose pointer argument is exactly
    /// `T` with the supplied access mode and lifetime.
    pub unsafe fn call<T>(
        self,
        mut bio: BioMut<'_>,
        command: i32,
        long_arg: c_long,
        argument: Option<&mut T>,
    ) -> c_long {
        let argument = argument.map_or(ptr::null_mut(), |value| ptr::from_mut(value).cast());
        // SAFETY: the caller establishes the command-to-argument contract.
        unsafe { (self.0)(bio.as_mut_ptr(), command, long_arg, argument) }
    }
}

impl BioMethodCreateCallback {
    /// Invoke a method's construction hook.
    ///
    /// # Safety
    ///
    /// The BIO must be in the construction phase expected by this method.
    pub unsafe fn call(self, mut bio: BioMut<'_>) -> i32 {
        // SAFETY: the caller establishes the required construction phase.
        unsafe { (self.0)(bio.as_mut_ptr()) }
    }
}

impl BioMethodDestroyCallback {
    /// Invoke a method's destruction hook.
    ///
    /// # Safety
    ///
    /// The BIO must be in the destruction phase expected by this method, and
    /// the callback must not be invoked again for the same initialized state.
    pub unsafe fn call(self, mut bio: BioMut<'_>) -> i32 {
        // SAFETY: the caller establishes the required destruction phase.
        unsafe { (self.0)(bio.as_mut_ptr()) }
    }
}

impl BioMethodCallbackCtrl {
    /// Invoke the callback-control hook.
    pub fn call(
        self,
        mut bio: BioMut<'_>,
        command: i32,
        callback: Option<BioInfoCallback>,
    ) -> c_long {
        // SAFETY: all arguments use their typed handles and the raw callback
        // was validated when this callable handle was constructed.
        unsafe {
            (self.0)(
                bio.as_mut_ptr(),
                command,
                callback.and_then(BioInfoCallback::as_raw),
            )
        }
    }
}

/// Wraps: BIO_get_new_index
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_get_new_index() -> i32 {
    // SAFETY: the allocator has no caller-side memory obligations.
    unsafe { ffi::BIO_get_new_index() }
}

/// Wraps: BIO_meth_free
/// Releases a dynamically allocated method immediately.
#[allow(non_snake_case)]
pub fn BIO_meth_free(method: CBox<BioMethod>) {
    drop(method);
}

/// Wraps: BIO_meth_new
/// Creates an owned method whose name is copied by OpenSSL.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_new(method_type: i32, name: &CStr) -> Option<CBox<BioMethod>> {
    // SAFETY: the input string is live and NUL-terminated; a non-null result
    // transfers the fresh allocation to its matching RAII destructor.
    unsafe { CBox::from_raw(ffi::BIO_meth_new(method_type, name.as_ptr())) }
}

macro_rules! setter {
    ($(#[$meta:meta])* $name:ident, $callback:ty, $ffi_name:ident) => {
        $(#[$meta])*
        #[must_use]
        #[allow(non_snake_case)]
        pub fn $name(mut method: BioMethodMut<'_>, callback: Option<$callback>) -> bool {
            // SAFETY: the exclusive method handle permits updating this slot;
            // callback handles carry the corresponding static C contract.
            unsafe {
                ffi::$ffi_name(
                    method.as_mut_ptr(),
                    callback.map(|callback| callback.raw()),
                ) == 1
            }
        }
    };
}

setter!(
    /// Wraps: BIO_meth_set_callback_ctrl
    BIO_meth_set_callback_ctrl,
    BioMethodCallbackCtrl,
    BIO_meth_set_callback_ctrl
);
setter!(
    /// Wraps: BIO_meth_set_create
    BIO_meth_set_create,
    BioMethodCreateCallback,
    BIO_meth_set_create
);
setter!(
    /// Wraps: BIO_meth_set_ctrl
    BIO_meth_set_ctrl,
    BioMethodCtrlCallback,
    BIO_meth_set_ctrl
);
setter!(
    /// Wraps: BIO_meth_set_destroy
    BIO_meth_set_destroy,
    BioMethodDestroyCallback,
    BIO_meth_set_destroy
);
setter!(
    /// Wraps: BIO_meth_set_gets
    BIO_meth_set_gets,
    BioMethodGetsCallback,
    BIO_meth_set_gets
);
setter!(
    /// Wraps: BIO_meth_set_puts
    BIO_meth_set_puts,
    BioMethodPutsCallback,
    BIO_meth_set_puts
);
setter!(
    /// Wraps: BIO_meth_set_read_ex
    BIO_meth_set_read_ex,
    BioMethodReadExCallback,
    BIO_meth_set_read_ex
);
setter!(
    /// Wraps: BIO_meth_set_write_ex
    BIO_meth_set_write_ex,
    BioMethodWriteExCallback,
    BIO_meth_set_write_ex
);

/// Wraps: BIO_meth_set_read
/// Installs the legacy read callback the method's conversion thunk dispatches to.
///
/// The callback is mandatory. `BIO_meth_set_read` stores `bread_conv` in the
/// extended slot whatever it is passed, and that thunk calls this pointer
/// without checking it, so a null callback would leave a method table whose
/// first non-empty `BIO_read` calls a null function pointer. Clear the pair
/// with [`BIO_meth_set_read_ex(method, None)`](BIO_meth_set_read_ex) instead.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_set_read(mut method: BioMethodMut<'_>, callback: BioMethodReadCallback) -> bool {
    // SAFETY: the exclusive method handle permits updating this slot, and the
    // callback handle carries the static C contract the thunk dispatches under.
    unsafe { ffi::BIO_meth_set_read(method.as_mut_ptr(), Some(callback.raw())) == 1 }
}

/// Wraps: BIO_meth_set_write
/// Installs the legacy write callback the method's conversion thunk dispatches to.
///
/// The callback is mandatory. `BIO_meth_set_write` stores `bwrite_conv` in the
/// extended slot whatever it is passed, and that thunk calls this pointer
/// without checking it, so a null callback would leave a method table whose
/// first `BIO_write` calls a null function pointer. Clear the pair with
/// [`BIO_meth_set_write_ex(method, None)`](BIO_meth_set_write_ex) instead.
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_set_write(mut method: BioMethodMut<'_>, callback: BioMethodWriteCallback) -> bool {
    // SAFETY: as `BIO_meth_set_read`, for the legacy write slot.
    unsafe { ffi::BIO_meth_set_write(method.as_mut_ptr(), Some(callback.raw())) == 1 }
}

/// Wraps: BIO_meth_set_recvmmsg
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_set_recvmmsg(
    mut method: BioMethodMut<'_>,
    callback: Option<BioMethodMmsgCallback>,
) -> bool {
    // SAFETY: the exclusive method handle permits replacing this static code
    // pointer and the callback wrapper establishes the slot contract.
    unsafe {
        ffi::BIO_meth_set_recvmmsg(
            method.as_mut_ptr(),
            callback.map(BioMethodMmsgCallback::raw),
        ) == 1
    }
}

/// Wraps: BIO_meth_set_sendmmsg
#[must_use]
#[allow(non_snake_case)]
pub fn BIO_meth_set_sendmmsg(
    mut method: BioMethodMut<'_>,
    callback: Option<BioMethodMmsgCallback>,
) -> bool {
    // SAFETY: as `BIO_meth_set_recvmmsg`, for the send slot.
    unsafe {
        ffi::BIO_meth_set_sendmmsg(
            method.as_mut_ptr(),
            callback.map(BioMethodMmsgCallback::raw),
        ) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::bio_lib::{BIO_method_name, BIO_method_type, BIO_new, BIO_write};

    #[test]
    fn dynamic_method_is_owned_and_constructs_a_borrowing_bio() {
        let method = BIO_meth_new(73, c"rust method").expect("BIO_meth_new");
        let bio = BIO_new(method.as_ref()).expect("BIO_new");
        assert_eq!(BIO_method_type(bio.as_ref()), 73);
        assert_eq!(BIO_method_name(bio.as_ref()), c"rust method");
    }

    unsafe extern "C" fn accept_every_write(
        _bio: *mut ffi::BIO,
        _data: *const c_char,
        length: c_int,
    ) -> c_int {
        length
    }

    #[test]
    fn the_legacy_write_slot_dispatches_through_its_conversion_thunk() {
        let mut method = BIO_meth_new(BIO_get_new_index(), c"rust writer").expect("BIO_meth_new");
        // SAFETY: the callback consumes no buffer, never unwinds, and reports
        // the whole run as written, which is the legacy write contract.
        let callback = unsafe { BioMethodWriteCallback::from_raw(accept_every_write) };
        assert!(BIO_meth_set_write(method.as_mut(), callback));

        let mut bio = BIO_new(method.as_ref()).expect("BIO_new");
        assert_eq!(BIO_write(&mut bio.as_mut(), b"abc"), 3);
    }

    #[test]
    fn clearing_a_legacy_slot_goes_through_its_extended_setter() {
        let mut method = BIO_meth_new(BIO_get_new_index(), c"rust writer").expect("BIO_meth_new");
        // SAFETY: as in the test above.
        let callback = unsafe { BioMethodWriteCallback::from_raw(accept_every_write) };
        assert!(BIO_meth_set_write(method.as_mut(), callback));
        assert!(BIO_meth_set_write_ex(method.as_mut(), None));

        let mut bio = BIO_new(method.as_ref()).expect("BIO_new");
        // An absent method reports "unsupported" rather than calling a thunk
        // whose legacy slot is null.
        assert_eq!(BIO_write(&mut bio.as_mut(), b"abc"), -2);
    }

    #[test]
    fn new_type_indices_are_distinct_and_increasing() {
        let first = BIO_get_new_index();
        let second = BIO_get_new_index();
        assert!(first > 0);
        assert!(second > first);
    }

    #[test]
    fn callback_slots_accept_explicit_absence() {
        let mut method = BIO_meth_new(74, c"empty callbacks").expect("BIO_meth_new");
        assert!(BIO_meth_set_write_ex(method.as_mut(), None));
        assert!(BIO_meth_set_read_ex(method.as_mut(), None));
        assert!(BIO_meth_set_puts(method.as_mut(), None));
        assert!(BIO_meth_set_gets(method.as_mut(), None));
        assert!(BIO_meth_set_ctrl(method.as_mut(), None));
        assert!(BIO_meth_set_create(method.as_mut(), None));
        assert!(BIO_meth_set_destroy(method.as_mut(), None));
        assert!(BIO_meth_set_callback_ctrl(method.as_mut(), None));
        assert!(BIO_meth_set_recvmmsg(method.as_mut(), None));
        assert!(BIO_meth_set_sendmmsg(method.as_mut(), None));
        assert!(crate::bio::openssl_bio::BIO_meth_get_recvmmsg(method.as_ref()).is_none());
        assert!(crate::bio::openssl_bio::BIO_meth_get_sendmmsg(method.as_ref()).is_none());
    }
}

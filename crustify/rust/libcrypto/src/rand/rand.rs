//! Wrappers assigned from `include/openssl/rand.h`.

use core::ffi::{c_int, c_void};
use core::ptr;

use ffibox::define_ctype;
use libcrypto_sys as ffi;

type RawSeed = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
type RawBytes = unsafe extern "C" fn(*mut u8, c_int) -> c_int;
type RawCleanup = unsafe extern "C" fn();
type RawAdd = unsafe extern "C" fn(*const c_void, c_int, f64) -> c_int;
type RawStatus = unsafe extern "C" fn() -> c_int;

macro_rules! callback_handle {
    ($name:ident, $raw:ty) => {
        #[derive(Clone, Copy)]
        pub struct $name($raw);

        impl $name {
            /// Adopts a callback obeying its `RAND_METHOD` slot contract.
            ///
            /// # Safety
            ///
            /// The callback must accept every buffer passed by its safe
            /// [`call`](Self::call) method, access it only for that call, never
            /// unwind across the C ABI, and satisfy OpenSSL's thread-safety
            /// requirements.
            #[must_use]
            pub unsafe fn from_raw(callback: $raw) -> Self {
                Self(callback)
            }

            const fn raw(self) -> $raw {
                self.0
            }
        }
    };
}

callback_handle!(RandSeedCallback, RawSeed);
callback_handle!(RandBytesCallback, RawBytes);
callback_handle!(RandCleanupCallback, RawCleanup);
callback_handle!(RandAddCallback, RawAdd);
callback_handle!(RandPseudorandCallback, RawBytes);
callback_handle!(RandStatusCallback, RawStatus);

impl RandSeedCallback {
    /// Supplies seed bytes, returning `None` when their length exceeds C `int`.
    #[must_use]
    pub fn call(self, seed: &[u8]) -> Option<i32> {
        let length = i32::try_from(seed.len()).ok()?;
        // SAFETY: the callback's construction contract admits this readable
        // slice for the duration of the synchronous call.
        Some(unsafe { (self.0)(seed.as_ptr().cast(), length) })
    }
}

impl RandBytesCallback {
    /// Fills an output buffer, returning `None` when its length exceeds C `int`.
    #[must_use]
    pub fn call(self, output: &mut [u8]) -> Option<i32> {
        let length = i32::try_from(output.len()).ok()?;
        // SAFETY: the callback's construction contract admits this writable
        // slice for the duration of the synchronous call.
        Some(unsafe { (self.0)(output.as_mut_ptr(), length) })
    }
}

impl RandCleanupCallback {
    /// Runs the method's cleanup callback.
    ///
    /// # Safety
    ///
    /// The method must be in its cleanup phase, and the callback must not be
    /// invoked again unless that particular method documents reinitialization.
    pub unsafe fn call(self) {
        // SAFETY: the caller establishes the callback's lifecycle phase; its
        // construction contract prohibits unwinding.
        unsafe { (self.0)() }
    }
}

impl RandAddCallback {
    /// Supplies additional bytes and their estimated entropy.
    #[must_use]
    pub fn call(self, additional: &[u8], randomness: f64) -> Option<i32> {
        let length = i32::try_from(additional.len()).ok()?;
        // SAFETY: the callback's construction contract admits this readable
        // slice for the duration of the synchronous call.
        Some(unsafe { (self.0)(additional.as_ptr().cast(), length, randomness) })
    }
}

impl RandPseudorandCallback {
    /// Fills a legacy pseudorandom output buffer.
    #[must_use]
    pub fn call(self, output: &mut [u8]) -> Option<i32> {
        let length = i32::try_from(output.len()).ok()?;
        // SAFETY: the callback's construction contract admits this writable
        // slice for the duration of the synchronous call.
        Some(unsafe { (self.0)(output.as_mut_ptr(), length) })
    }
}

impl RandStatusCallback {
    /// Queries whether the method has enough seed material.
    #[must_use]
    pub fn call(self) -> i32 {
        // SAFETY: the callback's construction contract covers this
        // no-argument invocation and prohibits unwinding.
        unsafe { (self.0)() }
    }
}

define_ctype!(
    /// Wraps: rand_meth_st
    ///
    /// Layout-compatible storage and borrow handles for OpenSSL's deprecated
    /// random-method callback table. The table borrows process-lifetime code;
    /// it owns no callback or pointed-to data and needs no destructor.
    RandMethod,
    RandMethodRef,
    RandMethodMut,
    ffi::rand_meth_st
);

impl RandMethodRef<'_> {
    /// Field: rand_meth_st.seed
    #[must_use]
    pub fn seed(&self) -> Option<RandSeedCallback> {
        // SAFETY: a shared handle addresses a live initialized table; reading
        // the optional function pointer forms no reference to C storage.
        unsafe { ptr::addr_of!((*self.as_ptr()).seed).read() }.map(RandSeedCallback)
    }

    /// Field: rand_meth_st.cleanup
    #[must_use]
    pub fn cleanup(&self) -> Option<RandCleanupCallback> {
        // SAFETY: as for `seed`; this copies the optional callback value.
        unsafe { ptr::addr_of!((*self.as_ptr()).cleanup).read() }.map(RandCleanupCallback)
    }

    /// Field: rand_meth_st.status
    #[must_use]
    pub fn status(&self) -> Option<RandStatusCallback> {
        // SAFETY: as for `seed`; this copies the optional callback value.
        unsafe { ptr::addr_of!((*self.as_ptr()).status).read() }.map(RandStatusCallback)
    }

    /// Field: rand_meth_st.bytes
    #[must_use]
    pub fn bytes(&self) -> Option<RandBytesCallback> {
        // SAFETY: as for `seed`; this copies the optional callback value.
        unsafe { ptr::addr_of!((*self.as_ptr()).bytes).read() }.map(RandBytesCallback)
    }

    /// Field: rand_meth_st.add
    #[must_use]
    pub fn add(&self) -> Option<RandAddCallback> {
        // SAFETY: as for `seed`; this copies the optional callback value.
        unsafe { ptr::addr_of!((*self.as_ptr()).add).read() }.map(RandAddCallback)
    }

    /// Field: rand_meth_st.pseudorand
    #[must_use]
    pub fn pseudorand(&self) -> Option<RandPseudorandCallback> {
        // SAFETY: as for `seed`; this copies the optional callback value.
        unsafe { ptr::addr_of!((*self.as_ptr()).pseudorand).read() }.map(RandPseudorandCallback)
    }
}

impl RandMethodMut<'_> {
    /// Replaces the optional seed callback.
    pub fn set_seed(&mut self, callback: Option<RandSeedCallback>) {
        // SAFETY: the exclusive handle permits writing this function-pointer
        // field, and `Option<RawSeed>` accepts every produced value.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).seed).write(callback.map(RandSeedCallback::raw));
        }
    }

    /// Replaces the optional byte-generation callback.
    pub fn set_bytes(&mut self, callback: Option<RandBytesCallback>) {
        // SAFETY: as for `set_seed`, for the `bytes` slot.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).bytes)
                .write(callback.map(RandBytesCallback::raw));
        }
    }

    /// Replaces the optional cleanup callback.
    pub fn set_cleanup(&mut self, callback: Option<RandCleanupCallback>) {
        // SAFETY: as for `set_seed`, for the `cleanup` slot.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).cleanup)
                .write(callback.map(RandCleanupCallback::raw));
        }
    }

    /// Replaces the optional additional-entropy callback.
    pub fn set_add(&mut self, callback: Option<RandAddCallback>) {
        // SAFETY: as for `set_seed`, for the `add` slot.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).add).write(callback.map(RandAddCallback::raw));
        }
    }

    /// Replaces the optional pseudorandom callback.
    pub fn set_pseudorand(&mut self, callback: Option<RandPseudorandCallback>) {
        // SAFETY: as for `set_seed`, for the `pseudorand` slot.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).pseudorand)
                .write(callback.map(RandPseudorandCallback::raw));
        }
    }

    /// Replaces the optional status callback.
    pub fn set_status(&mut self, callback: Option<RandStatusCallback>) {
        // SAFETY: as for `set_seed`, for the `status` slot.
        unsafe {
            ptr::addr_of_mut!((*self.as_mut_ptr()).status)
                .write(callback.map(RandStatusCallback::raw));
        }
    }
}

/// Wraps: RAND_OpenSSL
/// Borrows OpenSSL's process-static default random-method table.
#[cfg(feature = "deprecated-3-0")]
#[allow(non_snake_case)]
#[must_use]
pub fn RAND_OpenSSL() -> RandMethodRef<'static> {
    // SAFETY: OpenSSL returns the non-null address of `ossl_rand_meth`, whose
    // static storage lives for the process. A shared handle deliberately does
    // not expose the C signature's incidental mutability.
    unsafe { RandMethodRef::from_ptr(ffi::RAND_OpenSSL()) }.expect("static RAND method")
}

/// Wraps: RAND_get_rand_method
/// Borrows the current process-global random-method table.
#[cfg(feature = "deprecated-3-0")]
#[allow(non_snake_case)]
#[must_use]
pub fn RAND_get_rand_method() -> Option<RandMethodRef<'static>> {
    // SAFETY: the installed table is either OpenSSL's static default or a
    // process-lifetime table accepted by the safe setter below. A null result
    // reports initialization or locking failure.
    unsafe { RandMethodRef::from_ptr(ffi::RAND_get_rand_method().cast_mut()) }
}

/// Wraps: RAND_set_rand_method
/// Installs a process-lifetime method table, or restores lazy default selection.
#[cfg(feature = "deprecated-3-0")]
#[allow(non_snake_case)]
#[must_use]
pub fn RAND_set_rand_method(method: Option<RandMethodRef<'static>>) -> bool {
    let method = method.map_or(ptr::null(), |method| method.as_ptr());
    // SAFETY: a non-null handle proves that the table and its callbacks remain
    // live for the process, which is the lifetime OpenSSL stores globally.
    unsafe { ffi::RAND_set_rand_method(method) == 1 }
}

/// Wraps: RAND_pseudo_bytes
/// Fills `output` through the deprecated compatibility random method.
#[cfg(feature = "deprecated-1-1-0")]
#[allow(non_snake_case)]
pub fn RAND_pseudo_bytes(output: &mut [u8]) -> i32 {
    let Ok(length) = i32::try_from(output.len()) else {
        return -1;
    };
    // SAFETY: `output` supplies exactly `length` writable bytes for the
    // synchronous generation call and is exclusively borrowed.
    unsafe { ffi::RAND_pseudo_bytes(output.as_mut_ptr(), length) }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    static CLEANED: AtomicBool = AtomicBool::new(false);

    unsafe extern "C" fn count_input(buffer: *const c_void, length: c_int) -> c_int {
        if length == 0 || !buffer.is_null() {
            length
        } else {
            -1
        }
    }

    unsafe extern "C" fn count_output(buffer: *mut u8, length: c_int) -> c_int {
        if length == 0 || !buffer.is_null() {
            length
        } else {
            -1
        }
    }

    unsafe extern "C" fn add_input(buffer: *const c_void, length: c_int, randomness: f64) -> c_int {
        if (length == 0 || !buffer.is_null()) && randomness >= 0.0 {
            length
        } else {
            -1
        }
    }

    unsafe extern "C" fn cleanup() {
        CLEANED.store(true, Ordering::Relaxed);
    }

    unsafe extern "C" fn status() -> c_int {
        7
    }

    #[test]
    fn method_layout_matches_the_public_c_table() {
        assert_eq!(size_of::<RandMethod>(), size_of::<ffi::rand_meth_st>());
        assert_eq!(align_of::<RandMethod>(), align_of::<ffi::rand_meth_st>());
        assert_eq!(
            size_of::<RandMethodRef<'static>>(),
            size_of::<*const ffi::rand_meth_st>()
        );
        assert_eq!(
            size_of::<RandMethodMut<'static>>(),
            size_of::<*mut ffi::rand_meth_st>()
        );
    }

    #[test]
    fn callback_fields_round_trip_through_typed_handles() {
        let mut storage = RandMethod::zeroed();
        let raw = ptr::addr_of_mut!(storage).cast::<ffi::rand_meth_st>();
        // SAFETY: `storage` is live initialized layout-compatible storage and
        // remains exclusively borrowed while `method` exists.
        let mut method = unsafe { RandMethodMut::from_ptr(raw) }.expect("stack method table");

        assert!(method.as_ref().seed().is_none());
        assert!(method.as_ref().bytes().is_none());
        assert!(method.as_ref().cleanup().is_none());
        assert!(method.as_ref().add().is_none());
        assert!(method.as_ref().pseudorand().is_none());
        assert!(method.as_ref().status().is_none());

        // SAFETY: these test callbacks synchronously inspect only pointer
        // nullness and lengths, do not retain data, and never unwind.
        unsafe {
            method.set_seed(Some(RandSeedCallback::from_raw(count_input)));
            method.set_bytes(Some(RandBytesCallback::from_raw(count_output)));
            method.set_cleanup(Some(RandCleanupCallback::from_raw(cleanup)));
            method.set_add(Some(RandAddCallback::from_raw(add_input)));
            method.set_pseudorand(Some(RandPseudorandCallback::from_raw(count_output)));
            method.set_status(Some(RandStatusCallback::from_raw(status)));
        }

        let shared = method.as_ref();
        assert_eq!(shared.seed().expect("seed").call(&[1, 2, 3]), Some(3));
        assert_eq!(shared.add().expect("add").call(&[4, 5], 1.0), Some(2));

        let mut output = [0_u8; 4];
        assert_eq!(shared.bytes().expect("bytes").call(&mut output), Some(4));
        assert_eq!(
            shared.pseudorand().expect("pseudorand").call(&mut output),
            Some(4)
        );
        assert_eq!(shared.status().expect("status").call(), 7);
        // SAFETY: this is the test method's sole cleanup invocation.
        unsafe { shared.cleanup().expect("cleanup").call() };
        assert!(CLEANED.load(Ordering::Relaxed));
    }

    #[cfg(feature = "deprecated-3-0")]
    #[test]
    fn deprecated_default_method_is_borrowed_from_static_storage() {
        let default = RAND_OpenSSL();
        assert!(RAND_set_rand_method(Some(default)));
        assert_eq!(
            RAND_get_rand_method()
                .expect("installed RAND method")
                .as_ptr(),
            default.as_ptr()
        );
    }
}

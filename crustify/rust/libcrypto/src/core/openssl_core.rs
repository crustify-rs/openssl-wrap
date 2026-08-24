//! Wrappers assigned from `include/openssl/core.h`.

use core::ffi::{CStr, c_void};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::{NonNull, addr_of, addr_of_mut};

use ffibox::{CCell, CPtr, CSlice, CSliceMut, CType, CVal, CValued};
use libcrypto_sys as ffi;

/// Wraps: ossl_param_st
///
/// Layout-compatible storage for one OpenSSL core parameter descriptor.
/// `OSSL_PARAM` owns nothing: `key` is a borrowed C string and `data` is
/// runtime-discriminated caller storage. The latter may be a native scalar, a
/// byte run, or a pointer slot, and may be written by an OpenSSL getter. The
/// lifetime parameter keeps both referents alive while the descriptor can be
/// used, and the byte view uses [`MaybeUninit`] because output buffers need
/// not have been initialized before OpenSSL fills them.
///
/// A null `key` is the published array terminator. A null `data` is also valid
/// and asks a setter to report its required size through `return_size`.
#[repr(transparent)]
pub struct OsslParam<'data> {
    inner: CType<ffi::ossl_param_st>,
    borrows: PhantomData<(&'data CStr, &'data mut [MaybeUninit<u8>])>,
}

/// Shared borrowed handle to an [`OsslParam`].
#[repr(transparent)]
pub struct OsslParamRef<'view, 'data>(CPtr<'view, OsslParam<'data>>);

impl Clone for OsslParamRef<'_, '_> {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for OsslParamRef<'_, '_> {}

/// Exclusive borrowed handle to an [`OsslParam`].
#[repr(transparent)]
pub struct OsslParamMut<'view, 'data>(OsslParamRef<'view, 'data>);

// SAFETY: `OsslParam` is transparent over `CType<ossl_param_st>` and its
// borrow marker is zero-sized. Both handles are transparent over a `CPtr`, and
// the shared handle provides no operation that writes through the descriptor.
unsafe impl<'data> CCell for OsslParam<'data> {
    type C = ffi::ossl_param_st;
    type Ref<'view>
        = OsslParamRef<'view, 'data>
    where
        'data: 'view;
    type Mut<'view>
        = OsslParamMut<'view, 'data>
    where
        'data: 'view;

    unsafe fn ref_from_raw<'view>(ptr: NonNull<Self>) -> Self::Ref<'view>
    where
        'data: 'view,
    {
        // SAFETY: the caller guarantees the descriptor is live for `'view`.
        OsslParamRef(unsafe { CPtr::new(ptr) })
    }

    unsafe fn mut_from_raw<'view>(ptr: NonNull<Self>) -> Self::Mut<'view>
    where
        'data: 'view,
    {
        // SAFETY: the caller additionally guarantees exclusive access.
        OsslParamMut(OsslParamRef(unsafe { CPtr::new(ptr) }))
    }
}

// SAFETY: the descriptor only borrows its key and data. Disposing inline
// storage must not release either caller-owned referent.
unsafe impl CValued for OsslParam<'_> {
    unsafe fn c_dispose(_this: NonNull<Self>) {}
}

impl OsslParam<'static> {
    /// Creates the null-key descriptor that terminates an `OSSL_PARAM` array.
    #[must_use]
    pub fn end() -> CVal<Self> {
        CVal::new(Self {
            inner: CType::new(ffi::ossl_param_st {
                key: core::ptr::null(),
                data_type: 0,
                data: core::ptr::null_mut(),
                data_size: 0,
                return_size: usize::MAX,
            }),
            borrows: PhantomData,
        })
    }
}

impl<'data> OsslParam<'data> {
    /// Creates inline descriptor storage over a caller-managed output buffer.
    ///
    /// `data_type` is one of OpenSSL's `OSSL_PARAM_*` values (or an extension
    /// understood by the receiving provider). The buffer remains exclusively
    /// borrowed until the returned value is dropped or its data is reclaimed
    /// with [`OsslParamMut::take_data`].
    #[must_use]
    pub fn for_buffer(
        key: &'data CStr,
        data_type: u32,
        mut data: CSliceMut<'data, MaybeUninit<u8>>,
    ) -> CVal<Self> {
        let data_size = data.len();
        let data = data.as_mut_elem_ptr().cast::<c_void>();
        CVal::new(Self {
            inner: CType::new(ffi::ossl_param_st {
                key: key.as_ptr(),
                data_type,
                data,
                data_size,
                return_size: usize::MAX,
            }),
            borrows: PhantomData,
        })
    }

    /// Creates inline descriptor storage from a Rust output buffer.
    #[must_use]
    pub fn for_slice(
        key: &'data CStr,
        data_type: u32,
        data: &'data mut [MaybeUninit<u8>],
    ) -> CVal<Self> {
        let len = data.len();
        // SAFETY: a mutable slice supplies `len` contiguous `MaybeUninit<u8>`
        // slots, and consuming its lifetime here leaves the descriptor as the
        // only Rust-visible route to them until the descriptor is dropped.
        let data =
            unsafe { CSliceMut::from_raw_parts(NonNull::new_unchecked(data.as_mut_ptr()), len) };
        Self::for_buffer(key, data_type, data)
    }
}

impl<'view, 'data> OsslParamRef<'view, 'data> {
    /// Borrows raw descriptor storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// A non-null pointer must address a live initialized `OSSL_PARAM` for
    /// `'view`. Its non-null `key` must be a NUL-terminated string and its
    /// non-null `data` must address `data_size` bytes, both live for `'data`.
    /// No path may write the data while the returned shared handle is in use.
    pub unsafe fn from_ptr(ptr: *mut ffi::ossl_param_st) -> Option<Self> {
        NonNull::new(ptr.cast::<OsslParam<'data>>()).map(|ptr| {
            // SAFETY: the caller supplies the liveness and field invariants.
            Self(unsafe { CPtr::new(ptr) })
        })
    }

    /// Read-only pointer for the raw FFI seam.
    #[must_use]
    pub fn as_ptr(&self) -> *const ffi::ossl_param_st {
        self.0.as_non_null().as_ptr().cast()
    }

    /// Field: ossl_param_st.key
    ///
    /// The borrowed parameter name, or `None` for the array terminator.
    #[must_use]
    pub fn key(&self) -> Option<&'view CStr> {
        // SAFETY: the handle's construction contract keeps a non-null key a
        // live NUL-terminated string for longer than `'view`.
        let key = unsafe { addr_of!((*self.as_ptr()).key).read() };
        if key.is_null() {
            None
        } else {
            // SAFETY: established by the handle contract above.
            Some(unsafe { CStr::from_ptr(key) })
        }
    }

    /// Field: ossl_param_st.data
    ///
    /// Returns the runtime-discriminated storage as possibly-uninitialized
    /// bytes. Interpret it only according to [`data_type`](Self::data_type).
    #[must_use]
    pub fn data(&self) -> Option<CSlice<'view, MaybeUninit<u8>>> {
        // SAFETY: both fields are copied through raw-place projections. The
        // handle contract keeps a non-null pointer live for `data_size` bytes
        // throughout `'view`; `MaybeUninit<u8>` permits output-buffer bytes.
        unsafe {
            let data = addr_of!((*self.as_ptr()).data)
                .read()
                .cast::<MaybeUninit<u8>>();
            let len = addr_of!((*self.as_ptr()).data_size).read();
            NonNull::new(data).map(|data| CSlice::from_raw_parts(data, len))
        }
    }

    /// Field: ossl_param_st.return_size
    ///
    /// The size written by the receiving getter, or its sentinel value.
    #[must_use]
    pub fn return_size(&self) -> usize {
        // SAFETY: this copies an initialized scalar through raw projection.
        unsafe { addr_of!((*self.as_ptr()).return_size).read() }
    }

    /// Field: ossl_param_st.data_size
    ///
    /// The byte capacity of [`data`](Self::data).
    #[must_use]
    pub fn data_size(&self) -> usize {
        // SAFETY: this copies an initialized scalar through raw projection.
        unsafe { addr_of!((*self.as_ptr()).data_size).read() }
    }

    /// Field: ossl_param_st.data_type
    ///
    /// The runtime `OSSL_PARAM_*` discriminator.
    #[must_use]
    pub fn data_type(&self) -> u32 {
        // SAFETY: this copies an initialized scalar through raw projection.
        unsafe { addr_of!((*self.as_ptr()).data_type).read() }
    }
}

impl<'view, 'data> OsslParamMut<'view, 'data> {
    /// Exclusively borrows raw descriptor storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// As [`OsslParamRef::from_ptr`], plus the descriptor and its data must be
    /// exclusively borrowed while the result is used.
    pub unsafe fn from_ptr(ptr: *mut ffi::ossl_param_st) -> Option<Self> {
        NonNull::new(ptr.cast::<OsslParam<'data>>()).map(|ptr| {
            // SAFETY: the caller supplies liveness, field invariants and
            // exclusive access.
            Self(OsslParamRef(unsafe { CPtr::new(ptr) }))
        })
    }

    /// Writable pointer for the raw FFI seam.
    #[must_use]
    pub fn as_mut_ptr(&mut self) -> *mut ffi::ossl_param_st {
        self.0.0.as_non_null().as_ptr().cast()
    }

    /// Reborrows this descriptor for shared field access.
    #[must_use]
    pub fn as_ref(&self) -> OsslParamRef<'_, 'data> {
        self.0
    }

    /// Exclusively views the possibly-uninitialized data buffer.
    #[must_use]
    pub fn data_mut(&mut self) -> Option<CSliceMut<'_, MaybeUninit<u8>>> {
        // SAFETY: the exclusive descriptor handle is the only route to this
        // buffer while the returned view lives, and the construction contract
        // guarantees `data_size` bytes at every non-null `data` pointer.
        unsafe {
            let data = addr_of!((*self.as_mut_ptr()).data)
                .read()
                .cast::<MaybeUninit<u8>>();
            let len = addr_of!((*self.as_mut_ptr()).data_size).read();
            NonNull::new(data).map(|data| CSliceMut::from_raw_parts(data, len))
        }
    }

    /// Replaces the borrowed key and returns the previous one.
    pub fn set_key(&mut self, key: Option<&'data CStr>) -> Option<&'data CStr> {
        // SAFETY: the existing key obeys this handle's contract, the new key
        // lives for `'data`, and the exclusive handle permits replacement.
        unsafe {
            let previous = addr_of!((*self.as_mut_ptr()).key).read();
            let key = key.map_or(core::ptr::null(), CStr::as_ptr);
            addr_of_mut!((*self.as_mut_ptr()).key).write(key);
            (!previous.is_null()).then(|| CStr::from_ptr(previous))
        }
    }

    /// Replaces `data` and `data_size` together, returning the previous run.
    ///
    /// Keeping the pair coupled prevents safe code from publishing a length
    /// larger than the buffer it borrowed.
    pub fn set_data(
        &mut self,
        data: Option<CSliceMut<'data, MaybeUninit<u8>>>,
    ) -> Option<CSliceMut<'data, MaybeUninit<u8>>> {
        let (data, len) = data.map_or((core::ptr::null_mut(), 0), |mut data| {
            (data.as_mut_elem_ptr().cast::<c_void>(), data.len())
        });
        // SAFETY: the exclusive handle permits replacing both fields. The old
        // pair described an exclusively borrowed run live for `'data`; after
        // clearing it from the descriptor that borrow can be returned.
        unsafe {
            let previous = addr_of!((*self.as_mut_ptr()).data)
                .read()
                .cast::<MaybeUninit<u8>>();
            let previous_len = addr_of!((*self.as_mut_ptr()).data_size).read();
            addr_of_mut!((*self.as_mut_ptr()).data).write(data);
            addr_of_mut!((*self.as_mut_ptr()).data_size).write(len);
            NonNull::new(previous).map(|previous| CSliceMut::from_raw_parts(previous, previous_len))
        }
    }

    /// Clears the data fields and reclaims the stored buffer borrow.
    pub fn take_data(&mut self) -> Option<CSliceMut<'data, MaybeUninit<u8>>> {
        self.set_data(None)
    }

    /// Sets the provider-written result size metadata.
    pub fn set_return_size(&mut self, return_size: usize) {
        // SAFETY: the exclusive handle permits writing this scalar field.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).return_size).write(return_size) }
    }

    /// Sets the runtime data discriminator.
    pub fn set_data_type(&mut self, data_type: u32) {
        // SAFETY: the exclusive handle permits writing this scalar field; the
        // byte-oriented data view does not assume a particular discriminator.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).data_type).write(data_type) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn wrapper_preserves_the_published_layout() {
        assert_eq!(
            size_of::<OsslParam<'static>>(),
            size_of::<ffi::ossl_param_st>()
        );
        assert_eq!(
            align_of::<OsslParam<'static>>(),
            align_of::<ffi::ossl_param_st>()
        );
    }

    #[test]
    fn borrowed_fields_round_trip_without_owning_their_storage() {
        let mut bytes = [MaybeUninit::new(1_u8), MaybeUninit::new(2_u8)];
        let mut param = OsslParam::for_slice(c"answer", 5, &mut bytes);

        let shared = param.as_ref();
        assert_eq!(shared.key(), Some(c"answer"));
        assert_eq!(shared.data_type(), 5);
        assert_eq!(shared.data_size(), 2);
        assert_eq!(shared.data().map(|data| data.len()), Some(2));
        assert_eq!(shared.return_size(), usize::MAX);

        let mut exclusive = param.as_mut();
        exclusive.set_data_type(4);
        exclusive.set_return_size(1);
        assert!(
            exclusive
                .data_mut()
                .expect("data buffer")
                .set_elem(0, MaybeUninit::new(9))
        );
        let data = exclusive.take_data().expect("stored data borrow");
        assert_eq!(data.len(), 2);
        // SAFETY: the first element was initialized immediately above.
        assert_eq!(unsafe { data.elem(0).unwrap().assume_init() }, 9);

        let shared = exclusive.as_ref();
        assert!(shared.data().is_none());
        assert_eq!(shared.data_size(), 0);
        assert_eq!(shared.data_type(), 4);
        assert_eq!(shared.return_size(), 1);
    }

    #[test]
    fn end_descriptor_has_the_null_sentinel_key() {
        let end = OsslParam::end();
        assert!(end.as_ref().key().is_none());
        assert!(end.as_ref().data().is_none());
    }
}

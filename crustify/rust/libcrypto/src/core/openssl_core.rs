//! Wrappers assigned from `include/openssl/core.h`.

use core::ffi::{CStr, c_int, c_void};
use core::marker::PhantomData;
use core::mem::MaybeUninit;
use core::ptr::{NonNull, addr_of, addr_of_mut};
use std::vec::Vec;

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
///
/// The wrapper rests on one invariant, which couples `data` to `data_type`: for
/// every value-carrying `OSSL_PARAM_*` type a non-null `data` addresses
/// `data_size` bytes, and for `OSSL_PARAM_UTF8_PTR` and `OSSL_PARAM_OCTET_PTR`
/// a non-null `data` addresses one aligned `*const c_void` slot.
/// `crypto/params.c` reaches the latter two as `*(const void **)p->data` and
/// uses `data_size` to bound the *referent* instead, so a byte run of
/// `data_size` bytes does not exist at `data` for them; the accessors report no
/// byte view rather than fabricating one, and [`OsslParamRef::data_type`]
/// recognizes them.
///
/// The safe surface maintains that coupling rather than merely documenting it,
/// because a descriptor reaches C through safe wrappers that hand the whole
/// array to a provider. [`OsslParam::for_buffer`] describes a byte run, so it
/// refuses the two pointer-slot types; [`OsslParamMut::set_data`] refuses to
/// install a byte run under one, and [`OsslParamMut::set_data_type`] refuses to
/// move a descriptor across the two classes while `data` is non-null. Without
/// those refusals safe code could hand C a one-byte buffer typed
/// `OSSL_PARAM_UTF8_PTR` and have `set_ptr_internal` /
/// `get_ptr_internal_skip_checks` load or store a whole pointer through it.
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

/// Whether `data_type` makes `data` a lone `void *` slot instead of a byte run.
///
/// `set_ptr_internal` and `get_ptr_internal_skip_checks` in `crypto/params.c`
/// reach `OSSL_PARAM_UTF8_PTR` and `OSSL_PARAM_OCTET_PTR` storage as
/// `*(const void **)p->data` and report `data_size` as the *referent* length,
/// which bounds no storage at `data`. Every other data type makes `data_size`
/// the byte capacity of `data`.
const fn is_pointer_slot(data_type: u32) -> bool {
    matches!(
        data_type,
        ffi::OSSL_PARAM_UTF8_PTR | ffi::OSSL_PARAM_OCTET_PTR
    )
}

/// The byte run addressable at a descriptor's `data`, when one exists.
///
/// Absent for the two pointer-slot types, which have no byte view at all.
const fn data_extent(data_type: u32, data_size: usize) -> Option<usize> {
    if is_pointer_slot(data_type) {
        None
    } else {
        Some(data_size)
    }
}

/// The exact descriptor published as `OSSL_PARAM_END`.
///
/// `include/openssl/params.h` spells the terminator `{ NULL, 0, NULL, 0, 0 }`
/// and `OSSL_PARAM_construct_end` returns that value, so its `return_size` is
/// zero rather than the `OSSL_PARAM_UNMODIFIED` sentinel that
/// `OSSL_PARAM_DEFN` gives a real descriptor.
const fn end_descriptor() -> ffi::ossl_param_st {
    ffi::ossl_param_st {
        key: core::ptr::null(),
        data_type: 0,
        data: core::ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

impl OsslParam<'static> {
    /// Creates the null-key descriptor that terminates an `OSSL_PARAM` array.
    #[must_use]
    pub fn end() -> CVal<Self> {
        CVal::new(Self {
            inner: CType::new(end_descriptor()),
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
    ///
    /// Deriving `data_size` from the buffer establishes the descriptor's byte
    /// invariant, so `None` reports the two pointer-slot types
    /// `OSSL_PARAM_UTF8_PTR` and `OSSL_PARAM_OCTET_PTR`: their `data` must be
    /// one aligned `void *` slot and their `data_size` describes the referent,
    /// neither of which a byte buffer states. Building one anyway would let a
    /// provider load or store a whole pointer through a buffer that need be
    /// neither eight bytes long nor pointer-aligned; see [`OsslParam`].
    #[must_use]
    pub fn for_buffer(
        key: &'data CStr,
        data_type: u32,
        mut data: CSliceMut<'data, MaybeUninit<u8>>,
    ) -> Option<CVal<Self>> {
        if is_pointer_slot(data_type) {
            return None;
        }
        let data_size = data.len();
        let data = data.as_mut_elem_ptr().cast::<c_void>();
        Some(CVal::new(Self {
            inner: CType::new(ffi::ossl_param_st {
                key: key.as_ptr(),
                data_type,
                data,
                data_size,
                return_size: usize::MAX,
            }),
            borrows: PhantomData,
        }))
    }

    /// Creates inline descriptor storage from a Rust output buffer.
    ///
    /// `None` for the two pointer-slot types, as in
    /// [`for_buffer`](Self::for_buffer).
    #[must_use]
    pub fn for_slice(
        key: &'data CStr,
        data_type: u32,
        data: &'data mut [MaybeUninit<u8>],
    ) -> Option<CVal<Self>> {
        let len = data.len();
        // SAFETY: a mutable slice supplies `len` contiguous `MaybeUninit<u8>`
        // slots, and consuming its lifetime here leaves the descriptor as the
        // only Rust-visible route to them until the descriptor is dropped.
        let data =
            unsafe { CSliceMut::from_raw_parts(NonNull::new_unchecked(data.as_mut_ptr()), len) };
        Self::for_buffer(key, data_type, data)
    }

    /// Reports whether the descriptor at `index` of a C-contract array is the
    /// published null-key terminator.
    ///
    /// The `key` projection lives here, in the descriptor's own accessor,
    /// rather than in each scanning caller, and the predicate keeps the
    /// borrowed key pointer from escaping the wrapper.
    ///
    /// # Safety
    ///
    /// `params` must address a live C-contract `OSSL_PARAM` array holding an
    /// initialized descriptor at `index`.
    #[must_use]
    pub(crate) unsafe fn is_terminator_at(
        params: NonNull<ffi::ossl_param_st>,
        index: usize,
    ) -> bool {
        // SAFETY: the caller guarantees an initialized descriptor at `index`;
        // projecting through `addr_of!` never materializes a reference to it.
        let key = unsafe { addr_of!((*params.as_ptr().add(index)).key).read() };
        key.is_null()
    }
}

/// An owned, automatically terminated array of `OSSL_PARAM` descriptors.
///
/// Descriptor headers are moved into stable Rust-owned storage, which appends
/// the trailing null-key sentinel itself. This lets safe wrappers pass the C
/// array convention without exposing a raw pointer or asking callers to
/// manufacture the terminator.
///
/// The array is the sole owner of the descriptors it carries, so the `'data`
/// borrows they hold — exclusive over every writable run, because
/// [`OsslParam::for_buffer`] consumes a [`CSliceMut`] to build one — pass to
/// the array and last as long as it does. That is what lets the array back an
/// OpenSSL *getter*, which writes through the copied `data` pointers and
/// `return_size` fields: copying headers out of shared [`OsslParamRef`]
/// handles instead would leave those runs only shared-borrowed while C wrote
/// them. Results are read back through [`as_list`](Self::as_list).
pub struct OsslParamArray<'data> {
    descriptors: Vec<ffi::ossl_param_st>,
    borrows: PhantomData<&'data mut [MaybeUninit<u8>]>,
}

impl<'data> OsslParamArray<'data> {
    /// Takes ownership of the descriptors and appends the required terminator.
    #[must_use]
    pub fn new(params: impl IntoIterator<Item = CVal<OsslParam<'data>>>) -> Self {
        let params = params.into_iter();
        let (lower, _) = params.size_hint();
        let mut descriptors = Vec::with_capacity(lower + 1);
        for param in params {
            // SAFETY: `CVal` owns one initialized descriptor at this address.
            // Copying its plain C header moves, rather than duplicates, the
            // `'data` referents: the source is consumed here, and dropping it
            // runs the descriptor's `c_dispose`, which releases nothing.
            descriptors.push(unsafe { param.as_ref().as_ptr().read() });
        }
        descriptors.push(end_descriptor());
        Self {
            descriptors,
            borrows: PhantomData,
        }
    }

    /// The descriptors as a validated run, for reading results back.
    #[must_use]
    pub fn as_list(&self) -> OsslParamListRef<'_, 'data> {
        let len = self.descriptors.len();
        // SAFETY: `descriptors` is a nonempty `Vec` of initialized headers, so
        // its pointer is non-null and covers `len` layout-compatible
        // `OsslParam` descriptors for this shared borrow.
        let params = unsafe {
            CSlice::from_raw_parts(
                NonNull::new_unchecked(
                    self.descriptors
                        .as_ptr()
                        .cast_mut()
                        .cast::<OsslParam<'data>>(),
                ),
                len,
            )
        };
        OsslParamListRef { params }
    }

    /// The descriptors as an exclusive validated run.
    #[must_use]
    pub fn as_list_mut(&mut self) -> OsslParamListMut<'_, 'data> {
        let len = self.descriptors.len();
        // SAFETY: as `as_list`, and the exclusive borrow of the array is the
        // only route to these descriptors while the returned run lives.
        let params = unsafe {
            CSliceMut::from_raw_parts(
                NonNull::new_unchecked(self.descriptors.as_mut_ptr().cast::<OsslParam<'data>>()),
                len,
            )
        };
        OsslParamListMut { params }
    }

    pub(crate) fn as_ptr(&self) -> *const ffi::ossl_param_st {
        self.descriptors.as_ptr()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::ossl_param_st {
        self.descriptors.as_mut_ptr()
    }
}

impl<'view, 'data> OsslParamRef<'view, 'data> {
    /// Borrows raw descriptor storage, returning `None` for null.
    ///
    /// # Safety
    ///
    /// A non-null pointer must address a live initialized `OSSL_PARAM` for
    /// `'view`. Its non-null `key` must be a NUL-terminated string live for
    /// `'data`. A non-null `data` must satisfy the descriptor's data-type
    /// coupling for `'data`: `data_size` bytes for a value-carrying type, and
    /// one aligned `*const c_void` slot when `data_type` is
    /// `OSSL_PARAM_UTF8_PTR` or `OSSL_PARAM_OCTET_PTR`, for which the
    /// accessors publish no byte view. No Rust path may form a reference over
    /// that data while the returned shared handle is in use; OpenSSL may still
    /// write it through the descriptor, which is why the view is raw rather
    /// than a `&[u8]`.
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
    ///
    /// `None` covers a null `data` and the two pointer-slot data types, for
    /// which `data_size` describes the referent rather than any run at `data`;
    /// see [`OsslParam`].
    #[must_use]
    pub fn data(&self) -> Option<CSlice<'view, MaybeUninit<u8>>> {
        // SAFETY: all three fields are copied through raw-place projections.
        // The handle contract keeps a non-null pointer live for `data_size`
        // bytes throughout `'view`, and `data_extent` withholds the view for
        // the pointer-slot types, whose `data_size` bounds no storage there.
        // `MaybeUninit<u8>` permits output-buffer bytes.
        unsafe {
            let len = data_extent(
                addr_of!((*self.as_ptr()).data_type).read(),
                addr_of!((*self.as_ptr()).data_size).read(),
            )?;
            let data = addr_of!((*self.as_ptr()).data)
                .read()
                .cast::<MaybeUninit<u8>>();
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
    ///
    /// `None` covers a null `data` and the two pointer-slot data types, as in
    /// [`OsslParamRef::data`].
    #[must_use]
    pub fn data_mut(&mut self) -> Option<CSliceMut<'_, MaybeUninit<u8>>> {
        // SAFETY: the exclusive descriptor handle is the only route to this
        // buffer while the returned view lives, the construction contract
        // guarantees `data_size` bytes at every non-null `data` pointer, and
        // `data_extent` withholds the view for the pointer-slot types.
        unsafe {
            let len = data_extent(
                addr_of!((*self.as_mut_ptr()).data_type).read(),
                addr_of!((*self.as_mut_ptr()).data_size).read(),
            )?;
            let data = addr_of!((*self.as_mut_ptr()).data)
                .read()
                .cast::<MaybeUninit<u8>>();
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
    /// larger than the buffer it borrowed. `Ok` carries the run the descriptor
    /// held, which is absent for a null `data` and for the two pointer-slot
    /// data types, as in [`OsslParamRef::data`].
    ///
    /// # Errors
    ///
    /// A byte run cannot be installed under `OSSL_PARAM_UTF8_PTR` or
    /// `OSSL_PARAM_OCTET_PTR`, whose `data` is one aligned `*const c_void`
    /// slot. Such a call leaves the descriptor untouched and hands the
    /// refused run back; clear the pointer slot with
    /// [`take_data`](Self::take_data) and retype the descriptor first if the
    /// intent was to make it carry bytes.
    pub fn set_data(
        &mut self,
        data: Option<CSliceMut<'data, MaybeUninit<u8>>>,
    ) -> Result<Option<CSliceMut<'data, MaybeUninit<u8>>>, CSliceMut<'data, MaybeUninit<u8>>> {
        if let Some(data) = data {
            // SAFETY: the handle contract keeps the descriptor live and this
            // raw-place read copies an initialized scalar out of it.
            let data_type = unsafe { addr_of!((*self.as_mut_ptr()).data_type).read() };
            if is_pointer_slot(data_type) {
                return Err(data);
            }
            return Ok(self.replace_data(Some(data)));
        }
        Ok(self.replace_data(None))
    }

    /// Writes the `data` / `data_size` pair, returning the previous run.
    ///
    /// The caller has already established that the new pair agrees with the
    /// descriptor's `data_type`.
    fn replace_data(
        &mut self,
        data: Option<CSliceMut<'data, MaybeUninit<u8>>>,
    ) -> Option<CSliceMut<'data, MaybeUninit<u8>>> {
        let (data, len) = data.map_or((core::ptr::null_mut(), 0), |mut data| {
            (data.as_mut_elem_ptr().cast::<c_void>(), data.len())
        });
        // SAFETY: the exclusive handle permits replacing both fields. The old
        // pair described an exclusively borrowed run live for `'data`; after
        // clearing it from the descriptor that borrow can be returned, unless
        // `data_extent` shows the old pair never described a run at all.
        unsafe {
            let previous = addr_of!((*self.as_mut_ptr()).data)
                .read()
                .cast::<MaybeUninit<u8>>();
            let previous_len = data_extent(
                addr_of!((*self.as_mut_ptr()).data_type).read(),
                addr_of!((*self.as_mut_ptr()).data_size).read(),
            );
            addr_of_mut!((*self.as_mut_ptr()).data).write(data);
            addr_of_mut!((*self.as_mut_ptr()).data_size).write(len);
            let previous_len = previous_len?;
            NonNull::new(previous).map(|previous| CSliceMut::from_raw_parts(previous, previous_len))
        }
    }

    /// Clears the data fields and reclaims the stored buffer borrow.
    ///
    /// Clearing is valid for every data type: it leaves a null `data` and a
    /// zero `data_size`, which describe no storage under either coupling. A
    /// pointer-slot descriptor therefore reports no reclaimed run while still
    /// being cleared.
    pub fn take_data(&mut self) -> Option<CSliceMut<'data, MaybeUninit<u8>>> {
        self.replace_data(None)
    }

    /// Sets the provider-written result size metadata.
    pub fn set_return_size(&mut self, return_size: usize) {
        // SAFETY: the exclusive handle permits writing this scalar field.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).return_size).write(return_size) }
    }

    /// Sets the runtime data discriminator, reporting whether it was applied.
    ///
    /// `data_type` decides how OpenSSL reaches `data`: the two pointer-slot
    /// types load and store a whole `*const c_void` there, every other type
    /// reads and writes `data_size` bytes. Moving a descriptor between those
    /// classes while `data` is non-null would therefore retype storage that
    /// was borrowed under the other contract, so it is refused and the
    /// descriptor is left untouched. Clear the pair with
    /// [`take_data`](Self::take_data) first; between two types of the same
    /// class the change always applies.
    #[must_use]
    pub fn set_data_type(&mut self, data_type: u32) -> bool {
        // SAFETY: the exclusive handle permits reading and writing these
        // scalar fields through raw-place projection, and the pointer read
        // only inspects the stored address.
        unsafe {
            let data = addr_of!((*self.as_mut_ptr()).data).read();
            let previous = addr_of!((*self.as_mut_ptr()).data_type).read();
            if !data.is_null() && is_pointer_slot(data_type) != is_pointer_slot(previous) {
                return false;
            }
            addr_of_mut!((*self.as_mut_ptr()).data_type).write(data_type);
        }
        true
    }
}

/// A validated, null-key-terminated run of `OSSL_PARAM` descriptors.
#[derive(Clone, Copy)]
pub struct OsslParamListRef<'view, 'data> {
    params: CSlice<'view, OsslParam<'data>>,
}

impl<'view, 'data> OsslParamListRef<'view, 'data> {
    /// Validates that `params` is nonempty and ends with `OSSL_PARAM_END`.
    #[must_use]
    pub fn new(params: CSlice<'view, OsslParam<'data>>) -> Option<Self> {
        let last = params.len().checked_sub(1)?;
        params.get(last)?.key().is_none().then_some(Self { params })
    }

    /// The parameter descriptors before the terminating entry.
    #[must_use]
    pub fn values(&self) -> CSlice<'view, OsslParam<'data>> {
        // SAFETY: validation established a nonempty run, so subtracting the
        // terminator leaves `len - 1` initialized descriptors at this pointer.
        unsafe {
            CSlice::from_raw_parts(
                NonNull::new_unchecked(self.params.as_ptr().cast()),
                self.params.len() - 1,
            )
        }
    }

    pub(crate) fn as_ptr(&self) -> *const ffi::ossl_param_st {
        self.params.as_ptr().cast_const()
    }
}

/// An exclusive validated, null-key-terminated `OSSL_PARAM` run.
pub struct OsslParamListMut<'view, 'data> {
    params: CSliceMut<'view, OsslParam<'data>>,
}

impl<'view, 'data> OsslParamListMut<'view, 'data> {
    /// Validates that `params` is nonempty and ends with `OSSL_PARAM_END`.
    #[must_use]
    pub fn new(params: CSliceMut<'view, OsslParam<'data>>) -> Option<Self> {
        let last = params.len().checked_sub(1)?;
        params.get(last)?.key().is_none().then_some(Self { params })
    }

    /// Validates a Rust-owned run of inline descriptors as a C-contract array.
    ///
    /// A caller that builds descriptors with [`OsslParam::for_slice`] holds
    /// them as `[CVal<OsslParam>]`. The array pointer a C parameter call needs
    /// must be derived from the borrow that covers the *whole* run: taking it
    /// from the first element instead yields a pointer valid for one
    /// descriptor, which C then walks past.
    #[must_use]
    pub fn from_values(params: &'view mut [CVal<OsslParam<'data>>]) -> Option<Self> {
        let len = params.len();
        let start = NonNull::new(params.as_mut_ptr())?.cast::<OsslParam<'data>>();
        // SAFETY: `CVal` is `repr(transparent)` over its value, so the slice is
        // `len` contiguous initialized `OsslParam` descriptors. `start` is
        // derived from the exclusive borrow of the entire slice, so it carries
        // provenance over every one of them for `'view`.
        let params = unsafe { CSliceMut::from_raw_parts(start, len) };
        Self::new(params)
    }

    /// Reborrows the validated run without write access.
    #[must_use]
    pub fn as_ref(&self) -> OsslParamListRef<'_, 'data> {
        OsslParamListRef {
            params: self.params.as_ref(),
        }
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut ffi::ossl_param_st {
        self.params.as_mut_ptr()
    }
}

/// Counts entries before the null-key terminator required by the C API.
///
/// # Safety
///
/// `params` must address a live C-contract `OSSL_PARAM` array whose null-key
/// terminator is reachable. Every descriptor through that terminator must be
/// initialized and remain live for the scan.
pub(crate) unsafe fn terminated_param_len(params: *const ffi::ossl_param_st) -> Option<usize> {
    let params = NonNull::new(params.cast_mut())?;
    let mut len = 0usize;
    loop {
        // SAFETY: the caller guarantees an initialized descriptor at every
        // position through the reachable terminator.
        if unsafe { OsslParam::is_terminator_at(params, len) } {
            return Some(len);
        }
        len = len.checked_add(1)?;
    }
}

/// Wraps: OSSL_CALLBACK
///
/// A Rust callback receiving a lifetime-bound view of the parameter array.
/// Raw callback state never leaves this module; callers invoke it directly or
/// pass it through wrappers that keep the mutable closure borrow live for the
/// complete synchronous C call.
pub struct OsslCallback<'callback, F> {
    callback: &'callback mut F,
}

impl<'callback, F> OsslCallback<'callback, F>
where
    F: for<'params> FnMut(CSlice<'params, OsslParam<'params>>) -> c_int,
{
    /// Wraps a Rust closure as an OpenSSL core callback.
    pub fn new(callback: &'callback mut F) -> Self {
        Self { callback }
    }

    /// Invokes the callback from Rust with an already bounded parameter run.
    pub fn call<'params>(&mut self, params: CSlice<'params, OsslParam<'params>>) -> c_int {
        (self.callback)(params)
    }

    /// Exposes the raw pair for one synchronous internal FFI call.
    ///
    /// # Safety
    ///
    /// The caller must not retain either value after releasing the mutable
    /// borrow of this callback and must prevent concurrent invocation.
    pub(crate) unsafe fn raw_parts(&mut self) -> (ffi::OSSL_CALLBACK, *mut c_void) {
        unsafe extern "C" fn trampoline<F>(
            params: *const ffi::ossl_param_st,
            arg: *mut c_void,
        ) -> c_int
        where
            F: for<'params> FnMut(CSlice<'params, OsslParam<'params>>) -> c_int,
        {
            // SAFETY: OpenSSL's callback contract supplies a live terminated
            // array for this invocation. A malformed null input is rejected.
            let Some(len) = (unsafe { terminated_param_len(params) }) else {
                return 0;
            };
            let Some(params) = NonNull::new(params.cast_mut().cast::<OsslParam<'_>>()) else {
                return 0;
            };
            // SAFETY: the scan established `len` initialized descriptors
            // before the terminator, all live for this callback invocation.
            let params = unsafe { CSlice::from_raw_parts(params, len) };
            // SAFETY: `raw_parts` passes the unique live `F` behind this
            // callback object and C invokes it only during that mutable borrow.
            let callback = unsafe { &mut *arg.cast::<F>() };
            callback(params)
        }

        (
            Some(trampoline::<F>),
            core::ptr::from_mut(self.callback).cast::<c_void>(),
        )
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
        let mut param = OsslParam::for_slice(c"answer", 5, &mut bytes).expect("byte descriptor");

        let shared = param.as_ref();
        assert_eq!(shared.key(), Some(c"answer"));
        assert_eq!(shared.data_type(), 5);
        assert_eq!(shared.data_size(), 2);
        assert_eq!(shared.data().map(|data| data.len()), Some(2));
        assert_eq!(shared.return_size(), usize::MAX);

        let mut exclusive = param.as_mut();
        assert!(exclusive.set_data_type(4));
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

    #[test]
    fn the_terminator_matches_the_published_constant() {
        // `OSSL_PARAM_END` is `{ NULL, 0, NULL, 0, 0 }`; in particular its
        // `return_size` is zero, not the `OSSL_PARAM_UNMODIFIED` sentinel a
        // real descriptor carries.
        // SAFETY: the constructor takes no arguments and returns the published
        // end descriptor by value, retaining nothing.
        let published = unsafe { ffi::OSSL_PARAM_construct_end() };
        let ours = end_descriptor();
        assert!(published.key.is_null() && ours.key.is_null());
        assert!(published.data.is_null() && ours.data.is_null());
        assert_eq!(ours.data_type, published.data_type);
        assert_eq!(ours.data_size, published.data_size);
        assert_eq!(ours.return_size, published.return_size);
        assert_eq!(ours.return_size, 0);

        let end = OsslParam::end();
        // SAFETY: `end` owns one initialized descriptor at this address.
        assert_eq!(unsafe { (*end.as_ref().as_ptr()).return_size }, 0);
        let array = OsslParamArray::new([]);
        // SAFETY: the array always owns at least its initialized terminator.
        assert_eq!(unsafe { (*array.as_ptr()).return_size }, 0);
    }

    #[test]
    fn a_validated_run_of_inline_descriptors_spans_the_whole_array() {
        let mut bytes = [MaybeUninit::new(0_u8); 4];
        let mut values = [
            OsslParam::for_slice(c"answer", 1, &mut bytes).expect("byte descriptor"),
            OsslParam::end(),
        ];
        let first = values[0].as_ref().as_ptr();

        let mut list = OsslParamListMut::from_values(&mut values).expect("terminated run");
        // The array pointer addresses the first descriptor and is derived from
        // the borrow of the whole run, so the terminator is reachable from it.
        assert_eq!(list.as_mut_ptr().cast_const(), first);
        // SAFETY: `list` validated a two-descriptor run at this address.
        assert!(unsafe {
            OsslParam::is_terminator_at(NonNull::new(list.as_mut_ptr()).unwrap(), 1)
        });
        assert_eq!(list.as_ref().values().len(), 1);
        assert_eq!(
            list.as_ref().values().get(0).unwrap().key(),
            Some(c"answer")
        );
    }

    #[test]
    fn an_unterminated_or_empty_run_is_rejected() {
        let mut bytes = [MaybeUninit::new(0_u8); 4];
        let mut unterminated =
            [OsslParam::for_slice(c"answer", 1, &mut bytes).expect("byte descriptor")];
        assert!(OsslParamListMut::from_values(&mut unterminated).is_none());

        let mut empty: [CVal<OsslParam<'static>>; 0] = [];
        assert!(OsslParamListMut::from_values(&mut empty).is_none());
    }

    #[test]
    fn terminated_lists_and_callbacks_bound_the_c_array() {
        let raw = [
            ffi::ossl_param_st {
                key: c"answer".as_ptr(),
                data_type: 1,
                data: core::ptr::null_mut(),
                data_size: 0,
                return_size: 0,
            },
            ffi::ossl_param_st {
                key: core::ptr::null(),
                data_type: 0,
                data: core::ptr::null_mut(),
                data_size: 0,
                return_size: 0,
            },
        ];
        // SAFETY: `OsslParam` is layout-compatible with `ossl_param_st`; both
        // initialized descriptors and their static key outlive this view.
        let run = unsafe {
            CSlice::from_raw_parts(
                NonNull::new_unchecked(raw.as_ptr().cast_mut().cast::<OsslParam<'static>>()),
                raw.len(),
            )
        };
        let list = OsslParamListRef::new(run).expect("terminated list");
        assert_eq!(list.values().len(), 1);

        let mut seen = 0usize;
        let mut closure = |params: CSlice<'_, OsslParam<'_>>| {
            seen += params.len();
            1
        };
        let mut callback = OsslCallback::new(&mut closure);
        // SAFETY: the pair is invoked synchronously while `callback` remains
        // mutably borrowed, with the same live terminated array as above.
        let (function, argument) = unsafe { callback.raw_parts() };
        // SAFETY: the raw pair and parameter array satisfy the callback
        // contract for this one synchronous invocation.
        let status = unsafe { function.expect("trampoline")(raw.as_ptr(), argument) };
        assert_eq!(status, 1);
        assert_eq!(seen, 1);
    }

    #[test]
    fn parameter_array_adds_its_terminator() {
        let array = OsslParamArray::new([]);
        // SAFETY: the array always owns at least its initialized terminator.
        assert!(unsafe { (*array.as_ptr()).key.is_null() });
        assert_eq!(array.as_list().values().len(), 0);
    }

    #[test]
    fn parameter_array_takes_over_the_descriptor_borrows_and_reads_back() {
        let mut bytes = [MaybeUninit::new(0_u8); 4];
        let mut array = OsslParamArray::new([
            OsslParam::for_slice(c"answer", 2, &mut bytes).expect("byte descriptor")
        ]);
        let start = array.as_ptr();

        // The moved descriptor is reachable again only through the array, and
        // still describes the same exclusively borrowed run.
        let values = array.as_list().values();
        assert_eq!(values.len(), 1);
        let first = values.get(0).expect("the moved descriptor");
        assert_eq!(first.key(), Some(c"answer"));
        assert_eq!(first.data().map(|data| data.len()), Some(4));

        // The exclusive run an OpenSSL getter is handed spans the whole array,
        // terminator included, and starts at the same descriptor.
        let mut list = array.as_list_mut();
        assert_eq!(list.as_mut_ptr().cast_const(), start);
        // SAFETY: the array owns two initialized descriptors at this address.
        assert!(unsafe {
            OsslParam::is_terminator_at(NonNull::new(list.as_mut_ptr()).unwrap(), 1)
        });
        assert_eq!(list.as_ref().values().len(), 1);
    }

    #[test]
    fn the_pointer_slot_data_types_publish_no_byte_view() {
        // `OSSL_PARAM_UTF8_PTR` / `OSSL_PARAM_OCTET_PTR` keep a lone `void *`
        // in `data` and use `data_size` for the referent, so `data_size` bytes
        // at `data` describe nothing. The accessors must not hand out that run.
        let mut buffer = [MaybeUninit::new(0_u8); 4];
        let mut slot: *const c_void = core::ptr::null();
        let mut raw = ffi::ossl_param_st {
            key: c"pointer".as_ptr(),
            data_type: ffi::OSSL_PARAM_OCTET_PTR,
            data: core::ptr::from_mut(&mut slot).cast::<c_void>(),
            data_size: 4096,
            return_size: 0,
        };

        // SAFETY: the descriptor and its pointer slot are live for this scope,
        // and nothing else reaches them while the handle is used.
        let mut exclusive =
            unsafe { OsslParamMut::from_ptr(core::ptr::from_mut(&mut raw)) }.expect("handle");
        assert_eq!(exclusive.as_ref().data_size(), 4096);
        assert!(exclusive.as_ref().data().is_none());
        assert!(exclusive.data_mut().is_none());
        // A byte run cannot be installed while the descriptor still says
        // "pointer slot": the provider would store a whole `void *` into it.
        // SAFETY: `buffer` outlives this handle and nothing else views it.
        let run = unsafe {
            CSliceMut::from_raw_parts(NonNull::new_unchecked(buffer.as_mut_ptr()), buffer.len())
        };
        let Err(run) = exclusive.set_data(Some(run)) else {
            panic!("a byte run must not be installed under a pointer-slot type")
        };
        assert_eq!(run.len(), 4);
        assert_eq!(exclusive.as_ref().data_size(), 4096);
        // Nor can the descriptor be retyped out of the pointer-slot class
        // while its `data` still addresses a pointer slot.
        assert!(!exclusive.set_data_type(5));
        assert_eq!(exclusive.as_ref().data_type(), ffi::OSSL_PARAM_OCTET_PTR);
        // Switching between the two pointer-slot types keeps the coupling.
        assert!(exclusive.set_data_type(ffi::OSSL_PARAM_UTF8_PTR));

        // Clearing still happens; only the reclaimed run is withheld.
        assert!(exclusive.take_data().is_none());
        assert_eq!(exclusive.as_ref().data_size(), 0);

        // With `data` cleared the class change is free, and the very same
        // descriptor read as an octet string does carry a run again.
        assert!(exclusive.set_data_type(5));
        let Ok(previous) = exclusive.set_data(Some(run)) else {
            panic!("a cleared descriptor accepts a byte run")
        };
        assert!(previous.is_none());
        assert_eq!(exclusive.as_ref().data().map(|data| data.len()), Some(4));
    }

    #[test]
    fn the_pointer_slot_data_types_have_no_byte_buffer_constructor() {
        // `crypto/params.c` loads and stores a whole `const void *` through
        // `data` for these two, so a byte buffer cannot describe one: it need
        // be neither pointer-sized nor pointer-aligned. Handing such a
        // descriptor to a provider is a misaligned out-of-bounds access, and
        // no `unsafe` would appear at the call site.
        let mut one_byte = [MaybeUninit::new(0_u8); 1];
        assert!(OsslParam::for_slice(c"mac", ffi::OSSL_PARAM_UTF8_PTR, &mut one_byte).is_none());
        assert!(OsslParam::for_slice(c"mac", ffi::OSSL_PARAM_OCTET_PTR, &mut one_byte).is_none());
        // A buffer that happens to be wide enough is refused just the same:
        // the descriptor's `data_size` would still have to mean the referent.
        let mut wide = [MaybeUninit::new(0_u8); 64];
        assert!(OsslParam::for_slice(c"mac", ffi::OSSL_PARAM_UTF8_PTR, &mut wide).is_none());
        // Every value-carrying type still builds.
        assert!(OsslParam::for_slice(c"mac", 5, &mut wide).is_some());
    }
}

//! Wrappers assigned from `include/openssl/crypto.h`.

use core::ffi::c_void;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::stack::stack::{Stack, StackMut, StackRef};

/// Wraps: stack_st_void
///
/// Type-erased instance of OpenSSL's generic stack. `DEFINE_STACK_OF` only
/// forward-declares the tag and casts every operation to `OPENSSL_STACK *`,
/// and the element type is `void`, so nothing about a stored element is
/// recoverable from the container.
///
/// It owns its pointer array and never its elements. `crypto/ex_data.c`
/// depends on exactly that split: `CRYPTO_free_ex_data` releases each slot
/// through the `free_func` its extra-data class registered and only then
/// calls `sk_void_free` on the container itself.
pub type VoidStack = Stack<c_void>;

/// Shared borrowed handle to a type-erased OpenSSL stack.
pub type VoidStackRef<'a> = StackRef<'a, c_void>;

/// Exclusive borrowed handle to a type-erased OpenSSL stack.
pub type VoidStackMut<'a> = StackMut<'a, c_void>;

ffibox::define_ctype!(
    /// Wraps: crypto_ex_data_st
    ///
    /// Layout-compatible storage for OpenSSL's per-object extra-data state.
    /// The value is embedded by value in the C object that owns it — a `BIO`,
    /// an `SSL`, an `X509` — and is never allocated on its own.
    ///
    /// Reviewed against `crypto/ex_data.c`, the only file in the tree that
    /// reads or writes either field. The two fields are not independent
    /// storage. `ctx` selects the `OSSL_EX_DATA_GLOBAL` class registry that
    /// every extra-data index resolves against, and slot `i` of `sk` belongs
    /// to the `EX_CALLBACK` registered at index `i` for the class the
    /// containing object was initialized with. Only the pair (class index,
    /// parent object) — which the value itself does not record — makes the
    /// contents interpretable, so every accessor able to pair a slot with a
    /// callback other than the one that created it is `unsafe`.
    ///
    /// The type deliberately carries no [`ffibox::CValued`] contract. Its
    /// complete teardown is `CRYPTO_free_ex_data(class_index, obj, ad)`, which
    /// hands each slot to its registered `free_func`, then releases the
    /// container with `sk_void_free` and nulls both fields while keeping the
    /// `CRYPTO_EX_DATA` storage itself. Neither the class index nor the parent
    /// object is recoverable from a `crypto_ex_data_st`, so a `c_dispose`
    /// could only perform the container half — C's own `err:` fallback — and
    /// would look like teardown while skipping every registered callback.
    /// [`CryptoExData::zeroed`] is both the state `ossl_crypto_new_ex_data_ex`
    /// starts from and the state `CRYPTO_free_ex_data` leaves behind, so an
    /// untouched value owns nothing and needs no teardown.
    CryptoExData,
    CryptoExDataRef,
    CryptoExDataMut,
    ffi::crypto_ex_data_st
);

impl<'a> CryptoExDataRef<'a> {
    /// Wraps: crypto_ex_data_st.ctx
    ///
    /// Returns the optional borrowed library context. A null field denotes
    /// OpenSSL's default context, which is what `CRYPTO_new_ex_data` installs.
    ///
    /// The extra-data state never reference-counts or releases the context:
    /// `ossl_crypto_new_ex_data_ex` stores the caller's pointer,
    /// `CRYPTO_dup_ex_data` copies it to the duplicate, and
    /// `CRYPTO_free_ex_data` only nulls it. C reaches through this borrow to
    /// mutate the context's extra-data globals under the context's own lock,
    /// which is why the borrow is shared rather than exclusive.
    #[must_use]
    pub fn ctx(&self) -> Option<OsslLibCtxRef<'a>> {
        // SAFETY: the handle carries a live shared borrow of initialized
        // extra-data storage. Raw-place projection copies the pointer without
        // forming a reference to C memory; the field's borrow is valid for the
        // containing extra-data lifetime.
        unsafe {
            let context = core::ptr::addr_of!((*self.as_ptr()).ctx).read();
            OsslLibCtxRef::from_ptr(context)
        }
    }

    /// Wraps: crypto_ex_data_st.sk
    ///
    /// Borrows the optional owned container. `CRYPTO_set_ex_data` allocates it
    /// lazily and pads it with null slots up to the requested index, so an
    /// absent container and a container shorter than an index both read back
    /// as "no data at that index".
    ///
    /// The container owns only its pointer array; its type-erased elements
    /// retain the ownership policies registered by their extra-data callbacks.
    #[must_use]
    pub fn sk(&self) -> Option<VoidStackRef<'a>> {
        // SAFETY: a non-null `sk` field owns a live `STACK_OF(void)` container.
        // Generated stack tags erase to `OPENSSL_STACK`, and raw-place
        // projection copies the pointer without forming a reference.
        unsafe {
            let stack = core::ptr::addr_of!((*self.as_ptr()).sk).read();
            VoidStackRef::from_ptr(stack.cast())
        }
    }
}

impl CryptoExDataMut<'_> {
    /// Exclusively reborrows the optional stack container.
    #[must_use]
    pub fn sk_mut(&mut self) -> Option<VoidStackMut<'_>> {
        // SAFETY: the exclusive extra-data handle supplies exclusive access to
        // its owned stack field for this reborrow. The generated stack tag and
        // `OPENSSL_STACK` have the representation guaranteed by OpenSSL's
        // `STACK_OF` API.
        unsafe {
            let stack = core::ptr::addr_of!((*self.as_mut_ptr()).sk).read();
            VoidStackMut::from_ptr(stack.cast())
        }
    }

    /// Stores a caller-managed library context, or selects OpenSSL's default
    /// context with `None`.
    ///
    /// # Safety
    ///
    /// A non-null `context` must remain live until this field is replaced or
    /// the containing C object's extra-data state can no longer be used.
    /// `CryptoExData` has no lifetime parameter with which to express that
    /// stored-borrow obligation.
    ///
    /// The field is also the class-registry selector: every index resolves
    /// through `ossl_lib_ctx_get_ex_data_global(ad->ctx)`. On a value that
    /// already holds data, the caller must keep that selection coherent — the
    /// `EX_CALLBACK` set of the new context must be the one that produced the
    /// stored slots, or `CRYPTO_free_ex_data` hands slot `i` to whatever
    /// `free_func` the new registry happens to hold at index `i`. `None` is
    /// not exempt from this: null selects the default context's registry, it
    /// does not disable the lookup.
    pub unsafe fn set_ctx(&mut self, context: Option<OsslLibCtxRef<'_>>) {
        let context = context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
        // SAFETY: the exclusive handle permits replacing the pointer field;
        // the caller supplies the otherwise-unexpressible stored lifetime and
        // registry coherence.
        unsafe { core::ptr::addr_of_mut!((*self.as_mut_ptr()).ctx).write(context) }
    }

    /// Replaces the owned stack container and releases the previous container.
    ///
    /// As with `OPENSSL_sk_free`, replacing the container does not release its
    /// type-erased elements; their registered extra-data callbacks own that
    /// policy.
    ///
    /// # Safety
    ///
    /// Slot `i` of `stack` is handed to the `EX_CALLBACK` registered at index
    /// `i` for the containing object's extra-data class: `dup_func` by
    /// `CRYPTO_dup_ex_data` and `free_func` by `CRYPTO_free_ex_data`, each of
    /// which casts it to its own application type. The caller must ensure
    /// every non-null slot satisfies the contract of the callback that will
    /// receive it — the same obligation
    /// [`BIO_set_ex_data`](crate::bio::bio_lib::BIO_set_ex_data) states for a
    /// single index, here for the whole indexed array at once. Nothing in a
    /// `STACK_OF(void)` records which class or index its slots were written
    /// for, so Rust cannot check it.
    pub unsafe fn set_sk(&mut self, stack: Option<CBox<VoidStack>>) {
        let stack = stack.map_or(ptr::null_mut(), |stack| stack.into_raw().cast());
        // SAFETY: the exclusive handle permits replacing the owned field. A
        // non-null old field carries the unique container ownership obligation
        // established by the `crypto_ex_data_st` contract.
        let previous = unsafe { core::ptr::addr_of_mut!((*self.as_mut_ptr()).sk).replace(stack) };
        // SAFETY: OpenSSL's generated `stack_st_void` tag erases to the live
        // `OPENSSL_STACK` allocation owned by this field. Ownership transfers
        // exactly once out of the field before the optional owner is dropped.
        drop(unsafe { CBox::<VoidStack>::from_raw(previous.cast()) });
    }

    /// Takes ownership of the stack container, leaving the field null.
    ///
    /// Null is both the state `CRYPTO_free_ex_data` leaves behind and the
    /// state `CRYPTO_set_ex_data` reallocates from, so the value stays usable.
    /// The slots leave with the container: no registered `free_func` will ever
    /// see them again, so the application data they address leaks unless the
    /// caller releases it or returns the container through
    /// [`set_sk`](Self::set_sk). Leaking is safe, which is why taking is.
    #[must_use]
    pub fn take_sk(&mut self) -> Option<CBox<VoidStack>> {
        // SAFETY: the exclusive handle permits replacing the owned pointer
        // with null, so a non-null old value transfers its unique obligation.
        let stack =
            unsafe { core::ptr::addr_of_mut!((*self.as_mut_ptr()).sk).replace(ptr::null_mut()) };
        // SAFETY: a non-null field is a fully initialized generated stack
        // whose representation and destructor are those of `OPENSSL_STACK`.
        unsafe { CBox::<VoidStack>::from_raw(stack.cast()) }
    }
}

#[cfg(test)]
mod tests {
    use core::ffi::{c_int, c_long};
    use core::ptr;
    use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
    use std::sync::{Mutex, OnceLock};

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::bio::context::OsslLibCtx;
    use crate::stack::stack::{
        OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value, StackElement,
    };

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn void_stack_uses_the_generic_stack_representation() {
        assert_owned_cloneable_cell::<VoidStack>();
        // The owner and both handles are one pointer wide: the generated tag
        // adds nothing to `OPENSSL_STACK`'s representation.
        assert_eq!(
            core::mem::size_of::<CBox<VoidStack>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<VoidStackRef<'static>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::size_of::<VoidStackMut<'static>>(),
            core::mem::size_of::<*mut ffi::OPENSSL_STACK>()
        );
    }

    #[test]
    fn void_stack_owner_produces_void_stack_handles() {
        // `OPENSSL_sk_dup(NULL)` returns a new empty container. Ownership is
        // transferred to `CBox`, whose generic stack strategy frees it.
        // SAFETY: the returned pointer is null or a fully initialized,
        // uniquely owned `OPENSSL_STACK` allocation.
        let mut stack = unsafe { CBox::<VoidStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
            .expect("allocate empty OpenSSL stack");
        let raw = stack.as_ptr();

        let shared: VoidStackRef<'_> = stack.as_ref();
        assert_eq!(shared.as_ptr(), raw.cast_const());
        let mut exclusive: VoidStackMut<'_> = stack.as_mut();
        assert_eq!(exclusive.as_mut_ptr(), raw);
    }

    #[test]
    fn void_stack_keeps_erased_slots_and_never_releases_them() {
        // The elements are opaque `void *` slots. A stack keeps their
        // addresses and, like `CRYPTO_free_ex_data`'s final `sk_void_free`,
        // hands them back without ever releasing them.
        let first = Box::new(0xC3_u8);
        let second = Box::new(0x3C_u8);
        // SAFETY: both boxes outlive every stack below, and a type-erased
        // stack has no comparator or destructor that could dereference them.
        let (first_element, second_element) = unsafe {
            (
                StackElement::<c_void>::from_raw(ptr::from_ref(&*first).cast_mut().cast())
                    .expect("non-null element address"),
                StackElement::<c_void>::from_raw(ptr::from_ref(&*second).cast_mut().cast())
                    .expect("non-null element address"),
            )
        };

        let mut stack = OPENSSL_sk_new_null::<c_void>().expect("allocate type-erased stack");
        {
            let mut exclusive: VoidStackMut<'_> = stack.as_mut();
            // SAFETY: both boxes outlive the stack, as established above.
            unsafe {
                assert_eq!(
                    OPENSSL_sk_push(Some(&mut exclusive), Some(first_element)),
                    Some(1)
                );
                assert_eq!(
                    OPENSSL_sk_push(Some(&mut exclusive), Some(second_element)),
                    Some(2)
                );
                // `CRYPTO_set_ex_data` grows the stack with null slots, which
                // the wrapper represents as an absent element.
                assert_eq!(OPENSSL_sk_push(Some(&mut exclusive), None), Some(3));
            }
        }
        let shared: VoidStackRef<'_> = stack.as_ref();
        assert_eq!(OPENSSL_sk_num(Some(shared)), Some(3));
        assert_eq!(
            OPENSSL_sk_value(Some(shared), 0).map(StackElement::as_non_null),
            Some(first_element.as_non_null())
        );
        assert!(OPENSSL_sk_value(Some(shared), 2).is_none());

        drop(stack);
        assert_eq!(*first, 0xC3);
        assert_eq!(*second, 0x3C);
    }

    #[test]
    fn crypto_ex_data_preserves_layout_and_handle_shape() {
        assert_eq!(
            core::mem::size_of::<CryptoExData>(),
            core::mem::size_of::<ffi::crypto_ex_data_st>()
        );
        assert_eq!(
            core::mem::align_of::<CryptoExData>(),
            core::mem::align_of::<ffi::crypto_ex_data_st>()
        );
        assert_eq!(
            core::mem::size_of::<CryptoExDataRef<'static>>(),
            core::mem::size_of::<*mut ffi::crypto_ex_data_st>()
        );
        assert_eq!(
            core::mem::size_of::<CryptoExDataMut<'static>>(),
            core::mem::size_of::<*mut ffi::crypto_ex_data_st>()
        );
    }

    #[test]
    fn crypto_ex_data_fields_preserve_borrows_and_stack_ownership() {
        let mut storage = CryptoExData::zeroed();
        let storage_ptr = core::ptr::addr_of_mut!(storage).cast::<ffi::crypto_ex_data_st>();
        // SAFETY: `storage` is initialized and remains live and exclusively
        // accessed through this handle until the end of the test.
        let mut ex_data = unsafe { CryptoExDataMut::from_ptr(storage_ptr) }
            .expect("address of local storage is non-null");

        assert!(ex_data.as_ref().ctx().is_none());
        assert!(ex_data.as_ref().sk().is_none());

        // SAFETY: the constructor returns null or a fresh context carrying one
        // ownership obligation.
        let context = unsafe { CBox::<OsslLibCtx>::from_raw(ffi::OSSL_LIB_CTX_new()) }
            .expect("allocate library context");
        let context_ptr = context.as_ptr();
        // SAFETY: `context` remains alive until after the field is cleared, and
        // this value holds no extra data, so retargeting its class registry
        // cannot pair a stored slot with a foreign callback.
        unsafe { ex_data.set_ctx(Some(context.as_ref())) };
        assert_eq!(
            ex_data.as_ref().ctx().expect("stored context").as_ptr(),
            context_ptr.cast_const()
        );
        // Null is the default-context selector, not an absent selector.
        // SAFETY: as above; the value still holds no extra data.
        unsafe { ex_data.set_ctx(None) };
        assert!(ex_data.as_ref().ctx().is_none());

        // `OPENSSL_sk_dup(NULL)` creates an empty container.
        // SAFETY: the returned pointer is null or a fully initialized, uniquely
        // owned stack allocation.
        let stack = unsafe { CBox::<VoidStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
            .expect("allocate empty stack");
        let stack_ptr = stack.as_ptr();
        // SAFETY: the container is empty and this value is never handed to
        // `CRYPTO_free_ex_data`, so no extra-data callback ever receives a
        // slot from it.
        unsafe { ex_data.set_sk(Some(stack)) };
        assert_eq!(
            ex_data.as_ref().sk().expect("stored stack").as_ptr(),
            stack_ptr.cast_const()
        );
        assert_eq!(
            ex_data.sk_mut().expect("stored mutable stack").as_mut_ptr(),
            stack_ptr
        );

        let taken = ex_data.take_sk().expect("take stored stack");
        assert_eq!(taken.as_ptr(), stack_ptr);
        assert!(ex_data.as_ref().sk().is_none());
        drop(taken);
        drop(context);
    }

    /// The extra-data class registry is process-global, so the tests that
    /// drive it share one registered index and run one at a time.
    static APP_CLASS_INDEX: OnceLock<c_int> = OnceLock::new();
    static APP_CLASS_LOCK: Mutex<()> = Mutex::new(());

    /// What the last `free_func` invocation was handed, for the assertions
    /// below: the parent object, the slot value and the index.
    static FREED_PARENT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FREED_SLOT: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());
    static FREED_INDEX: AtomicI32 = AtomicI32::new(-1);
    static DUPLICATED: AtomicI32 = AtomicI32::new(0);

    /// `CRYPTO_EX_free` for the test class: records its arguments instead of
    /// releasing anything, since the tests own the storage it is handed.
    unsafe extern "C" fn record_free(
        parent: *mut c_void,
        slot: *mut c_void,
        _ad: *mut ffi::CRYPTO_EX_DATA,
        index: c_int,
        _argl: c_long,
        _argp: *mut c_void,
    ) {
        if !slot.is_null() {
            FREED_PARENT.store(parent, Ordering::SeqCst);
            FREED_SLOT.store(slot, Ordering::SeqCst);
            FREED_INDEX.store(index, Ordering::SeqCst);
        }
    }

    /// `CRYPTO_EX_dup` for the test class: keeps the source value, which
    /// `CRYPTO_dup_ex_data` then stores in the destination.
    unsafe extern "C" fn record_dup(
        _to: *mut ffi::CRYPTO_EX_DATA,
        _from: *const ffi::CRYPTO_EX_DATA,
        _from_d: *mut *mut c_void,
        _index: c_int,
        _argl: c_long,
        _argp: *mut c_void,
    ) -> c_int {
        DUPLICATED.fetch_add(1, Ordering::SeqCst);
        1
    }

    /// Registers the one application extra-data index these tests use.
    fn app_class_index() -> c_int {
        *APP_CLASS_INDEX.get_or_init(|| {
            // SAFETY: the class is a valid `CRYPTO_EX_INDEX_*` constant and
            // both callbacks have the C signatures their typedefs require.
            let index = unsafe {
                ffi::CRYPTO_get_ex_new_index(
                    ffi::CRYPTO_EX_INDEX_APP as c_int,
                    0,
                    ptr::null_mut(),
                    None,
                    Some(record_dup),
                    Some(record_free),
                )
            };
            assert!(index >= 0, "register an application extra-data index");
            index
        })
    }

    #[test]
    fn crypto_ex_data_view_tracks_the_c_extra_data_machinery() {
        let _serialized = APP_CLASS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let index = app_class_index();
        let slot = usize::try_from(index).expect("a registered index is non-negative");

        // Stands in for the C object that embeds the extra-data value, and for
        // the application data stored at `index`.
        let mut parent = 0_u8;
        let parent_ptr = ptr::from_mut(&mut parent).cast::<c_void>();
        let mut value = 0xA5_u8;
        let value_ptr = ptr::from_mut(&mut value).cast::<c_void>();

        let mut storage = CryptoExData::zeroed();
        let raw = core::ptr::addr_of_mut!(storage).cast::<ffi::crypto_ex_data_st>();

        // SAFETY: `raw` addresses live, zero-initialized extra-data storage,
        // which is the state this initializer expects.
        let initialized =
            unsafe { ffi::CRYPTO_new_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, parent_ptr, raw) };
        assert_eq!(initialized, 1);
        {
            // SAFETY: `storage` is live and no other handle to it exists here.
            let view = unsafe { CryptoExDataRef::from_ptr(raw) }.expect("non-null storage");
            // `CRYPTO_new_ex_data` installs the caller's context — null here,
            // the default one — and leaves the container unallocated until the
            // first `CRYPTO_set_ex_data`.
            assert!(view.ctx().is_none());
            assert!(view.sk().is_none());
        }

        // SAFETY: `raw` is live extra-data storage and `value` outlives every
        // use of the slot below.
        assert_eq!(unsafe { ffi::CRYPTO_set_ex_data(raw, index, value_ptr) }, 1);
        {
            // SAFETY: as above.
            let view = unsafe { CryptoExDataRef::from_ptr(raw) }.expect("non-null storage");
            let container = view
                .sk()
                .expect("CRYPTO_set_ex_data allocates the container");
            // The container is padded with null slots up to `index`, so the
            // wrapper sees exactly the array C built.
            assert_eq!(OPENSSL_sk_num(Some(container)), Some(slot + 1));
            assert_eq!(
                OPENSSL_sk_value(Some(container), slot)
                    .map(|element| element.as_non_null().as_ptr()),
                Some(value_ptr)
            );
        }

        // The owning getter and setter round-trip C's own container: after
        // taking it the value reads as empty, and after returning it the slot
        // is visible again.
        {
            // SAFETY: `storage` is live and exclusively accessed through this
            // handle for the block.
            let mut ex_data = unsafe { CryptoExDataMut::from_ptr(raw) }.expect("non-null storage");
            let container = ex_data.take_sk().expect("owned container");
            assert!(ex_data.as_ref().sk().is_none());
            // SAFETY: `raw` is live extra-data storage.
            assert!(unsafe { ffi::CRYPTO_get_ex_data(raw, index) }.is_null());
            // SAFETY: this is the very container C allocated for this value,
            // holding the slots this class's own callbacks wrote, so every
            // index still pairs with the callback that created it.
            unsafe { ex_data.set_sk(Some(container)) };
        }
        // SAFETY: `raw` is live extra-data storage.
        assert_eq!(unsafe { ffi::CRYPTO_get_ex_data(raw, index) }, value_ptr);

        FREED_SLOT.store(ptr::null_mut(), Ordering::SeqCst);
        // SAFETY: `raw` is live extra-data storage initialized for this class,
        // and `parent`/`value` outlive the callbacks it runs.
        unsafe { ffi::CRYPTO_free_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, parent_ptr, raw) };
        assert_eq!(FREED_PARENT.load(Ordering::SeqCst), parent_ptr);
        assert_eq!(FREED_SLOT.load(Ordering::SeqCst), value_ptr);
        assert_eq!(FREED_INDEX.load(Ordering::SeqCst), index);

        // The disposer releases the container and nulls both fields, leaving
        // the storage reusable — the state `zeroed()` produces.
        // SAFETY: `storage` is still live; only its fields were cleared.
        let view = unsafe { CryptoExDataRef::from_ptr(raw) }.expect("non-null storage");
        assert!(view.ctx().is_none());
        assert!(view.sk().is_none());
    }

    #[test]
    fn crypto_ex_data_duplicate_shares_the_context_and_owns_its_container() {
        let _serialized = APP_CLASS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let index = app_class_index();

        let mut parent = 0_u8;
        let parent_ptr = ptr::from_mut(&mut parent).cast::<c_void>();
        let mut value = 0x5A_u8;
        let value_ptr = ptr::from_mut(&mut value).cast::<c_void>();

        let mut source = CryptoExData::zeroed();
        let source_raw = core::ptr::addr_of_mut!(source).cast::<ffi::crypto_ex_data_st>();
        let mut copy = CryptoExData::zeroed();
        let copy_raw = core::ptr::addr_of_mut!(copy).cast::<ffi::crypto_ex_data_st>();

        // SAFETY: both addresses are live, zero-initialized extra-data storage,
        // and `value` outlives every use of the slot.
        unsafe {
            assert_eq!(
                ffi::CRYPTO_new_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, parent_ptr, source_raw),
                1
            );
            assert_eq!(ffi::CRYPTO_set_ex_data(source_raw, index, value_ptr), 1);
            assert_eq!(
                ffi::CRYPTO_new_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, parent_ptr, copy_raw),
                1
            );
            assert_eq!(
                ffi::CRYPTO_dup_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, copy_raw, source_raw),
                1
            );
        }
        assert!(DUPLICATED.load(Ordering::SeqCst) > 0);

        // SAFETY: both values are live and no other handle to either exists.
        let (source_view, copy_view) = unsafe {
            (
                CryptoExDataRef::from_ptr(source_raw).expect("non-null storage"),
                CryptoExDataRef::from_ptr(copy_raw).expect("non-null storage"),
            )
        };
        // `to->ctx = from->ctx` copies a borrow: neither value released or
        // reference-counted the context, so both select the same registry.
        assert_eq!(
            source_view.ctx().map(|ctx| ctx.as_ptr()),
            copy_view.ctx().map(|ctx| ctx.as_ptr())
        );
        // The container, by contrast, is owned: the duplicate allocated its
        // own through `CRYPTO_set_ex_data`, and only the slot value is shared.
        let source_container = source_view.sk().expect("source container");
        let copy_container = copy_view.sk().expect("duplicate container");
        assert_ne!(source_container.as_ptr(), copy_container.as_ptr());
        assert_eq!(
            OPENSSL_sk_value(Some(copy_container), usize::try_from(index).unwrap())
                .map(|element| element.as_non_null().as_ptr()),
            Some(value_ptr)
        );

        // Both containers are freed independently; neither release touches the
        // shared slot value, which the test still owns.
        // SAFETY: both are live extra-data values initialized for this class,
        // and `parent`/`value` outlive the callbacks they run.
        unsafe {
            ffi::CRYPTO_free_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, parent_ptr, source_raw);
            ffi::CRYPTO_free_ex_data(ffi::CRYPTO_EX_INDEX_APP as c_int, parent_ptr, copy_raw);
        }
        assert_eq!(value, 0x5A);
    }
}

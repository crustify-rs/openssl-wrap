//! Wrappers assigned from `include/openssl/crypto.h`.

use core::ffi::c_void;
use core::ptr;

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::stack::stack::{Stack, StackMut, StackRef};

/// Wraps: stack_st_void
/// Type-erased instance of OpenSSL's generic stack representation.
pub type VoidStack = Stack<c_void>;

/// Shared borrowed handle to a type-erased OpenSSL stack.
pub type VoidStackRef<'a> = StackRef<'a, c_void>;

/// Exclusive borrowed handle to a type-erased OpenSSL stack.
pub type VoidStackMut<'a> = StackMut<'a, c_void>;

ffibox::define_ctype!(
    /// Wraps: crypto_ex_data_st
    ///
    /// Layout-compatible storage for OpenSSL's per-object extra-data state.
    /// The value is normally embedded in another C object. Its complete
    /// disposal also needs that object's extra-data class and parent pointer,
    /// so the layout wrapper does not claim an independent drop strategy.
    CryptoExData,
    CryptoExDataRef,
    CryptoExDataMut,
    ffi::crypto_ex_data_st
);

impl<'a> CryptoExDataRef<'a> {
    /// Wraps: crypto_ex_data_st.ctx
    ///
    /// Returns the optional borrowed library context. A null field denotes
    /// OpenSSL's default context.
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
    /// Borrows the optional owned container. Its type-erased elements retain
    /// the ownership policies registered by their extra-data callbacks.
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

    /// Stores a caller-managed library context.
    ///
    /// # Safety
    ///
    /// A non-null `context` must remain live until this field is cleared or
    /// the containing C object's extra-data state can no longer be used.
    /// `CryptoExData` has no lifetime parameter with which to express that
    /// stored-borrow obligation.
    pub unsafe fn set_ctx(&mut self, context: Option<OsslLibCtxRef<'_>>) {
        let context = context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
        // SAFETY: the exclusive handle permits replacing the pointer field;
        // the caller supplies the otherwise-unexpressible stored lifetime.
        unsafe { core::ptr::addr_of_mut!((*self.as_mut_ptr()).ctx).write(context) }
    }

    /// Clears the borrowed context, selecting OpenSSL's default context.
    pub fn clear_ctx(&mut self) {
        // SAFETY: null is the valid default-context representation and the
        // exclusive handle permits replacing this field.
        unsafe { core::ptr::addr_of_mut!((*self.as_mut_ptr()).ctx).write(ptr::null_mut()) }
    }

    /// Replaces the owned stack container and releases the previous container.
    ///
    /// As with `OPENSSL_sk_free`, replacing the container does not release its
    /// type-erased elements; their registered extra-data callbacks own that
    /// policy.
    pub fn set_sk(&mut self, stack: Option<CBox<VoidStack>>) {
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
    use core::ptr;

    use ffibox::{CBox, CCell, CCloned, CDropped};
    use libcrypto_sys as ffi;

    use super::*;
    use crate::bio::context::OsslLibCtx;

    fn assert_owned_cloneable_cell<T: CCell + CCloned + CDropped>() {}

    #[test]
    fn void_stack_uses_the_generic_stack_representation() {
        assert_owned_cloneable_cell::<VoidStack>();
        assert_eq!(
            core::mem::size_of::<VoidStack>(),
            core::mem::size_of::<ffi::OPENSSL_STACK>()
        );
        assert_eq!(
            core::mem::align_of::<VoidStack>(),
            core::mem::align_of::<ffi::OPENSSL_STACK>()
        );
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
        // SAFETY: `context` remains alive until after the field is cleared.
        unsafe { ex_data.set_ctx(Some(context.as_ref())) };
        assert_eq!(
            ex_data.as_ref().ctx().expect("stored context").as_ptr(),
            context_ptr.cast_const()
        );
        ex_data.clear_ctx();
        assert!(ex_data.as_ref().ctx().is_none());

        // `OPENSSL_sk_dup(NULL)` creates an empty container.
        // SAFETY: the returned pointer is null or a fully initialized, uniquely
        // owned stack allocation.
        let stack = unsafe { CBox::<VoidStack>::from_raw(ffi::OPENSSL_sk_dup(ptr::null())) }
            .expect("allocate empty stack");
        let stack_ptr = stack.as_ptr();
        ex_data.set_sk(Some(stack));
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
}

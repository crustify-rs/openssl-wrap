//! Wrappers assigned from `crypto/evp/mac_lib.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_char, c_void};
use core::ptr;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use crate::core::openssl_core::{OsslParamListMut, OsslParamListRef};
use crate::evp::evp::{EvpMacRef, EvpSkeyRef};
use crate::evp::evp_local::{BorrowedEvpMacCtx, EvpMacCtxMut, EvpMacCtxRef};

/// Wraps: EVP_MAC_CTX_dup
/// Deep-copies a MAC context while retaining its provider dependency.
#[must_use]
pub fn EVP_MAC_CTX_dup(ctx: EvpMacCtxRef<'_>) -> Option<BorrowedEvpMacCtx<'_>> {
    ctx.try_dup()
}

/// Wraps: EVP_MAC_CTX_free
/// Releases an owned MAC context early; dropping it is equivalent.
pub fn EVP_MAC_CTX_free(ctx: Option<BorrowedEvpMacCtx<'_>>) {
    drop(ctx);
}

/// Wraps: EVP_MAC_CTX_get0_mac
/// Borrows the MAC method retained by an operation context.
#[must_use]
pub fn EVP_MAC_CTX_get0_mac<'a>(ctx: EvpMacCtxRef<'a>) -> Option<EvpMacRef<'a>> {
    // SAFETY: the context is live and retains its method reference.
    let mac = unsafe { ffi::EVP_MAC_CTX_get0_mac(ctx.as_ptr().cast_mut()) };
    // SAFETY: no ownership transfers; the method remains live for `ctx`'s
    // borrow, including its provider/library-context dependency.
    unsafe { EvpMacRef::from_ptr(mac) }
}

/// Wraps: EVP_MAC_CTX_get_block_size
/// Returns the active MAC's block-size hint, or zero when unavailable.
#[must_use]
pub fn EVP_MAC_CTX_get_block_size(ctx: &mut EvpMacCtxMut<'_>) -> usize {
    // SAFETY: the exclusive handle permits querying provider context state.
    unsafe { ffi::EVP_MAC_CTX_get_block_size(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_MAC_CTX_get_mac_size
/// Returns the active MAC output size, or zero when unavailable.
#[must_use]
pub fn EVP_MAC_CTX_get_mac_size(ctx: &mut EvpMacCtxMut<'_>) -> usize {
    // SAFETY: the exclusive handle permits querying provider context state.
    unsafe { ffi::EVP_MAC_CTX_get_mac_size(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_MAC_CTX_get_params
/// Retrieves context parameters into a validated writable descriptor list.
pub fn EVP_MAC_CTX_get_params(
    ctx: &mut EvpMacCtxMut<'_>,
    params: &mut OsslParamListMut<'_, '_>,
) -> i32 {
    // SAFETY: both exclusive borrows are live and the descriptor run is
    // initialized and terminated.
    unsafe { ffi::EVP_MAC_CTX_get_params(ctx.as_mut_ptr(), params.as_mut_ptr()) }
}

/// Wraps: EVP_MAC_CTX_new
/// Creates a MAC context retaining the supplied provider method.
#[must_use]
pub fn EVP_MAC_CTX_new<'a>(mac: EvpMacRef<'a>) -> Option<BorrowedEvpMacCtx<'a>> {
    // SAFETY: the live method supplies its constructor. A non-null result is a
    // fully initialized context carrying one free obligation.
    let ctx = unsafe { ffi::EVP_MAC_CTX_new(mac.as_ptr().cast_mut()) };
    // SAFETY: ownership transfers once and `'a` retains the method's library
    // context for as long as the context can use it.
    unsafe { BorrowedEvpMacCtx::from_raw(ctx) }
}

/// Wraps: EVP_MAC_CTX_set_params
/// Applies a validated, read-only parameter list to provider context state.
pub fn EVP_MAC_CTX_set_params(
    ctx: &mut EvpMacCtxMut<'_>,
    params: &OsslParamListRef<'_, '_>,
) -> i32 {
    // SAFETY: the exclusive context and terminated parameter list remain live
    // throughout the synchronous provider call.
    unsafe { ffi::EVP_MAC_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
}

/// Wraps: EVP_MAC_final
/// Finalizes a MAC into a bounded output buffer and returns the byte count.
pub fn EVP_MAC_final(ctx: &mut EvpMacCtxMut<'_>, output: &mut [u8]) -> Result<usize, i32> {
    let mut written = 0usize;
    // SAFETY: the slice supplies exactly `output.len()` writable bytes and the
    // exclusive context permits finalization. `written` is a live out-slot.
    let status = unsafe {
        ffi::EVP_MAC_final(
            ctx.as_mut_ptr(),
            output.as_mut_ptr(),
            &mut written,
            output.len(),
        )
    };
    if status == 1 && written <= output.len() {
        Ok(written)
    } else {
        Err(status)
    }
}

/// Wraps: EVP_MAC_finalXOF
/// Finalizes an extendable-output MAC into exactly `output.len()` bytes.
pub fn EVP_MAC_finalXOF(ctx: &mut EvpMacCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the exclusive context is live and the slice supplies the exact
    // writable extent passed to the provider.
    unsafe { ffi::EVP_MAC_finalXOF(ctx.as_mut_ptr(), output.as_mut_ptr(), output.len()) }
}

/// Wraps: EVP_MAC_get0_description
/// Borrows the provider's optional MAC description.
#[must_use]
pub fn EVP_MAC_get0_description<'a>(mac: EvpMacRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the live method retains the provider description.
    let description = unsafe { ffi::EVP_MAC_get0_description(mac.as_ptr()) };
    (!description.is_null()).then(|| {
        // SAFETY: OpenSSL publishes a retained NUL-terminated string.
        unsafe { CStr::from_ptr(description) }
    })
}

/// Wraps: EVP_MAC_get0_name
/// Borrows the method's copied primary algorithm name.
#[must_use]
pub fn EVP_MAC_get0_name<'a>(mac: EvpMacRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the method owns its NUL-terminated primary name.
    let name = unsafe { ffi::EVP_MAC_get0_name(mac.as_ptr()) };
    (!name.is_null()).then(|| {
        // SAFETY: the string remains live for the method borrow.
        unsafe { CStr::from_ptr(name) }
    })
}

/// Wraps: EVP_MAC_get_params
/// Retrieves implementation parameters into a validated writable list.
pub fn EVP_MAC_get_params(mac: EvpMacRef<'_>, params: &mut OsslParamListMut<'_, '_>) -> i32 {
    // SAFETY: the shared method and exclusive descriptor list are live; the
    // method record is only read and the list is writable and terminated.
    unsafe { ffi::EVP_MAC_get_params(mac.as_ptr().cast_mut(), params.as_mut_ptr()) }
}

/// Wraps: EVP_MAC_init
/// Initializes or reinitializes a MAC with an optional key and parameters.
pub fn EVP_MAC_init(
    ctx: &mut EvpMacCtxMut<'_>,
    key: Option<&[u8]>,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    let (key, key_len) = key.map_or((ptr::null(), 0), |key| (key.as_ptr(), key.len()));
    let params = params.map_or(ptr::null(), OsslParamListRef::as_ptr);
    // SAFETY: non-null pointers are backed by live bounded slices/lists, and
    // the context is exclusively borrowed for provider initialization.
    unsafe { ffi::EVP_MAC_init(ctx.as_mut_ptr(), key, key_len, params) }
}

/// Wraps: EVP_MAC_init_SKEY
/// Initializes a MAC context from a provider secret key and parameter list.
pub fn EVP_MAC_init_SKEY(
    ctx: &mut EvpMacCtxMut<'_>,
    skey: EvpSkeyRef<'_>,
    params: &OsslParamListRef<'_, '_>,
) -> i32 {
    // SAFETY: both typed handles are live for the synchronous call and the
    // validated parameter list includes its required null-key terminator.
    unsafe { ffi::EVP_MAC_init_SKEY(ctx.as_mut_ptr(), skey.as_ptr().cast_mut(), params.as_ptr()) }
}

/// Wraps: EVP_MAC_is_a
/// Reports whether an optional MAC method has the requested algorithm name.
#[must_use]
pub fn EVP_MAC_is_a(mac: Option<EvpMacRef<'_>>, name: &CStr) -> bool {
    let mac = mac.map_or(ptr::null(), |mac| mac.as_ptr());
    // SAFETY: null is accepted for the method and `name` is NUL-terminated;
    // the lookup is synchronous and retains neither pointer.
    unsafe { ffi::EVP_MAC_is_a(mac, name.as_ptr()) == 1 }
}

/// Wraps: EVP_MAC_names_do_all
/// Synchronously visits every name associated with a MAC method.
pub fn EVP_MAC_names_do_all<F>(mac: EvpMacRef<'_>, callback: &mut F) -> bool
where
    F: for<'name> FnMut(&'name CStr),
{
    struct CallbackContext<'callback, F> {
        callback: &'callback mut F,
        panic: Option<Box<dyn core::any::Any + Send>>,
        valid: bool,
    }

    unsafe extern "C" fn trampoline<F>(name: *const c_char, data: *mut c_void)
    where
        F: for<'name> FnMut(&'name CStr),
    {
        // SAFETY: the wrapper passes this exact context and keeps it uniquely
        // borrowed throughout OpenSSL's synchronous traversal.
        let context = unsafe { &mut *data.cast::<CallbackContext<'_, F>>() };
        if context.panic.is_some() {
            return;
        }
        if name.is_null() {
            context.valid = false;
            return;
        }
        // SAFETY: OpenSSL supplies a live NUL-terminated name for this call.
        let name = unsafe { CStr::from_ptr(name) };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (context.callback)(name))) {
            context.panic = Some(panic);
        }
    }

    let mut context = CallbackContext {
        callback,
        panic: None,
        valid: true,
    };
    // SAFETY: the method is live and the callback context remains valid and
    // exclusively borrowed until the synchronous enumeration returns.
    let complete = unsafe {
        ffi::EVP_MAC_names_do_all(
            mac.as_ptr(),
            Some(trampoline::<F>),
            ptr::from_mut(&mut context).cast(),
        ) == 1
    };
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
    complete && context.valid
}

/// Wraps: EVP_MAC_update
/// Supplies the next byte run to an initialized MAC context.
pub fn EVP_MAC_update(ctx: &mut EvpMacCtxMut<'_>, data: &[u8]) -> i32 {
    // SAFETY: the exclusive context handle is live and `data` supplies exactly
    // the readable byte count passed to the synchronous provider callback.
    unsafe { ffi::EVP_MAC_update(ctx.as_mut_ptr(), data.as_ptr(), data.len()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::mac_meth::EVP_MAC_fetch;

    #[test]
    fn fetched_mac_context_retains_method_metadata() {
        let mac = EVP_MAC_fetch(None, c"HMAC", None).expect("fetch HMAC");
        assert_eq!(EVP_MAC_get0_name(mac.as_ref()), Some(c"HMAC"));
        let _ = EVP_MAC_get0_description(mac.as_ref());
        assert!(EVP_MAC_is_a(Some(mac.as_ref()), c"HMAC"));
        let mut saw_hmac = false;
        assert!(EVP_MAC_names_do_all(mac.as_ref(), &mut |name| {
            saw_hmac |= name.to_bytes().eq_ignore_ascii_case(b"HMAC");
        }));
        assert!(saw_hmac);

        let mut ctx = EVP_MAC_CTX_new(mac.as_ref()).expect("new MAC context");
        assert_eq!(
            EVP_MAC_CTX_get0_mac(ctx.as_ref()).map(|value| value.as_ptr()),
            Some(mac.as_ref().as_ptr())
        );
        let _ = EVP_MAC_CTX_get_block_size(&mut ctx.as_mut());
        let _ = EVP_MAC_CTX_get_mac_size(&mut ctx.as_mut());
        assert!(EVP_MAC_CTX_dup(ctx.as_ref()).is_some());
    }
}

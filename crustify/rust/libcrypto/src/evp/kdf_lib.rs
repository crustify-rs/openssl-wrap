//! Wrappers assigned from `crypto/evp/kdf_lib.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_char, c_void};
use core::ptr;
use std::any::Any;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use libcrypto_sys as ffi;

use crate::core::openssl_core::{OsslParamListMut, OsslParamListRef};
use crate::evp::evp::{EvpKdfRef, EvpSkeyRef, SharedEvpKdf, SharedEvpSkey};
use crate::evp::evp_local::{BorrowedEvpKdfCtx, EvpKdfCtxMut, EvpKdfCtxRef, EvpSkeymgmtRef};
use crate::provider::provider_core::OsslProviderRef;

struct NameCallback<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
    valid: bool,
}

/// Wraps: EVP_KDF_CTX_dup
/// Deep-copies a KDF context while retaining its provider dependency.
#[must_use]
pub fn EVP_KDF_CTX_dup(ctx: EvpKdfCtxRef<'_>) -> Option<BorrowedEvpKdfCtx<'_>> {
    ctx.try_dup()
}

/// Wraps: EVP_KDF_CTX_free
/// Releases an owned KDF context early; dropping it has the same effect.
pub fn EVP_KDF_CTX_free(ctx: Option<BorrowedEvpKdfCtx<'_>>) {
    drop(ctx);
}

/// Wraps: EVP_KDF_CTX_get0_kdf
/// Borrows the method retained by a KDF context.
#[must_use]
pub fn EVP_KDF_CTX_get0_kdf<'a>(ctx: EvpKdfCtxRef<'a>) -> Option<EvpKdfRef<'a>> {
    // SAFETY: the context is live and retains the returned method reference.
    let kdf = unsafe { ffi::EVP_KDF_CTX_get0_kdf(ctx.as_ptr()) };
    // SAFETY: a non-null result is borrowed from `ctx` and remains live for
    // the context borrow; no ownership is transferred.
    unsafe { EvpKdfRef::from_ptr(kdf.cast_mut()) }
}

/// Wraps: EVP_KDF_CTX_get1_kdf
/// Raises and returns a shared reference to the context's KDF method.
#[must_use]
pub fn EVP_KDF_CTX_get1_kdf<'a>(ctx: EvpKdfCtxRef<'a>) -> Option<SharedEvpKdf<'a>> {
    // SAFETY: the context is live. A non-null result carries one public method
    // reference and inherits the context's library-context dependency.
    let kdf = unsafe { ffi::EVP_KDF_CTX_get1_kdf(ctx.as_ptr()) };
    // SAFETY: the returned count is settled by `EVP_KDF_free`, and `'a`
    // retains the context from which the cached method was obtained.
    unsafe { SharedEvpKdf::from_raw(kdf) }
}

/// Wraps: EVP_KDF_CTX_get_kdf_size
/// Returns the provider's current output-size hint, or zero when unavailable.
#[must_use]
pub fn EVP_KDF_CTX_get_kdf_size(ctx: &mut EvpKdfCtxMut<'_>) -> usize {
    // SAFETY: the exclusive handle permits the provider parameter query.
    unsafe { ffi::EVP_KDF_CTX_get_kdf_size(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_KDF_CTX_get_params
/// Retrieves context parameters into a validated writable descriptor list.
pub fn EVP_KDF_CTX_get_params(
    ctx: &mut EvpKdfCtxMut<'_>,
    params: &mut OsslParamListMut<'_, '_>,
) -> i32 {
    // SAFETY: both exclusive borrows are live and the parameter list has a
    // reachable initialized terminator.
    unsafe { ffi::EVP_KDF_CTX_get_params(ctx.as_mut_ptr(), params.as_mut_ptr()) }
}

/// Wraps: EVP_KDF_CTX_new
/// Creates a provider context retaining the supplied KDF method.
#[must_use]
pub fn EVP_KDF_CTX_new<'a>(kdf: EvpKdfRef<'a>) -> Option<BorrowedEvpKdfCtx<'a>> {
    // SAFETY: the live method supplies its provider constructor. A non-null
    // result is initialized and carries one context-free obligation.
    let ctx = unsafe { ffi::EVP_KDF_CTX_new(kdf.as_ptr().cast_mut()) };
    // SAFETY: ownership transfers once and the result retains the method's
    // provider dependency, represented by `'a`.
    unsafe { BorrowedEvpKdfCtx::from_raw(ctx) }
}

/// Wraps: EVP_KDF_CTX_reset
/// Resets provider state while keeping the context reusable.
pub fn EVP_KDF_CTX_reset(ctx: &mut EvpKdfCtxMut<'_>) {
    // SAFETY: the exclusive handle permits mutation of provider state.
    unsafe { ffi::EVP_KDF_CTX_reset(ctx.as_mut_ptr()) }
}

/// Wraps: EVP_KDF_CTX_set_SKEY
/// Supplies a provider secret key to a KDF context.
pub fn EVP_KDF_CTX_set_SKEY(
    ctx: &mut EvpKdfCtxMut<'_>,
    key: EvpSkeyRef<'_>,
    parameter_name: Option<&CStr>,
) -> i32 {
    let parameter_name = parameter_name.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: both handles and the optional string are live for the call. The
    // implementation synchronously imports or reads key data and retains no
    // Rust borrow.
    unsafe { ffi::EVP_KDF_CTX_set_SKEY(ctx.as_mut_ptr(), key.as_ptr().cast_mut(), parameter_name) }
}

/// Wraps: EVP_KDF_CTX_set_params
/// Applies a validated, read-only parameter list to provider context state.
pub fn EVP_KDF_CTX_set_params(
    ctx: &mut EvpKdfCtxMut<'_>,
    params: &OsslParamListRef<'_, '_>,
) -> i32 {
    // SAFETY: the exclusive context and terminated descriptor list remain live
    // throughout the synchronous provider call.
    unsafe { ffi::EVP_KDF_CTX_set_params(ctx.as_mut_ptr(), params.as_ptr()) }
}

/// Wraps: EVP_KDF_derive
/// Derives exactly `output.len()` bytes into a bounded output buffer.
pub fn EVP_KDF_derive(
    ctx: &mut EvpKdfCtxMut<'_>,
    output: &mut [u8],
    params: Option<&OsslParamListRef<'_, '_>>,
) -> i32 {
    let params = params.map_or(ptr::null(), OsslParamListRef::as_ptr);
    // SAFETY: the slice supplies the exact writable extent passed to C, the
    // optional list is validated and live, and the context is exclusive.
    unsafe { ffi::EVP_KDF_derive(ctx.as_mut_ptr(), output.as_mut_ptr(), output.len(), params) }
}

/// Wraps: EVP_KDF_derive_SKEY
/// Derives a reference-counted provider secret key.
#[must_use]
pub fn EVP_KDF_derive_SKEY<'a>(
    ctx: &mut EvpKdfCtxMut<'a>,
    management: Option<EvpSkeymgmtRef<'_>>,
    key_type: &CStr,
    property_query: Option<&CStr>,
    key_len: usize,
    params: Option<&OsslParamListRef<'_, '_>>,
) -> Option<SharedEvpSkey<'a>> {
    let management = management.map_or(ptr::null_mut(), |value| value.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), CStr::as_ptr);
    let params = params.map_or(ptr::null(), OsslParamListRef::as_ptr);
    // SAFETY: every non-null pointer is backed by a live typed borrow. A
    // successful result transfers one `EVP_SKEY_free` obligation and may
    // retain a method belonging to the context's library context.
    let key = unsafe {
        ffi::EVP_KDF_derive_SKEY(
            ctx.as_mut_ptr(),
            management,
            key_type.as_ptr(),
            property_query,
            key_len,
            params,
        )
    };
    // SAFETY: the new public key reference is tied conservatively to the KDF
    // context borrow that retains its provider dependencies.
    unsafe { SharedEvpSkey::from_raw(key) }
}

/// Wraps: EVP_KDF_get0_description
/// Borrows the provider's optional algorithm description.
#[must_use]
pub fn EVP_KDF_get0_description<'a>(kdf: EvpKdfRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the method retains the provider-owned description for `'a`.
    let description = unsafe { ffi::EVP_KDF_get0_description(kdf.as_ptr()) };
    (!description.is_null()).then(|| {
        // SAFETY: OpenSSL publishes a NUL-terminated string retained by `kdf`.
        unsafe { CStr::from_ptr(description) }
    })
}

/// Wraps: EVP_KDF_get0_name
/// Borrows the method's copied primary algorithm name.
#[must_use]
pub fn EVP_KDF_get0_name<'a>(kdf: EvpKdfRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the live method owns its NUL-terminated primary name.
    let name = unsafe { ffi::EVP_KDF_get0_name(kdf.as_ptr()) };
    (!name.is_null()).then(|| {
        // SAFETY: the string remains live for the method borrow.
        unsafe { CStr::from_ptr(name) }
    })
}

/// Wraps: EVP_KDF_get0_provider
/// Borrows the provider retained by a KDF method.
#[must_use]
pub fn EVP_KDF_get0_provider<'a>(kdf: EvpKdfRef<'a>) -> Option<OsslProviderRef<'a>> {
    // SAFETY: the live method retains its provider reference.
    let provider = unsafe { ffi::EVP_KDF_get0_provider(kdf.as_ptr()) };
    // SAFETY: no ownership transfers and the provider is bounded by `kdf`.
    unsafe { OsslProviderRef::from_ptr(provider.cast_mut()) }
}

/// Wraps: EVP_KDF_get_params
/// Retrieves implementation parameters into a validated writable list.
pub fn EVP_KDF_get_params(kdf: EvpKdfRef<'_>, params: &mut OsslParamListMut<'_, '_>) -> i32 {
    // SAFETY: the shared method and exclusive descriptor list are live; the
    // method record is only read and the list has a reachable terminator.
    unsafe { ffi::EVP_KDF_get_params(kdf.as_ptr().cast_mut(), params.as_mut_ptr()) }
}

/// Wraps: EVP_KDF_is_a
/// Tests whether a method has the requested algorithm name.
#[must_use]
pub fn EVP_KDF_is_a(kdf: EvpKdfRef<'_>, name: &CStr) -> bool {
    // SAFETY: the method and NUL-terminated name are live for the query.
    unsafe { ffi::EVP_KDF_is_a(kdf.as_ptr(), name.as_ptr()) == 1 }
}

/// Wraps: EVP_KDF_names_do_all
/// Synchronously visits every name associated with a KDF method.
pub fn EVP_KDF_names_do_all<F>(kdf: EvpKdfRef<'_>, callback: &mut F) -> bool
where
    F: for<'name> FnMut(&'name CStr),
{
    unsafe extern "C" fn trampoline<F>(name: *const c_char, data: *mut c_void)
    where
        F: for<'name> FnMut(&'name CStr),
    {
        // SAFETY: the wrapper passes this exact state and keeps it uniquely
        // borrowed throughout synchronous enumeration.
        let state = unsafe { &mut *data.cast::<NameCallback<'_, F>>() };
        if state.panic.is_some() {
            return;
        }
        if name.is_null() {
            state.valid = false;
            return;
        }
        // SAFETY: OpenSSL supplies a live NUL-terminated name for this call.
        let name = unsafe { CStr::from_ptr(name) };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (state.callback)(name))) {
            state.panic = Some(panic);
        }
    }

    let mut state = NameCallback {
        callback,
        panic: None,
        valid: true,
    };
    // SAFETY: the method and callback/state pair remain live, unique, and are
    // not retained after this synchronous traversal.
    let complete = unsafe {
        ffi::EVP_KDF_names_do_all(
            kdf.as_ptr(),
            Some(trampoline::<F>),
            core::ptr::from_mut(&mut state).cast(),
        ) == 1
    };
    if let Some(panic) = state.panic {
        resume_unwind(panic);
    }
    complete && state.valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::kdf_meth::EVP_KDF_fetch;

    #[test]
    fn fetched_kdf_context_exposes_lifetime_bound_method_metadata() {
        let kdf = EVP_KDF_fetch(None, c"HKDF", None).expect("fetch HKDF");
        assert!(EVP_KDF_is_a(kdf.as_ref(), c"HKDF"));
        assert_eq!(EVP_KDF_get0_name(kdf.as_ref()), Some(c"HKDF"));
        assert!(EVP_KDF_get0_provider(kdf.as_ref()).is_some());

        let mut names = Vec::new();
        assert!(EVP_KDF_names_do_all(kdf.as_ref(), &mut |name: &CStr| {
            names.push(name.to_owned());
        }));
        assert!(names.iter().any(|name| name.as_c_str() == c"HKDF"));

        let mut ctx = EVP_KDF_CTX_new(kdf.as_ref()).expect("new KDF context");
        assert_eq!(
            EVP_KDF_CTX_get0_kdf(ctx.as_ref()).map(|value| value.as_ptr()),
            Some(kdf.as_ref().as_ptr())
        );
        assert!(EVP_KDF_CTX_get1_kdf(ctx.as_ref()).is_some());
        EVP_KDF_CTX_reset(&mut ctx.as_mut());
        assert!(EVP_KDF_CTX_dup(ctx.as_ref()).is_some());
    }
}

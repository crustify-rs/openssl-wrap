//! Wrappers assigned from `crypto/evp/kdf_meth.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_void};
use core::ptr::{self, NonNull};
use std::any::Any;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use ffibox::CSlice;
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{OsslParam, terminated_param_len};
use crate::evp::evp::{EvpKdfRef, SharedEvpKdf};
use crate::evp::evp_local::EvpKdfCtxMut;

struct CallbackContext<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
    valid: bool,
}

unsafe fn kdf_params<'a>(params: *const ffi::OSSL_PARAM) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the caller establishes a live provider-owned terminated table.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'a>>())?;
    // SAFETY: the scan established `len` initialized entries and the caller's
    // borrow retains their provider-owned storage.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_KDF_CTX_gettable_params
/// Returns the context's provider-owned retrievable-parameter table.
#[must_use]
pub fn EVP_KDF_CTX_gettable_params<'a>(
    ctx: &'a mut EvpKdfCtxMut<'_>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the exclusive reborrow keeps context/provider state live while
    // the provider selects its constant advertised table.
    let params = unsafe { ffi::EVP_KDF_CTX_gettable_params(ctx.as_mut_ptr()) };
    // SAFETY: a non-null result is a terminated provider-owned table retained
    // by the context for this reborrow.
    unsafe { kdf_params(params) }
}

/// Wraps: EVP_KDF_CTX_settable_params
/// Returns the context's provider-owned settable-parameter table.
#[must_use]
pub fn EVP_KDF_CTX_settable_params<'a>(
    ctx: &'a mut EvpKdfCtxMut<'_>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: as `EVP_KDF_CTX_gettable_params`.
    let params = unsafe { ffi::EVP_KDF_CTX_settable_params(ctx.as_mut_ptr()) };
    // SAFETY: the context reborrow retains the terminated advertised table.
    unsafe { kdf_params(params) }
}

/// Wraps: EVP_KDF_do_all_provided
/// Synchronously visits every KDF activated in a library context.
pub fn EVP_KDF_do_all_provided<F>(libctx: Option<OsslLibCtxRef<'_>>, callback: &mut F) -> bool
where
    F: for<'method> FnMut(EvpKdfRef<'method>),
{
    unsafe extern "C" fn trampoline<F>(kdf: *mut ffi::EVP_KDF, arg: *mut c_void)
    where
        F: for<'method> FnMut(EvpKdfRef<'method>),
    {
        // SAFETY: the wrapper passes this exact uniquely borrowed state.
        let state = unsafe { &mut *arg.cast::<CallbackContext<'_, F>>() };
        if state.panic.is_some() {
            return;
        }
        // SAFETY: OpenSSL supplies a live method for this callback invocation.
        let Some(kdf) = (unsafe { EvpKdfRef::from_ptr(kdf) }) else {
            state.valid = false;
            return;
        };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (state.callback)(kdf))) {
            state.panic = Some(panic);
        }
    }

    let mut state = CallbackContext {
        callback,
        panic: None,
        valid: true,
    };
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: null selects the default context; otherwise the context and the
    // callback/state pair remain live throughout synchronous traversal.
    unsafe {
        ffi::EVP_KDF_do_all_provided(
            libctx,
            Some(trampoline::<F>),
            core::ptr::from_mut(&mut state).cast(),
        );
    }
    if let Some(panic) = state.panic {
        resume_unwind(panic);
    }
    state.valid
}

/// Wraps: EVP_KDF_fetch
/// Fetches one shared KDF method from the selected library context.
#[must_use]
pub fn EVP_KDF_fetch<'a>(
    libctx: Option<OsslLibCtxRef<'a>>,
    algorithm: &CStr,
    properties: Option<&CStr>,
) -> Option<SharedEvpKdf<'a>> {
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the context and C strings are live for the synchronous fetch.
    let kdf = unsafe { ffi::EVP_KDF_fetch(libctx, algorithm.as_ptr(), properties) };
    // SAFETY: a non-null result transfers one public method reference and `'a`
    // retains the explicit library context, if any.
    unsafe { SharedEvpKdf::from_raw(kdf) }
}

/// Wraps: EVP_KDF_free
/// Releases one owned KDF reference early; dropping it is equivalent.
pub fn EVP_KDF_free(kdf: Option<SharedEvpKdf<'_>>) {
    drop(kdf);
}

/// Wraps: EVP_KDF_gettable_ctx_params
/// Returns retrievable context parameters advertised by a KDF method.
#[must_use]
pub fn EVP_KDF_gettable_ctx_params<'a>(kdf: EvpKdfRef<'a>) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the live method retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KDF_gettable_ctx_params(kdf.as_ptr()) };
    // SAFETY: the method borrow retains the returned terminated table.
    unsafe { kdf_params(params) }
}

/// Wraps: EVP_KDF_gettable_params
/// Returns retrievable implementation parameters advertised by a KDF method.
#[must_use]
pub fn EVP_KDF_gettable_params<'a>(kdf: EvpKdfRef<'a>) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the live method retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KDF_gettable_params(kdf.as_ptr()) };
    // SAFETY: the method borrow retains the returned terminated table.
    unsafe { kdf_params(params) }
}

/// Wraps: EVP_KDF_settable_ctx_params
/// Returns settable context parameters advertised by a KDF method.
#[must_use]
pub fn EVP_KDF_settable_ctx_params<'a>(kdf: EvpKdfRef<'a>) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the live method retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KDF_settable_ctx_params(kdf.as_ptr()) };
    // SAFETY: the method borrow retains the returned terminated table.
    unsafe { kdf_params(params) }
}

/// Wraps: EVP_KDF_up_ref
/// Raises one public reference and returns a shared-only owner.
#[must_use]
pub fn EVP_KDF_up_ref(kdf: EvpKdfRef<'_>) -> Option<SharedEvpKdf<'_>> {
    kdf.try_share()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetched_kdf_advertises_parameters_and_enumerates_synchronously() {
        let kdf = EVP_KDF_fetch(None, c"HKDF", None).expect("fetch HKDF");
        for params in [
            EVP_KDF_gettable_params(kdf.as_ref()),
            EVP_KDF_gettable_ctx_params(kdf.as_ref()),
            EVP_KDF_settable_ctx_params(kdf.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            assert!(params.iter().all(|param| param.key().is_some()));
        }

        let raised = EVP_KDF_up_ref(kdf.as_ref()).expect("up-ref");
        assert_eq!(raised.as_ptr(), kdf.as_ptr());

        let mut count = 0usize;
        assert!(EVP_KDF_do_all_provided(None, &mut |_| count += 1));
        assert!(count > 0);
        let panic = std::panic::catch_unwind(|| {
            EVP_KDF_do_all_provided(None, &mut |_| panic!("callback panic"));
        });
        assert!(panic.is_err());
    }
}

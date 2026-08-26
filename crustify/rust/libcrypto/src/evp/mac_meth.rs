//! Wrappers assigned from `crypto/evp/mac_meth.c`.

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
use crate::evp::evp::{EvpMacRef, SharedEvpMac};
use crate::evp::evp_local::EvpMacCtxMut;
use crate::provider::provider_core::OsslProviderRef;

struct CallbackContext<'a, F> {
    callback: &'a mut F,
    panic: Option<Box<dyn Any + Send>>,
    valid: bool,
}

unsafe fn mac_params<'a>(params: *const ffi::OSSL_PARAM) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the caller establishes a live provider-owned terminated table.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'a>>())?;
    // SAFETY: the scan established the initialized entries and the caller's
    // method/context borrow retains their provider-owned storage.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_MAC_CTX_gettable_params
/// Returns the context's provider-owned retrievable-parameter table.
#[must_use]
pub fn EVP_MAC_CTX_gettable_params<'a>(
    ctx: &'a mut EvpMacCtxMut<'_>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the exclusive reborrow keeps provider context state live while
    // it selects its constant advertised table.
    let params = unsafe { ffi::EVP_MAC_CTX_gettable_params(ctx.as_mut_ptr()) };
    // SAFETY: a non-null result is terminated and retained for this reborrow.
    unsafe { mac_params(params) }
}

/// Wraps: EVP_MAC_CTX_settable_params
/// Returns the context's provider-owned settable-parameter table.
#[must_use]
pub fn EVP_MAC_CTX_settable_params<'a>(
    ctx: &'a mut EvpMacCtxMut<'_>,
) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: as `EVP_MAC_CTX_gettable_params`.
    let params = unsafe { ffi::EVP_MAC_CTX_settable_params(ctx.as_mut_ptr()) };
    // SAFETY: the context reborrow retains the terminated advertised table.
    unsafe { mac_params(params) }
}

/// Wraps: EVP_MAC_do_all_provided
/// Synchronously visits every MAC activated in a library context.
pub fn EVP_MAC_do_all_provided<F>(libctx: Option<OsslLibCtxRef<'_>>, callback: &mut F) -> bool
where
    F: for<'method> FnMut(EvpMacRef<'method>),
{
    unsafe extern "C" fn trampoline<F>(mac: *mut ffi::EVP_MAC, arg: *mut c_void)
    where
        F: for<'method> FnMut(EvpMacRef<'method>),
    {
        // SAFETY: the wrapper passes this exact uniquely borrowed state.
        let state = unsafe { &mut *arg.cast::<CallbackContext<'_, F>>() };
        if state.panic.is_some() {
            return;
        }
        // SAFETY: OpenSSL supplies a live method for this callback invocation.
        let Some(mac) = (unsafe { EvpMacRef::from_ptr(mac) }) else {
            state.valid = false;
            return;
        };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (state.callback)(mac))) {
            state.panic = Some(panic);
        }
    }

    let mut state = CallbackContext {
        callback,
        panic: None,
        valid: true,
    };
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the optional context and callback/state pair remain live and are
    // not retained beyond this synchronous traversal.
    unsafe {
        ffi::EVP_MAC_do_all_provided(
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

/// Wraps: EVP_MAC_fetch
/// Fetches one shared MAC method from the selected library context.
#[must_use]
pub fn EVP_MAC_fetch<'a>(
    libctx: Option<OsslLibCtxRef<'a>>,
    algorithm: &CStr,
    properties: Option<&CStr>,
) -> Option<SharedEvpMac<'a>> {
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the optional context and both C strings are live for the fetch.
    let mac = unsafe { ffi::EVP_MAC_fetch(libctx, algorithm.as_ptr(), properties) };
    // SAFETY: a non-null result transfers one public method reference and `'a`
    // retains the explicit library context, if any.
    unsafe { SharedEvpMac::from_raw(mac) }
}

/// Wraps: EVP_MAC_free
/// Releases one owned MAC reference early; dropping it is equivalent.
pub fn EVP_MAC_free(mac: Option<SharedEvpMac<'_>>) {
    drop(mac);
}

/// Wraps: EVP_MAC_get0_provider
/// Borrows the provider retained by a MAC method.
#[must_use]
pub fn EVP_MAC_get0_provider<'a>(mac: EvpMacRef<'a>) -> Option<OsslProviderRef<'a>> {
    // SAFETY: the live method retains its provider reference.
    let provider = unsafe { ffi::EVP_MAC_get0_provider(mac.as_ptr()) };
    // SAFETY: no ownership transfers and the provider remains live for `mac`.
    unsafe { OsslProviderRef::from_ptr(provider.cast_mut()) }
}

/// Wraps: EVP_MAC_gettable_ctx_params
/// Returns retrievable context parameters advertised by a MAC method.
#[must_use]
pub fn EVP_MAC_gettable_ctx_params<'a>(mac: EvpMacRef<'a>) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the live method retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_MAC_gettable_ctx_params(mac.as_ptr()) };
    // SAFETY: the method borrow retains the returned terminated table.
    unsafe { mac_params(params) }
}

/// Wraps: EVP_MAC_gettable_params
/// Returns retrievable implementation parameters advertised by a MAC method.
#[must_use]
pub fn EVP_MAC_gettable_params<'a>(mac: EvpMacRef<'a>) -> Option<CSlice<'a, OsslParam<'a>>> {
    // SAFETY: the live method retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_MAC_gettable_params(mac.as_ptr()) };
    // SAFETY: the method borrow retains the returned terminated table.
    unsafe { mac_params(params) }
}

/// Wraps: EVP_MAC_settable_ctx_params
/// Returns the provider-owned descriptors for settable MAC parameters.
#[must_use]
pub fn EVP_MAC_settable_ctx_params<'mac>(
    mac: EvpMacRef<'mac>,
) -> Option<CSlice<'mac, OsslParam<'mac>>> {
    // SAFETY: the live method retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_MAC_settable_ctx_params(mac.as_ptr()) };
    // SAFETY: the method borrow retains the returned terminated table.
    unsafe { mac_params(params) }
}

/// Wraps: EVP_MAC_up_ref
/// Raises a MAC method reference and returns a shared-only owner.
#[must_use]
pub fn EVP_MAC_up_ref<'a>(mac: EvpMacRef<'a>) -> Option<SharedEvpMac<'a>> {
    mac.try_share()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetched_mac_advertises_parameters_and_enumerates_synchronously() {
        let mac = EVP_MAC_fetch(None, c"HMAC", None).expect("fetch HMAC");
        assert!(EVP_MAC_get0_provider(mac.as_ref()).is_some());
        assert!(EVP_MAC_settable_ctx_params(mac.as_ref()).is_some());
        let second = EVP_MAC_up_ref(mac.as_ref()).expect("up-ref");
        assert_eq!(second.as_ptr(), mac.as_ptr());
        for params in [
            EVP_MAC_gettable_params(mac.as_ref()),
            EVP_MAC_gettable_ctx_params(mac.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            assert!(params.iter().all(|param| param.key().is_some()));
        }

        let mut count = 0usize;
        assert!(EVP_MAC_do_all_provided(None, &mut |_| count += 1));
        assert!(count > 0);
        let panic = std::panic::catch_unwind(|| {
            EVP_MAC_do_all_provided(None, &mut |_| panic!("callback panic"));
        });
        assert!(panic.is_err());
    }
}

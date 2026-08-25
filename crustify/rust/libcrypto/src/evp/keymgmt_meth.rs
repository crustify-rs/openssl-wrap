//! Wrappers assigned from `crypto/evp/keymgmt_meth.c`.

use core::ffi::{CStr, c_char, c_void};
use core::ptr::{self, NonNull};
use std::any::Any;
use std::boxed::Box;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use ffibox::CSlice;
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::core::openssl_core::{OsslParam, terminated_param_len};
use crate::evp::evp_local::{EvpKeymgmtRef, SharedEvpKeymgmt};
use crate::provider::provider_core::OsslProviderRef;

struct CallbackContext<'callback, F> {
    callback: &'callback mut F,
    panic: Option<Box<dyn Any + Send>>,
    valid: bool,
}

/// Reconstructs a provider-owned, null-key-terminated parameter descriptor run.
///
/// # Safety
///
/// `params` must be null or the provider-owned result of one of the key-management
/// descriptor getters, live for `'keymgmt` with a reachable null-key terminator.
unsafe fn keymgmt_params<'keymgmt>(
    params: *const ffi::OSSL_PARAM,
) -> Option<CSlice<'keymgmt, OsslParam<'keymgmt>>> {
    // SAFETY: the caller supplies the provider descriptor-array contract.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'keymgmt>>())?;
    // SAFETY: the scan established `len` initialized descriptors before the
    // terminator, all retained by the method's provider for `'keymgmt`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_KEYMGMT_do_all_provided
///
/// Synchronously visits every key-management implementation activated in
/// `libctx`. Each method handle is valid only for its callback invocation.
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_do_all_provided<F>(libctx: Option<OsslLibCtxRef<'_>>, callback: &mut F) -> bool
where
    F: for<'method> FnMut(EvpKeymgmtRef<'method>),
{
    unsafe extern "C" fn trampoline<F>(keymgmt: *mut ffi::EVP_KEYMGMT, arg: *mut c_void)
    where
        F: for<'method> FnMut(EvpKeymgmtRef<'method>),
    {
        // SAFETY: the wrapper passes this exact context and keeps it uniquely
        // borrowed throughout OpenSSL's synchronous traversal.
        let context = unsafe { &mut *arg.cast::<CallbackContext<'_, F>>() };
        if context.panic.is_some() {
            return;
        }
        // SAFETY: OpenSSL supplies a live method from its store for the
        // duration of this callback. Reject a malformed null callback value.
        let Some(keymgmt) = (unsafe { EvpKeymgmtRef::from_ptr(keymgmt) }) else {
            context.valid = false;
            return;
        };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (context.callback)(keymgmt))) {
            context.panic = Some(panic);
        }
    }

    let mut context = CallbackContext {
        callback,
        panic: None,
        valid: true,
    };
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: null selects the process-wide default context. Otherwise the
    // borrowed context is live; the trampoline and state remain valid and
    // uniquely borrowed until this synchronous call returns.
    unsafe {
        ffi::EVP_KEYMGMT_do_all_provided(
            libctx,
            Some(trampoline::<F>),
            core::ptr::from_mut(&mut context).cast(),
        );
    }
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
    context.valid
}

/// Wraps: EVP_KEYMGMT_fetch
///
/// Fetches one shared key-management method. The returned owner retains its
/// method reference and cannot expose exclusive access to the cached object.
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_fetch<'ctx>(
    ctx: Option<OsslLibCtxRef<'ctx>>,
    algorithm: &CStr,
    properties: Option<&CStr>,
) -> Option<SharedEvpKeymgmt<'ctx>> {
    let ctx = ctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: null selects the default context or property query; all non-null
    // inputs are live C strings/context handles for this synchronous fetch.
    let keymgmt = unsafe { ffi::EVP_KEYMGMT_fetch(ctx, algorithm.as_ptr(), properties) };
    // SAFETY: a non-null fetch result transfers one public method reference,
    // settled by `EVP_KEYMGMT_free`, and its context cannot outlive `'ctx`.
    unsafe { SharedEvpKeymgmt::from_raw(keymgmt) }
}

/// Wraps: EVP_KEYMGMT_gen_gettable_params
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_gen_gettable_params<'keymgmt>(
    keymgmt: EvpKeymgmtRef<'keymgmt>,
) -> Option<CSlice<'keymgmt, OsslParam<'keymgmt>>> {
    // SAFETY: the method is live and retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KEYMGMT_gen_gettable_params(keymgmt.as_ptr()) };
    // SAFETY: a non-null provider result follows the documented constant,
    // null-key-terminated descriptor-array contract.
    unsafe { keymgmt_params(params) }
}

/// Wraps: EVP_KEYMGMT_gen_settable_params
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_gen_settable_params<'keymgmt>(
    keymgmt: EvpKeymgmtRef<'keymgmt>,
) -> Option<CSlice<'keymgmt, OsslParam<'keymgmt>>> {
    // SAFETY: the method is live and retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KEYMGMT_gen_settable_params(keymgmt.as_ptr()) };
    // SAFETY: a non-null provider result follows the documented constant,
    // null-key-terminated descriptor-array contract.
    unsafe { keymgmt_params(params) }
}

/// Wraps: EVP_KEYMGMT_get0_description
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_get0_description<'keymgmt>(
    keymgmt: EvpKeymgmtRef<'keymgmt>,
) -> Option<&'keymgmt CStr> {
    // SAFETY: the live method retains any non-null NUL-terminated description.
    let description = unsafe { ffi::EVP_KEYMGMT_get0_description(keymgmt.as_ptr()) };
    if description.is_null() {
        None
    } else {
        // SAFETY: the method's provider retains this string for `'keymgmt`.
        Some(unsafe { CStr::from_ptr(description) })
    }
}

/// Wraps: EVP_KEYMGMT_get0_name
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_get0_name<'keymgmt>(keymgmt: EvpKeymgmtRef<'keymgmt>) -> Option<&'keymgmt CStr> {
    // SAFETY: the live method owns its copied, NUL-terminated first name.
    let name = unsafe { ffi::EVP_KEYMGMT_get0_name(keymgmt.as_ptr()) };
    if name.is_null() {
        None
    } else {
        // SAFETY: the method retains the string for `'keymgmt`.
        Some(unsafe { CStr::from_ptr(name) })
    }
}

/// Wraps: EVP_KEYMGMT_get0_provider
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_get0_provider<'keymgmt>(
    keymgmt: EvpKeymgmtRef<'keymgmt>,
) -> Option<OsslProviderRef<'keymgmt>> {
    // SAFETY: the live method retains its provider reference, if any.
    let provider = unsafe { ffi::EVP_KEYMGMT_get0_provider(keymgmt.as_ptr()) };
    // SAFETY: a non-null provider remains live through the method borrow and
    // no ownership is transferred by this getter.
    unsafe { OsslProviderRef::from_ptr(provider.cast_mut()) }
}

/// Wraps: EVP_KEYMGMT_gettable_params
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_gettable_params<'keymgmt>(
    keymgmt: EvpKeymgmtRef<'keymgmt>,
) -> Option<CSlice<'keymgmt, OsslParam<'keymgmt>>> {
    // SAFETY: the method is live and retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KEYMGMT_gettable_params(keymgmt.as_ptr()) };
    // SAFETY: a non-null provider result follows the documented constant,
    // null-key-terminated descriptor-array contract.
    unsafe { keymgmt_params(params) }
}

/// Wraps: EVP_KEYMGMT_is_a
#[allow(non_snake_case)]
#[must_use]
pub fn EVP_KEYMGMT_is_a(keymgmt: Option<EvpKeymgmtRef<'_>>, name: &CStr) -> bool {
    let keymgmt = keymgmt.map_or(ptr::null(), |keymgmt| keymgmt.as_ptr());
    // SAFETY: null is explicitly accepted for the method, while every
    // non-null method and the requested algorithm name are live for the call.
    unsafe { ffi::EVP_KEYMGMT_is_a(keymgmt, name.as_ptr()) == 1 }
}

/// Wraps: EVP_KEYMGMT_names_do_all
///
/// Synchronously visits every name associated with `keymgmt`.
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_names_do_all<F>(keymgmt: EvpKeymgmtRef<'_>, callback: &mut F) -> bool
where
    F: for<'name> FnMut(&'name CStr),
{
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
        // SAFETY: OpenSSL supplies a live NUL-terminated algorithm name for
        // the duration of this callback invocation.
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
    // SAFETY: the method is live, and the callback/state pair remains valid
    // and uniquely borrowed until synchronous enumeration returns.
    let complete = unsafe {
        ffi::EVP_KEYMGMT_names_do_all(
            keymgmt.as_ptr(),
            Some(trampoline::<F>),
            core::ptr::from_mut(&mut context).cast(),
        ) == 1
    };
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
    complete && context.valid
}

/// Wraps: EVP_KEYMGMT_settable_params
#[allow(non_snake_case)]
pub fn EVP_KEYMGMT_settable_params<'keymgmt>(
    keymgmt: EvpKeymgmtRef<'keymgmt>,
) -> Option<CSlice<'keymgmt, OsslParam<'keymgmt>>> {
    // SAFETY: the method is live and retains its provider and dispatch table.
    let params = unsafe { ffi::EVP_KEYMGMT_settable_params(keymgmt.as_ptr()) };
    // SAFETY: a non-null provider result follows the documented constant,
    // null-key-terminated descriptor-array contract.
    unsafe { keymgmt_params(params) }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;

    use super::*;

    #[test]
    fn fetched_method_exposes_lifetime_bound_metadata() {
        let keymgmt = EVP_KEYMGMT_fetch(None, c"RSA", None).expect("fetch RSA key manager");
        let method = keymgmt.as_ref();

        assert!(EVP_KEYMGMT_is_a(Some(method), c"RSA"));
        assert!(!EVP_KEYMGMT_is_a(None, c"RSA"));
        assert!(EVP_KEYMGMT_get0_provider(method).is_some());
        assert!(EVP_KEYMGMT_get0_name(method).is_some());
        let _ = EVP_KEYMGMT_get0_description(method);

        let mut names = Vec::<CString>::new();
        assert!(EVP_KEYMGMT_names_do_all(method, &mut |name: &CStr| {
            names.push(name.to_owned());
        }));
        assert!(names.iter().any(|name| name.as_c_str() == c"RSA"));

        for params in [
            EVP_KEYMGMT_gettable_params(method),
            EVP_KEYMGMT_settable_params(method),
            EVP_KEYMGMT_gen_gettable_params(method),
            EVP_KEYMGMT_gen_settable_params(method),
        ]
        .into_iter()
        .flatten()
        {
            assert!(params.iter().all(|param| param.key().is_some()));
        }
    }

    #[test]
    fn do_all_callbacks_are_synchronous_and_panics_do_not_cross_c() {
        let mut count = 0usize;
        assert!(EVP_KEYMGMT_do_all_provided(None, &mut |_| count += 1));
        assert!(count > 0);

        let panic = std::panic::catch_unwind(|| {
            EVP_KEYMGMT_do_all_provided(None, &mut |_| panic!("callback panic"));
        });
        assert!(panic.is_err());
    }
}

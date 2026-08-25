//! Wrappers assigned from `crypto/evp/evp_lib.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use ffibox::CBox;
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::{EvpMdRef, EvpPkeyCtxMut};
use crate::evp::p_lib::BorrowedEvpPkey;
use crate::x509::x509::{X509Algor, X509AlgorMut, X509AlgorRef};

/// The documented, type-safe argument shapes accepted by `EVP_PKEY_Q_keygen`.
pub enum QuickKeygen<'a> {
    /// Generate an RSA key with the requested modulus size.
    Rsa {
        bits: usize,
    },
    /// Generate an EC key on the named curve.
    Ec {
        curve: &'a CStr,
    },
    Ed25519,
    Ed448,
    Sm2,
    X25519,
    X448,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    MlKem512,
    MlKem768,
    MlKem1024,
}

/// Wraps: EVP_PKEY_Q_keygen
/// Performs one of OpenSSL's documented quick key-generation forms.
#[must_use]
pub fn EVP_PKEY_Q_keygen<'a>(
    library_context: Option<OsslLibCtxRef<'a>>,
    property_query: Option<&CStr>,
    request: QuickKeygen<'_>,
) -> Option<BorrowedEvpPkey<'a>> {
    let library_context =
        library_context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the fixed pointers are null or live borrowed values. Each match
    // arm supplies exactly the variadic type required by the documented key
    // type, avoiding C's otherwise-untyped varargs contract.
    let raw = unsafe {
        match request {
            QuickKeygen::Rsa { bits } => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"RSA".as_ptr(), bits)
            }
            QuickKeygen::Ec { curve } => ffi::EVP_PKEY_Q_keygen(
                library_context,
                property_query,
                c"EC".as_ptr(),
                curve.as_ptr(),
            ),
            QuickKeygen::Ed25519 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ED25519".as_ptr())
            }
            QuickKeygen::Ed448 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ED448".as_ptr())
            }
            QuickKeygen::Sm2 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"SM2".as_ptr())
            }
            QuickKeygen::X25519 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"X25519".as_ptr())
            }
            QuickKeygen::X448 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"X448".as_ptr())
            }
            QuickKeygen::MlDsa44 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ML-DSA-44".as_ptr())
            }
            QuickKeygen::MlDsa65 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ML-DSA-65".as_ptr())
            }
            QuickKeygen::MlDsa87 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ML-DSA-87".as_ptr())
            }
            QuickKeygen::MlKem512 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ML-KEM-512".as_ptr())
            }
            QuickKeygen::MlKem768 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ML-KEM-768".as_ptr())
            }
            QuickKeygen::MlKem1024 => {
                ffi::EVP_PKEY_Q_keygen(library_context, property_query, c"ML-KEM-1024".as_ptr())
            }
        }
    };
    // SAFETY: a non-null result transfers one `EVP_PKEY_free` obligation and
    // remains conservatively tied to the selected library context.
    unsafe { BorrowedEvpPkey::from_raw(raw) }
}

/// Wraps: EVP_PKEY_CTX_get_group_name
/// Writes the NUL-terminated group name into `output` when successful.
pub fn EVP_PKEY_CTX_get_group_name(ctx: &mut EvpPkeyCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the context is exclusively borrowed and `output` supplies its
    // exact initialized, writable capacity for the synchronous query.
    unsafe {
        ffi::EVP_PKEY_CTX_get_group_name(ctx.as_mut_ptr(), output.as_mut_ptr().cast(), output.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quick_generation_uses_a_typed_non_variadic_rust_surface() {
        let key =
            EVP_PKEY_Q_keygen(None, None, QuickKeygen::Ed25519).expect("ED25519 quick keygen");
        assert!(!key.as_ref().as_ptr().is_null());
    }

    #[test]
    fn group_name_configures_an_ec_generation_context() {
        use ffibox::CBox;

        use crate::evp::evp::EvpPkeyCtx;
        use crate::evp::pmeth_gn::EVP_PKEY_paramgen_init;

        // SAFETY: null selects the process default context and properties; a
        // non-null result transfers one fully initialized context allocation.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"EC".as_ptr(), ptr::null())
        };
        // SAFETY: ownership of the fresh context transfers to this owner once.
        let mut ctx = unsafe { CBox::<EvpPkeyCtx>::from_raw(raw) }.expect("EC context");
        assert_eq!(EVP_PKEY_paramgen_init(&mut ctx.as_mut()), 1);
        assert_eq!(
            EVP_PKEY_CTX_set_group_name(&mut ctx.as_mut(), c"prime256v1"),
            1
        );
    }
}

/// Wraps: EVP_PKEY_CTX_set_group_name
/// Selects a NUL-terminated group name for key or parameter generation.
pub fn EVP_PKEY_CTX_set_group_name(
    ctx: &mut crate::evp::evp::EvpPkeyCtxMut<'_>,
    name: &CStr,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and `name` is a live
    // NUL-terminated string consumed synchronously by the parameter setter.
    unsafe { ffi::EVP_PKEY_CTX_set_group_name(ctx.as_mut_ptr(), name.as_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_get_algor
///
/// Retrieves a newly allocated algorithm identifier. Any partial output from
/// an unsuccessful decode is reclaimed before returning `None`.
#[must_use]
pub fn EVP_PKEY_CTX_get_algor(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<CBox<X509Algor>>) {
    let mut algorithm = ptr::null_mut();
    // SAFETY: the context is exclusively borrowed and the initialized local
    // slot is writable. Starting with null selects the allocating C contract.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_algor(ctx.as_mut_ptr(), &mut algorithm) };
    // SAFETY: the slot started null. Any non-null value written by the decoder
    // carries exactly one X509_ALGOR_free obligation, even if decoding later
    // reports failure.
    let algorithm = unsafe { CBox::from_raw(algorithm) };
    if status == 1 {
        (status, algorithm)
    } else {
        drop(algorithm);
        (status, None)
    }
}

/// Wraps: EVP_PKEY_CTX_get_algor_params
///
/// Replaces the algorithm identifier's owned parameter with the value
/// reported by the active provider operation.
pub fn EVP_PKEY_CTX_get_algor_params(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: &mut X509AlgorMut<'_>,
) -> i32 {
    // SAFETY: both handles are exclusively borrowed. The algorithm identifier
    // is non-null and owns its optional parameter, which the C decoder may
    // reuse or replace while preserving its destructor contract.
    unsafe { ffi::EVP_PKEY_CTX_get_algor_params(ctx.as_mut_ptr(), algorithm.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_set_algor_params
///
/// Passes the borrowed algorithm identifier parameter to the active provider
/// operation without transferring it.
pub fn EVP_PKEY_CTX_set_algor_params(
    ctx: &mut EvpPkeyCtxMut<'_>,
    algorithm: X509AlgorRef<'_>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and the algorithm identifier
    // remains live and readable for the synchronous encoding and dispatch.
    unsafe { ffi::EVP_PKEY_CTX_set_algor_params(ctx.as_mut_ptr(), algorithm.as_ptr()) }
}

#[cfg(test)]
mod algorithm_identifier_tests {
    use super::*;

    #[test]
    fn calls_preserve_typed_ownership() {
        use crate::evp::evp::EvpPkeyCtx;
        use crate::evp::pmeth_gn::EVP_PKEY_paramgen_init;

        // SAFETY: null selects the process default context and properties; a
        // non-null result transfers one fully initialized context allocation.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"EC".as_ptr(), ptr::null())
        };
        // SAFETY: ownership of the fresh context transfers to this owner once.
        let mut ctx = unsafe { CBox::<EvpPkeyCtx>::from_raw(raw) }.expect("EC context");
        assert_eq!(EVP_PKEY_paramgen_init(&mut ctx.as_mut()), 1);

        let mut algorithm = X509Algor::new().expect("algorithm identifier");
        let address = algorithm.as_ref().as_ptr();
        let _ = EVP_PKEY_CTX_set_algor_params(&mut ctx.as_mut(), algorithm.as_ref());
        let _ = EVP_PKEY_CTX_get_algor_params(&mut ctx.as_mut(), &mut algorithm.as_mut());
        assert_eq!(algorithm.as_ref().as_ptr(), address);

        let (status, retrieved) = EVP_PKEY_CTX_get_algor(&mut ctx.as_mut());
        assert!(status != 1 || retrieved.is_some());
    }
}

/// Wraps: EVP_MD_get_flags
/// Returns the implementation flags of a live digest.
#[must_use]
pub fn EVP_MD_get_flags(md: EvpMdRef<'_>) -> c_ulong {
    // SAFETY: the shared digest handle is live and the getter retains nothing.
    unsafe { ffi::EVP_MD_get_flags(md.as_ptr()) }
}

/// Wraps: EVP_MD_get_pkey_type
/// Returns the legacy public-key signing algorithm NID associated with `md`.
#[must_use]
pub fn EVP_MD_get_pkey_type(md: EvpMdRef<'_>) -> c_int {
    // SAFETY: the shared digest handle is live and the getter retains nothing.
    unsafe { ffi::EVP_MD_get_pkey_type(md.as_ptr()) }
}

/// Wraps: EVP_MD_get_size
/// Returns the digest size, or `-1` for a missing digest or other failure.
#[must_use]
pub fn EVP_MD_get_size(md: Option<EvpMdRef<'_>>) -> c_int {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is explicitly accepted; otherwise the shared digest is live.
    unsafe { ffi::EVP_MD_get_size(md) }
}

/// Wraps: EVP_MD_get_type
/// Returns the object-identifier NID associated with a live digest.
#[must_use]
pub fn EVP_MD_get_type(md: EvpMdRef<'_>) -> c_int {
    // SAFETY: the shared digest handle is live and the getter retains nothing.
    unsafe { ffi::EVP_MD_get_type(md.as_ptr()) }
}

/// Wraps: EVP_MD_is_a
/// Reports whether `md` is identified by the requested NUL-terminated name.
#[must_use]
pub fn EVP_MD_is_a(md: Option<EvpMdRef<'_>>, name: &CStr) -> bool {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is accepted for the digest; every non-null digest and the
    // NUL-terminated name are live for the synchronous lookup.
    unsafe { ffi::EVP_MD_is_a(md, name.as_ptr()) == 1 }
}

/// Wraps: EVP_MD_names_do_all
/// Synchronously visits every name associated with a fetched digest.
pub fn EVP_MD_names_do_all<F>(md: EvpMdRef<'_>, callback: &mut F) -> bool
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
    // SAFETY: the digest is live, and the callback/state pair remains valid
    // and uniquely borrowed until synchronous enumeration returns.
    let complete = unsafe {
        ffi::EVP_MD_names_do_all(
            md.as_ptr(),
            Some(trampoline::<F>),
            ptr::from_mut(&mut context).cast(),
        ) == 1
    };
    if let Some(panic) = context.panic {
        resume_unwind(panic);
    }
    complete && context.valid
}

/// Wraps: EVP_MD_xof
/// Reports whether the optional digest is an extendable-output function.
#[must_use]
pub fn EVP_MD_xof(md: Option<EvpMdRef<'_>>) -> bool {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is explicitly accepted; otherwise the shared digest is live.
    unsafe { ffi::EVP_MD_xof(md) == 1 }
}

#[cfg(test)]
mod digest_metadata_tests {
    use super::*;
    use crate::evp::evp::SharedEvpMd;

    fn sha256() -> SharedEvpMd<'static> {
        // SAFETY: null selects the process-wide default context and properties;
        // the name is NUL-terminated and a non-null result transfers one ref.
        let raw = unsafe { ffi::EVP_MD_fetch(ptr::null_mut(), c"SHA2-256".as_ptr(), ptr::null()) };
        // SAFETY: the default context is process-wide and the fresh result
        // transfers one `EVP_MD_free` obligation.
        unsafe { SharedEvpMd::from_raw(raw) }.expect("SHA2-256 digest")
    }

    #[test]
    fn metadata_queries_use_shared_digest_handles() {
        let digest = sha256();
        let md = digest.as_ref();

        assert_eq!(EVP_MD_get_size(Some(md)), 32);
        assert_ne!(EVP_MD_get_type(md), 0);
        let _ = EVP_MD_get_pkey_type(md);
        let _ = EVP_MD_get_flags(md);
        assert!(EVP_MD_is_a(Some(md), c"SHA2-256"));
        assert!(!EVP_MD_xof(Some(md)));

        let mut names = Vec::new();
        assert!(EVP_MD_names_do_all(md, &mut |name| {
            names.push(name.to_bytes().to_vec());
        }));
        assert!(!names.is_empty());
    }

    #[test]
    fn nullable_queries_preserve_the_c_null_contract() {
        assert_eq!(EVP_MD_get_size(None), -1);
        assert!(!EVP_MD_is_a(None, c"SHA2-256"));
        assert!(!EVP_MD_xof(None));
    }

    #[test]
    fn callback_panics_resume_only_after_c_returns() {
        let digest = sha256();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            EVP_MD_names_do_all(digest.as_ref(), &mut |_| panic!("callback panic"));
        }));
        assert!(panic.is_err());
    }
}

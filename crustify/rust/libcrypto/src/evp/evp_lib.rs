//! Wrappers assigned from `crypto/evp/evp_lib.c`.

#![allow(non_snake_case)]

use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use ffibox::CBox;
#[cfg(feature = "deprecated-3-0")]
use ffibox::{CSlice, CSliceMut};
use libcrypto_sys as ffi;

use crate::asn1::openssl_asn1::{Asn1TypeMut, Asn1TypeRef};
use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::{
    EvpCipherRef, EvpMdRef, EvpPkeyCtxMut, EvpPkeyCtxRef, SharedEvpCipher, SharedEvpMd,
};
use crate::evp::evp_local::{EvpCipherCtxMut, EvpCipherCtxRef, EvpMdCtxMut, EvpMdCtxRef};
use crate::evp::p_lib::BorrowedEvpPkey;
use crate::provider::provider_core::OsslProviderRef;
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
        #[cfg(feature = "deprecated-3-0")]
        use ffibox::{CSlice, CSliceMut};

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

/// A type-erased legacy digest-data pointer borrowed from a digest context.
///
/// No value of this type is reachable in this tree: the only wrapper that
/// produces one is [`EVP_MD_CTX_get0_md_data`], whose C implementation is a
/// deprecated stub that always returns null. It is retained because the C
/// declaration still publishes the erased-borrow shape.
#[derive(Clone, Copy)]
pub struct EvpMdCtxData<'a> {
    pointer: NonNull<c_void>,
    borrow: PhantomData<EvpMdCtxRef<'a>>,
}

impl EvpMdCtxData<'_> {
    /// Reinterprets the legacy provider-specific data pointer.
    ///
    /// # Safety
    /// The active legacy digest must store a live, aligned `T` at this pointer,
    /// and the caller must prevent conflicting access.
    #[must_use]
    pub unsafe fn cast<T>(self) -> NonNull<T> {
        self.pointer.cast()
    }
}

/// Wraps: EVP_MD_CTX_clear_flags
pub fn EVP_MD_CTX_clear_flags(ctx: &mut EvpMdCtxMut<'_>, flags: i32) {
    // SAFETY: the exclusive handle permits updating the context flags.
    unsafe { ffi::EVP_MD_CTX_clear_flags(ctx.as_mut_ptr(), flags) }
}

/// Wraps: EVP_MD_CTX_get0_md
/// Borrows the digest record the context was initialized with.
///
/// The result is `ctx->reqdigest`. A context initialized through
/// `EVP_DigestInit*` owns that record, because `evp_md_init_internal` adopts a
/// reference into `ctx->fetched_digest`. A context initialized through
/// [`EVP_DigestSignInit_with_md`](crate::evp::m_sigver::EVP_DigestSignInit_with_md)
/// or its verify twin does not: those store the caller's pointer unreferenced,
/// which is exactly the obligation those `unsafe` wrappers place on their
/// caller.
#[must_use]
pub fn EVP_MD_CTX_get0_md<'a>(ctx: EvpMdCtxRef<'a>) -> Option<EvpMdRef<'a>> {
    // SAFETY: the context is live and the returned digest remains bounded by
    // its borrow.
    let raw = unsafe { ffi::EVP_MD_CTX_get0_md(ctx.as_ptr()) };
    // SAFETY: OpenSSL returns null or the record `ctx` was initialized with,
    // which stays live for `'a` by the initializer's contract.
    unsafe { EvpMdRef::from_ptr(raw.cast_mut()) }
}

#[cfg(feature = "deprecated-4-0")]
/// Wraps: EVP_MD_CTX_get0_md_data
/// Always yields `None`.
///
/// The legacy `md_data` slot is gone: `EVP_MD_CTX_get0_md_data` is retained
/// only for backward compatibility and its body is `return NULL;`. The call is
/// still made rather than short-circuited, so this wrapper keeps tracking the C
/// implementation if it ever grows a result again.
#[must_use]
pub fn EVP_MD_CTX_get0_md_data<'a>(ctx: EvpMdCtxRef<'a>) -> Option<EvpMdCtxData<'a>> {
    // SAFETY: the context is live; the deprecated stub reads nothing from it
    // and returns null.
    NonNull::new(unsafe { ffi::EVP_MD_CTX_get0_md_data(ctx.as_ptr()) }).map(|pointer| {
        EvpMdCtxData {
            pointer,
            borrow: PhantomData,
        }
    })
}

/// Wraps: EVP_MD_CTX_get1_md
#[must_use]
pub fn EVP_MD_CTX_get1_md<'a>(ctx: EvpMdCtxRef<'a>) -> Option<SharedEvpMd<'a>> {
    // The C signature is non-const for historical reasons; only the digest
    // reference count is changed.
    // SAFETY: the context is live and a non-null result transfers one count.
    let raw = unsafe { ffi::EVP_MD_CTX_get1_md(ctx.as_ptr().cast_mut()) };
    // SAFETY: one successful up-reference is released by the shared owner and
    // its context dependency is retained by `'a`.
    unsafe { SharedEvpMd::from_raw(raw) }
}

/// Wraps: EVP_MD_CTX_get_pkey_ctx
#[must_use]
pub fn EVP_MD_CTX_get_pkey_ctx<'a>(ctx: EvpMdCtxRef<'a>) -> Option<EvpPkeyCtxRef<'a>> {
    // SAFETY: the context is live and the returned pointer remains borrowed
    // from it.
    let raw = unsafe { ffi::EVP_MD_CTX_get_pkey_ctx(ctx.as_ptr()) };
    // SAFETY: null is represented as `None`; non-null is retained by `ctx`.
    unsafe { EvpPkeyCtxRef::from_ptr(raw) }
}

/// Wraps: EVP_MD_CTX_get_size_ex
#[must_use]
pub fn EVP_MD_CTX_get_size_ex(ctx: EvpMdCtxRef<'_>) -> i32 {
    // SAFETY: the shared context is live and the query retains no pointer.
    unsafe { ffi::EVP_MD_CTX_get_size_ex(ctx.as_ptr()) }
}

#[cfg(feature = "deprecated-3-0")]
/// Wraps: EVP_MD_CTX_md
#[must_use]
pub fn EVP_MD_CTX_md<'a>(ctx: EvpMdCtxRef<'a>) -> Option<EvpMdRef<'a>> {
    // SAFETY: the context is live and the returned digest is borrowed from it.
    let raw = unsafe { ffi::EVP_MD_CTX_md(ctx.as_ptr()) };
    // SAFETY: null maps to `None`; non-null stays bounded by `'a`.
    unsafe { EvpMdRef::from_ptr(raw.cast_mut()) }
}

/// Wraps: EVP_MD_CTX_set_flags
pub fn EVP_MD_CTX_set_flags(ctx: &mut EvpMdCtxMut<'_>, flags: i32) {
    // SAFETY: the exclusive handle permits updating flags.
    unsafe { ffi::EVP_MD_CTX_set_flags(ctx.as_mut_ptr(), flags) }
}

/// Wraps: EVP_MD_CTX_set_pkey_ctx
///
/// Installs, or with `None` clears, the public-key context a digest context
/// drives. The call first releases whatever `ctx->pctx` already held unless
/// `EVP_MD_CTX_FLAG_KEEP_PKEY_CTX` is set — so it frees the operation context
/// an `EVP_Digest{Sign,Verify}Init*` created — and then sets that flag for a
/// non-null `pctx`, leaving the installed one caller-owned.
///
/// # Safety
/// A non-null `pctx` is stored as a caller-owned borrow and must outlive the
/// digest context. It must remain valid and free of conflicting access until
/// replaced or the digest context is destroyed.
///
/// Two further paths release that storage while the caller still owns it, and
/// the caller must keep the context away from both. `EVP_MD_CTX_reset` and
/// `EVP_MD_CTX_free` consult `EVP_MD_CTX_FLAG_KEEP_PKEY_CTX`, which this call
/// sets, so clearing it through [`EVP_MD_CTX_clear_flags`] re-arms them. And
/// [`EVP_MD_CTX_copy_ex`](crate::evp::digest::EVP_MD_CTX_copy_ex) frees
/// `out->pctx` without consulting the flag at all on its in-place copy path,
/// so this context must not be used as a copy destination either.
pub unsafe fn EVP_MD_CTX_set_pkey_ctx(
    ctx: &mut EvpMdCtxMut<'_>,
    pctx: Option<&mut EvpPkeyCtxMut<'_>>,
) {
    let pctx = pctx.map_or(ptr::null_mut(), |pctx| pctx.as_mut_ptr());
    // SAFETY: the caller establishes the stored-borrow lifetime and aliasing
    // contract; both typed handles are live for this call.
    unsafe { ffi::EVP_MD_CTX_set_pkey_ctx(ctx.as_mut_ptr(), pctx) }
}

/// Wraps: EVP_MD_CTX_test_flags
#[must_use]
pub fn EVP_MD_CTX_test_flags(ctx: EvpMdCtxRef<'_>, flags: i32) -> i32 {
    // SAFETY: the shared context is live and the query only reads flags.
    unsafe { ffi::EVP_MD_CTX_test_flags(ctx.as_ptr(), flags) }
}

/// Wraps: EVP_MD_get0_description
#[must_use]
pub fn EVP_MD_get0_description<'a>(digest: EvpMdRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the digest is live and retains its description or legacy object
    // database entry.
    let raw = unsafe { ffi::EVP_MD_get0_description(digest.as_ptr()) };
    (!raw.is_null()).then(|| {
        // SAFETY: OpenSSL publishes the non-null result as NUL-terminated and
        // keeps it live with the digest.
        unsafe { CStr::from_ptr(raw) }
    })
}

/// Wraps: EVP_MD_get0_name
#[must_use]
pub fn EVP_MD_get0_name<'a>(digest: EvpMdRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the digest is live and retains its name.
    let raw = unsafe { ffi::EVP_MD_get0_name(digest.as_ptr()) };
    (!raw.is_null()).then(|| {
        // SAFETY: OpenSSL publishes a NUL-terminated name bounded by `digest`.
        unsafe { CStr::from_ptr(raw) }
    })
}

/// Wraps: EVP_MD_get0_provider
#[must_use]
pub fn EVP_MD_get0_provider<'a>(digest: EvpMdRef<'a>) -> Option<OsslProviderRef<'a>> {
    // SAFETY: the digest is live and retains its optional provider.
    let raw = unsafe { ffi::EVP_MD_get0_provider(digest.as_ptr()) };
    // SAFETY: a non-null provider stays live with the digest borrow.
    unsafe { OsslProviderRef::from_ptr(raw.cast_mut()) }
}

/// Wraps: EVP_MD_get_block_size
#[must_use]
pub fn EVP_MD_get_block_size(digest: EvpMdRef<'_>) -> i32 {
    // SAFETY: the digest is live and the scalar query retains nothing.
    unsafe { ffi::EVP_MD_get_block_size(digest.as_ptr()) }
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

#[cfg(feature = "deprecated-3-0")]
const EVP_MAX_BLOCK_LENGTH: usize = 32;

/// Wraps: EVP_CIPHER_CTX_buf_noconst
#[cfg(feature = "deprecated-3-0")]
pub fn EVP_CIPHER_CTX_buf_noconst<'a>(ctx: &'a mut EvpCipherCtxMut<'_>) -> CSliceMut<'a, u8> {
    // SAFETY: the exclusive reborrow retains the context and its inline,
    // initialized `EVP_MAX_BLOCK_LENGTH` byte array.
    let buffer = unsafe { ffi::EVP_CIPHER_CTX_buf_noconst(ctx.as_mut_ptr()) };
    // SAFETY: the C getter always returns the start of that inline array.
    unsafe { CSliceMut::from_raw_parts(NonNull::new_unchecked(buffer), EVP_MAX_BLOCK_LENGTH) }
}

/// Wraps: EVP_CIPHER_CTX_cipher
#[cfg(feature = "deprecated-3-0")]
#[must_use]
pub fn EVP_CIPHER_CTX_cipher<'a>(ctx: EvpCipherCtxRef<'a>) -> Option<EvpCipherRef<'a>> {
    // SAFETY: the live context retains its optional active cipher.
    let cipher = unsafe { ffi::EVP_CIPHER_CTX_cipher(ctx.as_ptr()) };
    // SAFETY: a non-null cipher remains live for the context borrow.
    unsafe { EvpCipherRef::from_ptr(cipher.cast_mut()) }
}

/// Wraps: EVP_CIPHER_CTX_clear_flags
pub fn EVP_CIPHER_CTX_clear_flags(ctx: &mut EvpCipherCtxMut<'_>, flags: c_int) {
    // SAFETY: the context is exclusively borrowed for this mutation.
    unsafe { ffi::EVP_CIPHER_CTX_clear_flags(ctx.as_mut_ptr(), flags) }
}

/// Wraps: EVP_CIPHER_CTX_get0_cipher
#[must_use]
pub fn EVP_CIPHER_CTX_get0_cipher<'a>(ctx: EvpCipherCtxRef<'a>) -> Option<EvpCipherRef<'a>> {
    // SAFETY: the live context retains its optional active cipher.
    let cipher = unsafe { ffi::EVP_CIPHER_CTX_get0_cipher(ctx.as_ptr()) };
    // SAFETY: a non-null cipher remains live for the context borrow.
    unsafe { EvpCipherRef::from_ptr(cipher.cast_mut()) }
}

/// Wraps: EVP_CIPHER_CTX_get1_cipher
#[must_use]
pub fn EVP_CIPHER_CTX_get1_cipher<'a>(ctx: EvpCipherCtxRef<'a>) -> Option<SharedEvpCipher<'a>> {
    // SAFETY: the context is live and C only reads its active cipher before
    // atomically raising that cipher's public reference count.
    let cipher = unsafe { ffi::EVP_CIPHER_CTX_get1_cipher(ctx.as_ptr().cast_mut()) };
    // SAFETY: a non-null result transfers the raised reference and remains
    // conservatively bounded by the context's dependencies.
    unsafe { SharedEvpCipher::from_raw(cipher) }
}

/// Wraps: EVP_CIPHER_CTX_get_app_data
///
/// # Safety
///
/// `T` must be the concrete type previously stored in this context, and that
/// object must still be live. The returned pointer remains non-owning.
#[must_use]
pub unsafe fn EVP_CIPHER_CTX_get_app_data<T>(ctx: EvpCipherCtxRef<'_>) -> Option<NonNull<T>> {
    // SAFETY: the context is live and C only returns the stored opaque value.
    NonNull::new(unsafe { ffi::EVP_CIPHER_CTX_get_app_data(ctx.as_ptr()) }.cast())
}

/// Wraps: EVP_CIPHER_CTX_get_block_size
#[must_use]
pub fn EVP_CIPHER_CTX_get_block_size(ctx: EvpCipherCtxRef<'_>) -> c_int {
    // SAFETY: the context is live and the query retains nothing.
    unsafe { ffi::EVP_CIPHER_CTX_get_block_size(ctx.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_get_cipher_data
///
/// # Safety
///
/// `T` must be the concrete type previously stored in this context, and that
/// object must still be live. The returned pointer remains non-owning.
#[must_use]
pub unsafe fn EVP_CIPHER_CTX_get_cipher_data<T>(ctx: EvpCipherCtxRef<'_>) -> Option<NonNull<T>> {
    // SAFETY: the context is live and C only returns the stored opaque value.
    NonNull::new(unsafe { ffi::EVP_CIPHER_CTX_get_cipher_data(ctx.as_ptr()) }.cast())
}

/// Wraps: EVP_CIPHER_CTX_get_iv_length
#[must_use]
pub fn EVP_CIPHER_CTX_get_iv_length(ctx: EvpCipherCtxRef<'_>) -> c_int {
    // SAFETY: the context is live; OpenSSL may update its internal length cache
    // but returns no borrow.
    unsafe { ffi::EVP_CIPHER_CTX_get_iv_length(ctx.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_get_key_length
#[must_use]
pub fn EVP_CIPHER_CTX_get_key_length(ctx: EvpCipherCtxRef<'_>) -> c_int {
    // SAFETY: the context is live; OpenSSL may update its internal length cache
    // but returns no borrow.
    unsafe { ffi::EVP_CIPHER_CTX_get_key_length(ctx.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_get_nid
#[must_use]
pub fn EVP_CIPHER_CTX_get_nid(ctx: EvpCipherCtxRef<'_>) -> c_int {
    // SAFETY: the context is live and the query retains nothing.
    unsafe { ffi::EVP_CIPHER_CTX_get_nid(ctx.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_get_num
#[cfg(feature = "deprecated-4-1")]
#[must_use]
pub fn EVP_CIPHER_CTX_get_num(ctx: EvpCipherCtxRef<'_>) -> c_int {
    // SAFETY: the context is live and C returns the provider's scalar value.
    unsafe { ffi::EVP_CIPHER_CTX_get_num(ctx.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_get_original_iv
pub fn EVP_CIPHER_CTX_get_original_iv(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> bool {
    // SAFETY: the exclusive context and exact writable byte extent remain live
    // throughout the synchronous provider call.
    unsafe {
        ffi::EVP_CIPHER_CTX_get_original_iv(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        ) == 1
    }
}

/// Wraps: EVP_CIPHER_CTX_get_tag_length
#[must_use]
pub fn EVP_CIPHER_CTX_get_tag_length(ctx: EvpCipherCtxRef<'_>) -> c_int {
    // SAFETY: the context is live and the query retains nothing.
    unsafe { ffi::EVP_CIPHER_CTX_get_tag_length(ctx.as_ptr()) }
}

/// Wraps: EVP_CIPHER_CTX_get_updated_iv
pub fn EVP_CIPHER_CTX_get_updated_iv(ctx: &mut EvpCipherCtxMut<'_>, output: &mut [u8]) -> bool {
    // SAFETY: the exclusive context and exact writable byte extent remain live
    // throughout the synchronous provider call.
    unsafe {
        ffi::EVP_CIPHER_CTX_get_updated_iv(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        ) == 1
    }
}

/// Wraps: EVP_CIPHER_CTX_is_encrypting
#[must_use]
pub fn EVP_CIPHER_CTX_is_encrypting(ctx: EvpCipherCtxRef<'_>) -> bool {
    // SAFETY: the context is live and the query retains nothing.
    unsafe { ffi::EVP_CIPHER_CTX_is_encrypting(ctx.as_ptr()) != 0 }
}

#[cfg(feature = "deprecated-3-0")]
unsafe fn deprecated_iv<'a>(
    ctx: EvpCipherCtxRef<'a>,
    get: unsafe extern "C" fn(*const ffi::EVP_CIPHER_CTX) -> *const u8,
) -> Option<CSlice<'a, u8>> {
    // SAFETY: the context is live and the scalar query retains nothing.
    let len = unsafe { ffi::EVP_CIPHER_CTX_get_iv_length(ctx.as_ptr()) };
    let len = usize::try_from(len).ok()?;
    // SAFETY: selected getter has the same live-context contract.
    let iv = unsafe { get(ctx.as_ptr()) };
    let iv = NonNull::new(iv.cast_mut())?;
    // SAFETY: OpenSSL publishes at least the active IV length at this pointer,
    // retained by the context for `'a`. `CSlice` forms no Rust reference.
    Some(unsafe { CSlice::from_raw_parts(iv, len) })
}

/// Wraps: EVP_CIPHER_CTX_iv
#[cfg(feature = "deprecated-3-0")]
#[must_use]
pub fn EVP_CIPHER_CTX_iv<'a>(ctx: EvpCipherCtxRef<'a>) -> Option<CSlice<'a, u8>> {
    // SAFETY: the selected C getter returns the running IV retained by `ctx`.
    unsafe { deprecated_iv(ctx, ffi::EVP_CIPHER_CTX_iv) }
}

/// Wraps: EVP_CIPHER_CTX_iv_noconst
#[cfg(feature = "deprecated-3-0")]
#[must_use]
pub fn EVP_CIPHER_CTX_iv_noconst<'a>(
    ctx: &'a mut EvpCipherCtxMut<'_>,
) -> Option<CSliceMut<'a, u8>> {
    // SAFETY: the context is live and the query retains nothing.
    let len = unsafe { ffi::EVP_CIPHER_CTX_get_iv_length(ctx.as_ref().as_ptr()) };
    let len = usize::try_from(len).ok()?;
    // SAFETY: the exclusive context permits requesting its writable running IV.
    let iv = unsafe { ffi::EVP_CIPHER_CTX_iv_noconst(ctx.as_mut_ptr()) };
    let iv = NonNull::new(iv)?;
    // SAFETY: OpenSSL publishes at least `len` writable IV bytes retained by
    // the exclusive reborrow. `CSliceMut` forms no Rust reference.
    Some(unsafe { CSliceMut::from_raw_parts(iv, len) })
}

/// Wraps: EVP_CIPHER_CTX_original_iv
#[cfg(feature = "deprecated-3-0")]
#[must_use]
pub fn EVP_CIPHER_CTX_original_iv<'a>(ctx: EvpCipherCtxRef<'a>) -> Option<CSlice<'a, u8>> {
    // SAFETY: the selected C getter returns the original IV retained by `ctx`.
    unsafe { deprecated_iv(ctx, ffi::EVP_CIPHER_CTX_original_iv) }
}

/// Wraps: EVP_CIPHER_CTX_set_app_data
///
/// # Safety
///
/// A non-null `data` must remain live and at a stable address until it is
/// replaced or the context is dropped, including across context duplication.
pub unsafe fn EVP_CIPHER_CTX_set_app_data<T>(
    ctx: &mut EvpCipherCtxMut<'_>,
    data: Option<NonNull<T>>,
) {
    // SAFETY: the exclusive context is live; the stored-lifetime obligation is
    // carried by the caller because the C context cannot encode it.
    unsafe {
        ffi::EVP_CIPHER_CTX_set_app_data(
            ctx.as_mut_ptr(),
            data.map_or(ptr::null_mut(), |data| data.as_ptr().cast()),
        )
    }
}

/// Wraps: EVP_CIPHER_CTX_set_cipher_data
///
/// # Safety
///
/// A non-null `data` must remain live and at a stable address until replaced
/// or the context is dropped, including across context duplication. `T` must
/// also match the type of any previously stored pointer returned here.
#[must_use]
pub unsafe fn EVP_CIPHER_CTX_set_cipher_data<T>(
    ctx: &mut EvpCipherCtxMut<'_>,
    data: Option<NonNull<T>>,
) -> Option<NonNull<T>> {
    // SAFETY: the exclusive context is live; the erased type and stored
    // lifetime are the caller obligations stated above.
    NonNull::new(
        unsafe {
            ffi::EVP_CIPHER_CTX_set_cipher_data(
                ctx.as_mut_ptr(),
                data.map_or(ptr::null_mut(), |data| data.as_ptr().cast()),
            )
        }
        .cast(),
    )
}

/// Wraps: EVP_CIPHER_CTX_set_flags
pub fn EVP_CIPHER_CTX_set_flags(ctx: &mut EvpCipherCtxMut<'_>, flags: c_int) {
    // SAFETY: the context is exclusively borrowed for this mutation.
    unsafe { ffi::EVP_CIPHER_CTX_set_flags(ctx.as_mut_ptr(), flags) }
}

/// Wraps: EVP_CIPHER_CTX_set_num
#[cfg(feature = "deprecated-4-1")]
pub fn EVP_CIPHER_CTX_set_num(ctx: &mut EvpCipherCtxMut<'_>, num: c_int) -> c_int {
    // SAFETY: the context is exclusively borrowed for this mutation.
    unsafe { ffi::EVP_CIPHER_CTX_set_num(ctx.as_mut_ptr(), num) }
}

/// Wraps: EVP_CIPHER_CTX_test_flags
#[must_use]
pub fn EVP_CIPHER_CTX_test_flags(ctx: EvpCipherCtxRef<'_>, flags: c_int) -> c_int {
    // SAFETY: the context is live and only its scalar flag word is inspected.
    unsafe { ffi::EVP_CIPHER_CTX_test_flags(ctx.as_ptr(), flags) }
}

/// Wraps: EVP_CIPHER_get0_description
#[must_use]
pub fn EVP_CIPHER_get0_description<'a>(cipher: EvpCipherRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the live cipher retains its optional NUL-terminated description.
    let description = unsafe { ffi::EVP_CIPHER_get0_description(cipher.as_ptr()) };
    if description.is_null() {
        None
    } else {
        // SAFETY: the cipher retains the string throughout `'a`.
        Some(unsafe { CStr::from_ptr(description) })
    }
}

/// Wraps: EVP_CIPHER_get0_name
#[must_use]
pub fn EVP_CIPHER_get0_name<'a>(cipher: EvpCipherRef<'a>) -> Option<&'a CStr> {
    // SAFETY: the live cipher retains or statically references its name.
    let name = unsafe { ffi::EVP_CIPHER_get0_name(cipher.as_ptr()) };
    if name.is_null() {
        None
    } else {
        // SAFETY: the cipher retains the NUL-terminated string throughout `'a`.
        Some(unsafe { CStr::from_ptr(name) })
    }
}

/// Wraps: EVP_CIPHER_get0_provider
#[must_use]
pub fn EVP_CIPHER_get0_provider<'a>(cipher: EvpCipherRef<'a>) -> Option<OsslProviderRef<'a>> {
    // SAFETY: the live cipher retains its optional provider reference.
    let provider = unsafe { ffi::EVP_CIPHER_get0_provider(cipher.as_ptr()) };
    // SAFETY: ownership is not transferred and the cipher keeps it live.
    unsafe { OsslProviderRef::from_ptr(provider.cast_mut()) }
}

/// Wraps: EVP_CIPHER_get_block_size
#[must_use]
pub fn EVP_CIPHER_get_block_size(cipher: EvpCipherRef<'_>) -> c_int {
    // SAFETY: the cipher is live and only immutable metadata is read.
    unsafe { ffi::EVP_CIPHER_get_block_size(cipher.as_ptr()) }
}

/// Wraps: EVP_CIPHER_get_flags
#[must_use]
pub fn EVP_CIPHER_get_flags(cipher: EvpCipherRef<'_>) -> c_ulong {
    // SAFETY: the cipher is live and only immutable metadata is read.
    unsafe { ffi::EVP_CIPHER_get_flags(cipher.as_ptr()) }
}

/// Wraps: EVP_CIPHER_get_iv_length
#[must_use]
pub fn EVP_CIPHER_get_iv_length(cipher: EvpCipherRef<'_>) -> c_int {
    // SAFETY: the cipher is live and only immutable metadata is read.
    unsafe { ffi::EVP_CIPHER_get_iv_length(cipher.as_ptr()) }
}

/// Wraps: EVP_CIPHER_get_key_length
#[must_use]
pub fn EVP_CIPHER_get_key_length(cipher: EvpCipherRef<'_>) -> c_int {
    // SAFETY: the cipher is live and only immutable metadata is read.
    unsafe { ffi::EVP_CIPHER_get_key_length(cipher.as_ptr()) }
}

/// Wraps: EVP_CIPHER_get_mode
#[must_use]
pub fn EVP_CIPHER_get_mode(cipher: EvpCipherRef<'_>) -> c_int {
    // SAFETY: the cipher is live and only immutable metadata is read.
    unsafe { ffi::EVP_CIPHER_get_mode(cipher.as_ptr()) }
}

#[cfg(test)]
mod cipher_metadata_tests {
    use super::*;
    use crate::evp::evp_enc::{EVP_CIPHER_CTX_new, EVP_CIPHER_fetch};

    #[test]
    fn fetched_cipher_metadata_is_lifetime_bound() {
        let cipher = EVP_CIPHER_fetch(None, c"AES-128-CBC", None).expect("cipher");
        let cipher = cipher.as_ref();
        assert_eq!(EVP_CIPHER_get_block_size(cipher), 16);
        assert_eq!(EVP_CIPHER_get_key_length(cipher), 16);
        assert_eq!(EVP_CIPHER_get_iv_length(cipher), 16);
        assert_eq!(
            EVP_CIPHER_get0_name(cipher).unwrap().to_bytes(),
            b"AES-128-CBC"
        );
        assert!(EVP_CIPHER_get0_provider(cipher).is_some());
    }

    #[test]
    fn empty_context_has_safe_scalar_queries() {
        let context = EVP_CIPHER_CTX_new().expect("context");
        let context = context.as_ref();
        assert!(EVP_CIPHER_CTX_get0_cipher(context).is_none());
        assert_eq!(EVP_CIPHER_CTX_get_block_size(context), 0);
        assert_eq!(EVP_CIPHER_CTX_get_iv_length(context), 0);
        assert_eq!(EVP_CIPHER_CTX_get_key_length(context), 0);
    }
}

/// Wraps: EVP_CIPHER_get_nid
#[must_use]
pub fn EVP_CIPHER_get_nid(cipher: Option<crate::evp::evp::EvpCipherRef<'_>>) -> c_int {
    let cipher = cipher.map_or(ptr::null(), |cipher| cipher.as_ptr());
    // SAFETY: null is accepted; otherwise the shared handle is live.
    unsafe { ffi::EVP_CIPHER_get_nid(cipher) }
}

/// Wraps: EVP_CIPHER_get_type
#[must_use]
pub fn EVP_CIPHER_get_type(cipher: Option<crate::evp::evp::EvpCipherRef<'_>>) -> c_int {
    let cipher = cipher.map_or(ptr::null(), |cipher| cipher.as_ptr());
    // SAFETY: null is accepted through the NID getter; otherwise the handle is live.
    unsafe { ffi::EVP_CIPHER_get_type(cipher) }
}

/// Wraps: EVP_CIPHER_impl_ctx_size
#[must_use]
pub fn EVP_CIPHER_impl_ctx_size(cipher: Option<crate::evp::evp::EvpCipherRef<'_>>) -> c_int {
    let cipher = cipher.map_or(ptr::null(), |cipher| cipher.as_ptr());
    // SAFETY: this compatibility implementation accepts null and retains nothing.
    unsafe { ffi::EVP_CIPHER_impl_ctx_size(cipher) }
}

/// Wraps: EVP_CIPHER_is_a
#[must_use]
pub fn EVP_CIPHER_is_a(cipher: Option<crate::evp::evp::EvpCipherRef<'_>>, name: &CStr) -> bool {
    let cipher = cipher.map_or(ptr::null(), |cipher| cipher.as_ptr());
    // SAFETY: null is accepted for the cipher and `name` is NUL-terminated.
    unsafe { ffi::EVP_CIPHER_is_a(cipher, name.as_ptr()) == 1 }
}

/// Wraps: EVP_CIPHER_names_do_all
/// Synchronously visits every provider name associated with a cipher.
pub fn EVP_CIPHER_names_do_all<F>(
    cipher: crate::evp::evp::EvpCipherRef<'_>,
    callback: &mut F,
) -> bool
where
    F: for<'name> FnMut(&'name CStr),
{
    struct State<'a, F> {
        callback: &'a mut F,
        panic: Option<Box<dyn core::any::Any + Send>>,
        valid: bool,
    }
    unsafe extern "C" fn trampoline<F>(name: *const c_char, data: *mut c_void)
    where
        F: for<'name> FnMut(&'name CStr),
    {
        // SAFETY: the wrapper keeps this exact state uniquely borrowed.
        let state = unsafe { &mut *data.cast::<State<'_, F>>() };
        if state.panic.is_some() {
            return;
        }
        if name.is_null() {
            state.valid = false;
            return;
        }
        // SAFETY: OpenSSL supplies a live NUL-terminated callback name.
        let name = unsafe { CStr::from_ptr(name) };
        if let Err(panic) = catch_unwind(AssertUnwindSafe(|| (state.callback)(name))) {
            state.panic = Some(panic);
        }
    }
    let mut state = State {
        callback,
        panic: None,
        valid: true,
    };
    // SAFETY: cipher, trampoline and state remain live until traversal returns.
    let complete = unsafe {
        ffi::EVP_CIPHER_names_do_all(
            cipher.as_ptr(),
            Some(trampoline::<F>),
            ptr::from_mut(&mut state).cast(),
        ) == 1
    };
    if let Some(panic) = state.panic {
        resume_unwind(panic);
    }
    complete && state.valid
}

/// Wraps: EVP_Cipher
/// Dispatches update or final after checking the implicit output capacity.
pub fn EVP_Cipher(
    ctx: &mut crate::evp::evp_local::EvpCipherCtxMut<'_>,
    output: &mut [u8],
    input: Option<&[u8]>,
) -> c_int {
    let input_len = match input.map_or(Ok(0), |input| u32::try_from(input.len())) {
        Ok(len) => len,
        Err(_) => return 0,
    };
    // SAFETY: the live context is queried synchronously for scalar metadata.
    let block = EVP_CIPHER_CTX_get_block_size(ctx.as_ref());
    let Ok(block) = usize::try_from(block) else {
        return 0;
    };
    if block == 0 {
        return 0;
    }
    let Some(required) =
        input
            .map_or(0, <[u8]>::len)
            .checked_add(if block == 1 { 0 } else { block })
    else {
        return 0;
    };
    if output.len() < required {
        return 0;
    }
    let output = output.as_mut_ptr();
    let input = input.map_or(ptr::null(), <[u8]>::as_ptr);
    // SAFETY: input has the supplied extent and output has worst-case capacity. Null input selects finalization and nothing is retained.
    unsafe { ffi::EVP_Cipher(ctx.as_mut_ptr(), output, input, input_len) }
}

#[cfg(test)]
mod scheduled_cipher_metadata_tests {
    use super::*;
    use crate::evp::evp::SharedEvpCipher;

    #[test]
    fn metadata_and_names_use_typed_borrows() {
        let cipher: SharedEvpCipher<'static> =
            crate::evp::evp_enc::EVP_CIPHER_fetch(None, c"AES-128-CBC", None).expect("AES-128-CBC");
        assert_ne!(
            EVP_CIPHER_get_nid(Some(cipher.as_ref())),
            ffi::NID_undef as i32
        );
        assert!(EVP_CIPHER_is_a(Some(cipher.as_ref()), c"AES-128-CBC"));
        assert_eq!(EVP_CIPHER_impl_ctx_size(Some(cipher.as_ref())), 0);
        let mut names = Vec::new();
        assert!(EVP_CIPHER_names_do_all(cipher.as_ref(), &mut |name| {
            names.push(name.to_bytes().to_vec());
        }));
        assert!(names.iter().any(|name| name == b"AES-128-CBC"));
    }
}

/// Wraps: EVP_CIPHER_asn1_to_param
///
/// Applies the borrowed ASN.1 algorithm parameters to an initialized cipher
/// context. A missing context preserves OpenSSL's error-returning null case.
pub fn EVP_CIPHER_asn1_to_param(
    ctx: Option<&mut EvpCipherCtxMut<'_>>,
    parameters: Asn1TypeRef<'_>,
) -> c_int {
    let ctx = ctx.map_or(ptr::null_mut(), |ctx| ctx.as_mut_ptr());
    // SAFETY: `ctx` is null or exclusively borrowed and `parameters` remains
    // live for the call. This conversion path only reads the ASN.1 value; the
    // legacy C signature predates const-correctness and retains neither input.
    unsafe { ffi::EVP_CIPHER_asn1_to_param(ctx, parameters.as_ptr().cast_mut()) }
}

/// Wraps: EVP_CIPHER_get_asn1_iv
///
/// Reads an optional ASN.1 octet string and installs it as the context IV.
pub fn EVP_CIPHER_get_asn1_iv(
    ctx: &mut EvpCipherCtxMut<'_>,
    parameters: Option<Asn1TypeRef<'_>>,
) -> c_int {
    let parameters = parameters.map_or(ptr::null_mut(), |value| value.as_ptr().cast_mut());
    // SAFETY: the context is exclusively borrowed. The optional ASN.1 value
    // is null or live and only read synchronously; OpenSSL retains no pointer.
    unsafe { ffi::EVP_CIPHER_get_asn1_iv(ctx.as_mut_ptr(), parameters) }
}

/// Wraps: EVP_CIPHER_param_to_asn1
///
/// Replaces the ASN.1 algorithm parameters with those of the cipher context.
/// A missing context preserves OpenSSL's error-returning null case.
pub fn EVP_CIPHER_param_to_asn1(
    ctx: Option<&mut EvpCipherCtxMut<'_>>,
    parameters: &mut Asn1TypeMut<'_>,
) -> c_int {
    let ctx = ctx.map_or(ptr::null_mut(), |ctx| ctx.as_mut_ptr());
    // SAFETY: `ctx` is null or exclusively borrowed and `parameters` is a live
    // exclusive ASN.1 value whose payload OpenSSL may replace synchronously.
    unsafe { ffi::EVP_CIPHER_param_to_asn1(ctx, parameters.as_mut_ptr()) }
}

/// Wraps: EVP_CIPHER_set_asn1_iv
///
/// Copies the context's original IV into an optional ASN.1 value.
pub fn EVP_CIPHER_set_asn1_iv(
    ctx: EvpCipherCtxRef<'_>,
    parameters: Option<&mut Asn1TypeMut<'_>>,
) -> c_int {
    let parameters = parameters.map_or(ptr::null_mut(), |value| value.as_mut_ptr());
    // SAFETY: the live context is only queried for its original IV and length.
    // The optional ASN.1 value is exclusively borrowed for payload replacement;
    // the C function copies the bytes and retains neither pointer.
    unsafe { ffi::EVP_CIPHER_set_asn1_iv(ctx.as_ptr().cast_mut(), parameters) }
}

#[cfg(test)]
mod cipher_asn1_parameter_tests {
    use super::*;
    use crate::asn1::openssl_asn1::Asn1Type;
    use crate::evp::evp_enc::{
        CipherDirection, EVP_CIPHER_CTX_new, EVP_CIPHER_fetch, EVP_CipherInit_ex2,
    };

    fn initialized_context(
        cipher: EvpCipherRef<'_>,
        iv: Option<&[u8]>,
    ) -> CBox<crate::evp::evp_local::EvpCipherCtx> {
        let mut ctx = EVP_CIPHER_CTX_new().expect("cipher context");
        assert_eq!(
            EVP_CipherInit_ex2(
                &mut ctx.as_mut(),
                Some(cipher),
                Some(&[0x42; 16]),
                iv,
                None,
                CipherDirection::Encrypt,
            ),
            1
        );
        ctx
    }

    #[test]
    fn cipher_iv_helpers_accept_their_documented_optional_parameter() {
        let cipher = EVP_CIPHER_fetch(None, c"AES-128-CBC", None).expect("AES-128-CBC");
        let mut ctx = initialized_context(cipher.as_ref(), Some(&[0x24; 16]));
        let mut parameters = Asn1Type::new().expect("ASN1_TYPE_new");

        assert_eq!(
            EVP_CIPHER_set_asn1_iv(ctx.as_ref(), Some(&mut parameters.as_mut())),
            1
        );
        assert_eq!(
            EVP_CIPHER_get_asn1_iv(&mut ctx.as_mut(), Some(parameters.as_ref())),
            16
        );
        assert_eq!(EVP_CIPHER_set_asn1_iv(ctx.as_ref(), None), 0);
        assert_eq!(EVP_CIPHER_get_asn1_iv(&mut ctx.as_mut(), None), 0);
    }

    #[test]
    fn cipher_parameters_round_trip_through_asn1() {
        let cipher = EVP_CIPHER_fetch(None, c"AES-128-CBC", None).expect("AES-128-CBC");
        let mut source = initialized_context(cipher.as_ref(), Some(&[0x24; 16]));
        let mut parameters = Asn1Type::new().expect("ASN1_TYPE_new");

        assert!(
            EVP_CIPHER_param_to_asn1(Some(&mut source.as_mut()), &mut parameters.as_mut(),) > 0
        );

        let mut target = initialized_context(cipher.as_ref(), None);
        assert!(EVP_CIPHER_asn1_to_param(Some(&mut target.as_mut()), parameters.as_ref()) > 0);
        assert!(EVP_CIPHER_param_to_asn1(None, &mut parameters.as_mut()) <= 0);
    }
}

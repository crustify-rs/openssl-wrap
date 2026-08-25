//! Wrappers assigned from `crypto/evp/digest.c`.

#![allow(non_snake_case)]

use core::ptr::{self, NonNull};

use ffibox::CSlice;
use libcrypto_sys as ffi;

use crate::core::openssl_core::{OsslParam, OsslParamArray, terminated_param_len};
use crate::evp::evp::EvpMdRef;

/// Wraps: EVP_MD_get_params
/// Retrieves digest implementation parameters into a terminated descriptor array.
pub fn EVP_MD_get_params(digest: Option<EvpMdRef<'_>>, params: &mut OsslParamArray<'_>) -> bool {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: null is accepted for the digest. The parameter array owns an
    // initialized terminator and exclusively borrows every writable data run.
    unsafe { ffi::EVP_MD_get_params(digest, params.as_mut_ptr()) == 1 }
}

/// Wraps: EVP_MD_gettable_ctx_params
/// Returns the provider-owned descriptor run for retrievable context parameters.
#[must_use]
pub fn EVP_MD_gettable_ctx_params<'md>(
    md: Option<EvpMdRef<'md>>,
) -> Option<CSlice<'md, OsslParam<'md>>> {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is accepted; a non-null shared digest remains live for `'md`.
    let params = unsafe { ffi::EVP_MD_gettable_ctx_params(md) };
    // SAFETY: a non-null provider result is a constant, initialized,
    // null-key-terminated descriptor array retained by the digest/provider.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'md>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the digest borrow retains their provider for `'md`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_MD_gettable_params
/// Returns the provider-owned descriptor run for retrievable digest parameters.
#[must_use]
pub fn EVP_MD_gettable_params<'md>(
    digest: Option<EvpMdRef<'md>>,
) -> Option<CSlice<'md, OsslParam<'md>>> {
    let digest = digest.map_or(ptr::null(), |digest| digest.as_ptr());
    // SAFETY: null is accepted; a non-null shared digest remains live for `'md`.
    let params = unsafe { ffi::EVP_MD_gettable_params(digest) };
    // SAFETY: a non-null provider result is a constant, initialized,
    // null-key-terminated descriptor array retained by the digest/provider.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'md>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the digest borrow retains their provider for `'md`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

/// Wraps: EVP_MD_settable_ctx_params
/// Returns the provider-owned descriptor run for settable context parameters.
#[must_use]
pub fn EVP_MD_settable_ctx_params<'md>(
    md: Option<EvpMdRef<'md>>,
) -> Option<CSlice<'md, OsslParam<'md>>> {
    let md = md.map_or(ptr::null(), |md| md.as_ptr());
    // SAFETY: null is accepted; a non-null shared digest remains live for `'md`.
    let params = unsafe { ffi::EVP_MD_settable_ctx_params(md) };
    // SAFETY: a non-null provider result is a constant, initialized,
    // null-key-terminated descriptor array retained by the digest/provider.
    let len = unsafe { terminated_param_len(params) }?;
    let params = NonNull::new(params.cast_mut().cast::<OsslParam<'md>>())?;
    // SAFETY: the scan established `len` initialized entries before the
    // terminator and the digest borrow retains their provider for `'md`.
    Some(unsafe { CSlice::from_raw_parts(params, len) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::evp::SharedEvpMd;

    fn fetch(name: &core::ffi::CStr) -> SharedEvpMd<'static> {
        // SAFETY: null selects the process-wide default context and properties;
        // the name is NUL-terminated and a non-null result transfers one ref.
        let raw = unsafe { ffi::EVP_MD_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        // SAFETY: the default context is process-wide and the fresh result
        // transfers one `EVP_MD_free` obligation.
        unsafe { SharedEvpMd::from_raw(raw) }.expect("fetched digest")
    }

    #[test]
    fn get_params_accepts_safe_owned_descriptor_storage() {
        let digest = fetch(c"SHA2-256");
        let mut params = OsslParamArray::new(&[]);
        assert!(EVP_MD_get_params(Some(digest.as_ref()), &mut params));
        assert!(!EVP_MD_get_params(None, &mut params));
    }

    #[test]
    fn descriptor_tables_are_lifetime_bound_to_the_digest() {
        let digest = fetch(c"SHAKE-128");
        let md = digest.as_ref();

        let gettable = EVP_MD_gettable_params(Some(md)).expect("digest parameters");
        assert!(!gettable.is_empty());
        for index in 0..gettable.len() {
            assert!(gettable.get(index).and_then(|param| param.key()).is_some());
        }

        let _ = EVP_MD_gettable_ctx_params(Some(md));
        let _ = EVP_MD_settable_ctx_params(Some(md));
        assert!(EVP_MD_gettable_params(None).is_none());
        assert!(EVP_MD_gettable_ctx_params(None).is_none());
        assert!(EVP_MD_settable_ctx_params(None).is_none());
    }
}

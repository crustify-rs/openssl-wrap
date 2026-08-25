//! Wrappers assigned from `crypto/evp/evp_lib.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr;

use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::EvpPkeyCtxMut;
use crate::evp::p_lib::BorrowedEvpPkey;

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
}

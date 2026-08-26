//! Wrappers assigned from `include/openssl/kdf.h`.

#![allow(non_snake_case)]

#[cfg(feature = "deprecated-4-1")]
use crate::evp::evp::EvpKdfRef;
#[cfg(feature = "deprecated-4-1")]
use crate::evp::evp_local::EvpKdfCtxRef;

/// Wraps: EVP_KDF_CTX_kdf
/// Deprecated spelling of [`crate::evp::kdf_lib::EVP_KDF_CTX_get0_kdf`].
#[cfg(feature = "deprecated-4-1")]
#[must_use]
pub fn EVP_KDF_CTX_kdf<'a>(ctx: EvpKdfCtxRef<'a>) -> Option<EvpKdfRef<'a>> {
    crate::evp::kdf_lib::EVP_KDF_CTX_get0_kdf(ctx)
}

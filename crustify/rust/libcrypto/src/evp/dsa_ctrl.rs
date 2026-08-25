//! Wrappers assigned from `crypto/evp/dsa_ctrl.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr;

use libcrypto_sys as ffi;

use crate::evp::evp::{EvpMdRef, EvpPkeyCtxMut};

macro_rules! scalar_setter {
    ($(#[$attr:meta])* $name:ident, $arg:ident) => {
        $(#[$attr])*
        pub fn $name(ctx: &mut EvpPkeyCtxMut<'_>, $arg: i32) -> i32 {
            // SAFETY: the context is exclusively borrowed and C validates the
            // by-value parameter for the active operation.
            unsafe { ffi::$name(ctx.as_mut_ptr(), $arg) }
        }
    };
}

scalar_setter!(
    /// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_bits
    EVP_PKEY_CTX_set_dsa_paramgen_bits, bits
);

scalar_setter!(
    /// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_gindex
    EVP_PKEY_CTX_set_dsa_paramgen_gindex, gindex
);

/// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_md
pub fn EVP_PKEY_CTX_set_dsa_paramgen_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest: EvpMdRef<'static>,
) -> i32 {
    // SAFETY: the context is exclusively borrowed and the immortal digest
    // handle remains valid if a legacy control path retains its pointer.
    unsafe { ffi::EVP_PKEY_CTX_set_dsa_paramgen_md(ctx.as_mut_ptr(), digest.as_ptr()) }
}

/// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_md_props
pub fn EVP_PKEY_CTX_set_dsa_paramgen_md_props(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest_name: &CStr,
    properties: Option<&CStr>,
) -> i32 {
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: both names are null or live NUL-terminated strings for the
    // synchronous parameter call; the exclusive context is live.
    unsafe {
        ffi::EVP_PKEY_CTX_set_dsa_paramgen_md_props(
            ctx.as_mut_ptr(),
            digest_name.as_ptr(),
            properties,
        )
    }
}

scalar_setter!(
    /// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_q_bits
    EVP_PKEY_CTX_set_dsa_paramgen_q_bits, bits
);

/// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_seed
pub fn EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx: &mut EvpPkeyCtxMut<'_>, seed: &[u8]) -> i32 {
    // SAFETY: `seed` supplies its exact readable length and remains live for
    // the synchronous parameter setter, which copies the seed value.
    unsafe { ffi::EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx.as_mut_ptr(), seed.as_ptr(), seed.len()) }
}

/// Wraps: EVP_PKEY_CTX_set_dsa_paramgen_type
pub fn EVP_PKEY_CTX_set_dsa_paramgen_type(ctx: &mut EvpPkeyCtxMut<'_>, name: &CStr) -> i32 {
    // SAFETY: the exclusive context and NUL-terminated name remain live for
    // the synchronous parameter setter.
    unsafe { ffi::EVP_PKEY_CTX_set_dsa_paramgen_type(ctx.as_mut_ptr(), name.as_ptr()) }
}

#[cfg(test)]
mod tests {
    use ffibox::CBox;

    use super::*;
    use crate::evp::evp::EvpPkeyCtx;
    use crate::evp::pmeth_gn::EVP_PKEY_paramgen_init;

    #[test]
    fn dsa_parameter_setters_accept_names_and_slices() {
        // SAFETY: default library context/properties are selected and a
        // non-null result transfers one initialized context.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"DSA".as_ptr(), ptr::null())
        };
        // SAFETY: the fresh allocation is adopted exactly once.
        let mut ctx = unsafe { CBox::<EvpPkeyCtx>::from_raw(raw) }.expect("DSA context");
        assert_eq!(EVP_PKEY_paramgen_init(&mut ctx.as_mut()), 1);
        assert_eq!(
            EVP_PKEY_CTX_set_dsa_paramgen_bits(&mut ctx.as_mut(), 1024),
            1
        );
        assert_eq!(
            EVP_PKEY_CTX_set_dsa_paramgen_type(&mut ctx.as_mut(), c"fips186_4"),
            1
        );
        assert_eq!(
            EVP_PKEY_CTX_set_dsa_paramgen_seed(&mut ctx.as_mut(), b"seed"),
            1
        );
    }
}

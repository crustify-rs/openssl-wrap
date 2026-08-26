//! Wrappers assigned from `crypto/evp/p_sign.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::mem::MaybeUninit;
use core::ptr;

use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::EvpPkeyRef;
use crate::evp::evp_local::EvpMdCtxMut;

fn signature_capacity(pkey: EvpPkeyRef<'_>, output_len: usize) -> Result<(), i32> {
    // SAFETY: the shared key handle is live and the size query retains nothing.
    let required = unsafe { ffi::EVP_PKEY_get_size(pkey.as_ptr()) };
    if required < 0 || usize::try_from(required).map_or(true, |len| output_len < len) {
        return Err(0);
    }
    Ok(())
}

fn initialized_signature(output: &mut [MaybeUninit<u8>], written: u32) -> Result<&mut [u8], i32> {
    let written = written as usize;
    if written > output.len() {
        return Err(0);
    }
    // SAFETY: a successful signing call promises that its first `written`
    // output bytes were initialized, and the check keeps that prefix in bounds.
    Ok(unsafe { core::slice::from_raw_parts_mut(output.as_mut_ptr().cast(), written) })
}

/// Wraps: EVP_SignFinal
///
/// Finalizes a digest copy and writes the resulting signature into `output`.
/// The returned slice is the initialized prefix. A short buffer is rejected
/// before OpenSSL can observe or modify the digest context.
pub fn EVP_SignFinal<'out>(
    ctx: &mut EvpMdCtxMut<'_>,
    output: &'out mut [MaybeUninit<u8>],
    pkey: EvpPkeyRef<'_>,
) -> Result<&'out mut [u8], i32> {
    signature_capacity(pkey, output.len())?;
    let mut written = 0_u32;
    // SAFETY: the context is exclusively borrowed, the key is live, and the
    // capacity check supplied the documented `EVP_PKEY_get_size` byte extent.
    let status = unsafe {
        ffi::EVP_SignFinal(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            &mut written,
            pkey.as_ptr().cast_mut(),
        )
    };
    if status != 1 {
        return Err(status);
    }
    initialized_signature(output, written)
}

/// Wraps: EVP_SignFinal_ex
///
/// Finalizes and signs while selecting the library context and property query
/// used to create the temporary key-operation context.
pub fn EVP_SignFinal_ex<'out>(
    ctx: &mut EvpMdCtxMut<'_>,
    output: &'out mut [MaybeUninit<u8>],
    pkey: EvpPkeyRef<'_>,
    library_context: Option<OsslLibCtxRef<'_>>,
    property_query: Option<&CStr>,
) -> Result<&'out mut [u8], i32> {
    signature_capacity(pkey, output.len())?;
    let library_context =
        library_context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), CStr::as_ptr);
    let mut written = 0_u32;
    // SAFETY: the context is exclusively borrowed, the key and optional
    // configuration borrows remain live for the synchronous operation, and
    // the output has the capacity OpenSSL documents for this key.
    let status = unsafe {
        ffi::EVP_SignFinal_ex(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            &mut written,
            pkey.as_ptr().cast_mut(),
            library_context,
            property_query,
        )
    };
    if status != 1 {
        return Err(status);
    }
    initialized_signature(output, written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::digest::{EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_new, EVP_MD_fetch};
    use crate::evp::evp_lib::{EVP_PKEY_Q_keygen, QuickKeygen};
    use crate::evp::p_lib::EVP_PKEY_get_size;

    #[test]
    fn signing_checks_capacity_and_returns_only_initialized_bytes() {
        let key = EVP_PKEY_Q_keygen(None, None, QuickKeygen::Rsa { bits: 2048 }).expect("RSA key");
        let digest = EVP_MD_fetch(None, c"SHA2-256", None).expect("SHA-256");
        let mut ctx = EVP_MD_CTX_new().expect("digest context");
        assert_eq!(
            EVP_DigestInit_ex(&mut ctx.as_mut(), Some(digest.as_ref())),
            1
        );
        assert_eq!(EVP_DigestUpdate(&mut ctx.as_mut(), b"message"), 1);

        let required = usize::try_from(EVP_PKEY_get_size(key.as_ref())).expect("key size");
        let mut short = vec![MaybeUninit::uninit(); required - 1];
        assert_eq!(
            EVP_SignFinal(&mut ctx.as_mut(), &mut short, key.as_ref()),
            Err(0)
        );

        let mut output = vec![MaybeUninit::uninit(); required];
        let signature = EVP_SignFinal_ex(&mut ctx.as_mut(), &mut output, key.as_ref(), None, None)
            .expect("signature");
        assert!(!signature.is_empty());
        assert!(signature.len() <= required);
    }
}

//! Wrappers assigned from `crypto/evp/p_verify.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr;

use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::EvpPkeyRef;
use crate::evp::evp_local::EvpMdCtxMut;

/// Wraps: EVP_VerifyFinal
///
/// Returns `1` for a valid signature, `0` for an invalid signature, and a
/// negative status for another verification error. A signature longer than
/// `u32::MAX` has no C length to carry it, so it is refused with `-1` without
/// calling OpenSSL and without queueing an error.
///
/// Only a copy of `ctx` is finalized, so `ctx` stays usable for further
/// [`EVP_DigestUpdate`](crate::evp::digest::EVP_DigestUpdate) and verification
/// calls. Two cases finalize `ctx` itself instead: `EVP_MD_CTX_FLAG_FINALISE`
/// set on it, or a provider that cannot duplicate its digest context. The
/// exclusive borrow covers both outcomes.
///
/// `pkey` is only read. The temporary key-operation context C builds around it
/// raises its own reference and releases it before this call returns.
pub fn EVP_VerifyFinal(ctx: &mut EvpMdCtxMut<'_>, signature: &[u8], pkey: EvpPkeyRef<'_>) -> i32 {
    let Ok(signature_len) = u32::try_from(signature.len()) else {
        return -1;
    };
    // SAFETY: the context is exclusively borrowed, the signature slice is
    // readable for the converted length, and the key stays live for a call
    // that retains no reference past its return.
    unsafe {
        ffi::EVP_VerifyFinal(
            ctx.as_mut_ptr(),
            signature.as_ptr(),
            signature_len,
            pkey.as_ptr().cast_mut(),
        )
    }
}

/// Wraps: EVP_VerifyFinal_ex
///
/// Verifies while selecting the library context and property query used to
/// create the temporary key-operation context. Both borrows are needed only
/// for the synchronous call: that context is freed before the return.
///
/// Return values, the length refusal, continuation and the key borrow are
/// those of [`EVP_VerifyFinal`], which is this function with both selectors
/// omitted.
pub fn EVP_VerifyFinal_ex(
    ctx: &mut EvpMdCtxMut<'_>,
    signature: &[u8],
    pkey: EvpPkeyRef<'_>,
    library_context: Option<OsslLibCtxRef<'_>>,
    property_query: Option<&CStr>,
) -> i32 {
    let Ok(signature_len) = u32::try_from(signature.len()) else {
        return -1;
    };
    let library_context =
        library_context.map_or(ptr::null_mut(), |context| context.as_ptr().cast_mut());
    let property_query = property_query.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the context is exclusively borrowed; the signature, key, and
    // optional configuration borrows remain live for the synchronous call.
    unsafe {
        ffi::EVP_VerifyFinal_ex(
            ctx.as_mut_ptr(),
            signature.as_ptr(),
            signature_len,
            pkey.as_ptr().cast_mut(),
            library_context,
            property_query,
        )
    }
}

#[cfg(test)]
mod tests {
    use core::mem::MaybeUninit;

    use super::*;
    use crate::evp::digest::{EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_new, EVP_MD_fetch};
    use crate::evp::evp_lib::{EVP_PKEY_Q_keygen, QuickKeygen};
    use crate::evp::p_lib::EVP_PKEY_get_size;
    use crate::evp::p_sign::EVP_SignFinal;

    fn digest_message(
        digest: crate::evp::evp::EvpMdRef<'_>,
    ) -> ffibox::CBox<crate::evp::evp_local::EvpMdCtx> {
        let mut ctx = EVP_MD_CTX_new().expect("digest context");
        assert_eq!(EVP_DigestInit_ex(&mut ctx.as_mut(), Some(digest)), 1);
        assert_eq!(EVP_DigestUpdate(&mut ctx.as_mut(), b"message"), 1);
        ctx
    }

    #[test]
    fn signature_round_trip_supports_default_and_explicit_variants() {
        let key = EVP_PKEY_Q_keygen(None, None, QuickKeygen::Rsa { bits: 2048 }).expect("RSA key");
        let digest = EVP_MD_fetch(None, c"SHA2-256", None).expect("SHA-256");
        let mut signer = digest_message(digest.as_ref());
        let required = usize::try_from(EVP_PKEY_get_size(key.as_ref())).expect("key size");
        let mut output = vec![MaybeUninit::uninit(); required];
        let signature =
            EVP_SignFinal(&mut signer.as_mut(), &mut output, key.as_ref()).expect("signature");

        let mut verifier = digest_message(digest.as_ref());
        assert_eq!(
            EVP_VerifyFinal(&mut verifier.as_mut(), signature, key.as_ref()),
            1
        );

        let mut verifier = digest_message(digest.as_ref());
        assert_eq!(
            EVP_VerifyFinal_ex(&mut verifier.as_mut(), signature, key.as_ref(), None, None,),
            1
        );

        let mut verifier = digest_message(digest.as_ref());
        let mut altered = signature.to_vec();
        altered[0] ^= 1;
        assert_ne!(
            EVP_VerifyFinal(&mut verifier.as_mut(), &altered, key.as_ref()),
            1
        );

        // An empty slice has no allocation behind it; the wrapper still passes
        // a matching zero length, so C never reads through the dangling
        // pointer and simply rejects the signature.
        let mut verifier = digest_message(digest.as_ref());
        assert_ne!(
            EVP_VerifyFinal(&mut verifier.as_mut(), &[], key.as_ref()),
            1
        );
    }
}

//! Wrappers assigned from `crypto/evp/pmeth_gn.c`.

use core::ptr;

use ffibox::{CBox, CLenDropped, CVec};
use libcrypto_sys as ffi;

use crate::core::openssl_core::{OsslParam, terminated_param_len};
use crate::evp::evp::{EvpPkey, EvpPkeyCtxMut, EvpPkeyRef};

fn generate(
    context: &mut EvpPkeyCtxMut<'_>,
    operation: unsafe extern "C" fn(*mut ffi::evp_pkey_ctx_st, *mut *mut ffi::evp_pkey_st) -> i32,
) -> Result<CBox<EvpPkey>, i32> {
    let mut output = ptr::null_mut();
    // SAFETY: the exclusive context is live, and the local owner slot starts
    // null so OpenSSL either creates a fresh key or leaves no ownership behind.
    let status = unsafe { operation(context.as_mut_ptr(), &mut output) };
    if status <= 0 {
        if let Some(unexpected) =
            // SAFETY: if a failing provider nevertheless left a key in the
            // caller-owned slot, adopting and immediately dropping it prevents
            // a leak while preserving the reported failure.
            unsafe { CBox::<EvpPkey>::from_raw(output) }
        {
            drop(unexpected);
        }
        return Err(status);
    }
    // SAFETY: successful generation stores one fresh, fully initialized key
    // reference in the required output slot.
    unsafe { CBox::from_raw(output) }.ok_or(status)
}

/// Wraps: EVP_PKEY_keygen
/// Generates a fresh key and returns the original OpenSSL status on failure.
#[allow(non_snake_case)]
pub fn EVP_PKEY_keygen(context: &mut EvpPkeyCtxMut<'_>) -> Result<CBox<EvpPkey>, i32> {
    generate(context, ffi::EVP_PKEY_keygen)
}

/// Wraps: EVP_PKEY_keygen_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_keygen_init(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context permits replacing its active operation state.
    unsafe { ffi::EVP_PKEY_keygen_init(context.as_mut_ptr()) }
}

/// Wraps: EVP_PKEY_new_mac_key
/// The unsupported legacy ENGINE argument is fixed to null.
#[must_use]
#[allow(non_snake_case)]
pub fn EVP_PKEY_new_mac_key(key_type: i32, key: &[u8]) -> Option<CBox<EvpPkey>> {
    let key_len = i32::try_from(key.len()).ok()?;
    // SAFETY: null is the implementation's required ENGINE value, and the key
    // slice remains readable while OpenSSL copies it into the fresh result.
    let raw =
        unsafe { ffi::EVP_PKEY_new_mac_key(key_type, ptr::null_mut(), key.as_ptr(), key_len) };
    // SAFETY: a non-null result transfers one initialized EVP_PKEY reference.
    unsafe { CBox::from_raw(raw) }
}

/// Wraps: EVP_PKEY_paramgen
/// Generates a fresh parameter key and returns the C status on failure.
#[allow(non_snake_case)]
pub fn EVP_PKEY_paramgen(context: &mut EvpPkeyCtxMut<'_>) -> Result<CBox<EvpPkey>, i32> {
    generate(context, ffi::EVP_PKEY_paramgen)
}

/// Wraps: EVP_PKEY_paramgen_init
#[allow(non_snake_case)]
pub fn EVP_PKEY_paramgen_init(context: &mut EvpPkeyCtxMut<'_>) -> i32 {
    // SAFETY: the exclusive context permits replacing its active operation state.
    unsafe { ffi::EVP_PKEY_paramgen_init(context.as_mut_ptr()) }
}

/// Release policy for the duplicated array returned by `EVP_PKEY_todata`.
pub struct OsslParamArrayFree;

// SAFETY: this strategy is used only with the base pointer returned through
// `EVP_PKEY_todata`; `OSSL_PARAM_free` releases that complete duplicated,
// terminated array and does not require the recovered byte length.
unsafe impl CLenDropped for OsslParamArrayFree {
    unsafe fn c_drop_len(ptr: *mut u8, _byte_len: usize) {
        // SAFETY: guaranteed by the strategy's construction contract above.
        unsafe { ffi::OSSL_PARAM_free(ptr.cast()) }
    }
}

/// Owned duplicated parameter descriptors returned by `EVP_PKEY_todata`.
pub type OwnedOsslParams = CVec<OsslParam<'static>, OsslParamArrayFree>;

/// Wraps: EVP_PKEY_todata
///
/// Duplicates the selected key material into an owned parameter array. The
/// returned owner releases descriptor keys, data, and array storage together
/// with `OSSL_PARAM_free`.
#[allow(non_snake_case)]
pub fn EVP_PKEY_todata(pkey: EvpPkeyRef<'_>, selection: i32) -> Result<OwnedOsslParams, i32> {
    let mut params = ptr::null_mut();
    // SAFETY: the key handle is live and `params` is a writable out-slot.
    // Success transfers the newly duplicated array to this function.
    let status = unsafe { ffi::EVP_PKEY_todata(pkey.as_ptr(), selection, &mut params) };
    if status != 1 {
        return Err(status);
    }

    // SAFETY: success promises a live null-key-terminated duplicated array.
    let Some(len) = (unsafe { terminated_param_len(params) }) else {
        // Defensive only: a successful null result violates the C contract.
        return Err(0);
    };
    // SAFETY: the successful call transfers the base pointer exactly once;
    // the scan established `len` initialized descriptors before its terminator,
    // and this policy releases the whole allocation without needing the length.
    unsafe { CVec::from_raw_parts(params.cast::<OsslParam<'static>>(), len) }.ok_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::p_lib::EVP_PKEY_is_a;

    #[test]
    fn provider_keygen_returns_an_owned_key() {
        // SAFETY: null selects the default process context, both C strings are
        // live, and a non-null result is a uniquely owned operation context.
        let raw = unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(ptr::null_mut(), c"ED25519".as_ptr(), ptr::null())
        };
        // SAFETY: ownership of the fresh context transfers to its registered destructor.
        let mut context = unsafe { CBox::<crate::evp::evp::EvpPkeyCtx>::from_raw(raw) }
            .expect("EVP_PKEY_CTX_new_from_name");

        let mut context_mut = context.as_mut();
        assert_eq!(EVP_PKEY_keygen_init(&mut context_mut), 1);
        let key = EVP_PKEY_keygen(&mut context_mut).expect("ED25519 keygen");
        assert!(EVP_PKEY_is_a(key.as_ref(), c"ED25519"));
    }
}

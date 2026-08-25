//! Wrappers assigned from `crypto/rsa/rsa_lib.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::ptr::{self, NonNull};

#[cfg(feature = "deprecated-3-0")]
use ffibox::CBox;
use ffibox::{CSlice, CVec};
use libcrypto_sys as ffi;

#[cfg(feature = "deprecated-3-0")]
use crate::bio::bn_bn_local::Bignum;
use crate::bio::bn_bn_local::BignumRef;
use crate::evp::evp::{EvpMdRef, EvpPkeyCtxMut};
use crate::evp::pmeth_lib::{Set0BufferError, set0_buffer};
use crate::mem::CryptoFree;

/// Wraps: EVP_PKEY_CTX_get0_rsa_oaep_label
pub fn EVP_PKEY_CTX_get0_rsa_oaep_label<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> Result<CSlice<'a, u8>, i32> {
    let mut label = ptr::null_mut();
    // SAFETY: the context is exclusively borrowed and the pointer output is writable.
    let len = unsafe { ffi::EVP_PKEY_CTX_get0_rsa_oaep_label(ctx.as_mut_ptr(), &mut label) };
    if len < 0 {
        return Err(len);
    }
    let len = len as usize;
    let Some(label) = NonNull::new(label).or_else(|| (len == 0).then(NonNull::dangling)) else {
        return Err(-1);
    };
    // SAFETY: OpenSSL reported `len` initialized bytes retained by the context;
    // the exclusive borrow prevents a conflicting label replacement.
    Ok(unsafe { CSlice::from_raw_parts(label, len) })
}

/// Wraps: EVP_PKEY_CTX_get_rsa_mgf1_md
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_mgf1_md<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> (i32, Option<EvpMdRef<'a>>) {
    let mut md = ptr::null();
    // SAFETY: the context is exclusive and the pointer output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_mgf1_md(ctx.as_mut_ptr(), &mut md) };
    // SAFETY: a non-null digest is retained by the context/provider state.
    let md = unsafe { EvpMdRef::from_ptr(md.cast_mut()) };
    (status, (status > 0).then_some(md).flatten())
}

/// Wraps: EVP_PKEY_CTX_get_rsa_mgf1_md_name
pub fn EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: &mut EvpPkeyCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the context is exclusive and `output` supplies its exact writable capacity.
    unsafe {
        ffi::EVP_PKEY_CTX_get_rsa_mgf1_md_name(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    }
}

/// Wraps: EVP_PKEY_CTX_get_rsa_oaep_md
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_oaep_md<'a>(
    ctx: &'a mut EvpPkeyCtxMut<'_>,
) -> (i32, Option<EvpMdRef<'a>>) {
    let mut md = ptr::null();
    // SAFETY: the context is exclusive and the pointer output slot is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_oaep_md(ctx.as_mut_ptr(), &mut md) };
    // SAFETY: a non-null digest is retained by the context/provider state.
    let md = unsafe { EvpMdRef::from_ptr(md.cast_mut()) };
    (status, (status > 0).then_some(md).flatten())
}

/// Wraps: EVP_PKEY_CTX_get_rsa_oaep_md_name
pub fn EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: &mut EvpPkeyCtxMut<'_>, output: &mut [u8]) -> i32 {
    // SAFETY: the context is exclusive and `output` supplies its exact writable capacity.
    unsafe {
        ffi::EVP_PKEY_CTX_get_rsa_oaep_md_name(
            ctx.as_mut_ptr(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    }
}

/// Wraps: EVP_PKEY_CTX_get_rsa_padding
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_padding(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<i32>) {
    let mut padding = 0;
    // SAFETY: the context is exclusive and the local scalar output is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_padding(ctx.as_mut_ptr(), &mut padding) };
    (status, (status == 1).then_some(padding))
}

/// Wraps: EVP_PKEY_CTX_get_rsa_pss_saltlen
#[must_use]
pub fn EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: &mut EvpPkeyCtxMut<'_>) -> (i32, Option<i32>) {
    let mut salt_len = 0;
    // SAFETY: the context is exclusive and the local scalar output is writable.
    let status = unsafe { ffi::EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx.as_mut_ptr(), &mut salt_len) };
    (status, (status == 1).then_some(salt_len))
}

/// Wraps: EVP_PKEY_CTX_set0_rsa_oaep_label
pub fn EVP_PKEY_CTX_set0_rsa_oaep_label(
    ctx: &mut EvpPkeyCtxMut<'_>,
    label: CVec<u8, CryptoFree>,
) -> Result<(), Set0BufferError> {
    set0_buffer(label, |raw, len| {
        // SAFETY: `set0_buffer` surrendered an OpenSSL allocation of exactly
        // `len` bytes. This C function consumes and frees it only on status 1.
        unsafe { ffi::EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.as_mut_ptr(), raw.cast(), len) }
    })
}

fn name_and_properties(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest_name: &CStr,
    properties: Option<&CStr>,
    setter: unsafe extern "C" fn(
        *mut ffi::evp_pkey_ctx_st,
        *const core::ffi::c_char,
        *const core::ffi::c_char,
    ) -> i32,
) -> i32 {
    let properties = properties.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the exclusive context and digest name are live, and properties
    // is null or a live NUL-terminated string for the synchronous setter.
    unsafe { setter(ctx.as_mut_ptr(), digest_name.as_ptr(), properties) }
}

/// Wraps: EVP_PKEY_CTX_set_rsa_keygen_bits
pub fn EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: &mut EvpPkeyCtxMut<'_>, bits: i32) -> i32 {
    // SAFETY: the context is exclusively borrowed and C validates the
    // by-value RSA control argument for the active operation.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.as_mut_ptr(), bits) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_keygen_primes
pub fn EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: &mut EvpPkeyCtxMut<'_>, primes: i32) -> i32 {
    // SAFETY: the context is exclusively borrowed and C validates the
    // by-value RSA control argument for the active operation.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_primes(ctx.as_mut_ptr(), primes) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_mgf1_md
pub fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: &mut EvpPkeyCtxMut<'_>, digest: EvpMdRef<'static>) -> i32 {
    // SAFETY: the digest handle is immortal and the context is exclusively
    // borrowed, covering provider copying and legacy RSA control retention.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.as_mut_ptr(), digest.as_ptr()) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_mgf1_md_name
pub fn EVP_PKEY_CTX_set_rsa_mgf1_md_name(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest_name: &CStr,
    properties: Option<&CStr>,
) -> i32 {
    name_and_properties(
        ctx,
        digest_name,
        properties,
        ffi::EVP_PKEY_CTX_set_rsa_mgf1_md_name,
    )
}
/// Wraps: EVP_PKEY_CTX_set_rsa_oaep_md
pub fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: &mut EvpPkeyCtxMut<'_>, digest: EvpMdRef<'static>) -> i32 {
    // SAFETY: the digest handle is immortal and the context is exclusively
    // borrowed, covering provider copying and legacy RSA control retention.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_oaep_md(ctx.as_mut_ptr(), digest.as_ptr()) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_oaep_md_name
pub fn EVP_PKEY_CTX_set_rsa_oaep_md_name(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest_name: &CStr,
    properties: Option<&CStr>,
) -> i32 {
    name_and_properties(
        ctx,
        digest_name,
        properties,
        ffi::EVP_PKEY_CTX_set_rsa_oaep_md_name,
    )
}
/// Wraps: EVP_PKEY_CTX_set_rsa_padding
pub fn EVP_PKEY_CTX_set_rsa_padding(ctx: &mut EvpPkeyCtxMut<'_>, padding: i32) -> i32 {
    // SAFETY: the context is exclusively borrowed and C validates the
    // by-value RSA control argument for the active operation.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_padding(ctx.as_mut_ptr(), padding) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_pss_keygen_md
pub fn EVP_PKEY_CTX_set_rsa_pss_keygen_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest: EvpMdRef<'static>,
) -> i32 {
    // SAFETY: the digest handle is immortal and the context is exclusively
    // borrowed, covering provider copying and legacy RSA control retention.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_pss_keygen_md(ctx.as_mut_ptr(), digest.as_ptr()) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_pss_keygen_md_name
pub fn EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest_name: &CStr,
    properties: Option<&CStr>,
) -> i32 {
    name_and_properties(
        ctx,
        digest_name,
        properties,
        ffi::EVP_PKEY_CTX_set_rsa_pss_keygen_md_name,
    )
}
/// Wraps: EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md
pub fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest: EvpMdRef<'static>,
) -> i32 {
    // SAFETY: the digest handle is immortal and the context is exclusively
    // borrowed, covering provider copying and legacy RSA control retention.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(ctx.as_mut_ptr(), digest.as_ptr()) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name
pub fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(
    ctx: &mut EvpPkeyCtxMut<'_>,
    digest_name: &CStr,
) -> i32 {
    // SAFETY: the exclusive context and NUL-terminated digest name remain live
    // for the synchronous RSA parameter setter.
    unsafe {
        ffi::EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx.as_mut_ptr(), digest_name.as_ptr())
    }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen
pub fn EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: &mut EvpPkeyCtxMut<'_>, salt_len: i32) -> i32 {
    // SAFETY: the context is exclusively borrowed and C validates the
    // by-value RSA control argument for the active operation.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx.as_mut_ptr(), salt_len) }
}
/// Wraps: EVP_PKEY_CTX_set_rsa_pss_saltlen
pub fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: &mut EvpPkeyCtxMut<'_>, salt_len: i32) -> i32 {
    // SAFETY: the context is exclusively borrowed and C validates the
    // by-value RSA control argument for the active operation.
    unsafe { ffi::EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx.as_mut_ptr(), salt_len) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bio::bn_bn_local::Bignum;
    use crate::evp::pmeth_lib::EVP_PKEY_CTX_new_from_name;
    use ffibox::CBox;

    fn public_exponent() -> CBox<Bignum> {
        // SAFETY: OpenSSL returns null or one fresh initialized BIGNUM.
        let raw = unsafe { ffi::BN_new() };
        // SAFETY: ownership of the fresh result transfers to the registered
        // BIGNUM owner and its matching BN_free destructor.
        let mut exponent = unsafe { CBox::<Bignum>::from_raw(raw) }.expect("BIGNUM");
        // SAFETY: the exclusive handle supplies a live writable BIGNUM.
        assert_eq!(
            unsafe { ffi::BN_set_word(exponent.as_mut().as_mut_ptr(), 65_537) },
            1
        );
        exponent
    }

    #[test]
    fn rsa_outputs_are_initialized_only_on_success() {
        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"RSA", None).expect("RSA context");
        let mut handle = ctx.as_mut();
        let (status, padding) = EVP_PKEY_CTX_get_rsa_padding(&mut handle);
        assert_eq!(padding.is_some(), status == 1);
        let (status, salt_len) = EVP_PKEY_CTX_get_rsa_pss_saltlen(&mut handle);
        assert_eq!(salt_len.is_some(), status == 1);
        let mut name = [0_u8; 80];
        assert!(EVP_PKEY_CTX_get_rsa_oaep_md_name(&mut handle, &mut name) <= 1);
    }
    #[test]
    fn keygen_setters_use_typed_values_and_names() {
        use crate::evp::pmeth_gn::EVP_PKEY_keygen_init;

        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"RSA-PSS", None).expect("RSA-PSS context");
        assert_eq!(EVP_PKEY_keygen_init(&mut ctx.as_mut()), 1);
        assert_eq!(EVP_PKEY_CTX_set_rsa_keygen_bits(&mut ctx.as_mut(), 1024), 1);
        assert_eq!(
            EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(&mut ctx.as_mut(), c"SHA256", None),
            1
        );
    }

    #[test]
    fn set1_public_exponent_copies_a_borrowed_bignum() {
        use crate::evp::pmeth_gn::EVP_PKEY_keygen_init;

        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"RSA", None).expect("RSA context");
        assert_eq!(EVP_PKEY_keygen_init(&mut ctx.as_mut()), 1);
        let exponent = public_exponent();
        let raw = exponent.as_ptr();

        assert_eq!(
            EVP_PKEY_CTX_set1_rsa_keygen_pubexp(&mut ctx.as_mut(), exponent.as_ref()),
            1
        );
        assert_eq!(exponent.as_ptr(), raw);
    }

    #[cfg(feature = "deprecated-3-0")]
    #[test]
    fn deprecated_set0_returns_owner_on_failure() {
        let mut ctx = EVP_PKEY_CTX_new_from_name(None, c"DH", None).expect("DH context");
        let exponent = public_exponent();
        let raw = exponent.as_ptr();

        let Err(error) = EVP_PKEY_CTX_set_rsa_keygen_pubexp(&mut ctx.as_mut(), exponent) else {
            panic!("an RSA control must not succeed on a DH context");
        };
        assert!(error.status() <= 0);
        assert_eq!(error.into_public_exponent().as_ptr(), raw);
    }
}

/// Wraps: EVP_PKEY_CTX_set1_rsa_keygen_pubexp
///
/// OpenSSL copies the public exponent before this function returns.
pub fn EVP_PKEY_CTX_set1_rsa_keygen_pubexp(
    ctx: &mut EvpPkeyCtxMut<'_>,
    public_exponent: BignumRef<'_>,
) -> i32 {
    // SAFETY: the context is exclusive and the live exponent is only read
    // while OpenSSL duplicates it or copies it into provider parameters.
    unsafe {
        ffi::EVP_PKEY_CTX_set1_rsa_keygen_pubexp(
            ctx.as_mut_ptr(),
            public_exponent.as_ptr().cast_mut(),
        )
    }
}

/// Failure from the deprecated set0 RSA exponent operation.
#[cfg(feature = "deprecated-3-0")]
#[must_use]
pub struct SetRsaKeygenPubexpError {
    status: i32,
    public_exponent: CBox<Bignum>,
}

#[cfg(feature = "deprecated-3-0")]
impl SetRsaKeygenPubexpError {
    /// Original OpenSSL status.
    #[must_use]
    pub fn status(&self) -> i32 {
        self.status
    }

    /// Recover the exponent that OpenSSL did not consume.
    pub fn into_public_exponent(self) -> CBox<Bignum> {
        self.public_exponent
    }
}

/// Wraps: EVP_PKEY_CTX_set_rsa_keygen_pubexp
///
/// Transfers the public exponent to OpenSSL on success and returns it on
/// failure. Prefer [`EVP_PKEY_CTX_set1_rsa_keygen_pubexp`].
#[cfg(feature = "deprecated-3-0")]
pub fn EVP_PKEY_CTX_set_rsa_keygen_pubexp(
    ctx: &mut EvpPkeyCtxMut<'_>,
    public_exponent: CBox<Bignum>,
) -> Result<(), SetRsaKeygenPubexpError> {
    let raw = public_exponent.into_raw();
    // SAFETY: `raw` transfers one complete BIGNUM owner to this set0 call and
    // the exclusive context permits replacing its key-generation exponent.
    let status = unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx.as_mut_ptr(), raw) };
    if status > 0 {
        Ok(())
    } else {
        // SAFETY: the C implementation takes custody only on positive status;
        // this failure path therefore still owns the exact surrendered value.
        let public_exponent =
            unsafe { CBox::from_raw(raw) }.expect("CBox always has a non-null pointer");
        Err(SetRsaKeygenPubexpError {
            status,
            public_exponent,
        })
    }
}

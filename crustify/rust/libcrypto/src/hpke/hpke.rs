//! Wrappers assigned from `crypto/hpke/hpke.c`.

#![allow(non_snake_case)]

use core::ffi::CStr;
use core::marker::PhantomData;
use core::ptr;

use ffibox::{CBox, define_ctype, impl_dropped};
use libcrypto_sys as ffi;

use crate::bio::context::OsslLibCtxRef;
use crate::evp::evp::EvpPkeyRef;
use crate::evp::p_lib::BorrowedEvpPkey;
use crate::hpke::openssl_hpke::{OsslHpkeSuiteMut, OsslHpkeSuiteRef};

define_ctype!(
    /// Wraps: ossl_hpke_ctx_st
    ///
    /// Opaque handle target for an OpenSSL HPKE sender or receiver context.
    /// Its algorithm state and secret buffers remain C-owned. Contexts are
    /// uniquely owned and borrow the library context supplied at construction.
    OsslHpkeCtx,
    OsslHpkeCtxRef,
    OsslHpkeCtxMut,
    ffi::ossl_hpke_ctx_st
);

// Releases fetched algorithms, duplicated keys and all copied secret buffers,
// clears secrets, and finally frees the unique context allocation.
impl_dropped!(OsslHpkeCtx, ffi::ossl_hpke_ctx_st, ffi::OSSL_HPKE_CTX_free);

/// Wraps: OSSL_HPKE_CTX_free
/// An HPKE context retaining the library-context lifetime used to build it;
/// dropping the owner invokes the matching C destructor.
#[must_use = "dropping the owner releases the HPKE context"]
pub struct BorrowedOsslHpkeCtx<'a> {
    inner: CBox<OsslHpkeCtx>,
    borrow: PhantomData<OsslLibCtxRef<'a>>,
}

impl BorrowedOsslHpkeCtx<'_> {
    unsafe fn from_raw(raw: *mut ffi::ossl_hpke_ctx_st) -> Option<Self> {
        // SAFETY: the caller transfers one initialized context and chooses the
        // lifetime covering its stored library-context pointer.
        unsafe { CBox::from_raw(raw) }.map(|inner| Self {
            inner,
            borrow: PhantomData,
        })
    }

    /// Borrow the context without write access.
    #[must_use]
    pub fn as_ref(&self) -> OsslHpkeCtxRef<'_> {
        self.inner.as_ref()
    }

    /// Exclusively borrow the context.
    #[must_use]
    pub fn as_mut(&mut self) -> OsslHpkeCtxMut<'_> {
        self.inner.as_mut()
    }
}

fn suite_value(suite: OsslHpkeSuiteRef<'_>) -> ffi::OSSL_HPKE_SUITE {
    // SAFETY: the shared suite handle covers a live initialized, pointer-free
    // value which the C API itself accepts by value.
    unsafe { suite.as_ptr().read() }
}

fn optional_cstr(value: Option<&CStr>) -> *const core::ffi::c_char {
    value.map_or(ptr::null(), CStr::as_ptr)
}

fn optional_bytes(value: Option<&[u8]>) -> (*const u8, usize) {
    value.map_or((ptr::null(), 0), |bytes| (bytes.as_ptr(), bytes.len()))
}

/// Wraps: OSSL_HPKE_CTX_new
/// Creates a sender or receiver context tied to its optional library context.
#[must_use]
pub fn OSSL_HPKE_CTX_new<'a>(
    mode: i32,
    suite: OsslHpkeSuiteRef<'_>,
    role: i32,
    libctx: Option<OsslLibCtxRef<'a>>,
    properties: Option<&CStr>,
) -> Option<BorrowedOsslHpkeCtx<'a>> {
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: the optional context and property string are live; OpenSSL copies
    // the property query and returns null or one initialized context.
    let raw = unsafe {
        ffi::OSSL_HPKE_CTX_new(
            mode,
            suite_value(suite),
            role,
            libctx,
            optional_cstr(properties),
        )
    };
    // SAFETY: a successful result transfers one free obligation and stores at
    // most the library-context borrow represented by `'a`.
    unsafe { BorrowedOsslHpkeCtx::from_raw(raw) }
}

/// Wraps: OSSL_HPKE_CTX_get_seq
/// Reads the current message sequence number.
#[must_use]
pub fn OSSL_HPKE_CTX_get_seq(ctx: OsslHpkeCtxRef<'_>) -> Option<u64> {
    let mut sequence = 0;
    // SAFETY: the shared handle is live; despite the C signature, the function
    // only reads the context and writes the local output slot.
    (unsafe { ffi::OSSL_HPKE_CTX_get_seq(ctx.as_ptr().cast_mut(), &mut sequence) } == 1)
        .then_some(sequence)
}

/// Wraps: OSSL_HPKE_CTX_set1_authpriv
/// Deep-copies an authentication private key into a sender context.
///
/// # Safety
///
/// Any library context retained by `private_key`'s provider implementation
/// must outlive the HPKE context, because the copied key inherits that
/// dependency and the context type cannot add it after construction.
pub unsafe fn OSSL_HPKE_CTX_set1_authpriv(
    ctx: &mut OsslHpkeCtxMut<'_>,
    private_key: EvpPkeyRef<'_>,
) -> i32 {
    // SAFETY: the caller establishes the copied key's provider lifetime and
    // both typed handles are live for the synchronous duplication.
    unsafe { ffi::OSSL_HPKE_CTX_set1_authpriv(ctx.as_mut_ptr(), private_key.as_ptr().cast_mut()) }
}

/// Wraps: OSSL_HPKE_CTX_set1_authpub
/// Validates and copies an encoded authentication public key.
pub fn OSSL_HPKE_CTX_set1_authpub(ctx: &mut OsslHpkeCtxMut<'_>, public_key: &[u8]) -> i32 {
    // SAFETY: the exclusive context is live and the byte slice supplies the
    // exact readable extent; OpenSSL stores only its own normalized copy.
    unsafe {
        ffi::OSSL_HPKE_CTX_set1_authpub(ctx.as_mut_ptr(), public_key.as_ptr(), public_key.len())
    }
}

/// Wraps: OSSL_HPKE_CTX_set1_ikme
/// Copies deterministic sender key-generation material into the context.
pub fn OSSL_HPKE_CTX_set1_ikme(ctx: &mut OsslHpkeCtxMut<'_>, ikm: &[u8]) -> i32 {
    // SAFETY: the slice covers the readable extent and OpenSSL stores a copy.
    unsafe { ffi::OSSL_HPKE_CTX_set1_ikme(ctx.as_mut_ptr(), ikm.as_ptr(), ikm.len()) }
}

/// Wraps: OSSL_HPKE_CTX_set1_psk
/// Copies a pre-shared key and its NUL-terminated identifier.
pub fn OSSL_HPKE_CTX_set1_psk(ctx: &mut OsslHpkeCtxMut<'_>, id: &CStr, psk: &[u8]) -> i32 {
    // SAFETY: the identifier is NUL-terminated, the key slice is readable, and
    // OpenSSL stores independent copies of both.
    unsafe { ffi::OSSL_HPKE_CTX_set1_psk(ctx.as_mut_ptr(), id.as_ptr(), psk.as_ptr(), psk.len()) }
}

/// Wraps: OSSL_HPKE_CTX_set_seq
/// Changes a receiver context's message sequence number.
pub fn OSSL_HPKE_CTX_set_seq(ctx: &mut OsslHpkeCtxMut<'_>, sequence: u64) -> i32 {
    // SAFETY: the exclusive handle supplies a live context for the mutation.
    unsafe { ffi::OSSL_HPKE_CTX_set_seq(ctx.as_mut_ptr(), sequence) }
}

/// Wraps: OSSL_HPKE_decap
/// Establishes a receiver context from an encapsulated key and private key.
pub fn OSSL_HPKE_decap(
    ctx: &mut OsslHpkeCtxMut<'_>,
    encapsulated: &[u8],
    recipient_private: EvpPkeyRef<'_>,
    info: &[u8],
) -> i32 {
    // SAFETY: all handles and slices are live for the synchronous operation;
    // OpenSSL retains none of the caller-provided pointers.
    unsafe {
        ffi::OSSL_HPKE_decap(
            ctx.as_mut_ptr(),
            encapsulated.as_ptr(),
            encapsulated.len(),
            recipient_private.as_ptr().cast_mut(),
            info.as_ptr(),
            info.len(),
        )
    }
}

/// Wraps: OSSL_HPKE_encap
/// Establishes a sender context and writes the public encapsulation.
pub fn OSSL_HPKE_encap(
    ctx: &mut OsslHpkeCtxMut<'_>,
    encapsulated: &mut [u8],
    recipient_public: &[u8],
    info: &[u8],
) -> Result<usize, i32> {
    if encapsulated.is_empty() {
        return Err(0);
    }
    let mut written = encapsulated.len();
    // SAFETY: the output slice covers its in/out capacity and both inputs are
    // readable for their exact lengths throughout the synchronous operation.
    let status = unsafe {
        ffi::OSSL_HPKE_encap(
            ctx.as_mut_ptr(),
            encapsulated.as_mut_ptr(),
            &mut written,
            recipient_public.as_ptr(),
            recipient_public.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    if status == 1 && written <= encapsulated.len() {
        Ok(written)
    } else {
        Err(status)
    }
}

/// Wraps: OSSL_HPKE_export
/// Derives exactly `secret.len()` exporter bytes under an optional label.
pub fn OSSL_HPKE_export(ctx: &mut OsslHpkeCtxMut<'_>, secret: &mut [u8], label: &[u8]) -> i32 {
    // SAFETY: the exclusive handle is live, `secret` supplies the writable
    // extent and `label` supplies the readable extent; neither is retained.
    unsafe {
        ffi::OSSL_HPKE_export(
            ctx.as_mut_ptr(),
            secret.as_mut_ptr(),
            secret.len(),
            label.as_ptr(),
            label.len(),
        )
    }
}

/// Wraps: OSSL_HPKE_get_ciphertext_size
/// Returns the ciphertext size for a suite and cleartext length.
#[must_use]
pub fn OSSL_HPKE_get_ciphertext_size(suite: OsslHpkeSuiteRef<'_>, cleartext_len: usize) -> usize {
    // SAFETY: the by-value suite contains only initialized integer identifiers.
    unsafe { ffi::OSSL_HPKE_get_ciphertext_size(suite_value(suite), cleartext_len) }
}

/// Wraps: OSSL_HPKE_get_grease_value
/// Produces a syntactically valid random GREASE suite, encapsulation and ciphertext.
pub fn OSSL_HPKE_get_grease_value(
    requested: Option<OsslHpkeSuiteRef<'_>>,
    chosen: &mut OsslHpkeSuiteMut<'_>,
    encapsulated: &mut [u8],
    ciphertext: &mut [u8],
    libctx: Option<OsslLibCtxRef<'_>>,
    properties: Option<&CStr>,
) -> Result<usize, i32> {
    if encapsulated.is_empty() || ciphertext.is_empty() {
        return Err(0);
    }
    let requested_value = requested.map(suite_value);
    let requested_ptr = requested_value.as_ref().map_or(ptr::null(), ptr::from_ref);
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    let mut written = encapsulated.len();
    // SAFETY: all optional pointers are null or live; both output slices cover
    // the supplied extents and `chosen` supplies exclusive suite storage.
    let status = unsafe {
        ffi::OSSL_HPKE_get_grease_value(
            requested_ptr,
            chosen.as_mut_ptr(),
            encapsulated.as_mut_ptr(),
            &mut written,
            ciphertext.as_mut_ptr(),
            ciphertext.len(),
            libctx,
            optional_cstr(properties),
        )
    };
    if status == 1 && written <= encapsulated.len() {
        Ok(written)
    } else {
        Err(status)
    }
}

/// Wraps: OSSL_HPKE_get_public_encap_size
/// Returns the public encapsulation size for a suite.
#[must_use]
pub fn OSSL_HPKE_get_public_encap_size(suite: OsslHpkeSuiteRef<'_>) -> usize {
    // SAFETY: the by-value suite contains only initialized integer identifiers.
    unsafe { ffi::OSSL_HPKE_get_public_encap_size(suite_value(suite)) }
}

/// Wraps: OSSL_HPKE_get_recommended_ikmelen
/// Returns the suite's recommended deterministic key-generation input length.
#[must_use]
pub fn OSSL_HPKE_get_recommended_ikmelen(suite: OsslHpkeSuiteRef<'_>) -> usize {
    // SAFETY: the by-value suite contains only initialized integer identifiers.
    unsafe { ffi::OSSL_HPKE_get_recommended_ikmelen(suite_value(suite)) }
}

/// Wraps: OSSL_HPKE_keygen
/// Generates a private key and writes its encoded public key.
pub fn OSSL_HPKE_keygen<'a>(
    suite: OsslHpkeSuiteRef<'_>,
    public_key: &mut [u8],
    ikm: Option<&[u8]>,
    libctx: Option<OsslLibCtxRef<'a>>,
    properties: Option<&CStr>,
) -> Result<(usize, BorrowedEvpPkey<'a>), i32> {
    if public_key.is_empty() || ikm.is_some_and(<[u8]>::is_empty) {
        return Err(0);
    }
    let mut written = public_key.len();
    let mut private = ptr::null_mut();
    let (ikm, ikm_len) = optional_bytes(ikm);
    let libctx = libctx.map_or(ptr::null_mut(), |ctx| ctx.as_ptr().cast_mut());
    // SAFETY: output capacity and all optional input pointers are valid for the
    // synchronous call; a successful private key is returned through `private`.
    let status = unsafe {
        ffi::OSSL_HPKE_keygen(
            suite_value(suite),
            public_key.as_mut_ptr(),
            &mut written,
            &mut private,
            ikm,
            ikm_len,
            libctx,
            optional_cstr(properties),
        )
    };
    if status != 1 {
        return Err(status);
    }
    // SAFETY: success transfers one initialized private-key reference whose
    // provider dependency is bounded by the supplied library-context lifetime.
    let private = unsafe { BorrowedEvpPkey::from_raw(private) }.ok_or(0)?;
    if written > public_key.len() {
        return Err(0);
    }
    Ok((written, private))
}

/// Wraps: OSSL_HPKE_open
/// Authenticates and decrypts a ciphertext into caller-owned storage.
pub fn OSSL_HPKE_open(
    ctx: &mut OsslHpkeCtxMut<'_>,
    plaintext: &mut [u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<usize, i32> {
    if plaintext.is_empty() || ciphertext.is_empty() {
        return Err(0);
    }
    let mut written = plaintext.len();
    // SAFETY: the output slice covers its in/out capacity and both input slices
    // cover their exact readable lengths for the synchronous operation.
    let status = unsafe {
        ffi::OSSL_HPKE_open(
            ctx.as_mut_ptr(),
            plaintext.as_mut_ptr(),
            &mut written,
            aad.as_ptr(),
            aad.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
        )
    };
    if status == 1 && written <= plaintext.len() {
        Ok(written)
    } else {
        Err(status)
    }
}

/// Wraps: OSSL_HPKE_seal
/// Encrypts and authenticates plaintext into caller-owned storage.
pub fn OSSL_HPKE_seal(
    ctx: &mut OsslHpkeCtxMut<'_>,
    ciphertext: &mut [u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<usize, i32> {
    if ciphertext.is_empty() || plaintext.is_empty() {
        return Err(0);
    }
    let mut written = ciphertext.len();
    // SAFETY: the output slice covers its in/out capacity and both input slices
    // cover their exact readable lengths for the synchronous operation.
    let status = unsafe {
        ffi::OSSL_HPKE_seal(
            ctx.as_mut_ptr(),
            ciphertext.as_mut_ptr(),
            &mut written,
            aad.as_ptr(),
            aad.len(),
            plaintext.as_ptr(),
            plaintext.len(),
        )
    };
    if status == 1 && written <= ciphertext.len() {
        Ok(written)
    } else {
        Err(status)
    }
}

/// Wraps: OSSL_HPKE_str2suite
/// Parses a NUL-terminated suite name into caller-owned suite storage.
pub fn OSSL_HPKE_str2suite(name: &CStr, suite: &mut OsslHpkeSuiteMut<'_>) -> i32 {
    // SAFETY: the name is NUL-terminated and the exclusive handle supplies a
    // writable initialized suite record.
    unsafe { ffi::OSSL_HPKE_str2suite(name.as_ptr(), suite.as_mut_ptr()) }
}

/// Wraps: OSSL_HPKE_suite_check
/// Reports whether all three suite identifiers form a supported combination.
#[must_use]
pub fn OSSL_HPKE_suite_check(suite: OsslHpkeSuiteRef<'_>) -> bool {
    // SAFETY: the by-value suite contains only initialized integer identifiers.
    unsafe { ffi::OSSL_HPKE_suite_check(suite_value(suite)) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpke::openssl_hpke::OsslHpkeSuite;

    #[test]
    fn suite_queries_and_context_sequence_are_typed() {
        let suite = OsslHpkeSuite::new(0x20, 0x01, 0xffff);
        assert!(OSSL_HPKE_suite_check(suite.as_ref()));
        assert!(OSSL_HPKE_get_public_encap_size(suite.as_ref()) > 0);
        let mut context =
            OSSL_HPKE_CTX_new(0, suite.as_ref(), 1, None, None).expect("receiver context");
        assert_eq!(OSSL_HPKE_CTX_get_seq(context.as_ref()), Some(0));
        assert_eq!(OSSL_HPKE_CTX_set_seq(&mut context.as_mut(), 7), 1);
        assert_eq!(OSSL_HPKE_CTX_get_seq(context.as_ref()), Some(7));
    }

    #[test]
    fn string_parser_writes_through_an_exclusive_suite_handle() {
        let mut suite = OsslHpkeSuite::new(0, 0, 0);
        assert_eq!(
            OSSL_HPKE_str2suite(c"X25519,HKDF-SHA256,EXPORTER", &mut suite.as_mut()),
            1
        );
        assert!(OSSL_HPKE_suite_check(suite.as_ref()));
    }

    #[test]
    fn sender_and_receiver_complete_an_authenticated_round_trip() {
        let suite = OsslHpkeSuite::new(0x20, 0x01, 0x01);
        let mut public = [0_u8; 133];
        let (public_len, private) =
            OSSL_HPKE_keygen(suite.as_ref(), &mut public, None, None, None).expect("keygen");
        let mut sender = OSSL_HPKE_CTX_new(0, suite.as_ref(), 0, None, None).expect("sender");
        let mut receiver = OSSL_HPKE_CTX_new(0, suite.as_ref(), 1, None, None).expect("receiver");

        let mut encapsulated = [0_u8; 133];
        let enc_len = OSSL_HPKE_encap(
            &mut sender.as_mut(),
            &mut encapsulated,
            &public[..public_len],
            b"context",
        )
        .expect("encap");
        assert_eq!(
            OSSL_HPKE_decap(
                &mut receiver.as_mut(),
                &encapsulated[..enc_len],
                private.as_ref(),
                b"context",
            ),
            1
        );

        let plaintext = b"HPKE safe wrapper";
        let mut ciphertext =
            vec![0_u8; OSSL_HPKE_get_ciphertext_size(suite.as_ref(), plaintext.len())];
        let ciphertext_len =
            OSSL_HPKE_seal(&mut sender.as_mut(), &mut ciphertext, b"aad", plaintext).expect("seal");
        let mut opened = vec![0_u8; plaintext.len()];
        let opened_len = OSSL_HPKE_open(
            &mut receiver.as_mut(),
            &mut opened,
            b"aad",
            &ciphertext[..ciphertext_len],
        )
        .expect("open");
        assert_eq!(&opened[..opened_len], plaintext);

        let mut sender_secret = [0_u8; 32];
        let mut receiver_secret = [0_u8; 32];
        assert_eq!(
            OSSL_HPKE_export(&mut sender.as_mut(), &mut sender_secret, b"label"),
            1
        );
        assert_eq!(
            OSSL_HPKE_export(&mut receiver.as_mut(), &mut receiver_secret, b"label"),
            1
        );
        assert_eq!(sender_secret, receiver_secret);
    }

    #[test]
    fn copied_setup_inputs_and_grease_outputs_use_bounded_storage() {
        let suite = OsslHpkeSuite::new(0x20, 0x01, 0x01);
        let mut public = [0_u8; 133];
        let (public_len, private) =
            OSSL_HPKE_keygen(suite.as_ref(), &mut public, None, None, None).expect("keygen");
        let mut psk = OSSL_HPKE_CTX_new(1, suite.as_ref(), 0, None, None).expect("PSK sender");
        assert_eq!(
            OSSL_HPKE_CTX_set1_psk(&mut psk.as_mut(), c"test-id", &[7_u8; 32]),
            1
        );
        assert_eq!(OSSL_HPKE_CTX_set1_ikme(&mut psk.as_mut(), &[9_u8; 32]), 1);

        let mut auth_sender =
            OSSL_HPKE_CTX_new(2, suite.as_ref(), 0, None, None).expect("auth sender");
        // SAFETY: `private` lives longer than `auth_sender` and both use the
        // process-wide library context, so the copied key's provider does too.
        assert_eq!(
            unsafe { OSSL_HPKE_CTX_set1_authpriv(&mut auth_sender.as_mut(), private.as_ref()) },
            1
        );
        let mut auth_receiver =
            OSSL_HPKE_CTX_new(2, suite.as_ref(), 1, None, None).expect("auth receiver");
        assert_eq!(
            OSSL_HPKE_CTX_set1_authpub(&mut auth_receiver.as_mut(), &public[..public_len],),
            1
        );

        let mut chosen = OsslHpkeSuite::new(0, 0, 0);
        let mut encapsulated = [0_u8; 133];
        let mut ciphertext = [0_u8; 32];
        let written = OSSL_HPKE_get_grease_value(
            Some(suite.as_ref()),
            &mut chosen.as_mut(),
            &mut encapsulated,
            &mut ciphertext,
            None,
            None,
        )
        .expect("grease");
        assert_eq!(written, OSSL_HPKE_get_public_encap_size(chosen.as_ref()));
        assert!(OSSL_HPKE_get_recommended_ikmelen(chosen.as_ref()) > 0);
    }
}

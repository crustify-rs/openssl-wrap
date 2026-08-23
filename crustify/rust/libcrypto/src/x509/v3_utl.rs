//! Wrappers assigned from `crypto/x509/v3_utl.c`.

use core::ffi::c_void;
use core::ptr::{self, NonNull};

use ffibox::{CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::stack::openssl_safestack::OpenSslStringStack;
use crate::x509::x509_internal::X509Ref;

unsafe extern "C" fn free_collected_string(string: *mut c_void) {
    // SAFETY: both collection routines allocate every stored string with the
    // active OpenSSL allocator, and the pop-free callback transfers it once.
    unsafe { ffi::CRYPTO_free(string, ptr::null(), 0) };
}

/// Full teardown policy for the strings returned by `X509_get1_email` and
/// `X509_get1_ocsp`.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmailAddressesFree;

// SAFETY: the result stack uniquely owns every OpenSSL-allocated string and
// the pointer array; pop-free invokes the allocator-matched callback once per
// element and then releases the stack.
unsafe impl CDropper<OpenSslStringStack> for EmailAddressesFree {
    unsafe fn c_drop(&self, object: NonNull<OpenSslStringStack>) {
        // SAFETY: the dropper contract supplies sole ownership of the complete
        // result and its generated stack erases to `OPENSSL_STACK`.
        unsafe { ffi::OPENSSL_sk_pop_free(object.as_ptr().cast(), Some(free_collected_string)) }
    }
}

/// An owned list of NUL-terminated email-address strings.
pub type EmailAddresses = CBoxWith<OpenSslStringStack, EmailAddressesFree>;

/// An owned list of NUL-terminated OCSP responder URI strings.
pub type OcspResponderUris = CBoxWith<OpenSslStringStack, EmailAddressesFree>;

/// Wraps: X509_get1_email
/// Collects independently allocated email addresses from a certificate.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get1_email(certificate: X509Ref<'_>) -> Option<EmailAddresses> {
    // SAFETY: the shared certificate remains live for the call. A non-null
    // result owns its stack and every string under `EmailAddressesFree`.
    unsafe {
        CBoxWith::from_raw(
            ffi::X509_get1_email(certificate.as_ptr()).cast(),
            EmailAddressesFree,
        )
    }
}

/// Wraps: X509_get1_ocsp
/// Collects independently allocated OCSP responder URIs from a certificate.
#[must_use]
#[allow(non_snake_case)]
pub fn X509_get1_ocsp(certificate: X509Ref<'_>) -> Option<OcspResponderUris> {
    // SAFETY: the shared certificate remains live for the call. A non-null
    // result owns its stack and every URI string under `EmailAddressesFree`.
    unsafe {
        CBoxWith::from_raw(
            ffi::X509_get1_ocsp(certificate.as_ptr()).cast(),
            EmailAddressesFree,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;
    use crate::x509::x_x509::X509_new;

    #[test]
    fn empty_certificate_has_no_collected_email_addresses() {
        let certificate = X509_new().expect("certificate");
        if let Some(addresses) = X509_get1_email(certificate.as_ref()) {
            assert_eq!(OPENSSL_sk_num(Some(addresses.as_ref())), Some(0));
        }
    }

    #[test]
    fn empty_certificate_has_no_ocsp_responder_uris() {
        let certificate = X509_new().expect("certificate");
        assert!(X509_get1_ocsp(certificate.as_ref()).is_none());
    }
}

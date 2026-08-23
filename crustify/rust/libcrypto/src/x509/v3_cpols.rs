//! Wrappers assigned from `crypto/x509/v3_cpols.c`.

use core::ptr::NonNull;

use ffibox::{CBox, CBoxWith, CDropper};
use libcrypto_sys as ffi;

use crate::x509::x509v3::{PolicyInfo, PolicyInfoStack};

/// Full ASN.1 teardown policy for a certificate-policies sequence.
#[derive(Clone, Copy, Debug, Default)]
pub struct CertificatePoliciesFree;

// SAFETY: the generated destructor releases every owned POLICYINFO and the
// stack allocation exactly once.
unsafe impl CDropper<PolicyInfoStack> for CertificatePoliciesFree {
    unsafe fn c_drop(&self, object: NonNull<PolicyInfoStack>) {
        // SAFETY: the dropper contract supplies a complete uniquely owned
        // generated stack, pointer-compatible with `OPENSSL_STACK`.
        unsafe { ffi::CERTIFICATEPOLICIES_free(object.as_ptr().cast()) }
    }
}

/// A certificate-policies stack that owns all policy-info elements.
pub type OwnedCertificatePolicies = CBoxWith<PolicyInfoStack, CertificatePoliciesFree>;

/// Wraps: CERTIFICATEPOLICIES_free
#[allow(non_snake_case)]
pub fn CERTIFICATEPOLICIES_free(value: OwnedCertificatePolicies) {
    drop(value);
}

/// Wraps: CERTIFICATEPOLICIES_new
#[must_use]
#[allow(non_snake_case)]
pub fn CERTIFICATEPOLICIES_new() -> Option<OwnedCertificatePolicies> {
    // SAFETY: a non-null constructor result is a fresh complete empty sequence
    // owing one matching full destruction.
    unsafe {
        CBoxWith::from_raw(
            ffi::CERTIFICATEPOLICIES_new().cast(),
            CertificatePoliciesFree,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::stack::OPENSSL_sk_num;

    #[test]
    fn constructor_returns_an_empty_owned_sequence() {
        let value = CERTIFICATEPOLICIES_new().expect("CERTIFICATEPOLICIES_new");
        assert_eq!(OPENSSL_sk_num(Some(value.as_ref())), Some(0));
        CERTIFICATEPOLICIES_free(value);
    }
}

/// Wraps: POLICYINFO_free
/// Consumes an optional complete certificate-policy record.
#[allow(non_snake_case)]
pub fn POLICYINFO_free(value: Option<CBox<PolicyInfo>>) {
    drop(value);
}

/// Wraps: POLICYINFO_new
/// Allocates an empty certificate-policy record.
#[must_use]
#[allow(non_snake_case)]
pub fn POLICYINFO_new() -> Option<CBox<PolicyInfo>> {
    // SAFETY: a non-null result is a fresh complete ASN.1 sequence whose
    // matching destructor is registered on `PolicyInfo`.
    unsafe { CBox::from_raw(ffi::POLICYINFO_new()) }
}

#[cfg(test)]
mod policy_info_tests {
    use super::*;

    #[test]
    fn constructor_returns_an_owned_empty_record() {
        let value = POLICYINFO_new().expect("POLICYINFO_new");
        assert!(value.as_ref().policy_id().is_some());
        assert!(value.as_ref().qualifiers().is_none());
        POLICYINFO_free(Some(value));
        POLICYINFO_free(None);
    }
}

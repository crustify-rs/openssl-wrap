//! Wrappers assigned from `crypto/x509/v3_lib.c`.

use core::ffi::c_void;
use core::ptr;

use ffibox::CBoxWith;
use libcrypto_sys as ffi;

use crate::x509::v3_cpols::{CertificatePoliciesFree, OwnedCertificatePolicies};
use crate::x509::v3_crld::{CrlDistPoints, CrlDistPointsFree};
use crate::x509::v3_extku::{ExtendedKeyUsage, ExtendedKeyUsageFree};
use crate::x509::v3_genn::{GeneralNames, GeneralNamesFree};
use crate::x509::v3_info::{AuthorityInfoAccess, AuthorityInfoAccessFree};
use crate::x509::v3_tlsf::{TlsFeature, TlsFeatureFree};
use crate::x509::x509::X509ExtensionStackRef;

/// Extension syntaxes whose decoded ownership is represented by this wrapper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X509V3ExtensionKind {
    AuthorityInfoAccess,
    CertificatePolicies,
    CrlDistributionPoints,
    ExtendedKeyUsage,
    GeneralNames,
    TlsFeature,
}

impl X509V3ExtensionKind {
    pub(crate) fn nid(self) -> i32 {
        match self {
            Self::AuthorityInfoAccess => ffi::NID_info_access as i32,
            Self::CertificatePolicies => ffi::NID_certificate_policies as i32,
            Self::CrlDistributionPoints => ffi::NID_crl_distribution_points as i32,
            Self::ExtendedKeyUsage => ffi::NID_ext_key_usage as i32,
            Self::GeneralNames => ffi::NID_subject_alt_name as i32,
            Self::TlsFeature => ffi::NID_tlsfeature as i32,
        }
    }
}

/// A decoded extension paired with the full destructor for its syntax.
pub enum DecodedX509V3Extension {
    AuthorityInfoAccess(AuthorityInfoAccess),
    CertificatePolicies(OwnedCertificatePolicies),
    CrlDistributionPoints(CrlDistPoints),
    ExtendedKeyUsage(ExtendedKeyUsage),
    GeneralNames(GeneralNames),
    TlsFeature(TlsFeature),
}

/// Successful decoded-extension metadata.
pub struct X509V3Decoded {
    pub value: DecodedX509V3Extension,
    pub critical: bool,
}

/// Reason an extension could not be decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum X509V3DecodeError {
    NotFound,
    Duplicate,
    DecodeFailed { critical: bool },
}

unsafe fn adopt_decoded(
    kind: X509V3ExtensionKind,
    raw: *mut c_void,
) -> Option<DecodedX509V3Extension> {
    match kind {
        X509V3ExtensionKind::AuthorityInfoAccess => {
            // SAFETY: the caller establishes the syntax selected by `kind`.
            unsafe { CBoxWith::from_raw(raw.cast(), AuthorityInfoAccessFree) }
                .map(DecodedX509V3Extension::AuthorityInfoAccess)
        }
        X509V3ExtensionKind::CertificatePolicies => {
            // SAFETY: the caller establishes the syntax selected by `kind`.
            unsafe { CBoxWith::from_raw(raw.cast(), CertificatePoliciesFree) }
                .map(DecodedX509V3Extension::CertificatePolicies)
        }
        X509V3ExtensionKind::CrlDistributionPoints => {
            // SAFETY: the caller establishes the syntax selected by `kind`.
            unsafe { CBoxWith::from_raw(raw.cast(), CrlDistPointsFree) }
                .map(DecodedX509V3Extension::CrlDistributionPoints)
        }
        X509V3ExtensionKind::ExtendedKeyUsage => {
            // SAFETY: the caller establishes the syntax selected by `kind`.
            unsafe { CBoxWith::from_raw(raw.cast(), ExtendedKeyUsageFree) }
                .map(DecodedX509V3Extension::ExtendedKeyUsage)
        }
        X509V3ExtensionKind::GeneralNames => {
            // SAFETY: the caller establishes the syntax selected by `kind`.
            unsafe { CBoxWith::from_raw(raw.cast(), GeneralNamesFree) }
                .map(DecodedX509V3Extension::GeneralNames)
        }
        X509V3ExtensionKind::TlsFeature => {
            // SAFETY: the caller establishes the syntax selected by `kind`.
            unsafe { CBoxWith::from_raw(raw.cast(), TlsFeatureFree) }
                .map(DecodedX509V3Extension::TlsFeature)
        }
    }
}

/// Classifies one `X509V3_EXT_d2i` outcome and adopts a decoded extension.
///
/// # Safety
///
/// A non-null `raw` must be a freshly decoded, solely owned extension of the
/// exact syntax `kind` names, produced by a lookup keyed on `kind.nid()`. The
/// adopted owner runs that syntax's full destructor, so any other pointer
/// would free storage under the wrong ASN.1 template.
pub(crate) unsafe fn decode_result(
    kind: X509V3ExtensionKind,
    critical: i32,
    raw: *mut c_void,
) -> Result<X509V3Decoded, X509V3DecodeError> {
    if raw.is_null() {
        return Err(match critical {
            -1 => X509V3DecodeError::NotFound,
            -2 => X509V3DecodeError::Duplicate,
            value => X509V3DecodeError::DecodeFailed {
                critical: value > 0,
            },
        });
    }
    // SAFETY: the caller guarantees `raw` came from decoding exactly
    // `kind.nid()`, so its concrete syntax and matching full destructor are
    // selected by the same enum arm.
    let value = unsafe { adopt_decoded(kind, raw) }.expect("raw was checked non-null");
    Ok(X509V3Decoded {
        value,
        critical: critical > 0,
    })
}

/// Wraps: X509V3_get_d2i
/// Finds and decodes one uniquely occurring extension with typed destruction.
#[allow(non_snake_case)]
pub fn X509V3_get_d2i(
    extensions: Option<X509ExtensionStackRef<'_>>,
    kind: X509V3ExtensionKind,
) -> Result<X509V3Decoded, X509V3DecodeError> {
    let extensions = extensions.map_or(ptr::null(), |value| value.as_ptr());
    let mut critical = -1;
    // SAFETY: the optional shared stack is live for the call, `critical` is a
    // valid output, and a null index requests duplicate rejection.
    let raw = unsafe {
        ffi::X509V3_get_d2i(
            extensions.cast(),
            kind.nid(),
            &mut critical,
            ptr::null_mut(),
        )
    };
    // SAFETY: the lookup above is keyed on `kind.nid()`, so a non-null result
    // is a freshly decoded, solely owned extension of exactly that syntax.
    unsafe { decode_result(kind, critical, raw) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_stack_reports_not_found_for_every_typed_syntax() {
        for kind in [
            X509V3ExtensionKind::AuthorityInfoAccess,
            X509V3ExtensionKind::CertificatePolicies,
            X509V3ExtensionKind::CrlDistributionPoints,
            X509V3ExtensionKind::ExtendedKeyUsage,
            X509V3ExtensionKind::GeneralNames,
            X509V3ExtensionKind::TlsFeature,
        ] {
            assert!(matches!(
                X509V3_get_d2i(None, kind),
                Err(X509V3DecodeError::NotFound)
            ));
        }
    }
}

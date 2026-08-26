//! Wrappers assigned from `include/openssl/hpke.h`.

use core::ptr::{NonNull, addr_of, addr_of_mut};

use ffibox::{CVal, CValued, define_ctype};
use libcrypto_sys as ffi;

define_ctype!(
    /// Wraps: OSSL_HPKE_SUITE
    ///
    /// Layout-compatible storage for the public HPKE algorithm identifiers.
    /// The record contains no pointers and owns no resources, so it can be
    /// held inline and copied into OpenSSL's by-value suite arguments.
    OsslHpkeSuite,
    OsslHpkeSuiteRef,
    OsslHpkeSuiteMut,
    ffi::OSSL_HPKE_SUITE
);

// SAFETY: the public record contains only three integers and owns no resource,
// so disposing Rust-owned inline storage is intentionally a no-op.
unsafe impl CValued for OsslHpkeSuite {
    unsafe fn c_dispose(_this: NonNull<Self>) {}
}

impl OsslHpkeSuite {
    /// Construct an inline HPKE suite value.
    #[must_use]
    pub fn new(kem_id: u16, kdf_id: u16, aead_id: u16) -> CVal<Self> {
        let mut suite = CVal::new(Self::zeroed());
        {
            let mut value = suite.as_mut();
            value.set_kem_id(kem_id);
            value.set_kdf_id(kdf_id);
            value.set_aead_id(aead_id);
        }
        suite
    }
}

impl OsslHpkeSuiteRef<'_> {
    /// Field: OSSL_HPKE_SUITE.aead_id
    ///
    /// The AEAD algorithm identifier.
    #[must_use]
    pub fn aead_id(&self) -> u16 {
        // SAFETY: the handle covers a live initialized suite; raw-place
        // projection copies its integer without forming a reference.
        unsafe { addr_of!((*self.as_ptr()).aead_id).read() }
    }

    /// Field: OSSL_HPKE_SUITE.kdf_id
    ///
    /// The key-derivation-function identifier.
    #[must_use]
    pub fn kdf_id(&self) -> u16 {
        // SAFETY: the handle covers a live initialized suite; raw-place
        // projection copies its integer without forming a reference.
        unsafe { addr_of!((*self.as_ptr()).kdf_id).read() }
    }

    /// Field: OSSL_HPKE_SUITE.kem_id
    ///
    /// The key-encapsulation-method identifier.
    #[must_use]
    pub fn kem_id(&self) -> u16 {
        // SAFETY: the handle covers a live initialized suite; raw-place
        // projection copies its integer without forming a reference.
        unsafe { addr_of!((*self.as_ptr()).kem_id).read() }
    }
}

impl OsslHpkeSuiteMut<'_> {
    /// Replace the AEAD algorithm identifier.
    pub fn set_aead_id(&mut self, value: u16) {
        // SAFETY: the exclusive handle supplies write provenance to the live
        // field; raw-place projection forms no reference.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).aead_id).write(value) }
    }

    /// Replace the key-derivation-function identifier.
    pub fn set_kdf_id(&mut self, value: u16) {
        // SAFETY: the exclusive handle supplies write provenance to the live
        // field; raw-place projection forms no reference.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).kdf_id).write(value) }
    }

    /// Replace the key-encapsulation-method identifier.
    pub fn set_kem_id(&mut self, value: u16) {
        // SAFETY: the exclusive handle supplies write provenance to the live
        // field; raw-place projection forms no reference.
        unsafe { addr_of_mut!((*self.as_mut_ptr()).kem_id).write(value) }
    }
}

#[cfg(test)]
mod tests {
    use core::mem::{align_of, size_of};

    use super::*;

    #[test]
    fn suite_layout_and_field_access_match_c() {
        assert_eq!(
            size_of::<OsslHpkeSuite>(),
            size_of::<ffi::OSSL_HPKE_SUITE>()
        );
        assert_eq!(
            align_of::<OsslHpkeSuite>(),
            align_of::<ffi::OSSL_HPKE_SUITE>()
        );

        let mut suite = OsslHpkeSuite::new(0x20, 0x01, 0x02);
        assert_eq!(suite.as_ref().kem_id(), 0x20);
        assert_eq!(suite.as_ref().kdf_id(), 0x01);
        assert_eq!(suite.as_ref().aead_id(), 0x02);

        suite.as_mut().set_aead_id(0x03);
        assert_eq!(suite.as_ref().aead_id(), 0x03);
    }
}
